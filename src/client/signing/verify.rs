// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Port of `VerifyWithFetcher` (Go `client/utils/verify`).

use std::collections::HashSet;

use super::keys::{verify_signature_with_key, KeyVerifier};
use super::oidc::OidcVerifier;
use crate::error::Result;
use crate::models::core_v1::RecordRef;
use crate::models::sign_v1::{
    signer_info, verify_request_provider::Request, Signature, SignerInfo, SignerInfoKey, VerifyOptionsOidc,
    VerifyRequest, VerifyRequestProvider, VerifyResponse, VerifyWithAny,
};

/// Supplies signatures and public keys for a record.
pub trait Fetcher {
    async fn pull_signatures(&self, record_ref: &RecordRef) -> Result<Vec<Signature>>;
    async fn pull_public_keys(&self, record_ref: &RecordRef) -> Result<Vec<String>>;
}

fn failure(message: &str) -> VerifyResponse {
    VerifyResponse {
        success: false,
        signers: Vec::new(),
        error_message: Some(message.into()),
    }
}

/// Verifies a signature against the given public keys (PEM or key
/// references); the first key that verifies wins.
fn verify_with_keys(payload: &[u8], public_keys: &[String], signature: &Signature) -> Option<SignerInfo> {
    public_keys.iter().find_map(|key| {
        let verifier: KeyVerifier = verify_signature_with_key(key, &signature.signature, payload).ok()?;
        Some(SignerInfo {
            r#type: Some(signer_info::Type::Key(SignerInfoKey {
                public_key: verifier.public_key_pem().ok()?,
                algorithm: verifier.algorithm(),
            })),
        })
    })
}

fn signer_key(signer: &SignerInfo) -> String {
    match &signer.r#type {
        Some(signer_info::Type::Key(k)) => format!("key:{}\0{}", k.public_key, k.algorithm),
        Some(signer_info::Type::Oidc(o)) => format!("oidc:{}\0{}\0{}", o.issuer, o.subject, o.certificate_issuer),
        None => String::new(),
    }
}

/// Lazily builds (and reuses) the trusted material for OIDC verification.
struct LazyOidc<'a> {
    opts: Option<&'a VerifyOptionsOidc>,
    verifier: Option<std::result::Result<OidcVerifier, String>>,
}

impl<'a> LazyOidc<'a> {
    fn new(opts: Option<&'a VerifyOptionsOidc>) -> Self {
        Self { opts, verifier: None }
    }

    async fn verify(
        &mut self,
        payload: &[u8],
        issuer: &str,
        subject: &str,
        signature: &Signature,
    ) -> std::result::Result<SignerInfo, String> {
        if self.verifier.is_none() {
            self.verifier = Some(OidcVerifier::new(self.opts).await.map_err(|e| e.to_string()));
        }
        match self.verifier.as_ref() {
            Some(Ok(v)) => v.verify(payload, issuer, subject, signature).map_err(|e| e.to_string()),
            Some(Err(e)) => Err(e.clone()),
            None => unreachable!("verifier initialised above"),
        }
    }
}

/// Runs signature verification for `req` with signatures and keys from `fetcher`.
pub async fn verify_with_fetcher(req: &VerifyRequest, fetcher: &impl Fetcher) -> Result<VerifyResponse> {
    let record_ref = match req.record_ref.as_ref() {
        Some(r) if !r.cid.is_empty() => r,
        _ => return Err(crate::error::Error::InvalidArgument("record ref is required".into())),
    };

    // Default provider: any valid signer with default OIDC options.
    let default_provider = VerifyRequestProvider {
        request: Some(Request::Any(VerifyWithAny {
            oidc_options: Some(VerifyOptionsOidc::default()),
        })),
    };
    let provider = match req.provider.as_ref() {
        Some(p) if p.request.is_some() => p,
        _ => &default_provider,
    };
    let request = provider.request.as_ref().expect("provider has a request");

    let signatures = fetcher.pull_signatures(record_ref).await?;
    if signatures.is_empty() {
        return Ok(failure("no signatures found"));
    }

    let public_keys = match request {
        Request::Key(k) => vec![k.public_key.clone()],
        Request::Any(_) => fetcher.pull_public_keys(record_ref).await?,
        Request::Oidc(_) => Vec::new(),
    };

    let payload = record_ref.cid.as_bytes();
    let any_opts = match request {
        Request::Any(a) => a.oidc_options.as_ref(),
        _ => None,
    };
    let oidc_opts = match request {
        Request::Oidc(o) => o.options.as_ref(),
        _ => None,
    };
    let mut oidc = LazyOidc::new(if matches!(request, Request::Oidc(_)) {
        oidc_opts
    } else {
        any_opts
    });

    let mut seen = HashSet::new();
    let mut signers = Vec::new();
    for sig in &signatures {
        let info = match request {
            Request::Oidc(p) => oidc.verify(payload, &p.issuer, &p.subject, sig).await.ok(),
            Request::Key(_) => verify_with_keys(payload, &public_keys, sig),
            Request::Any(_) if sig.content_bundle.is_empty() => verify_with_keys(payload, &public_keys, sig),
            Request::Any(_) => oidc.verify(payload, "", "", sig).await.ok(),
        };
        // Failed verifications carry no SignerInfo; one result per signer.
        let Some(info) = info else { continue };
        if seen.insert(signer_key(&info)) {
            signers.push(info);
        }
    }

    if signers.is_empty() {
        return Ok(failure("no valid signatures found matching verification criteria"));
    }
    Ok(VerifyResponse {
        success: true,
        signers,
        error_message: None,
    })
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    use super::*;
    use crate::client::signing::keys::tests::{COSIGN_KEY, COSIGN_PASSWORD};
    use crate::client::signing::keys::{detect_key_algorithm, load_private_key};
    use crate::models::sign_v1::{VerifyWithKey, VerifyWithOidc};

    struct Fixed {
        sigs: Vec<Signature>,
        keys: Vec<String>,
    }

    impl Fetcher for Fixed {
        async fn pull_signatures(&self, _: &RecordRef) -> Result<Vec<Signature>> {
            Ok(self.sigs.clone())
        }
        async fn pull_public_keys(&self, _: &RecordRef) -> Result<Vec<String>> {
            Ok(self.keys.clone())
        }
    }

    fn request(cid: &str, request: Option<Request>) -> VerifyRequest {
        VerifyRequest {
            record_ref: Some(RecordRef { cid: cid.into() }),
            provider: request.map(|r| VerifyRequestProvider { request: Some(r) }),
            from_server: false,
        }
    }

    fn signed(cid: &str) -> (Signature, String) {
        let signer = load_private_key(COSIGN_KEY, COSIGN_PASSWORD).unwrap();
        let pem = signer.public_key_pem().unwrap();
        let sig = Signature {
            signature: B64.encode(signer.sign(cid.as_bytes()).unwrap()),
            algorithm: detect_key_algorithm(&pem),
            ..Default::default()
        };
        (sig, pem)
    }

    #[tokio::test]
    async fn any_provider_with_pulled_key_verifies_and_dedupes() {
        let (sig, pem) = signed("bafy1");
        let fetcher = Fixed {
            sigs: vec![sig.clone(), sig],
            keys: vec!["junk".into(), pem.clone()],
        };
        // no provider -> default (any)
        let resp = verify_with_fetcher(&request("bafy1", None), &fetcher).await.unwrap();
        assert!(resp.success, "{:?}", resp.error_message);
        assert_eq!(resp.signers.len(), 1);
        match &resp.signers[0].r#type {
            Some(signer_info::Type::Key(k)) => {
                assert_eq!(k.public_key, pem);
                assert_eq!(k.algorithm, "ECDSA-P-256");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn key_provider_uses_supplied_key_only() {
        let (sig, pem) = signed("bafy1");
        let fetcher = Fixed {
            sigs: vec![sig],
            keys: vec![],
        };
        let ok = request("bafy1", Some(Request::Key(VerifyWithKey { public_key: pem })));
        assert!(verify_with_fetcher(&ok, &fetcher).await.unwrap().success);

        // wrong payload (different CID) must not verify
        let other = request(
            "bafy2",
            Some(Request::Key(VerifyWithKey {
                public_key: String::new(),
            })),
        );
        let resp = verify_with_fetcher(&other, &fetcher).await.unwrap();
        assert!(!resp.success);
        assert_eq!(
            resp.error_message.as_deref(),
            Some("no valid signatures found matching verification criteria")
        );
    }

    #[tokio::test]
    async fn cid_mismatch_with_pulled_keys_fails() {
        let (sig, pem) = signed("bafy1");
        let fetcher = Fixed {
            sigs: vec![sig],
            keys: vec![pem],
        };
        let resp = verify_with_fetcher(&request("bafy2", None), &fetcher).await.unwrap();
        assert!(!resp.success);
    }

    #[tokio::test]
    async fn no_signatures_found() {
        let fetcher = Fixed {
            sigs: vec![],
            keys: vec![],
        };
        let resp = verify_with_fetcher(&request("bafy1", None), &fetcher).await.unwrap();
        assert!(!resp.success);
        assert_eq!(resp.error_message.as_deref(), Some("no signatures found"));
    }

    #[tokio::test]
    async fn requires_record_ref() {
        let fetcher = Fixed {
            sigs: vec![],
            keys: vec![],
        };
        assert!(verify_with_fetcher(&VerifyRequest::default(), &fetcher).await.is_err());
    }

    #[tokio::test]
    async fn oidc_provider_rejects_key_signature_and_garbage_bundle() {
        let (sig, _) = signed("bafy1");
        let mut bundle_sig = sig.clone();
        bundle_sig.content_bundle = "{not a bundle".into();
        let fetcher = Fixed {
            sigs: vec![sig, bundle_sig],
            keys: vec![],
        };
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root.json");
        std::fs::write(&root, sigstore_trust_root::SIGSTORE_PRODUCTION_TRUSTED_ROOT).unwrap();
        let req = request(
            "bafy1",
            Some(Request::Oidc(VerifyWithOidc {
                issuer: String::new(),
                subject: String::new(),
                options: Some(VerifyOptionsOidc {
                    trusted_root_path: root.to_string_lossy().into(),
                    ..Default::default()
                }),
            })),
        );
        let resp = verify_with_fetcher(&req, &fetcher).await.unwrap();
        assert!(!resp.success);
    }
}
