// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Keyless (Sigstore) signing and bundle verification.
//!
//! Signing mirrors `SignBlobWithOIDC` of the Go SDK: an ephemeral ECDSA P-256
//! key, a Fulcio certificate for the supplied identity token, an optional
//! Rekor `hashedrekord` entry (unless `skip_tlog`) and an RFC 3161 timestamp,
//! packaged as a Sigstore v0.3 message-signature bundle. The Fulcio / Rekor /
//! TSA protocol work is done by the `sigstore-*` crates.
//!
//! Verification mirrors `VerifyWithOIDC`: the bundle is verified against a
//! Sigstore trusted root (TUF mirror or a local `trusted_root.json`) by
//! `sigstore-verify`, then the signer identity is matched against the
//! requested issuer / subject.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use regex::Regex;
use sigstore_bundle::BundleV03;
use sigstore_crypto::{sha256, KeyPair};
use sigstore_fulcio::{reqwest, FulcioClient};
use sigstore_oidc::IdentityToken;
use sigstore_rekor::{HashedRekord, RekorClient};
use sigstore_trust_root::{SigstoreInstance, TrustedRoot, TufBootstrap, TufConfig};
use sigstore_tsa::TimestampClient;
use sigstore_types::{Bundle, KindVersion};
use sigstore_verify::{VerificationPolicy, Verifier};
use x509_cert::der::Decode;

use crate::error::{Error, Result};
use crate::models::sign_v1::{
    signer_info, PublicKey, SignOptionsOidc, SignWithOidc, Signature, SignerInfo, SignerInfoOidc, VerifyOptionsOidc,
};

pub const DEFAULT_FULCIO_URL: &str = "https://fulcio.sigstore.dev";
pub const DEFAULT_REKOR_URL: &str = "https://rekor.sigstore.dev";
pub const DEFAULT_TIMESTAMP_URL: &str = "https://timestamp.sigstore.dev/api/v1/timestamp";
pub const DEFAULT_TUF_MIRROR_URL: &str = "https://tuf-repo-cdn.sigstore.dev";

const FULCIO_TIMEOUT: Duration = Duration::from_secs(30);
const TIMESTAMP_AUTHORITY_TIMEOUT: Duration = Duration::from_secs(30);
const REKOR_TIMEOUT: Duration = Duration::from_secs(90);

fn or_default(value: &str, default: &str) -> String {
    if value.is_empty() { default } else { value }.to_string()
}

fn http_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| Error::Sign(format!("failed to build HTTP client: {e}")))
}

/// Signs `payload` keylessly with the identity in `req.id_token`.
pub async fn sign_blob_with_oidc(payload: &[u8], req: &SignWithOidc) -> Result<(Signature, PublicKey)> {
    let signed_at = chrono::Utc::now();
    let defaults = SignOptionsOidc::default();
    let opts = req.options.as_ref().unwrap_or(&defaults);

    let fulcio_url = or_default(&opts.fulcio_url, DEFAULT_FULCIO_URL);
    let rekor_url = or_default(&opts.rekor_url, DEFAULT_REKOR_URL);
    let tsa_url = or_default(&opts.timestamp_url, DEFAULT_TIMESTAMP_URL);

    if req.id_token.is_empty() {
        return Err(Error::Sign(
            "failed to sign record: id_token is required for OIDC signing".into(),
        ));
    }
    let token = IdentityToken::from_jwt(&req.id_token)
        .map_err(|e| Error::Sign(format!("failed to sign record: invalid identity token: {e}")))?;

    // Ephemeral keypair
    let key_pair =
        KeyPair::generate_ecdsa_p256().map_err(|e| Error::Sign(format!("failed to create ephemeral keypair: {e}")))?;
    let public_key_pem = key_pair
        .public_key_der()
        .map_err(|e| Error::Sign(format!("failed to get public key: {e}")))?
        .to_pem();

    // Certificate from Fulcio
    let fulcio = FulcioClient::builder(&fulcio_url)
        .with_http_client(http_client(FULCIO_TIMEOUT)?)
        .build()
        .map_err(|e| Error::Sign(format!("failed to create Fulcio client: {e}")))?;
    let leaf = fulcio
        .create_signing_certificate(&token, &key_pair)
        .await
        .map_err(|e| Error::Sign(format!("failed to sign record: Fulcio: {e}")))?
        .leaf_certificate()
        .clone();

    // Sign the payload digest (message-signature bundle)
    let artifact_hash = sha256(payload);
    let signature = key_pair
        .sign_digest(&artifact_hash)
        .map_err(|e| Error::Sign(format!("failed to sign record: {e}")))?;

    // Transparency log entry (unless skipped)
    let tlog_entry = if opts.skip_tlog {
        None
    } else {
        let rekor = RekorClient::builder(&rekor_url)
            .with_http_client(http_client(REKOR_TIMEOUT)?)
            .build()
            .map_err(|e| Error::Sign(format!("failed to create Rekor client: {e}")))?;
        let entry = rekor
            .create_entry(HashedRekord::new(&artifact_hash, &signature, &leaf))
            .await
            .map_err(|e| Error::Sign(format!("failed to sign record: Rekor: {e}")))?;
        Some(
            entry
                .to_bundle_entry(KindVersion::HashedRekordV001)
                .map_err(|e| Error::Sign(format!("failed to sign record: invalid Rekor response: {e}")))?,
        )
    };

    // RFC 3161 timestamp over the signature
    let tsa = TimestampClient::builder(&tsa_url)
        .with_http_client(http_client(TIMESTAMP_AUTHORITY_TIMEOUT)?)
        .build()
        .map_err(|e| Error::Sign(format!("failed to create timestamp client: {e}")))?;
    let timestamp = tsa
        .timestamp_signature(&signature)
        .await
        .map_err(|e| Error::Sign(format!("failed to sign record: timestamp authority: {e}")))?;

    let mut bundle = BundleV03::with_certificate_and_signature(leaf.clone(), signature.clone(), artifact_hash)
        .with_rfc3161_timestamp(timestamp);
    if let Some(entry) = tlog_entry {
        bundle = bundle.with_tlog_entry(entry);
    }
    let bundle = bundle.into_bundle();
    let bundle_json = bundle
        .to_json()
        .map_err(|e| Error::Sign(format!("failed to marshal bundle to JSON: {e}")))?;

    let signature = Signature {
        signature: B64.encode(signature.as_bytes()),
        certificate: B64.encode(leaf.as_bytes()),
        content_type: bundle.media_type().as_str().to_string(),
        content_bundle: bundle_json,
        signed_at: signed_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ..Default::default()
    };
    Ok((signature, PublicKey { key: public_key_pem }))
}

// --- verification ----------------------------------------------------------

/// Identity matcher with the Go SDK semantics: empty matches anything, a value
/// that is a valid regular expression is matched as a regexp, anything else
/// exactly. Regular expressions must match the whole value (anchored).
pub struct ValueMatcher {
    exact: Option<String>,
    regex: Option<Regex>,
}

impl ValueMatcher {
    pub fn new(value: &str) -> Self {
        if value.is_empty() {
            return Self {
                exact: None,
                regex: None,
            };
        }
        match Regex::new(&format!("^(?:{value})$")) {
            Ok(re) if Regex::new(value).is_ok() => Self {
                exact: None,
                regex: Some(re),
            },
            _ => Self {
                exact: Some(value.to_string()),
                regex: None,
            },
        }
    }

    pub fn matches(&self, actual: &str) -> bool {
        match (&self.exact, &self.regex) {
            (Some(exact), _) => exact == actual,
            (None, Some(re)) => re.is_match(actual),
            (None, None) => true,
        }
    }
}

/// Loads the trusted root selected by the verify options: a local file, or a
/// TUF mirror (default: the public-good Sigstore mirror).
pub async fn load_trusted_root(opts: &VerifyOptionsOidc) -> Result<TrustedRoot> {
    if !opts.trusted_root_path.is_empty() {
        return TrustedRoot::from_file(&opts.trusted_root_path).map_err(|e| {
            Error::Verify(format!(
                "failed to load trusted root from path {}: {e}",
                opts.trusted_root_path
            ))
        });
    }
    let url = or_default(&opts.tuf_mirror_url, DEFAULT_TUF_MIRROR_URL);
    let instance = if url.contains("sigstage") {
        SigstoreInstance::Staging
    } else {
        SigstoreInstance::PublicGood
    };
    let config = TufConfig::custom(url, TufBootstrap::trusted(instance.tuf_root()));
    TrustedRoot::from_tuf(config)
        .await
        .map_err(|e| Error::Verify(format!("failed to fetch trusted root from TUF: {e}")))
}

/// Verifies Sigstore bundles against one trusted root.
pub struct OidcVerifier {
    verifier: Verifier,
    opts: VerifyOptionsOidc,
}

impl OidcVerifier {
    /// Applies the Go defaults to `opts` and loads the trusted material.
    pub async fn new(opts: Option<&VerifyOptionsOidc>) -> Result<Self> {
        let mut opts = opts.cloned().unwrap_or_default();
        if opts.tuf_mirror_url.is_empty() {
            opts.tuf_mirror_url = DEFAULT_TUF_MIRROR_URL.into();
        }
        let root = load_trusted_root(&opts)
            .await
            .map_err(|e| Error::Verify(format!("failed to get trusted material: {e}")))?;
        let verifier = Verifier::new(&root).map_err(|e| Error::Verify(format!("failed to create verifier: {e}")))?;
        Ok(Self { verifier, opts })
    }

    /// Verifies the bundle in `signature` over `payload` and checks the
    /// signer against `issuer` / `subject`.
    ///
    /// Fails closed. Compared with sigstore-go (see `docs`): the certificate
    /// chain is always verified, a verified time source (TSA timestamp or
    /// SET-backed Rekor time) is always required, and `ignore_tlog` +
    /// `ignore_tsa` together (verification at "current time") is not
    /// supported for bundles that carry no verifiable time.
    pub fn verify(&self, payload: &[u8], issuer: &str, subject: &str, signature: &Signature) -> Result<SignerInfo> {
        let fail = |msg: String| Error::Verify(format!("verification failed: {msg}"));

        let bundle = Bundle::from_json(&signature.content_bundle)
            .map_err(|e| Error::Verify(format!("failed to parse bundle: {e}")))?;

        let mut policy = VerificationPolicy::any_identity();
        if self.opts.ignore_tlog {
            policy = policy.skip_tlog_unsafe();
        }
        if self.opts.ignore_sct {
            policy = policy.skip_sct();
        }
        let result = self
            .verifier
            .verify(payload, &bundle, &policy)
            .map_err(|e| fail(e.to_string()))?;

        // Requirements the library does not enforce on its own.
        if !result.certificate_verified() {
            return Err(fail("certificate chain was not verified".into()));
        }
        if !self.opts.ignore_sct && !result.sct_verified() {
            return Err(fail("signed certificate timestamp was not verified".into()));
        }
        if !self.opts.ignore_tlog && (!result.tlog_verified() || bundle.verification_material.tlog_entries.is_empty()) {
            return Err(fail("no transparency log entry verified".into()));
        }
        if !self.opts.ignore_tsa
            && bundle
                .verification_material
                .timestamp_verification_data
                .rfc3161_timestamps
                .is_empty()
        {
            return Err(fail("no signed timestamp found".into()));
        }

        let cert_issuer = result.issuer().unwrap_or_default();
        let cert_subject = result.identity().map(|i| i.as_str()).unwrap_or_default();
        if !ValueMatcher::new(issuer).matches(cert_issuer) {
            return Err(fail(format!(
                "certificate issuer {cert_issuer:?} does not match {issuer:?}"
            )));
        }
        if !ValueMatcher::new(subject).matches(cert_subject) {
            return Err(fail(format!(
                "certificate subject {cert_subject:?} does not match {subject:?}"
            )));
        }

        let certificate_issuer = bundle
            .signing_certificate()
            .and_then(|c| x509_cert::Certificate::from_der(c.as_bytes()).ok())
            .map(|c| c.tbs_certificate.issuer.to_string())
            .unwrap_or_default();

        Ok(SignerInfo {
            r#type: Some(signer_info::Type::Oidc(SignerInfoOidc {
                issuer: cert_issuer.to_string(),
                subject: cert_subject.to_string(),
                certificate_issuer,
            })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matcher_semantics() {
        // empty: anything
        assert!(ValueMatcher::new("").matches("whatever"));
        // regex, anchored
        let re = ValueMatcher::new("https://github.com/agntcy/.*");
        assert!(re.matches("https://github.com/agntcy/dir/.github/workflows/x.yml@refs/heads/main"));
        assert!(!re.matches("https://evil.example/https://github.com/agntcy/dir"));
        let partial = ValueMatcher::new("agntcy");
        assert!(partial.matches("agntcy"));
        assert!(!partial.matches("https://github.com/agntcy"));
        // alternation must not escape the anchors
        let alt = ValueMatcher::new("a|b");
        assert!(alt.matches("a") && alt.matches("b") && !alt.matches("ab") && !alt.matches("xa"));
        // not a valid regexp: exact match
        let exact = ValueMatcher::new("user(@example.com");
        assert!(exact.matches("user(@example.com"));
        assert!(!exact.matches("user"));
    }

    #[tokio::test]
    async fn sign_requires_id_token() {
        let err = sign_blob_with_oidc(b"cid", &SignWithOidc::default()).await.unwrap_err();
        assert!(err.to_string().contains("id_token"), "{err}");
    }

    #[tokio::test]
    async fn trusted_root_from_missing_path_fails() {
        let opts = VerifyOptionsOidc {
            trusted_root_path: "/definitely/not/there.json".into(),
            ..Default::default()
        };
        assert!(load_trusted_root(&opts).await.is_err());
    }

    // --- bundle verification against a real cosign v3 bundle (public-good
    // root, embedded in sigstore-trust-root). Fixture from sigstore-rust
    // (Apache-2.0), signed by a GitHub-login identity.

    const BUNDLE: &str = include_str!("testdata/cosign-v3-blob.sigstore.json");
    const PAYLOAD: &[u8] = include_bytes!("testdata/cosign-v3-blob.txt");

    async fn verifier(opts: VerifyOptionsOidc) -> (OidcVerifier, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("trusted_root.json");
        std::fs::write(&root, sigstore_trust_root::SIGSTORE_PRODUCTION_TRUSTED_ROOT).unwrap();
        let opts = VerifyOptionsOidc {
            trusted_root_path: root.to_string_lossy().into(),
            ..opts
        };
        (OidcVerifier::new(Some(&opts)).await.unwrap(), dir)
    }

    fn sig(bundle: &str) -> Signature {
        Signature {
            content_bundle: bundle.into(),
            ..Default::default()
        }
    }

    fn bundle_without(field: &str) -> String {
        let mut v: serde_json::Value = serde_json::from_str(BUNDLE).unwrap();
        let material = v["verificationMaterial"].as_object_mut().unwrap();
        assert!(material.remove(field).is_some());
        v.to_string()
    }

    const GITHUB_ISSUER: &str = "https://github.com/login/oauth";

    #[tokio::test]
    async fn verifies_real_bundle_and_reports_signer() {
        let (v, _dir) = verifier(Default::default()).await;
        let info = v.verify(PAYLOAD, GITHUB_ISSUER, "", &sig(BUNDLE)).unwrap();
        let Some(signer_info::Type::Oidc(o)) = info.r#type else {
            panic!("expected OIDC signer");
        };
        assert_eq!(o.issuer, GITHUB_ISSUER);
        assert!(!o.subject.is_empty());
        assert!(o.certificate_issuer.contains("sigstore"), "{}", o.certificate_issuer);

        // exact and regexp subject / issuer matchers
        v.verify(PAYLOAD, "", &o.subject, &sig(BUNDLE)).unwrap();
        v.verify(PAYLOAD, "https://github\\.com/.*", ".*", &sig(BUNDLE))
            .unwrap();
        assert!(v.verify(PAYLOAD, "", "someone-else@example.com", &sig(BUNDLE)).is_err());
        assert!(v
            .verify(PAYLOAD, "https://accounts.google.com", "", &sig(BUNDLE))
            .is_err());
    }

    #[tokio::test]
    async fn rejects_tampered_payload() {
        let (v, _dir) = verifier(Default::default()).await;
        assert!(v.verify(b"bafy-not-the-signed-payload", "", "", &sig(BUNDLE)).is_err());
        assert!(v.verify(PAYLOAD, "", "", &sig("{garbage")).is_err());
        assert!(v.verify(PAYLOAD, "", "", &sig("")).is_err());
    }

    #[tokio::test]
    async fn tsa_and_tlog_are_required_unless_ignored() {
        // no signed timestamp: fails by default, accepted with ignore_tsa
        // (the SET-backed Rekor time still provides a verified time)
        let no_tsa = bundle_without("timestampVerificationData");
        let (strict, _d1) = verifier(Default::default()).await;
        assert!(strict.verify(PAYLOAD, "", "", &sig(&no_tsa)).is_err());
        let (lenient, _d2) = verifier(VerifyOptionsOidc {
            ignore_tsa: true,
            ..Default::default()
        })
        .await;
        lenient.verify(PAYLOAD, "", "", &sig(&no_tsa)).unwrap();

        // no transparency log entry: fails by default, accepted with ignore_tlog
        // (the TSA timestamp still provides a verified time)
        let no_tlog = bundle_without("tlogEntries");
        assert!(strict.verify(PAYLOAD, "", "", &sig(&no_tlog)).is_err());
        let (lenient, _d3) = verifier(VerifyOptionsOidc {
            ignore_tlog: true,
            ..Default::default()
        })
        .await;
        lenient.verify(PAYLOAD, "", "", &sig(&no_tlog)).unwrap();
    }
}
