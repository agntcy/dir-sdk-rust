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
use sigstore_types::{
    Bundle, DerCertificate, KindVersion, Sha256Hash, SignatureBytes, TimestampToken, TransparencyLogEntry,
};
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

    package_signature(
        Packaged {
            leaf,
            signature,
            artifact_hash,
            timestamp,
            tlog_entry,
            signed_at,
        },
        public_key_pem,
    )
}

/// The signing material gathered from Fulcio, Rekor and the TSA.
struct Packaged {
    leaf: DerCertificate,
    signature: SignatureBytes,
    artifact_hash: Sha256Hash,
    timestamp: TimestampToken,
    tlog_entry: Option<TransparencyLogEntry>,
    signed_at: chrono::DateTime<chrono::Utc>,
}

/// Packages the signing material as a Sigstore v0.3 message-signature bundle
/// and the [`Signature`] / [`PublicKey`] referrers stored for the record.
fn package_signature(material: Packaged, public_key_pem: String) -> Result<(Signature, PublicKey)> {
    let Packaged {
        leaf,
        signature,
        artifact_hash,
        timestamp,
        tlog_entry,
        signed_at,
    } = material;
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
        assert!(o.certificate_issuer.contains("sigstore"));

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

    // --- signing against mocked Fulcio / Rekor / TSA endpoints ---------------

    use std::sync::Arc;

    use sigstore_types::SignatureContent;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Minimal HTTP/1.1 server answering `(status, body)` per request path.
    async fn mock_http(routes: impl Fn(&str) -> (u16, String) + Send + Sync + 'static) -> String {
        let routes = Arc::new(routes);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (header_end, length) = loop {
                        let n = stream.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                            let length = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            break (end + 4, length);
                        }
                    };
                    while buf.len() < header_end + length {
                        let n = stream.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let request = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let path = request.split_whitespace().nth(1).unwrap_or_default();
                    let (status, body) = routes(path);
                    let response = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        base
    }

    /// An (unsigned) JWT: Fulcio is the only party that validates the token.
    fn jwt() -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let claims = serde_json::json!({
            "iss": "https://issuer.example", "sub": "subject", "aud": "sigstore",
            "exp": 4_102_444_800u64, "iat": 1_700_000_000u64,
            "email": "dev@example.com", "email_verified": true,
        });
        format!(
            "{}.{}.sig",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    fn fixture() -> Bundle {
        Bundle::from_json(BUNDLE).unwrap()
    }

    fn fulcio_ok() -> (u16, String) {
        let chain = serde_json::json!({
            "signedCertificateEmbeddedSct": {"chain": {"certificates": [fixture().signing_certificate().unwrap().to_pem()]}}
        });
        (201, chain.to_string())
    }

    fn sign_request(base: &str, skip_tlog: bool) -> SignWithOidc {
        SignWithOidc {
            id_token: jwt(),
            options: Some(SignOptionsOidc {
                fulcio_url: base.into(),
                rekor_url: base.into(),
                timestamp_url: format!("{base}/tsa"),
                skip_tlog,
                ..Default::default()
            }),
        }
    }

    async fn sign_error(request: &SignWithOidc) -> String {
        match sign_blob_with_oidc(b"cid", request).await {
            Err(e) => e.to_string(),
            Ok(_) => panic!("signing unexpectedly succeeded"),
        }
    }

    #[tokio::test]
    async fn sign_rejects_a_malformed_identity_token() {
        let mut request = SignWithOidc {
            id_token: "not-a-jwt".into(),
            ..Default::default()
        };
        assert!(sign_error(&request).await.contains("invalid identity token"));
        request.id_token = "a.!!.c".into();
        assert!(sign_error(&request).await.contains("invalid identity token"));
    }

    #[tokio::test]
    async fn sign_reports_fulcio_failures() {
        // unreachable
        let request = sign_request("http://127.0.0.1:1", true);
        assert!(sign_error(&request).await.contains("Fulcio"));
        // rejected token
        let base = mock_http(|_| (401, "unauthorized".into())).await;
        let err = sign_error(&sign_request(&base, true)).await;
        assert!(err.contains("Fulcio") && err.contains("401"), "{err}");
    }

    #[tokio::test]
    async fn sign_reports_rekor_failures() {
        let base = mock_http(|path| {
            if path.contains("signingCert") {
                fulcio_ok()
            } else {
                (500, "rekor down".into())
            }
        })
        .await;
        let err = sign_error(&sign_request(&base, false)).await;
        assert!(err.contains("Rekor"), "{err}");
    }

    #[tokio::test]
    async fn sign_reports_timestamp_authority_failures() {
        for (status, body) in [(500, "tsa down"), (200, "not a timestamp response")] {
            let base = mock_http(move |path| {
                if path.contains("signingCert") {
                    fulcio_ok()
                } else {
                    (status, body.into())
                }
            })
            .await;
            // the transparency log is skipped, so the TSA is the first failing step
            let err = sign_error(&sign_request(&base, true)).await;
            assert!(err.contains("timestamp authority"), "{err}");
        }
    }

    /// A Rekor v1 `create_entry` response built from the fixture's log entry.
    fn rekor_ok(checkpoint: Option<&str>) -> (u16, String) {
        let hex = |b64: &str| -> String { B64.decode(b64).unwrap().iter().map(|b| format!("{b:02x}")).collect() };
        let bundle: serde_json::Value = serde_json::from_str(BUNDLE).unwrap();
        let entry = &bundle["verificationMaterial"]["tlogEntries"][0];
        let proof = &entry["inclusionProof"];
        let response = serde_json::json!({
            "a".repeat(64): {
                "body": entry["canonicalizedBody"],
                "integratedTime": 1_764_787_003,
                "logID": hex(entry["logId"]["keyId"].as_str().unwrap()),
                "logIndex": 738_312_748,
                "verification": {
                    "signedEntryTimestamp": entry["inclusionPromise"]["signedEntryTimestamp"],
                    "inclusionProof": {
                        "logIndex": 616_408_486,
                        "rootHash": hex(proof["rootHash"].as_str().unwrap()),
                        "treeSize": 616_408_488,
                        "hashes": proof["hashes"].as_array().unwrap().iter()
                            .map(|h| hex(h.as_str().unwrap())).collect::<Vec<_>>(),
                        "checkpoint": checkpoint.unwrap_or(proof["checkpoint"]["envelope"].as_str().unwrap()),
                    },
                },
            }
        });
        (201, response.to_string())
    }

    #[tokio::test]
    async fn sign_reports_invalid_rekor_entries_and_continues_with_valid_ones() {
        // an unparsable checkpoint is rejected
        let base = mock_http(|path| {
            if path.contains("signingCert") {
                fulcio_ok()
            } else {
                rekor_ok(Some("not a checkpoint"))
            }
        })
        .await;
        let err = sign_error(&sign_request(&base, false)).await;
        assert!(err.contains("invalid Rekor response"), "{err}");

        // a valid entry is accepted; the (failing) timestamp authority is next
        let base = mock_http(|path| match path {
            p if p.contains("signingCert") => fulcio_ok(),
            p if p.contains("log/entries") => rekor_ok(None),
            _ => (500, "tsa down".into()),
        })
        .await;
        let err = sign_error(&sign_request(&base, false)).await;
        assert!(err.contains("timestamp authority"), "{err}");
    }

    #[test]
    fn http_client_and_defaults() {
        assert_eq!(or_default("", "default"), "default");
        assert_eq!(or_default("custom", "default"), "custom");
        http_client(Duration::from_secs(1)).unwrap();
    }

    #[tokio::test]
    async fn packaged_signature_is_a_verifiable_bundle() {
        let original = fixture();
        let SignatureContent::MessageSignature(message) = &original.content else {
            panic!("fixture is a message signature bundle");
        };
        let material = |tlog_entry| Packaged {
            leaf: original.signing_certificate().unwrap().clone(),
            signature: message.signature.clone(),
            artifact_hash: sha256(PAYLOAD),
            timestamp: original
                .verification_material
                .timestamp_verification_data
                .rfc3161_timestamps[0]
                .signed_timestamp
                .clone(),
            tlog_entry,
            signed_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        };
        let tlog_entry = original.verification_material.tlog_entries[0].clone();

        let (signature, public_key) = package_signature(material(Some(tlog_entry)), "PEM".into()).unwrap();
        assert_eq!(public_key.key, "PEM");
        assert_eq!(signature.signed_at, "2023-11-14T22:13:20Z");
        assert_eq!(signature.content_type, "application/vnd.dev.sigstore.bundle.v0.3+json");
        assert_eq!(B64.decode(&signature.signature).unwrap(), message.signature.as_bytes());
        assert_eq!(
            B64.decode(&signature.certificate).unwrap(),
            original.signing_certificate().unwrap().as_bytes()
        );

        // the produced bundle verifies like the cosign original
        let (v, _dir) = verifier(Default::default()).await;
        v.verify(PAYLOAD, GITHUB_ISSUER, "", &signature).unwrap();

        // without a transparency log entry (skip_tlog) the bundle only carries the timestamp
        let (signature, _) = package_signature(material(None), "PEM".into()).unwrap();
        let bundle = Bundle::from_json(&signature.content_bundle).unwrap();
        assert!(bundle.verification_material.tlog_entries.is_empty());
        assert_eq!(
            bundle
                .verification_material
                .timestamp_verification_data
                .rfc3161_timestamps
                .len(),
            1
        );
    }

    // --- trusted root / verifier construction ---------------------------------

    #[tokio::test]
    async fn trusted_root_from_unreachable_tuf_mirror_fails() {
        for mirror in ["http://127.0.0.1:1", "http://127.0.0.1:1/sigstage"] {
            let opts = VerifyOptionsOidc {
                tuf_mirror_url: mirror.into(),
                ..Default::default()
            };
            let err = load_trusted_root(&opts).await.err().unwrap();
            assert!(
                err.to_string().contains("failed to fetch trusted root from TUF"),
                "{err}"
            );
            let err = OidcVerifier::new(Some(&opts)).await.err().unwrap();
            assert!(err.to_string().contains("failed to get trusted material"), "{err}");
        }
    }

    #[tokio::test]
    async fn invalid_trusted_root_is_rejected_by_the_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("trusted_root.json");
        std::fs::write(&root, "{}").unwrap();
        let opts = VerifyOptionsOidc {
            trusted_root_path: root.to_string_lossy().into(),
            ..Default::default()
        };
        assert!(OidcVerifier::new(Some(&opts)).await.is_err());
    }

    #[tokio::test]
    async fn sct_check_can_be_ignored() {
        let (v, _dir) = verifier(VerifyOptionsOidc {
            ignore_sct: true,
            ..Default::default()
        })
        .await;
        v.verify(PAYLOAD, GITHUB_ISSUER, "", &sig(BUNDLE)).unwrap();
    }
}
