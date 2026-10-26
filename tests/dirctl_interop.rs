// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Interoperability tests between the SDK and the `dirctl` CLI.
//!
//! Records signed by the SDK must verify with `dirctl`, and records signed by
//! `dirctl` must verify with the SDK. The tests need a running Directory server
//! (`DIRECTORY_CLIENT_SERVER_ADDRESS`, default `0.0.0.0:8888`), the `dirctl`
//! binary (`DIRCTL_PATH` or `PATH`) and the `cosign` binary (`COSIGN_PATH` or
//! `PATH`). They are `#[ignore]`d like the other live tests and, when run with
//! `--ignored`, skip (pass) with a message if any of those is unavailable:
//!
//! ```sh
//! DIRCTL_PATH=.bin/dirctl COSIGN_PATH=.bin/cosign cargo test --test dirctl_interop -- --ignored --nocapture
//! ```
//!
//! Only key-based signing is covered; keyless signing needs live Sigstore services.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use agntcy_dir::models::core_v1::{Record, RecordRef};
use agntcy_dir::models::sign_v1::{
    self, sign_request_provider, signer_info, verify_request_provider, PublicKey, Signature,
};
use agntcy_dir::models::store_v1::PushReferrerRequest;
use agntcy_dir::{Client, Config};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use pkcs8::LineEnding;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};

/// Password of the keys created by these tests (random for every run).
fn key_password() -> &'static str {
    static PASSWORD: OnceLock<String> = OnceLock::new();
    PASSWORD.get_or_init(|| {
        let mut bytes = <[u8; 16]>::default();
        OsRng.fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    })
}
const SIGNATURE_TYPE: &str = "agntcy.dir.sign.v1.Signature";
const PUBLIC_KEY_TYPE: &str = "agntcy.dir.sign.v1.PublicKey";
const ECDSA: &str = "ECDSA-P-256";
const ED25519: &str = "Ed25519";

/// Finds `name` through the `*_PATH` environment variable or `PATH`.
fn binary(env_var: &str, name: &str) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(env_var).filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(path));
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn server_address() -> String {
    std::env::var("DIRECTORY_CLIENT_SERVER_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8888".into())
}

/// A cosign-format key pair on disk.
struct KeyPair {
    private: String,
    public: String,
    public_pem: String,
}

/// Everything an interop test needs; `None` (after a message) when unavailable.
struct Env {
    client: Client,
    dirctl: PathBuf,
    cosign: PathBuf,
    dir: tempfile::TempDir,
    ecdsa: KeyPair,
    ed25519: KeyPair,
}

async fn setup() -> Option<Env> {
    let (Some(dirctl), Some(cosign)) = (binary("DIRCTL_PATH", "dirctl"), binary("COSIGN_PATH", "cosign")) else {
        eprintln!("skipping: the dirctl (DIRCTL_PATH) and cosign (COSIGN_PATH) binaries are required");
        return None;
    };
    let client = Client::new(Config {
        server_address: server_address(),
        ..Config::from_env().expect("valid DIRECTORY_CLIENT_* configuration")
    })
    .await
    .expect("client");
    if let Err(e) = client.push(vec![record("probe")]).await {
        eprintln!("skipping: the Directory server is not reachable: {e}");
        return None;
    }

    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(&cosign)
        .arg("generate-key-pair")
        .current_dir(dir.path())
        .env("COSIGN_PASSWORD", key_password())
        .output()
        .expect("run cosign");
    assert!(output.status.success(), "cosign generate-key-pair: {}", stderr(&output));
    let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
    let ecdsa = KeyPair {
        private: path("cosign.key"),
        public: path("cosign.pub"),
        public_pem: std::fs::read_to_string(path("cosign.pub")).unwrap(),
    };
    let ed25519 = write_ed25519_key(dir.path());
    Some(Env {
        client,
        dirctl,
        cosign,
        dir,
        ecdsa,
        ed25519,
    })
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Writes an Ed25519 key pair in the cosign encrypted-key format (cosign
/// itself only generates ECDSA keys).
fn write_ed25519_key(dir: &Path) -> KeyPair {
    use crypto_secretbox::aead::{Aead, KeyInit};
    use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pkcs8 = key.to_pkcs8_der().unwrap();

    let (mut salt, mut nonce) = (<[u8; 32]>::default(), <[u8; 24]>::default());
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let mut derived = <[u8; 32]>::default();
    let params = scrypt::Params::new(15, 8, 1, 32).unwrap();
    scrypt::scrypt(key_password().as_bytes(), &salt, &params, &mut derived).unwrap();
    let ciphertext = XSalsa20Poly1305::new(Key::from_slice(&derived))
        .encrypt(Nonce::from_slice(&nonce), pkcs8.as_bytes())
        .unwrap();

    let envelope = json!({
        "kdf": {"name": "scrypt", "params": {"N": 32768, "r": 8, "p": 1}, "salt": B64.encode(salt)},
        "cipher": {"name": "nacl/secretbox", "nonce": B64.encode(nonce)},
        "ciphertext": B64.encode(ciphertext),
    });
    let body = B64.encode(envelope.to_string());
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let private = dir.join("ed25519.key");
    std::fs::write(
        &private,
        format!(
            "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\n{}\n-----END ENCRYPTED SIGSTORE PRIVATE KEY-----\n",
            lines.join("\n")
        ),
    )
    .unwrap();
    let public_pem = key.verifying_key().to_public_key_pem(LineEnding::LF).unwrap();
    let public = dir.join("ed25519.pub");
    std::fs::write(&public, &public_pem).unwrap();
    KeyPair {
        private: private.to_string_lossy().into_owned(),
        public: public.to_string_lossy().into_owned(),
        public_pem,
    }
}

fn record(name: &str) -> Record {
    serde_json::from_value(json!({
        "data": {
            "name": format!("agntcy-interop-{name}-{:08x}", rand::random::<u32>()),
            "version": "v3.0.0",
            "schema_version": "1.1.0",
            "description": "Record used to test dirctl and SDK interoperability.",
            "authors": ["Cisco Systems"],
            "created_at": "2025-03-19T17:06:37Z",
            "skills": [{
                "name": "language_processing/language_generation/text_completion",
                "id": 10301
            }],
            "locators": [{"type": "container_image", "urls": ["https://ghcr.io/agntcy/marketing-strategy"]}],
            "domains": [{"name": "technology/networking", "id": 103}],
            "modules": []
        }
    }))
    .unwrap()
}

impl Env {
    fn keys(&self) -> [(&'static str, &KeyPair); 2] {
        [(ECDSA, &self.ecdsa), (ED25519, &self.ed25519)]
    }

    async fn push(&self, name: &str) -> RecordRef {
        self.client.push(vec![record(name)]).await.unwrap().remove(0)
    }

    fn dirctl(&self, args: &[&str]) -> Output {
        Command::new(&self.dirctl)
            .args(args)
            .env("COSIGN_PASSWORD", key_password())
            .env("DIRECTORY_CLIENT_SERVER_ADDRESS", server_address())
            .output()
            .expect("run dirctl")
    }

    fn dirctl_sign(&self, cid: &str, private_key: &str) {
        let output = self.dirctl(&["sign", cid, "--key", private_key]);
        assert!(output.status.success(), "dirctl sign: {}", stderr(&output));
    }

    /// `dirctl verify --output json`; note that `success` is omitted when false.
    fn dirctl_verify(&self, cid: &str, public_key: Option<&str>) -> Value {
        let mut args = vec!["verify", cid, "--output", "json"];
        if let Some(key) = public_key {
            args.extend(["--key", key]);
        }
        let output = self.dirctl(&args);
        assert!(output.status.success(), "dirctl verify: {}", stderr(&output));
        serde_json::from_slice(&output.stdout).expect("dirctl verify prints JSON")
    }

    fn dirctl_accepts(&self, cid: &str, public_key: Option<&str>) -> bool {
        self.dirctl_verify(cid, public_key)["success"]
            .as_bool()
            .unwrap_or(false)
    }

    async fn sdk_sign(&self, record_ref: &RecordRef, private_key: &str) {
        self.client
            .sign(&sign_v1::SignRequest {
                record_ref: Some(record_ref.clone()),
                provider: Some(sign_v1::SignRequestProvider {
                    request: Some(sign_request_provider::Request::Key(sign_v1::SignWithKey {
                        private_key: private_key.into(),
                        password: Some(key_password().as_bytes().to_vec()),
                    })),
                }),
            })
            .await
            .unwrap();
    }

    async fn sdk_verify(&self, record_ref: &RecordRef, public_key: Option<&str>) -> sign_v1::VerifyResponse {
        let request = match public_key {
            Some(key) => verify_request_provider::Request::Key(sign_v1::VerifyWithKey { public_key: key.into() }),
            None => verify_request_provider::Request::Any(Default::default()),
        };
        self.client
            .verify(sign_v1::VerifyRequest {
                record_ref: Some(record_ref.clone()),
                provider: Some(sign_v1::VerifyRequestProvider { request: Some(request) }),
                from_server: false,
            })
            .await
            .unwrap()
    }

    async fn signatures(&self, record_ref: &RecordRef) -> Vec<Signature> {
        self.client.sign_service().pull_signatures(record_ref).await.unwrap()
    }

    async fn public_keys(&self, record_ref: &RecordRef) -> Vec<String> {
        self.client.sign_service().pull_public_keys(record_ref).await.unwrap()
    }

    /// Attaches `data` (protojson) as a referrer of `record_ref`.
    async fn attach(&self, record_ref: &RecordRef, referrer_type: &str, data: Value) {
        let request: PushReferrerRequest = serde_json::from_value(json!({
            "recordRef": {"cid": record_ref.cid},
            "type": referrer_type,
            "data": data,
        }))
        .unwrap();
        self.client.push_referrer(vec![request]).await.unwrap();
    }
}

fn key_signer(response: &sign_v1::VerifyResponse) -> &sign_v1::SignerInfoKey {
    match &response.signers[0].r#type {
        Some(signer_info::Type::Key(key)) => key,
        other => panic!("expected a key signer, got {other:?}"),
    }
}

macro_rules! env_or_skip {
    () => {
        match setup().await {
            Some(env) => env,
            None => return,
        }
    };
}

#[tokio::test]
#[ignore = "requires a live Directory node, dirctl and cosign"]
async fn sdk_signature_verifies_with_dirctl() {
    let env = env_or_skip!();
    for (algorithm, keys) in env.keys() {
        let record_ref = env.push(&format!("sdk-{algorithm}")).await;
        env.sdk_sign(&record_ref, &keys.private).await;

        for result in [
            env.dirctl_verify(&record_ref.cid, None),
            env.dirctl_verify(&record_ref.cid, Some(&keys.public)),
        ] {
            assert_eq!(result["success"], json!(true), "{algorithm}: {result}");
            let signer = &result["signers"][0]["key"];
            assert_eq!(signer["algorithm"], json!(algorithm), "{result}");
            assert_eq!(signer["publicKey"], json!(keys.public_pem), "{result}");
        }
    }
}

#[tokio::test]
#[ignore = "requires a live Directory node, dirctl and cosign"]
async fn dirctl_signature_verifies_with_sdk() {
    let env = env_or_skip!();
    for (algorithm, keys) in env.keys() {
        let record_ref = env.push(&format!("dirctl-{algorithm}")).await;
        env.dirctl_sign(&record_ref.cid, &keys.private);

        for response in [
            env.sdk_verify(&record_ref, None).await,
            env.sdk_verify(&record_ref, Some(&keys.public)).await,
        ] {
            assert!(response.success, "{algorithm}: {:?}", response.error_message);
            let signer = key_signer(&response);
            assert_eq!(signer.algorithm, algorithm);
            assert_eq!(signer.public_key, keys.public_pem);
        }
    }
}

#[tokio::test]
#[ignore = "requires a live Directory node, dirctl and cosign"]
async fn sdk_and_dirctl_produce_equivalent_referrers() {
    let env = env_or_skip!();
    for (algorithm, keys) in env.keys() {
        let sdk_ref = env.push(&format!("equiv-sdk-{algorithm}")).await;
        let dirctl_ref = env.push(&format!("equiv-dirctl-{algorithm}")).await;
        env.sdk_sign(&sdk_ref, &keys.private).await;
        env.dirctl_sign(&dirctl_ref.cid, &keys.private);

        let (sdk_sigs, dirctl_sigs) = (env.signatures(&sdk_ref).await, env.signatures(&dirctl_ref).await);
        assert_eq!((sdk_sigs.len(), dirctl_sigs.len()), (1, 1), "{algorithm}");
        let (sdk_sig, dirctl_sig) = (&sdk_sigs[0], &dirctl_sigs[0]);

        // Same populated fields and metadata; only the values that depend on
        // time and (for ECDSA) randomness may differ.
        let populated = |sig: &Signature| -> BTreeSet<String> {
            serde_json::to_value(sig)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect()
        };
        assert_eq!(populated(sdk_sig), populated(dirctl_sig), "{algorithm}");
        assert_eq!(sdk_sig.algorithm, algorithm);
        assert_eq!(dirctl_sig.algorithm, algorithm);
        assert!(sdk_sig.content_bundle.is_empty() && dirctl_sig.content_bundle.is_empty());
        assert_eq!(env.public_keys(&sdk_ref).await, env.public_keys(&dirctl_ref).await);
        if algorithm == ED25519 {
            // Ed25519ph is deterministic: signing the same CID gives the same bytes.
            let again = env.push(&format!("equiv-determinism-{algorithm}")).await;
            env.sdk_sign(&again, &keys.private).await;
            // different `signed_at`, so the store keeps both referrers
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            env.dirctl_sign(&again.cid, &keys.private);
            let sigs = env.signatures(&again).await;
            assert_eq!(sigs.len(), 2, "{sigs:?}");
            assert_eq!(sigs[0].signature, sigs[1].signature);
        }
    }
}

#[tokio::test]
#[ignore = "requires a live Directory node, dirctl and cosign"]
async fn signature_is_rejected_for_a_different_record() {
    let env = env_or_skip!();
    for (algorithm, keys) in env.keys() {
        let signed = env.push(&format!("payload-signed-{algorithm}")).await;
        let other = env.push(&format!("payload-other-{algorithm}")).await;
        env.sdk_sign(&signed, &keys.private).await;

        // Re-attach the SDK's referrers to a different record.
        for signature in env.signatures(&signed).await {
            env.attach(&other, SIGNATURE_TYPE, serde_json::to_value(&signature).unwrap())
                .await;
        }
        env.attach(
            &other,
            PUBLIC_KEY_TYPE,
            serde_json::to_value(PublicKey {
                key: keys.public_pem.clone(),
            })
            .unwrap(),
        )
        .await;

        assert!(!env.sdk_verify(&other, Some(&keys.public)).await.success, "{algorithm}");
        assert!(!env.sdk_verify(&other, None).await.success, "{algorithm}");
        assert!(!env.dirctl_accepts(&other.cid, Some(&keys.public)), "{algorithm}");
        assert!(!env.dirctl_accepts(&other.cid, None), "{algorithm}");
    }
}

#[tokio::test]
#[ignore = "requires a live Directory node, dirctl and cosign"]
async fn wrong_key_is_rejected_by_both() {
    let env = env_or_skip!();
    for (signing, wrong) in [(&env.ecdsa, &env.ed25519), (&env.ed25519, &env.ecdsa)] {
        let sdk_ref = env.push("wrong-key-sdk").await;
        env.sdk_sign(&sdk_ref, &signing.private).await;
        let dirctl_ref = env.push("wrong-key-dirctl").await;
        env.dirctl_sign(&dirctl_ref.cid, &signing.private);

        for record_ref in [&sdk_ref, &dirctl_ref] {
            assert!(!env.sdk_verify(record_ref, Some(&wrong.public)).await.success);
            assert!(!env.dirctl_accepts(&record_ref.cid, Some(&wrong.public)));
            // and the right key still works
            assert!(env.sdk_verify(record_ref, Some(&signing.public)).await.success);
            assert!(env.dirctl_accepts(&record_ref.cid, Some(&signing.public)));
        }
    }
}

#[tokio::test]
#[ignore = "requires a live Directory node, dirctl and cosign"]
async fn cosign_verifies_the_sdk_signature() {
    let env = env_or_skip!();
    let record_ref = env.push("cosign").await;
    env.sdk_sign(&record_ref, &env.ecdsa.private).await;
    let signature = env.signatures(&record_ref).await.remove(0).signature;

    // The signed payload is the record CID.
    let payload = env.dir.path().join("payload.txt");
    std::fs::write(&payload, record_ref.cid.as_bytes()).unwrap();
    let verify = |signature: &str| {
        Command::new(&env.cosign)
            .args([
                "verify-blob",
                "--key",
                &env.ecdsa.public,
                "--signature",
                signature,
                "--insecure-ignore-tlog",
            ])
            .arg(&payload)
            .output()
            .expect("run cosign")
    };
    let output = verify(&signature);
    assert!(output.status.success(), "cosign verify-blob: {}", stderr(&output));

    // a tampered signature is rejected
    let mut raw = B64.decode(&signature).unwrap();
    *raw.last_mut().unwrap() ^= 1;
    assert!(!verify(&B64.encode(raw)).status.success());
}
