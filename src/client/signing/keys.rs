// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Key-based signing and verification, compatible with cosign.
//!
//! Mirrors `SignBlobWithKey` / `VerifyWithKeys` of the Go SDK:
//!
//! * private keys are cosign encrypted keys (`ENCRYPTED SIGSTORE PRIVATE KEY`:
//!   scrypt + NaCl secretbox around a PKCS#8 key) or plain PEM
//!   (`PRIVATE KEY`, `EC PRIVATE KEY`, `RSA PRIVATE KEY`), given inline or as
//!   a file path / `env://VAR` reference;
//! * ECDSA and RSA (PKCS#1 v1.5) sign SHA-256 digests, Ed25519 keys sign as
//!   Ed25519ph (cosign's default for loaded keys);
//! * verification accepts a PKIX public key (inline PEM or file / `env://`
//!   reference) and, for Ed25519, falls back from pure Ed25519 to Ed25519ph.
//!
//! KMS / URL key references are not supported.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};
use pkcs8::der::pem;
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey, LineEnding};
use rand_core::OsRng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;
use sha2_010::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};

const COSIGN_ENCRYPTED_LABEL: &str = "ENCRYPTED SIGSTORE PRIVATE KEY";

/// Upper bound for the scrypt `N` parameter accepted from a key file.
const MAX_SCRYPT_LOG_N: u8 = 22;

/// A loaded private key able to sign messages.
pub enum KeySigner {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    Rsa(Box<RsaPrivateKey>),
    /// Signs as Ed25519ph.
    Ed25519(ed25519_dalek::SigningKey),
}

impl KeySigner {
    /// Signs `message` (ECDSA: ASN.1 DER over SHA-256; RSA: PKCS#1 v1.5 over
    /// SHA-256; Ed25519: Ed25519ph with an empty context).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let digest = Sha256::digest(message);
        let sign_err = |e: &dyn std::fmt::Display| Error::Sign(format!("signing blob: {e}"));
        match self {
            KeySigner::P256(k) => {
                let sig: p256::ecdsa::Signature = k.sign_prehash(&digest).map_err(|e| sign_err(&e))?;
                Ok(sig.to_der().as_bytes().to_vec())
            }
            KeySigner::P384(k) => {
                let sig: p384::ecdsa::Signature = k.sign_prehash(&digest).map_err(|e| sign_err(&e))?;
                Ok(sig.to_der().as_bytes().to_vec())
            }
            KeySigner::Rsa(k) => {
                use rsa::signature::{RandomizedSigner, SignatureEncoding};
                let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new((**k).clone());
                let sig = signing_key
                    .try_sign_with_rng(&mut OsRng, message)
                    .map_err(|e| sign_err(&e))?;
                Ok(sig.to_vec())
            }
            KeySigner::Ed25519(k) => {
                let sig = k
                    .sign_prehashed(Sha512::new_with_prefix(message), None)
                    .map_err(|e| sign_err(&e))?;
                Ok(sig.to_bytes().to_vec())
            }
        }
    }

    /// The PKIX public key as PEM (`PUBLIC KEY`, LF line endings).
    pub fn public_key_pem(&self) -> Result<String> {
        let pem = match self {
            KeySigner::P256(k) => k.verifying_key().to_public_key_pem(LineEnding::LF),
            KeySigner::P384(k) => k.verifying_key().to_public_key_pem(LineEnding::LF),
            KeySigner::Rsa(k) => k.to_public_key().to_public_key_pem(LineEnding::LF),
            KeySigner::Ed25519(k) => k.verifying_key().to_public_key_pem(LineEnding::LF),
        };
        pem.map_err(|e| Error::Sign(format!("getting public key: {e}")))
    }
}

/// A loaded public key able to verify signatures.
pub enum KeyVerifier {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    Rsa(Box<RsaPublicKey>),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl KeyVerifier {
    /// Verifies `signature` over `message`. Ed25519 keys are first tried as
    /// pure Ed25519 and then as Ed25519ph, like the Go implementation.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let digest = Sha256::digest(message);
        match self {
            KeyVerifier::P256(k) => p256::ecdsa::Signature::from_der(signature)
                .map(|s| k.verify_prehash(&digest, &s).is_ok())
                .unwrap_or(false),
            KeyVerifier::P384(k) => p384::ecdsa::Signature::from_der(signature)
                .map(|s| k.verify_prehash(&digest, &s).is_ok())
                .unwrap_or(false),
            KeyVerifier::Rsa(k) => {
                use rsa::signature::Verifier;
                let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new((**k).clone());
                rsa::pkcs1v15::Signature::try_from(signature)
                    .map(|s| verifying_key.verify(message, &s).is_ok())
                    .unwrap_or(false)
            }
            KeyVerifier::Ed25519(k) => {
                let Ok(sig) = ed25519_dalek::Signature::from_slice(signature) else {
                    return false;
                };
                k.verify_strict(message, &sig).is_ok()
                    || k.verify_prehashed_strict(Sha512::new_with_prefix(message), None, &sig)
                        .is_ok()
            }
        }
    }

    /// The PKIX public key as PEM (`PUBLIC KEY`, LF line endings).
    pub fn public_key_pem(&self) -> Result<String> {
        let pem = match self {
            KeyVerifier::P256(k) => k.to_public_key_pem(LineEnding::LF),
            KeyVerifier::P384(k) => k.to_public_key_pem(LineEnding::LF),
            KeyVerifier::Rsa(k) => k.to_public_key_pem(LineEnding::LF),
            KeyVerifier::Ed25519(k) => k.to_public_key_pem(LineEnding::LF),
        };
        pem.map_err(|e| Error::Verify(format!("failed to marshal public key to PEM: {e}")))
    }

    /// Algorithm name as reported by the Go SDK (`ECDSA-P-256`, `Ed25519`,
    /// `RSA-2048`, ...).
    pub fn algorithm(&self) -> String {
        match self {
            KeyVerifier::P256(_) => "ECDSA-P-256".into(),
            KeyVerifier::P384(_) => "ECDSA-P-384".into(),
            KeyVerifier::Rsa(k) => format!("RSA-{}", k.size() * 8),
            KeyVerifier::Ed25519(_) => "Ed25519".into(),
        }
    }
}

/// Algorithm of a PKIX PEM public key; `"unknown"` when it cannot be parsed.
pub fn detect_key_algorithm(public_key_pem: &str) -> String {
    parse_public_key_pem(public_key_pem)
        .map(|k| k.algorithm())
        .unwrap_or_else(|_| "unknown".into())
}

// --- loading ---------------------------------------------------------------

/// Reads inline PEM, or resolves a key reference (`env://VAR` or a file path).
fn resolve_key_material(key: &str) -> Result<String> {
    if let Some(var) = key.strip_prefix("env://") {
        return std::env::var(var)
            .map_err(|_| Error::InvalidArgument(format!("environment variable {var} is not set")));
    }
    if key.contains("://") {
        return Err(Error::InvalidArgument(format!(
            "unsupported key reference {key:?}: only PEM content, file paths and env:// references are supported"
        )));
    }
    std::fs::read_to_string(key).map_err(|e| Error::InvalidArgument(format!("reading key {key:?}: {e}")))
}

/// Loads a private key from raw PEM, falling back to a key reference (file
/// path or `env://VAR`), like the Go SDK.
pub fn load_private_key(private_key: &str, password: &[u8]) -> Result<KeySigner> {
    if private_key.trim().is_empty() {
        return Err(Error::InvalidArgument("private_key is required".into()));
    }
    match parse_private_key_pem(private_key.as_bytes(), password) {
        Ok(key) => Ok(key),
        // Inline PEM that does not load (wrong password, bad key): report that.
        Err(e) if private_key.contains("-----BEGIN") => Err(e),
        Err(_) => {
            let material = resolve_key_material(private_key)
                .map_err(|e| Error::Sign(format!("loading private key from reference: {e}")))?;
            parse_private_key_pem(material.as_bytes(), password)
        }
    }
}

fn parse_private_key_pem(pem_bytes: &[u8], password: &[u8]) -> Result<KeySigner> {
    let bad = |e: &dyn std::fmt::Display| Error::Sign(format!("unable to parse private key: {e}"));
    let (label, der) = pem::decode_vec(pem_bytes).map_err(|e| bad(&e))?;
    match label {
        COSIGN_ENCRYPTED_LABEL => key_from_pkcs8(&decrypt_cosign_key(&der, password)?),
        "PRIVATE KEY" => key_from_pkcs8(&der),
        "EC PRIVATE KEY" => p256::SecretKey::from_sec1_der(&der)
            .map(|k| KeySigner::P256(k.into()))
            .or_else(|_| p384::SecretKey::from_sec1_der(&der).map(|k| KeySigner::P384(k.into())))
            .map_err(|_| Error::Sign("unsupported EC private key (only P-256 and P-384)".into())),
        "RSA PRIVATE KEY" => RsaPrivateKey::from_pkcs1_der(&der)
            .map(|k| KeySigner::Rsa(Box::new(k)))
            .map_err(|e| bad(&e)),
        "ENCRYPTED PRIVATE KEY" => Err(Error::Sign(
            "password-protected PKCS#8 keys are not supported; use a cosign encrypted key".into(),
        )),
        other => Err(Error::Sign(format!("unsupported private key PEM type {other:?}"))),
    }
}

fn key_from_pkcs8(der: &[u8]) -> Result<KeySigner> {
    if let Ok(k) = p256::SecretKey::from_pkcs8_der(der) {
        return Ok(KeySigner::P256(k.into()));
    }
    if let Ok(k) = p384::SecretKey::from_pkcs8_der(der) {
        return Ok(KeySigner::P384(k.into()));
    }
    if let Ok(k) = ed25519_dalek::SigningKey::from_pkcs8_der(der) {
        return Ok(KeySigner::Ed25519(k));
    }
    if let Ok(k) = RsaPrivateKey::from_pkcs8_der(der) {
        return Ok(KeySigner::Rsa(Box::new(k)));
    }
    Err(Error::Sign(
        "unsupported private key type (expected ECDSA P-256/P-384, Ed25519 or RSA)".into(),
    ))
}

#[derive(Deserialize)]
struct EncryptedKey {
    kdf: Kdf,
    cipher: Cipher,
    ciphertext: String,
}

#[derive(Deserialize)]
struct Kdf {
    name: String,
    params: ScryptParams,
    salt: String,
}

#[derive(Deserialize)]
struct ScryptParams {
    #[serde(rename = "N")]
    n: u64,
    r: u32,
    p: u32,
}

#[derive(Deserialize)]
struct Cipher {
    name: String,
    nonce: String,
}

/// Decrypts the body of an `ENCRYPTED SIGSTORE PRIVATE KEY` PEM block into
/// PKCS#8 DER.
fn decrypt_cosign_key(body: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let enc: EncryptedKey =
        serde_json::from_slice(body).map_err(|e| Error::Sign(format!("unable to parse encrypted private key: {e}")))?;
    if enc.kdf.name != "scrypt" || enc.cipher.name != "nacl/secretbox" {
        return Err(Error::Sign(format!(
            "unsupported key encryption {}/{}",
            enc.kdf.name, enc.cipher.name
        )));
    }
    let decode = |s: &str, what: &str| {
        B64.decode(s)
            .map_err(|e| Error::Sign(format!("invalid {what} in encrypted private key: {e}")))
    };
    let salt = decode(&enc.kdf.salt, "salt")?;
    let nonce = decode(&enc.cipher.nonce, "nonce")?;
    let ciphertext = decode(&enc.ciphertext, "ciphertext")?;
    if nonce.len() != 24 {
        return Err(Error::Sign("invalid nonce length in encrypted private key".into()));
    }

    let n = enc.kdf.params.n;
    if !n.is_power_of_two() || n < 2 || n.trailing_zeros() > u32::from(MAX_SCRYPT_LOG_N) {
        return Err(Error::Sign("unsupported scrypt cost parameter".into()));
    }
    let params = scrypt::Params::new(n.trailing_zeros() as u8, enc.kdf.params.r, enc.kdf.params.p, 32)
        .map_err(|e| Error::Sign(format!("invalid scrypt parameters: {e}")))?;
    let mut key = [0u8; 32];
    scrypt::scrypt(password, &salt, &params, &mut key).map_err(|e| Error::Sign(format!("deriving key: {e}")))?;

    XSalsa20Poly1305::new(Key::from_slice(&key))
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|_| Error::Sign("unable to decrypt private key: wrong password or corrupt key".into()))
}

/// Loads a PKIX public key from inline PEM or a key reference (file path or
/// `env://VAR`).
pub fn load_public_key(public_key: &str) -> Result<KeyVerifier> {
    match parse_public_key_pem(public_key) {
        Ok(key) => Ok(key),
        Err(e) if public_key.contains("-----BEGIN") => Err(e),
        Err(_) => parse_public_key_pem(&resolve_key_material(public_key)?),
    }
}

fn parse_public_key_pem(pem_str: &str) -> Result<KeyVerifier> {
    if let Ok(k) = p256::PublicKey::from_public_key_pem(pem_str) {
        return Ok(KeyVerifier::P256(k.into()));
    }
    if let Ok(k) = p384::PublicKey::from_public_key_pem(pem_str) {
        return Ok(KeyVerifier::P384(k.into()));
    }
    if let Ok(k) = ed25519_dalek::VerifyingKey::from_public_key_pem(pem_str) {
        return Ok(KeyVerifier::Ed25519(k));
    }
    if let Ok(k) = RsaPublicKey::from_public_key_pem(pem_str) {
        return Ok(KeyVerifier::Rsa(Box::new(k)));
    }
    Err(Error::Verify(
        "failed to load public key (expected a PKIX ECDSA P-256/P-384, Ed25519 or RSA key)".into(),
    ))
}

/// Verifies a single signature with one public key reference/PEM; returns the
/// loaded key on success. The signature is base64, with the raw string as
/// fallback when it is not valid base64 (as in Go).
pub fn verify_signature_with_key(public_key: &str, signature: &str, payload: &[u8]) -> Result<KeyVerifier> {
    let verifier = load_public_key(public_key)?;
    let sig_bytes = B64.decode(signature).unwrap_or_else(|_| signature.as_bytes().to_vec());
    if verifier.verify(payload, &sig_bytes) {
        Ok(verifier)
    } else {
        Err(Error::Verify("signature verification failed".into()))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Throwaway ECDSA P-256 key generated with `cosign generate-key-pair`
    // (cosign 3.1.3), password "testing-key". Used only by these tests.
    pub const COSIGN_KEY: &str = include_str!("testdata/cosign.key");
    pub const COSIGN_PUB: &str = include_str!("testdata/cosign.pub");
    pub const COSIGN_PASSWORD: &[u8] = b"testing-key";

    fn pkcs8_pem(der_label: &str, der: &[u8]) -> String {
        pem::encode_string(der_label, LineEnding::LF, der).unwrap()
    }

    fn roundtrip(signer: KeySigner, algorithm: &str) {
        let payload = b"bafkreiexamplecid";
        let sig = signer.sign(payload).unwrap();
        let pem = signer.public_key_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert_eq!(detect_key_algorithm(&pem), algorithm);

        let verified = verify_signature_with_key(&pem, &B64.encode(&sig), payload).unwrap();
        assert_eq!(verified.algorithm(), algorithm);
        assert_eq!(verified.public_key_pem().unwrap(), pem);

        assert!(verify_signature_with_key(&pem, &B64.encode(&sig), b"other").is_err());
        let mut bad = sig.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(verify_signature_with_key(&pem, &B64.encode(&bad), payload).is_err());
    }

    #[test]
    fn loads_real_cosign_encrypted_key_and_roundtrips() {
        let signer = load_private_key(COSIGN_KEY, COSIGN_PASSWORD).unwrap();
        assert!(matches!(signer, KeySigner::P256(_)));
        // the public key matches the one cosign wrote next to it
        let pem = signer.public_key_pem().unwrap();
        assert_eq!(pem.trim(), COSIGN_PUB.trim());
        roundtrip(signer, "ECDSA-P-256");
    }

    #[test]
    fn wrong_password_is_rejected() {
        assert!(load_private_key(COSIGN_KEY, b"nope").is_err());
        assert!(load_private_key(COSIGN_KEY, b"").is_err());
    }

    #[test]
    fn key_reference_file_and_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cosign.key");
        std::fs::write(&path, COSIGN_KEY).unwrap();
        let signer = load_private_key(path.to_str().unwrap(), COSIGN_PASSWORD).unwrap();
        let sig = signer.sign(b"cid").unwrap();

        // public key by file reference
        let pub_path = dir.path().join("cosign.pub");
        std::fs::write(&pub_path, COSIGN_PUB).unwrap();
        verify_signature_with_key(pub_path.to_str().unwrap(), &B64.encode(sig), b"cid").unwrap();

        assert!(load_private_key("/definitely/not/a/key", b"").is_err());
        assert!(load_private_key("hashivault://key", b"").is_err());
        assert!(load_private_key("", b"").is_err());
    }

    #[test]
    fn plain_pkcs8_ecdsa_p384() {
        let key = p384::SecretKey::random(&mut OsRng);
        let der = pkcs8::EncodePrivateKey::to_pkcs8_der(&key).unwrap();
        let pem = pkcs8_pem("PRIVATE KEY", der.as_bytes());
        let signer = load_private_key(&pem, b"").unwrap();
        assert!(matches!(signer, KeySigner::P384(_)));
        roundtrip(signer, "ECDSA-P-384");
    }

    #[test]
    fn sec1_ec_private_key() {
        let key = p256::SecretKey::random(&mut OsRng);
        let pem = key.to_sec1_pem(LineEnding::LF).unwrap();
        let signer = load_private_key(&pem, b"").unwrap();
        roundtrip(signer, "ECDSA-P-256");
    }

    #[test]
    fn ed25519_signs_as_ph_and_verifies_both_modes() {
        let mut seed = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut seed);
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let der = pkcs8::EncodePrivateKey::to_pkcs8_der(&key).unwrap();
        let pem = pkcs8_pem("PRIVATE KEY", der.as_bytes());
        let signer = load_private_key(&pem, b"").unwrap();
        assert!(matches!(signer, KeySigner::Ed25519(_)));
        roundtrip(signer, "Ed25519");

        // pure Ed25519 signatures are accepted too
        let pub_pem = key.verifying_key().to_public_key_pem(LineEnding::LF).unwrap();
        let pure = ed25519_dalek::Signer::sign(&key, b"cid");
        verify_signature_with_key(&pub_pem, &B64.encode(pure.to_bytes()), b"cid").unwrap();
        // and Ed25519ph must not verify as a different payload
        let ph = key.sign_prehashed(Sha512::new_with_prefix(b"cid"), None).unwrap();
        assert!(verify_signature_with_key(&pub_pem, &B64.encode(ph.to_bytes()), b"cid2").is_err());
    }

    #[test]
    fn rsa_pkcs1_and_pkcs8() {
        let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pkcs1 = rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_pem(&key, LineEnding::LF).unwrap();
        roundtrip(load_private_key(&pkcs1, b"").unwrap(), "RSA-2048");
        let pkcs8 = pkcs8::EncodePrivateKey::to_pkcs8_pem(&key, LineEnding::LF).unwrap();
        roundtrip(load_private_key(&pkcs8, b"").unwrap(), "RSA-2048");
    }

    #[test]
    fn invalid_base64_signature_falls_back_to_raw_bytes() {
        let signer = load_private_key(COSIGN_KEY, COSIGN_PASSWORD).unwrap();
        let pem = signer.public_key_pem().unwrap();
        assert!(verify_signature_with_key(&pem, "!!not base64!!", b"cid").is_err());
    }

    #[test]
    fn unknown_algorithm_for_garbage() {
        assert_eq!(detect_key_algorithm("garbage"), "unknown");
    }
}
