// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use super::{rpc, StoreService};
use crate::client::signing::keys::{detect_key_algorithm, load_private_key};
use crate::client::signing::oidc::sign_blob_with_oidc;
use crate::client::signing::referrer::{
    public_key_from_referrer, public_key_to_push_request, signature_from_referrer, signature_to_push_request,
    PUBLIC_KEY_REFERRER_TYPE, SIGNATURE_REFERRER_TYPE,
};
use crate::client::signing::verify::{verify_with_fetcher, Fetcher};
use crate::client::transport::GrpcChannel;
use crate::error::{Error, Result};
use crate::models::core_v1::RecordRef;
use crate::models::sign_v1::sign_request_provider::Request as SignProvider;
use crate::models::sign_v1::sign_service_client::SignServiceClient;
use crate::models::sign_v1::{PublicKey, SignRequest, SignWithKey, Signature, VerifyRequest, VerifyResponse};
use crate::models::store_v1::PullReferrerRequest;

/// Record signing and signature verification, implemented natively (cosign
/// keys and keyless Sigstore) on top of the store's referrers.
#[derive(Clone)]
pub struct SignService {
    client: SignServiceClient<GrpcChannel>,
    store: StoreService,
}

impl SignService {
    pub(crate) fn new(channel: GrpcChannel, store: StoreService) -> Self {
        Self {
            client: SignServiceClient::new(channel),
            store,
        }
    }

    pub fn client(&self) -> SignServiceClient<GrpcChannel> {
        self.client.clone()
    }

    /// Signs a record (over its CID) and pushes the public key and signature
    /// to the store as referrers.
    pub async fn sign(&self, request: &SignRequest) -> Result<()> {
        let provider = request
            .provider
            .as_ref()
            .and_then(|p| p.request.as_ref())
            .ok_or_else(|| Error::InvalidArgument("signature provider must be specified".into()))?;
        let record_ref = match request.record_ref.as_ref() {
            Some(r) if !r.cid.is_empty() => r,
            _ => return Err(Error::InvalidArgument("record ref must be specified".into())),
        };
        let payload = record_ref.cid.as_bytes();

        let (signature, public_key) = match provider {
            SignProvider::Key(key) => sign_blob_with_key(payload, key).await?,
            SignProvider::Oidc(oidc) => sign_blob_with_oidc(payload, oidc).await?,
        };

        self.store
            .push_referrer(vec![public_key_to_push_request(record_ref, &public_key)?])
            .await?;
        self.store
            .push_referrer(vec![signature_to_push_request(record_ref, &signature)?])
            .await?;
        Ok(())
    }

    /// Verifies a record, on the server when `from_server` is set and locally
    /// (signatures and public keys pulled from the store) otherwise.
    pub async fn verify(&self, request: VerifyRequest) -> Result<VerifyResponse> {
        let record_ref = match request.record_ref.as_ref() {
            Some(r) if !r.cid.is_empty() => r.clone(),
            _ => {
                return Err(Error::InvalidArgument(if request.from_server {
                    "VerifyRequest.record_ref with cid is required".into()
                } else {
                    "record CID is required".into()
                }))
            }
        };
        if request.from_server {
            return Ok(self.client().verify(request).await.map_err(rpc("verify"))?.into_inner());
        }

        if let Err(e) = self.store.lookup(vec![record_ref]).await {
            if e.to_string().contains("record not found") {
                return Ok(VerifyResponse {
                    success: false,
                    signers: Vec::new(),
                    error_message: Some("record not found".into()),
                });
            }
            return Err(e);
        }

        verify_with_fetcher(&request, self).await
    }

    async fn pull_referrers(
        &self,
        record_ref: &RecordRef,
        referrer_type: &str,
    ) -> Result<Vec<crate::models::core_v1::RecordReferrer>> {
        let responses = self
            .store
            .pull_referrer(vec![PullReferrerRequest {
                record_ref: Some(record_ref.clone()),
                referrer_type: Some(referrer_type.into()),
                referrer_ref: None,
            }])
            .await?;
        Ok(responses.into_iter().filter_map(|r| r.referrer).collect())
    }

    /// Fetches all signature referrers of a record (undecodable ones are skipped).
    pub async fn pull_signatures(&self, record_ref: &RecordRef) -> Result<Vec<Signature>> {
        Ok(self
            .pull_referrers(record_ref, SIGNATURE_REFERRER_TYPE)
            .await?
            .iter()
            .filter_map(|r| signature_from_referrer(r).ok())
            .collect())
    }

    /// Fetches all public key referrers of a record as PEM strings.
    pub async fn pull_public_keys(&self, record_ref: &RecordRef) -> Result<Vec<String>> {
        Ok(self
            .pull_referrers(record_ref, PUBLIC_KEY_REFERRER_TYPE)
            .await?
            .iter()
            .filter_map(|r| public_key_from_referrer(r).ok())
            .map(|k| k.key)
            .filter(|k| !k.is_empty())
            .collect())
    }
}

impl Fetcher for SignService {
    async fn pull_signatures(&self, record_ref: &RecordRef) -> Result<Vec<Signature>> {
        SignService::pull_signatures(self, record_ref).await
    }

    async fn pull_public_keys(&self, record_ref: &RecordRef) -> Result<Vec<String>> {
        SignService::pull_public_keys(self, record_ref).await
    }
}

/// Signs `payload` with a cosign / PEM private key.
async fn sign_blob_with_key(payload: &[u8], req: &SignWithKey) -> Result<(Signature, PublicKey)> {
    let private_key = req.private_key.clone();
    let password = req.password.clone().unwrap_or_default();
    let payload = payload.to_vec();
    // scrypt key derivation is CPU heavy: keep it off the async workers.
    tokio::task::spawn_blocking(move || {
        let signer = load_private_key(&private_key, &password)?;
        let signature = signer.sign(&payload)?;
        let public_key_pem = signer.public_key_pem()?;
        Ok::<_, Error>((
            Signature {
                signed_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                signature: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature),
                algorithm: detect_key_algorithm(&public_key_pem),
                ..Default::default()
            },
            PublicKey { key: public_key_pem },
        ))
    })
    .await
    .map_err(|e| Error::Sign(format!("signing task failed: {e}")))?
}
