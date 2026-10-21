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

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    use pkcs8::EncodePrivateKey;
    use tokio_stream::wrappers::TcpListenerStream;
    use tokio_stream::{Stream, StreamExt};
    use tonic::{Request, Response, Status, Streaming};

    use super::*;
    use crate::client::config::Config;
    use crate::client::signing::keys::tests::{no_password, random_bytes, COSIGN_KEY, COSIGN_PASSWORD, COSIGN_PUB};
    use crate::client::Client;
    use crate::models::core_v1::{Record, RecordMeta, RecordReferrer};
    use crate::models::sign_v1::sign_service_server::{SignService as SignApi, SignServiceServer};
    use crate::models::sign_v1::{
        verify_request_provider, SignRequestProvider, SignResponse, SignWithOidc, VerifyRequestProvider, VerifyWithKey,
    };
    use crate::models::store_v1::store_service_server::{StoreService as StoreApi, StoreServiceServer};
    use crate::models::store_v1::{
        DeleteReferrerRequest, DeleteReferrerResponse, PullReferrerResponse, PushReferrerRequest, PushReferrerResponse,
    };

    const CID: &str = "bafkreitestcid";
    const OTHER_CID: &str = "bafkreiother";

    type Out<T> = Pin<Box<dyn Stream<Item = std::result::Result<T, Status>> + Send>>;

    fn out<T: Send + 'static>(items: Vec<T>) -> Response<Out<T>> {
        Response::new(Box::pin(tokio_stream::iter(items.into_iter().map(Ok))))
    }

    #[derive(Default)]
    struct State {
        /// `(record cid, referrer)` pairs, as pushed by the client.
        referrers: Vec<(String, RecordReferrer)>,
        push_calls: usize,
        fail_push_call: Option<usize>,
        fail_pull_type: Option<String>,
        lookup_error: Option<Status>,
        extra_referrers: Vec<PullReferrerResponse>,
        verify_response: VerifyResponse,
    }

    /// In-process Directory server implementing the store and sign services.
    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<State>>);

    impl Fake {
        fn state(&self) -> std::sync::MutexGuard<'_, State> {
            self.0.lock().unwrap()
        }

        async fn start(&self) -> Client {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tonic::transport::Server::builder()
                .add_service(StoreServiceServer::new(self.clone()))
                .add_service(SignServiceServer::new(self.clone()))
                .serve_with_incoming(TcpListenerStream::new(listener));
            tokio::spawn(server);
            Client::new(Config {
                server_address: address.to_string(),
                ..Default::default()
            })
            .await
            .unwrap()
        }
    }

    #[tonic::async_trait]
    impl StoreApi for Fake {
        type PushStream = Out<RecordRef>;
        type PullStream = Out<Record>;
        type LookupStream = Out<RecordMeta>;
        type PushReferrerStream = Out<PushReferrerResponse>;
        type PullReferrerStream = Out<PullReferrerResponse>;
        type DeleteReferrerStream = Out<DeleteReferrerResponse>;

        async fn push(&self, _: Request<Streaming<Record>>) -> std::result::Result<Response<Self::PushStream>, Status> {
            Err(Status::unimplemented("push"))
        }

        async fn pull(
            &self,
            _: Request<Streaming<RecordRef>>,
        ) -> std::result::Result<Response<Self::PullStream>, Status> {
            Err(Status::unimplemented("pull"))
        }

        async fn lookup(
            &self,
            request: Request<Streaming<RecordRef>>,
        ) -> std::result::Result<Response<Self::LookupStream>, Status> {
            if let Some(status) = self.state().lookup_error.clone() {
                return Err(status);
            }
            let refs: Vec<RecordRef> = request.into_inner().map(|r| r.unwrap()).collect().await;
            Ok(out(refs
                .into_iter()
                .map(|r| RecordMeta {
                    cid: r.cid,
                    ..Default::default()
                })
                .collect()))
        }

        async fn delete(
            &self,
            _: Request<Streaming<RecordRef>>,
        ) -> std::result::Result<Response<pbjson_types::Empty>, Status> {
            Err(Status::unimplemented("delete"))
        }

        async fn push_referrer(
            &self,
            request: Request<Streaming<PushReferrerRequest>>,
        ) -> std::result::Result<Response<Self::PushReferrerStream>, Status> {
            let requests: Vec<PushReferrerRequest> = request.into_inner().map(|r| r.unwrap()).collect().await;
            let mut state = self.state();
            state.push_calls += 1;
            if state.fail_push_call == Some(state.push_calls) {
                return Err(Status::internal("push boom"));
            }
            for r in requests {
                let cid = r.record_ref.map(|r| r.cid).unwrap_or_default();
                state.referrers.push((
                    cid,
                    RecordReferrer {
                        r#type: r.r#type,
                        data: r.data,
                        ..Default::default()
                    },
                ));
            }
            Ok(out(vec![PushReferrerResponse {
                success: true,
                ..Default::default()
            }]))
        }

        async fn pull_referrer(
            &self,
            request: Request<Streaming<PullReferrerRequest>>,
        ) -> std::result::Result<Response<Self::PullReferrerStream>, Status> {
            let requests: Vec<PullReferrerRequest> = request.into_inner().map(|r| r.unwrap()).collect().await;
            let state = self.state();
            let mut items = Vec::new();
            for r in requests {
                let cid = r.record_ref.map(|r| r.cid).unwrap_or_default();
                let wanted = r.referrer_type.unwrap_or_default();
                if state.fail_pull_type.as_deref() == Some(wanted.as_str()) {
                    return Err(Status::unavailable("pull boom"));
                }
                items.extend(
                    state
                        .referrers
                        .iter()
                        .filter(|(c, referrer)| *c == cid && referrer.r#type == wanted)
                        .map(|(_, referrer)| PullReferrerResponse {
                            referrer: Some(referrer.clone()),
                        }),
                );
                items.extend(state.extra_referrers.clone());
            }
            Ok(out(items))
        }

        async fn delete_referrer(
            &self,
            _: Request<Streaming<DeleteReferrerRequest>>,
        ) -> std::result::Result<Response<Self::DeleteReferrerStream>, Status> {
            Err(Status::unimplemented("delete_referrer"))
        }
    }

    #[tonic::async_trait]
    impl SignApi for Fake {
        async fn sign(&self, _: Request<SignRequest>) -> std::result::Result<Response<SignResponse>, Status> {
            Err(Status::unimplemented("sign"))
        }

        async fn verify(&self, _: Request<VerifyRequest>) -> std::result::Result<Response<VerifyResponse>, Status> {
            Ok(Response::new(self.state().verify_response.clone()))
        }
    }

    fn record_ref(cid: &str) -> Option<RecordRef> {
        Some(RecordRef { cid: cid.into() })
    }

    fn key_sign_request(private_key: &str, password: &[u8]) -> SignRequest {
        SignRequest {
            record_ref: record_ref(CID),
            provider: Some(SignRequestProvider {
                request: Some(SignProvider::Key(SignWithKey {
                    private_key: private_key.into(),
                    password: Some(password.to_vec()),
                })),
            }),
        }
    }

    fn verify_request(cid: &str, public_key: Option<&str>) -> VerifyRequest {
        VerifyRequest {
            record_ref: record_ref(cid),
            provider: public_key.map(|k| VerifyRequestProvider {
                request: Some(verify_request_provider::Request::Key(VerifyWithKey {
                    public_key: k.into(),
                })),
            }),
            from_server: false,
        }
    }

    async fn signed() -> (Fake, Client) {
        let fake = Fake::default();
        let client = fake.start().await;
        client
            .sign_service()
            .sign(&key_sign_request(COSIGN_KEY, COSIGN_PASSWORD))
            .await
            .unwrap();
        (fake, client)
    }

    #[tokio::test]
    async fn sign_pushes_public_key_then_signature_and_verifies() {
        let (fake, client) = signed().await;
        {
            let state = fake.state();
            let types: Vec<_> = state.referrers.iter().map(|(_, r)| r.r#type.as_str()).collect();
            assert_eq!(types, [PUBLIC_KEY_REFERRER_TYPE, SIGNATURE_REFERRER_TYPE]);
        }

        let service = client.sign_service();
        let reference = RecordRef { cid: CID.into() };
        assert_eq!(service.pull_public_keys(&reference).await.unwrap(), [COSIGN_PUB]);
        let signatures = service.pull_signatures(&reference).await.unwrap();
        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures[0].algorithm, "ECDSA-P-256");

        // default provider (any) and an explicit public key
        for request in [verify_request(CID, None), verify_request(CID, Some(COSIGN_PUB))] {
            let response = service.verify(request).await.unwrap();
            assert!(response.success, "{:?}", response.error_message);
            assert_eq!(response.signers.len(), 1);
        }
    }

    #[tokio::test]
    async fn ed25519_key_signs_and_verifies_through_the_store() {
        let mut seed = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
        let pem = ed25519_dalek::SigningKey::from_bytes(&seed)
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .unwrap();

        let client = Fake::default().start().await;
        let service = client.sign_service();
        service
            .sign(&key_sign_request(pem.as_str(), no_password()))
            .await
            .unwrap();
        let response = service.verify(verify_request(CID, None)).await.unwrap();
        assert!(response.success, "{:?}", response.error_message);
    }

    #[tokio::test]
    async fn sign_validates_the_request() {
        let client = Fake::default().start().await;
        let service = client.sign_service();

        let mut request = key_sign_request(COSIGN_KEY, COSIGN_PASSWORD);
        request.provider = None;
        let err = service.sign(&request).await.unwrap_err();
        assert!(err.to_string().contains("provider must be specified"), "{err}");
        request.provider = Some(SignRequestProvider::default());
        assert!(service.sign(&request).await.is_err());

        for record_ref in [None, Some(RecordRef::default())] {
            let mut request = key_sign_request(COSIGN_KEY, COSIGN_PASSWORD);
            request.record_ref = record_ref;
            let err = service.sign(&request).await.unwrap_err();
            assert!(err.to_string().contains("record ref must be specified"), "{err}");
        }

        // an unusable key never reaches the store
        let err = service
            .sign(&key_sign_request(COSIGN_KEY, &random_bytes(8)))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Sign(_)), "{err}");
    }

    #[tokio::test]
    async fn oidc_provider_requires_an_id_token() {
        let fake = Fake::default();
        let client = fake.start().await;
        let request = SignRequest {
            record_ref: record_ref(CID),
            provider: Some(SignRequestProvider {
                request: Some(SignProvider::Oidc(SignWithOidc::default())),
            }),
        };
        let err = client.sign_service().sign(&request).await.unwrap_err();
        assert!(err.to_string().contains("id_token"), "{err}");
        assert!(fake.state().referrers.is_empty());
    }

    #[tokio::test]
    async fn push_failures_are_reported() {
        for failing_call in [1, 2] {
            let fake = Fake::default();
            fake.state().fail_push_call = Some(failing_call);
            let client = fake.start().await;
            let err = client
                .sign_service()
                .sign(&key_sign_request(COSIGN_KEY, COSIGN_PASSWORD))
                .await
                .unwrap_err();
            assert!(err.to_string().starts_with("push_referrer failed:"), "{err}");
            assert_eq!(fake.state().referrers.len(), failing_call - 1);
        }
    }

    #[tokio::test]
    async fn verify_validates_the_request() {
        let client = Fake::default().start().await;
        let service = client.sign_service();

        for from_server in [false, true] {
            for record_ref in [None, Some(RecordRef::default())] {
                let err = service
                    .verify(VerifyRequest {
                        record_ref,
                        from_server,
                        ..Default::default()
                    })
                    .await
                    .unwrap_err();
                let expected = if from_server {
                    "VerifyRequest.record_ref with cid is required"
                } else {
                    "record CID is required"
                };
                assert!(err.to_string().contains(expected), "{err}");
            }
        }
    }

    #[tokio::test]
    async fn verify_on_the_server_returns_its_response() {
        let fake = Fake::default();
        fake.state().verify_response = VerifyResponse {
            success: true,
            error_message: Some("from the server".into()),
            ..Default::default()
        };
        let client = fake.start().await;
        let mut request = verify_request(CID, None);
        request.from_server = true;
        let response = client.sign_service().verify(request).await.unwrap();
        assert!(response.success);
        assert_eq!(response.error_message.as_deref(), Some("from the server"));
    }

    #[tokio::test]
    async fn verify_reports_missing_records_and_lookup_failures() {
        let fake = Fake::default();
        let client = fake.start().await;
        let service = client.sign_service();

        fake.state().lookup_error = Some(Status::not_found("record not found in store"));
        let response = service.verify(verify_request(CID, None)).await.unwrap();
        assert!(!response.success);
        assert_eq!(response.error_message.as_deref(), Some("record not found"));

        fake.state().lookup_error = Some(Status::unavailable("down"));
        let err = service.verify(verify_request(CID, None)).await.unwrap_err();
        assert!(err.to_string().starts_with("lookup failed:"), "{err}");

        fake.state().lookup_error = None;
        let response = service.verify(verify_request(CID, None)).await.unwrap();
        assert_eq!(response.error_message.as_deref(), Some("no signatures found"));
    }

    #[tokio::test]
    async fn pull_failures_are_reported() {
        let (fake, client) = signed().await;
        let service = client.sign_service();
        let reference = RecordRef { cid: CID.into() };

        fake.state().fail_pull_type = Some(SIGNATURE_REFERRER_TYPE.into());
        let err = service.verify(verify_request(CID, None)).await.unwrap_err();
        assert!(err.to_string().starts_with("pull_referrer failed:"), "{err}");
        assert!(service.pull_signatures(&reference).await.is_err());

        // signatures load, the public keys do not (only needed without an explicit key)
        fake.state().fail_pull_type = Some(PUBLIC_KEY_REFERRER_TYPE.into());
        assert!(service.verify(verify_request(CID, None)).await.is_err());
        assert!(service.pull_public_keys(&reference).await.is_err());
        assert!(
            service
                .verify(verify_request(CID, Some(COSIGN_PUB)))
                .await
                .unwrap()
                .success
        );
    }

    #[tokio::test]
    async fn unusable_referrers_are_skipped() {
        let (fake, client) = signed().await;
        let referrer = |data: Option<serde_json::Value>| PullReferrerResponse {
            referrer: Some(RecordReferrer {
                data: data.map(|d| serde_json::from_value(d).unwrap()),
                ..Default::default()
            }),
        };
        fake.state().extra_referrers = vec![
            // no referrer at all
            PullReferrerResponse::default(),
            // a referrer without data
            referrer(None),
            // data that decodes into neither a signature nor a public key
            referrer(Some(serde_json::json!({"signature": [1], "key": [1]}))),
            // a public key referrer with an empty key
            referrer(Some(serde_json::json!({"key": ""}))),
        ];
        let service = client.sign_service();
        let reference = RecordRef { cid: CID.into() };
        assert_eq!(service.pull_public_keys(&reference).await.unwrap(), [COSIGN_PUB]);
        assert_eq!(service.pull_signatures(&reference).await.unwrap().len(), 1);
        assert!(service.verify(verify_request(CID, None)).await.unwrap().success);
    }

    #[tokio::test]
    async fn signature_is_rejected_for_a_different_record() {
        let (fake, client) = signed().await;
        // replay the key and signature referrers on another record
        let replayed: Vec<_> = fake
            .state()
            .referrers
            .iter()
            .map(|(_, r)| (OTHER_CID.to_string(), r.clone()))
            .collect();
        fake.state().referrers.extend(replayed);

        let service = client.sign_service();
        for request in [
            verify_request(OTHER_CID, None),
            verify_request(OTHER_CID, Some(COSIGN_PUB)),
        ] {
            let response = service.verify(request).await.unwrap();
            assert!(!response.success);
            assert_eq!(
                response.error_message.as_deref(),
                Some("no valid signatures found matching verification criteria")
            );
        }
    }

    #[tokio::test]
    async fn wrong_key_is_rejected() {
        let (_, client) = signed().await;
        let other = p256::SecretKey::random(&mut rand_core::OsRng);
        let other_pem =
            p256::pkcs8::EncodePublicKey::to_public_key_pem(&other.public_key(), pkcs8::LineEnding::LF).unwrap();
        let response = client
            .sign_service()
            .verify(verify_request(CID, Some(&other_pem)))
            .await
            .unwrap();
        assert!(!response.success);
    }
}
