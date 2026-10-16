// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The high-level [`Client`].

pub mod auth;
pub mod config;
pub mod dirctl;
pub mod services;
mod spiffe;
pub mod transport;

use tonic::Streaming;

use self::auth::OAuthSessionManager;
use self::config::Config;
use self::services::{
    EventService, IdentityService, PublicationService, RoutingService, SearchService, SignService, StoreService,
    SyncService,
};
use crate::error::{Error, Result};
use crate::models::core_v1::{Record, RecordMeta, RecordRef};
use crate::models::events_v1::{ListenRequest, ListenResponse};
use crate::models::identity::{GetVerificationInfoRequest, GetVerificationInfoResponse};
use crate::models::identity_v1::{ResolveRequest, ResolveResponse};
use crate::models::routing_v1::{
    CreatePublicationResponse, GetPublicationRequest, GetPublicationResponse, ListPublicationsItem,
    ListPublicationsRequest, ListRequest, ListResponse, PublishRequest, SearchRequest, SearchResponse,
    UnpublishRequest,
};
use crate::models::search_v1::{SearchCiDsRequest, SearchCiDsResponse, SearchRecordsRequest, SearchRecordsResponse};
use crate::models::sign_v1::{SignRequest, VerifyRequest, VerifyResponse};
use crate::models::store_v1::{
    CreateSyncRequest, CreateSyncResponse, DeleteReferrerRequest, DeleteReferrerResponse, DeleteSyncRequest,
    DeleteSyncResponse, GetSyncRequest, GetSyncResponse, ListSyncsItem, ListSyncsRequest, PullReferrerRequest,
    PullReferrerResponse, PushReferrerRequest, PushReferrerResponse,
};

/// High-level client for the AGNTCY Directory services.
///
/// Cheap to clone; clones share the underlying connection.
#[derive(Clone)]
pub struct Client {
    config: Config,
    oauth_session: OAuthSessionManager,
    store_service: StoreService,
    routing_service: RoutingService,
    publication_service: PublicationService,
    search_service: SearchService,
    sign_service: SignService,
    sync_service: SyncService,
    event_service: EventService,
    identity_service: IdentityService,
}

impl Client {
    /// Creates a client for `config`. The connection is established lazily.
    ///
    /// For the `x509` and `jwt` auth modes the SPIFFE Workload API is
    /// contacted here to obtain credentials.
    pub async fn new(config: Config) -> Result<Self> {
        let oauth_session = OAuthSessionManager::new(&config);
        let channel = transport::create_channel(&config, oauth_session.oauth_holder()).await?;

        Ok(Self {
            store_service: StoreService::new(channel.clone()),
            routing_service: RoutingService::new(channel.clone()),
            publication_service: PublicationService::new(channel.clone()),
            search_service: SearchService::new(channel.clone()),
            sign_service: SignService::new(config.clone(), channel.clone()),
            sync_service: SyncService::new(channel.clone()),
            event_service: EventService::new(channel.clone()),
            identity_service: IdentityService::new(channel),
            oauth_session,
            config,
        })
    }

    /// Creates a client from `DIRECTORY_CLIENT_*` environment variables.
    pub async fn from_env() -> Result<Self> {
        Self::new(Config::from_env()?).await
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn oauth_session(&self) -> &OAuthSessionManager {
        &self.oauth_session
    }

    // Per-service access (raw gRPC clients are available through `.client()`).
    pub fn store_service(&self) -> &StoreService {
        &self.store_service
    }
    pub fn routing_service(&self) -> &RoutingService {
        &self.routing_service
    }
    pub fn publication_service(&self) -> &PublicationService {
        &self.publication_service
    }
    pub fn search_service(&self) -> &SearchService {
        &self.search_service
    }
    pub fn sign_service(&self) -> &SignService {
        &self.sign_service
    }
    pub fn sync_service(&self) -> &SyncService {
        &self.sync_service
    }
    pub fn event_service(&self) -> &EventService {
        &self.event_service
    }
    pub fn identity_service(&self) -> &IdentityService {
        &self.identity_service
    }

    // --- OIDC -------------------------------------------------------------

    /// Whether an OIDC access token is currently available.
    pub fn has_cached_oauth_token(&self) -> bool {
        self.oauth_session.has_access_token()
    }

    /// The current OIDC access token.
    pub fn access_token(&self) -> Result<String> {
        self.oauth_session
            .oauth_holder()
            .ok_or_else(|| Error::Auth("OAuth token holder not initialized".into()))?
            .get_access_token()
    }

    /// Runs the interactive OAuth PKCE login (requires `auth_mode = oidc`).
    pub async fn authenticate_oauth_pkce(&self) -> Result<()> {
        self.oauth_session.authenticate().await
    }

    // --- Store ------------------------------------------------------------

    pub async fn push(&self, records: Vec<Record>) -> Result<Vec<RecordRef>> {
        self.store_service.push(records).await
    }
    pub async fn push_referrer(&self, requests: Vec<PushReferrerRequest>) -> Result<Vec<PushReferrerResponse>> {
        self.store_service.push_referrer(requests).await
    }
    pub async fn pull(&self, refs: Vec<RecordRef>) -> Result<Vec<Record>> {
        self.store_service.pull(refs).await
    }
    pub async fn pull_referrer(&self, requests: Vec<PullReferrerRequest>) -> Result<Vec<PullReferrerResponse>> {
        self.store_service.pull_referrer(requests).await
    }
    pub async fn lookup(&self, refs: Vec<RecordRef>) -> Result<Vec<RecordMeta>> {
        self.store_service.lookup(refs).await
    }
    pub async fn delete(&self, refs: Vec<RecordRef>) -> Result<()> {
        self.store_service.delete(refs).await
    }
    pub async fn delete_referrer(&self, request: DeleteReferrerRequest) -> Result<DeleteReferrerResponse> {
        self.store_service.delete_referrer(request).await
    }

    // --- Search -----------------------------------------------------------

    pub async fn search_cids(&self, request: SearchCiDsRequest) -> Result<Vec<SearchCiDsResponse>> {
        self.search_service.search_cids(request).await
    }
    pub async fn search_records(&self, request: SearchRecordsRequest) -> Result<Vec<SearchRecordsResponse>> {
        self.search_service.search_records(request).await
    }

    // --- Routing ----------------------------------------------------------

    pub async fn list(&self, request: ListRequest) -> Result<Vec<ListResponse>> {
        self.routing_service.list(request).await
    }
    pub async fn search_routing(&self, request: SearchRequest) -> Result<Vec<SearchResponse>> {
        self.routing_service.search_routing(request).await
    }
    pub async fn publish(&self, request: PublishRequest) -> Result<()> {
        self.routing_service.publish(request).await
    }
    pub async fn unpublish(&self, request: UnpublishRequest) -> Result<()> {
        self.routing_service.unpublish(request).await
    }

    // --- Publications -----------------------------------------------------

    pub async fn create_publication(&self, request: PublishRequest) -> Result<CreatePublicationResponse> {
        self.publication_service.create_publication(request).await
    }
    pub async fn list_publication(&self, request: ListPublicationsRequest) -> Result<Vec<ListPublicationsItem>> {
        self.publication_service.list_publication(request).await
    }
    pub async fn get_publication(&self, request: GetPublicationRequest) -> Result<GetPublicationResponse> {
        self.publication_service.get_publication(request).await
    }

    // --- Signing ----------------------------------------------------------

    /// Signs a record via `dirctl`.
    pub async fn sign(&self, request: &SignRequest) -> Result<()> {
        self.sign_service.sign(request).await
    }
    pub async fn verify(&self, request: VerifyRequest) -> Result<VerifyResponse> {
        self.sign_service.verify(request).await
    }

    // --- Sync -------------------------------------------------------------

    pub async fn create_sync(&self, request: CreateSyncRequest) -> Result<CreateSyncResponse> {
        self.sync_service.create_sync(request).await
    }
    pub async fn list_syncs(&self, request: ListSyncsRequest) -> Result<Vec<ListSyncsItem>> {
        self.sync_service.list_syncs(request).await
    }
    pub async fn get_sync(&self, request: GetSyncRequest) -> Result<GetSyncResponse> {
        self.sync_service.get_sync(request).await
    }
    pub async fn delete_sync(&self, request: DeleteSyncRequest) -> Result<DeleteSyncResponse> {
        self.sync_service.delete_sync(request).await
    }

    // --- Events -----------------------------------------------------------

    /// Opens the event stream; poll it with `Streaming::message`.
    pub async fn listen(&self, request: ListenRequest) -> Result<Streaming<ListenResponse>> {
        self.event_service.listen(request).await
    }

    // --- Identity ---------------------------------------------------------

    pub async fn resolve(&self, request: ResolveRequest) -> Result<ResolveResponse> {
        self.identity_service.resolve(request).await
    }
    pub async fn get_verification_info(
        &self,
        request: GetVerificationInfoRequest,
    ) -> Result<GetVerificationInfoResponse> {
        self.identity_service.get_verification_info(request).await
    }
}
