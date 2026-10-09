// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use super::{collect, rpc};
use crate::client::transport::GrpcChannel;
use crate::error::Result;
use crate::models::store_v1::sync_service_client::SyncServiceClient;
use crate::models::store_v1::{
    CreateSyncRequest, CreateSyncResponse, DeleteSyncRequest, DeleteSyncResponse, GetSyncRequest, GetSyncResponse,
    ListSyncsItem, ListSyncsRequest,
};

/// Synchronization with remote Directory nodes.
#[derive(Clone)]
pub struct SyncService {
    client: SyncServiceClient<GrpcChannel>,
}

impl SyncService {
    pub(crate) fn new(channel: GrpcChannel) -> Self {
        Self {
            client: SyncServiceClient::new(channel),
        }
    }

    pub fn client(&self) -> SyncServiceClient<GrpcChannel> {
        self.client.clone()
    }

    pub async fn create_sync(&self, request: CreateSyncRequest) -> Result<CreateSyncResponse> {
        Ok(self
            .client()
            .create_sync(request)
            .await
            .map_err(rpc("create_sync"))?
            .into_inner())
    }

    pub async fn list_syncs(&self, request: ListSyncsRequest) -> Result<Vec<ListSyncsItem>> {
        let resp = self.client().list_syncs(request).await.map_err(rpc("list_syncs"))?;
        collect("list_syncs", resp.into_inner()).await
    }

    pub async fn get_sync(&self, request: GetSyncRequest) -> Result<GetSyncResponse> {
        Ok(self
            .client()
            .get_sync(request)
            .await
            .map_err(rpc("get_sync"))?
            .into_inner())
    }

    pub async fn delete_sync(&self, request: DeleteSyncRequest) -> Result<DeleteSyncResponse> {
        Ok(self
            .client()
            .delete_sync(request)
            .await
            .map_err(rpc("delete_sync"))?
            .into_inner())
    }
}
