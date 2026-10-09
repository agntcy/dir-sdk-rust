// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use super::{collect, rpc};
use crate::client::transport::GrpcChannel;
use crate::error::Result;
use crate::models::routing_v1::publication_service_client::PublicationServiceClient;
use crate::models::routing_v1::{
    CreatePublicationResponse, GetPublicationRequest, GetPublicationResponse, ListPublicationsItem,
    ListPublicationsRequest, PublishRequest,
};

/// Asynchronous publication requests.
#[derive(Clone)]
pub struct PublicationService {
    client: PublicationServiceClient<GrpcChannel>,
}

impl PublicationService {
    pub(crate) fn new(channel: GrpcChannel) -> Self {
        Self {
            client: PublicationServiceClient::new(channel),
        }
    }

    pub fn client(&self) -> PublicationServiceClient<GrpcChannel> {
        self.client.clone()
    }

    pub async fn create_publication(&self, request: PublishRequest) -> Result<CreatePublicationResponse> {
        let resp = self
            .client()
            .create_publication(request)
            .await
            .map_err(rpc("create_publication"))?;
        Ok(resp.into_inner())
    }

    pub async fn list_publication(&self, request: ListPublicationsRequest) -> Result<Vec<ListPublicationsItem>> {
        let resp = self
            .client()
            .list_publications(request)
            .await
            .map_err(rpc("list_publication"))?;
        collect("list_publication", resp.into_inner()).await
    }

    pub async fn get_publication(&self, request: GetPublicationRequest) -> Result<GetPublicationResponse> {
        let resp = self
            .client()
            .get_publication(request)
            .await
            .map_err(rpc("get_publication"))?;
        Ok(resp.into_inner())
    }
}
