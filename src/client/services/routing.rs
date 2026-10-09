// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use super::{collect, rpc};
use crate::client::transport::GrpcChannel;
use crate::error::Result;
use crate::models::routing_v1::routing_service_client::RoutingServiceClient;
use crate::models::routing_v1::{
    ListRequest, ListResponse, PublishRequest, SearchRequest, SearchResponse, UnpublishRequest,
};

/// Routing: publish records to the network and discover them.
#[derive(Clone)]
pub struct RoutingService {
    client: RoutingServiceClient<GrpcChannel>,
}

impl RoutingService {
    pub(crate) fn new(channel: GrpcChannel) -> Self {
        Self {
            client: RoutingServiceClient::new(channel),
        }
    }

    pub fn client(&self) -> RoutingServiceClient<GrpcChannel> {
        self.client.clone()
    }

    pub async fn publish(&self, request: PublishRequest) -> Result<()> {
        self.client().publish(request).await.map_err(rpc("publish"))?;
        Ok(())
    }

    pub async fn unpublish(&self, request: UnpublishRequest) -> Result<()> {
        self.client().unpublish(request).await.map_err(rpc("unpublish"))?;
        Ok(())
    }

    pub async fn list(&self, request: ListRequest) -> Result<Vec<ListResponse>> {
        let resp = self.client().list(request).await.map_err(rpc("list"))?;
        collect("list", resp.into_inner()).await
    }

    pub async fn search_routing(&self, request: SearchRequest) -> Result<Vec<SearchResponse>> {
        let resp = self.client().search(request).await.map_err(rpc("search_routing"))?;
        collect("search_routing", resp.into_inner()).await
    }
}
