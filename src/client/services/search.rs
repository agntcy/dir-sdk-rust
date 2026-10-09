// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use super::{collect, rpc};
use crate::client::transport::GrpcChannel;
use crate::error::Result;
use crate::models::search_v1::search_service_client::SearchServiceClient;
use crate::models::search_v1::{SearchCiDsRequest, SearchCiDsResponse, SearchRecordsRequest, SearchRecordsResponse};

/// Local record search.
#[derive(Clone)]
pub struct SearchService {
    client: SearchServiceClient<GrpcChannel>,
}

impl SearchService {
    pub(crate) fn new(channel: GrpcChannel) -> Self {
        Self {
            client: SearchServiceClient::new(channel),
        }
    }

    pub fn client(&self) -> SearchServiceClient<GrpcChannel> {
        self.client.clone()
    }

    pub async fn search_cids(&self, request: SearchCiDsRequest) -> Result<Vec<SearchCiDsResponse>> {
        let resp = self.client().search_ci_ds(request).await.map_err(rpc("search_cids"))?;
        collect("search_cids", resp.into_inner()).await
    }

    pub async fn search_records(&self, request: SearchRecordsRequest) -> Result<Vec<SearchRecordsResponse>> {
        let resp = self
            .client()
            .search_records(request)
            .await
            .map_err(rpc("search_records"))?;
        collect("search_records", resp.into_inner()).await
    }
}
