// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use super::rpc;
use crate::client::transport::GrpcChannel;
use crate::error::Result;
use crate::models::naming_v1::naming_service_client::NamingServiceClient;
use crate::models::naming_v1::{
    GetVerificationInfoRequest, GetVerificationInfoResponse, ResolveRequest, ResolveResponse,
};

/// Name resolution and name-ownership verification.
#[derive(Clone)]
pub struct NamingService {
    client: NamingServiceClient<GrpcChannel>,
}

impl NamingService {
    pub(crate) fn new(channel: GrpcChannel) -> Self {
        Self {
            client: NamingServiceClient::new(channel),
        }
    }

    pub fn client(&self) -> NamingServiceClient<GrpcChannel> {
        self.client.clone()
    }

    pub async fn resolve(&self, request: ResolveRequest) -> Result<ResolveResponse> {
        Ok(self
            .client()
            .resolve(request)
            .await
            .map_err(rpc("resolve"))?
            .into_inner())
    }

    pub async fn get_verification_info(
        &self,
        request: GetVerificationInfoRequest,
    ) -> Result<GetVerificationInfoResponse> {
        Ok(self
            .client()
            .get_verification_info(request)
            .await
            .map_err(rpc("get_verification_info"))?
            .into_inner())
    }
}
