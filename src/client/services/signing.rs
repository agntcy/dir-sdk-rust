// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use super::rpc;
use crate::client::config::Config;
use crate::client::dirctl;
use crate::client::transport::GrpcChannel;
use crate::error::{Error, Result};
use crate::models::sign_v1::sign_service_client::SignServiceClient;
use crate::models::sign_v1::{SignRequest, VerifyRequest, VerifyResponse};

/// Record signing (via `dirctl`) and signature verification.
#[derive(Clone)]
pub struct SignService {
    config: Config,
    client: SignServiceClient<GrpcChannel>,
}

impl SignService {
    pub(crate) fn new(config: Config, channel: GrpcChannel) -> Self {
        Self {
            config,
            client: SignServiceClient::new(channel),
        }
    }

    pub fn client(&self) -> SignServiceClient<GrpcChannel> {
        self.client.clone()
    }

    /// Signs a record by invoking `dirctl sign`.
    pub async fn sign(&self, request: &SignRequest) -> Result<()> {
        dirctl::sign_record(&self.config, request).await
    }

    /// Verifies a record, on the server when `from_server` is set and
    /// locally through `dirctl verify` otherwise.
    pub async fn verify(&self, request: VerifyRequest) -> Result<VerifyResponse> {
        if request.from_server {
            if request.record_ref.as_ref().map_or(true, |r| r.cid.is_empty()) {
                return Err(Error::InvalidArgument(
                    "VerifyRequest.record_ref with cid is required".into(),
                ));
            }
            return Ok(self.client().verify(request).await.map_err(rpc("verify"))?.into_inner());
        }
        dirctl::verify_record(&self.config, &request).await
    }
}
