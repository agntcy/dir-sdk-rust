// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use tonic::Streaming;

use super::rpc;
use crate::client::transport::GrpcChannel;
use crate::error::Result;
use crate::models::events_v1::event_service_client::EventServiceClient;
use crate::models::events_v1::{ListenRequest, ListenResponse};

/// Server-sent events about the Directory.
#[derive(Clone)]
pub struct EventService {
    client: EventServiceClient<GrpcChannel>,
}

impl EventService {
    pub(crate) fn new(channel: GrpcChannel) -> Self {
        Self {
            client: EventServiceClient::new(channel),
        }
    }

    pub fn client(&self) -> EventServiceClient<GrpcChannel> {
        self.client.clone()
    }

    /// Opens the event stream; poll it with `Streaming::message`.
    pub async fn listen(&self, request: ListenRequest) -> Result<Streaming<ListenResponse>> {
        Ok(self.client().listen(request).await.map_err(rpc("listen"))?.into_inner())
    }
}
