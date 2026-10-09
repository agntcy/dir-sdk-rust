// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use tokio_stream::iter;
use tonic::Request;

use super::{collect, rpc};
use crate::client::transport::GrpcChannel;
use crate::error::{Error, Result};
use crate::models::core_v1::{Record, RecordMeta, RecordRef};
use crate::models::store_v1::store_service_client::StoreServiceClient;
use crate::models::store_v1::{
    DeleteReferrerRequest, DeleteReferrerResponse, PullReferrerRequest, PullReferrerResponse, PushReferrerRequest,
    PushReferrerResponse,
};

/// Record storage: push, pull, lookup, delete and referrers.
#[derive(Clone)]
pub struct StoreService {
    client: StoreServiceClient<GrpcChannel>,
}

impl StoreService {
    pub(crate) fn new(channel: GrpcChannel) -> Self {
        Self {
            client: StoreServiceClient::new(channel),
        }
    }

    /// The underlying generated gRPC client.
    pub fn client(&self) -> StoreServiceClient<GrpcChannel> {
        self.client.clone()
    }

    pub async fn push(&self, records: Vec<Record>) -> Result<Vec<RecordRef>> {
        let resp = self
            .client()
            .push(Request::new(iter(records)))
            .await
            .map_err(rpc("push"))?;
        collect("push", resp.into_inner()).await
    }

    pub async fn push_referrer(&self, requests: Vec<PushReferrerRequest>) -> Result<Vec<PushReferrerResponse>> {
        let resp = self
            .client()
            .push_referrer(Request::new(iter(requests)))
            .await
            .map_err(rpc("push_referrer"))?;
        collect("push_referrer", resp.into_inner()).await
    }

    pub async fn pull(&self, refs: Vec<RecordRef>) -> Result<Vec<Record>> {
        let resp = self
            .client()
            .pull(Request::new(iter(refs)))
            .await
            .map_err(rpc("pull"))?;
        collect("pull", resp.into_inner()).await
    }

    pub async fn pull_referrer(&self, requests: Vec<PullReferrerRequest>) -> Result<Vec<PullReferrerResponse>> {
        let resp = self
            .client()
            .pull_referrer(Request::new(iter(requests)))
            .await
            .map_err(rpc("pull_referrer"))?;
        collect("pull_referrer", resp.into_inner()).await
    }

    pub async fn lookup(&self, refs: Vec<RecordRef>) -> Result<Vec<RecordMeta>> {
        let resp = self
            .client()
            .lookup(Request::new(iter(refs)))
            .await
            .map_err(rpc("lookup"))?;
        collect("lookup", resp.into_inner()).await
    }

    pub async fn delete(&self, refs: Vec<RecordRef>) -> Result<()> {
        self.client()
            .delete(Request::new(iter(refs)))
            .await
            .map_err(rpc("delete"))?;
        Ok(())
    }

    pub async fn delete_referrer(&self, request: DeleteReferrerRequest) -> Result<DeleteReferrerResponse> {
        let resp = self
            .client()
            .delete_referrer(Request::new(iter(vec![request])))
            .await
            .map_err(rpc("delete_referrer"))?;
        collect("delete_referrer", resp.into_inner())
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Rpc {
                op: "delete_referrer",
                source: Box::new(tonic::Status::unknown("empty response")),
            })
    }
}
