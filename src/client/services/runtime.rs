// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use super::{collect, rpc};
use crate::client::config::Config;
use crate::client::transport::{self, GrpcChannel};
use crate::error::Result;
use crate::models::runtime_v1::discovery_service_client::DiscoveryServiceClient;
use crate::models::runtime_v1::{GetWorkloadRequest, ListWorkloadsRequest, Workload};

/// Runtime discovery (`agntcy.dir.runtime.v1.DiscoveryService`), served by
/// dir-runtime and `dirctl daemon`.
///
/// dir-runtime listens on its own address (`localhost:8888` by default in
/// `dirctl daemon`), so this service has its own connection and is not part
/// of [`Client`](crate::Client): the Directory's credentials, such as the
/// OIDC token, are never sent to it.
#[derive(Clone)]
pub struct RuntimeService {
    client: DiscoveryServiceClient<GrpcChannel>,
}

impl RuntimeService {
    /// Connects to dir-runtime at `server_address` (`host:port` or a full
    /// `http(s)://` URL) without authentication. The connection is
    /// established lazily.
    pub async fn connect(server_address: impl Into<String>) -> Result<Self> {
        let config = Config {
            server_address: server_address.into(),
            ..Config::default()
        };
        let channel = transport::create_channel(&config, None).await?;
        Ok(Self {
            client: DiscoveryServiceClient::new(channel),
        })
    }

    pub fn client(&self) -> DiscoveryServiceClient<GrpcChannel> {
        self.client.clone()
    }

    /// Gets a workload by hostname or workload ID.
    pub async fn get_workload(&self, request: GetWorkloadRequest) -> Result<Workload> {
        let resp = self.client().get_workload(request).await.map_err(rpc("get_workload"))?;
        Ok(resp.into_inner())
    }

    /// Lists the workloads matching the request's filters.
    pub async fn list_workloads(&self, request: ListWorkloadsRequest) -> Result<Vec<Workload>> {
        let resp = self
            .client()
            .list_workloads(request)
            .await
            .map_err(rpc("list_workloads"))?;
        collect("list_workloads", resp.into_inner()).await
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;

    use tokio_stream::wrappers::TcpListenerStream;
    use tokio_stream::Stream;
    use tonic::{Request, Response, Status};

    use super::*;
    use crate::models::runtime_v1::discovery_service_server::{DiscoveryService, DiscoveryServiceServer};

    type Out<T> = Pin<Box<dyn Stream<Item = std::result::Result<T, Status>> + Send>>;

    fn workload(id: &str, runtime: &str) -> Workload {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "name": format!("{id}-name"),
            "runtime": runtime,
            "locators": [{"protocol": "http", "url": "http://10.0.0.1:80"}]
        }))
        .unwrap()
    }

    /// In-process dir-runtime holding a fixed set of workloads; it applies
    /// only the `runtime_types` filter.
    struct Fake(Vec<Workload>);

    #[tonic::async_trait]
    impl DiscoveryService for Fake {
        type ListWorkloadsStream = Out<Workload>;

        async fn get_workload(
            &self,
            request: Request<GetWorkloadRequest>,
        ) -> std::result::Result<Response<Workload>, Status> {
            let id = request.into_inner().id;
            self.0
                .iter()
                .find(|w| w.id == id)
                .cloned()
                .map(Response::new)
                .ok_or_else(|| Status::not_found(id))
        }

        async fn list_workloads(
            &self,
            request: Request<ListWorkloadsRequest>,
        ) -> std::result::Result<Response<Self::ListWorkloadsStream>, Status> {
            let types = request.into_inner().runtime_types;
            let items: Vec<_> = self
                .0
                .iter()
                .filter(|w| types.is_empty() || types.contains(&w.runtime))
                .cloned()
                .map(Ok)
                .collect();
            Ok(Response::new(Box::pin(tokio_stream::iter(items))))
        }
    }

    async fn start() -> RuntimeService {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fake = Fake(vec![workload("a", "docker"), workload("b", "kubernetes")]);
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(DiscoveryServiceServer::new(fake))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        RuntimeService::connect(address.to_string()).await.unwrap()
    }

    #[tokio::test]
    async fn lists_workloads_with_filters() {
        let svc = start().await;
        let all = svc.list_workloads(ListWorkloadsRequest::default()).await.unwrap();
        assert_eq!(all.len(), 2);

        let docker = svc
            .list_workloads(ListWorkloadsRequest {
                runtime_types: vec!["docker".into()],
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(docker.len(), 1);
        assert_eq!(docker[0].id, "a");
        assert_eq!(docker[0].locators[0].url, "http://10.0.0.1:80");
    }

    #[tokio::test]
    async fn gets_workload_and_reports_operation_on_error() {
        let svc = start().await;
        let w = svc.get_workload(GetWorkloadRequest { id: "b".into() }).await.unwrap();
        assert_eq!(w.runtime, "kubernetes");

        let err = svc
            .get_workload(GetWorkloadRequest { id: "missing".into() })
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("get_workload failed:"), "{err}");
    }

    #[test]
    fn workload_serializes_as_protobuf_json() {
        let json = serde_json::to_value(workload("a", "docker")).unwrap();
        assert_eq!(json["id"], "a");
        assert_eq!(json["locators"][0]["protocol"], "http");
    }
}
