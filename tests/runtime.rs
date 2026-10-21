// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests of the runtime discovery client against a real
//! `dirctl daemon` that discovers a labelled Docker container. They skip
//! themselves unless `DIRECTORY_RUNTIME_ADDRESS` is set; run them with
//! `task test:runtime`, which starts the daemon and the container.

use std::time::Duration;

use agntcy_dir::client::services::RuntimeService;
use agntcy_dir::models::runtime_v1::{GetWorkloadRequest, ListWorkloadsRequest, Workload};
use tokio::time::{sleep, Instant};

/// The runtime service and the name of the workload the test environment started.
async fn env() -> Option<(RuntimeService, String)> {
    let address = std::env::var("DIRECTORY_RUNTIME_ADDRESS").ok()?;
    let name = std::env::var("RUNTIME_E2E_WORKLOAD_NAME").expect("RUNTIME_E2E_WORKLOAD_NAME must be set");
    Some((RuntimeService::connect(address).await.unwrap(), name))
}

/// Matches only containers carrying the test label; the workload itself is
/// picked out by name client-side (the name is not a request filter).
fn request() -> ListWorkloadsRequest {
    ListWorkloadsRequest {
        labels: [("sdk.agntcy/discover".to_string(), "true".to_string())].into(),
        ..Default::default()
    }
}

async fn discovered(svc: &RuntimeService, name: &str) -> Workload {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let found = svc
            .list_workloads(request())
            .await
            .unwrap()
            .into_iter()
            .find(|w| w.name == name);
        if let Some(w) = found {
            return w;
        }
        assert!(Instant::now() < deadline, "workload {name} was never discovered");
        sleep(Duration::from_secs(2)).await;
    }
}

#[tokio::test]
async fn lists_and_gets_the_discovered_workload() {
    let Some((svc, name)) = env().await else {
        eprintln!("DIRECTORY_RUNTIME_ADDRESS not set, skipping");
        return;
    };

    let listed = discovered(&svc, &name).await;
    assert_eq!(listed.runtime, "docker");
    assert_eq!(listed.r#type, "container");
    assert_eq!(
        listed.labels.get("sdk.agntcy/agent-type").map(String::as_str),
        Some("a2a")
    );
    assert!(
        listed
            .locators
            .iter()
            .any(|l| l.protocol == "tcp" && l.url.starts_with("tcp://")),
        "{:?}",
        listed.locators
    );

    let got = svc
        .get_workload(GetWorkloadRequest { id: listed.id.clone() })
        .await
        .unwrap();
    assert_eq!(got.id, listed.id);
    assert_eq!(got.name, name);
}

#[tokio::test]
async fn filters_narrow_the_result() {
    let Some((svc, name)) = env().await else {
        return;
    };
    discovered(&svc, &name).await;

    let matching = |req: ListWorkloadsRequest| {
        let svc = svc.clone();
        let name = name.clone();
        async move { svc.list_workloads(req).await.unwrap().iter().any(|w| w.name == name) }
    };
    let base = request;

    assert!(
        matching(ListWorkloadsRequest {
            runtime_types: vec!["docker".into()],
            ..base()
        })
        .await
    );
    assert!(
        matching(ListWorkloadsRequest {
            locator_protocols: vec!["tcp".into()],
            ..base()
        })
        .await
    );
    assert!(
        !matching(ListWorkloadsRequest {
            runtime_types: vec!["kubernetes".into()],
            ..base()
        })
        .await
    );
    assert!(
        !matching(ListWorkloadsRequest {
            locator_protocols: vec!["slim".into()],
            ..base()
        })
        .await
    );
    assert!(
        !matching(ListWorkloadsRequest {
            labels: [("sdk.agntcy/discover".to_string(), "false".to_string())].into(),
            ..Default::default()
        })
        .await
    );
}

#[tokio::test]
async fn unknown_workload_reports_the_operation() {
    let Some((svc, _)) = env().await else {
        return;
    };
    let err = svc
        .get_workload(GetWorkloadRequest {
            id: "does-not-exist".into(),
        })
        .await
        .unwrap_err();
    assert!(err.to_string().starts_with("get_workload failed:"), "{err}");
    assert!(err.to_string().contains("workload not found"), "{err}");
}
