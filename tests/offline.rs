// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Tests that need no Directory node.

use agntcy_dir::models::core_v1::Record;
use agntcy_dir::{Client, Config};
use serde_json::json;

#[test]
fn record_json_roundtrip() {
    let r: Record = serde_json::from_value(json!({"data": {"name": "roundtrip", "skills": [{"id": 1}]}})).unwrap();
    let back: Record = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(r, back);
    assert_eq!(serde_json::to_value(&back).unwrap()["data"]["name"], json!("roundtrip"));
}

#[tokio::test]
async fn unreachable_server_reports_operation() {
    let client = Client::new(Config {
        server_address: "127.0.0.1:1".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    let err = client.lookup(vec![]).await.unwrap_err();
    assert!(err.to_string().starts_with("lookup failed:"), "{err}");
}
