// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Push, pull, search, publish and delete records.
//!
//! ```sh
//! DIRECTORY_CLIENT_SERVER_ADDRESS=localhost:8888 cargo run --example example
//! ```

use agntcy_dir::models::core_v1::Record;
use agntcy_dir::models::routing_v1::{self, publish_request, RecordRefs};
use agntcy_dir::models::search_v1::{self, RecordQuery, RecordQueryType};
use agntcy_dir::{Client, Config};
use serde_json::json;

fn generate_record(name: &str) -> Result<Record, serde_json::Error> {
    serde_json::from_value(json!({
        "data": {
            "name": name,
            "version": "v1.0.0",
            "schema_version": "0.8.0",
            "description": "My example agent",
            "authors": ["AGNTCY"],
            "created_at": "2025-03-19T17:06:37Z",
            "skills": [
                {"name": "natural_language_processing/natural_language_generation/text_completion", "id": 10201},
                {"name": "natural_language_processing/analytical_reasoning/problem_solving", "id": 10702}
            ],
            "locators": [{"type": "docker_image", "url": "https://ghcr.io/agntcy/marketing-strategy"}],
            "domains": [{"name": "technology/networking", "id": 103}],
            "annotations": {"env": "prod"}
        }
    }))
}

#[tokio::main]
async fn main() -> agntcy_dir::Result<()> {
    let client = Client::new(Config::from_env()?).await?;

    let records = vec![generate_record("example-record")?, generate_record("example-record2")?];

    let refs = client.push(records).await?;
    for r in &refs {
        println!("Pushed object ref: {}", r.cid);
    }

    for record in client.pull(refs.clone()).await? {
        println!("Pulled object: {}", serde_json::to_string(&record)?);
    }

    for meta in client.lookup(refs.clone()).await? {
        println!("Lookup result: {}", serde_json::to_string(&meta)?);
    }

    let skill_hits = client
        .search_cids(search_v1::SearchCiDsRequest {
            queries: vec![RecordQuery {
                r#type: RecordQueryType::SkillId as i32,
                value: "10201".into(),
                negate: false,
            }],
            limit: Some(3),
            ..Default::default()
        })
        .await?;
    println!("Search result: {} hit(s)", skill_hits.len());

    let annotation_hits = client
        .search_cids(search_v1::SearchCiDsRequest {
            queries: vec![RecordQuery {
                r#type: RecordQueryType::Annotation as i32,
                value: "env:prod".into(),
                negate: false,
            }],
            limit: Some(3),
            ..Default::default()
        })
        .await?;
    println!("Annotation search result: {} hit(s)", annotation_hits.len());

    client
        .publish(routing_v1::PublishRequest {
            request: Some(publish_request::Request::RecordRefs(RecordRefs { refs: refs.clone() })),
        })
        .await?;
    println!("Objects published.");

    let listed = client
        .list(routing_v1::ListRequest {
            queries: vec![routing_v1::RecordQuery {
                r#type: routing_v1::RecordQueryType::Skill as i32,
                value: "natural_language_processing/analytical_reasoning/problem_solving".into(),
            }],
            limit: None,
        })
        .await?;
    for r in listed {
        println!("Listed object: {}", serde_json::to_string(&r)?);
    }

    client
        .unpublish(routing_v1::UnpublishRequest {
            request: Some(routing_v1::unpublish_request::Request::RecordRefs(RecordRefs {
                refs: refs.clone(),
            })),
        })
        .await?;
    println!("Objects unpublished.");

    client.delete(refs).await?;
    println!("Objects deleted.");
    Ok(())
}
