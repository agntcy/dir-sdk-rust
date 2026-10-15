// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Integration tests against a live Directory node (port of the JS/Python SDK
//! suites). They are `#[ignore]`d so a plain `cargo test` stays offline; run
//! them with `task test` (spins up a kind cluster) or, against an existing
//! node:
//!
//! ```sh
//! DIRECTORY_CLIENT_SERVER_ADDRESS=localhost:8888 cargo test --test client -- --ignored
//! ```
//!
//! Environment: `DIRCTL_PATH` (or `DIRCTL_IMAGE`/`DIRCTL_IMAGE_TAG`) and
//! `COSIGN_PATH` for signing; optional `OIDC_TOKEN` / `OIDC_PROVIDER_URL` /
//! `OIDC_CLIENT_ID` for keyless signing; `DIRECTORY_SERVER_PEER1_ADDRESS` for sync.

use std::time::Duration;

use agntcy_dir::models::core_v1::{Record, RecordRef};
use agntcy_dir::models::identity::GetVerificationInfoRequest;
use agntcy_dir::models::sign_v1::{self, signer_info, SignerInfo};
use agntcy_dir::models::store_v1::{
    CreateSyncRequest, DeleteReferrerRequest, DeleteSyncRequest, GetSyncRequest, ListSyncsRequest, PullReferrerRequest,
    PushReferrerRequest,
};
use agntcy_dir::models::{events_v1, identity_v1, routing_v1, search_v1};
use agntcy_dir::{Client, Config};
use rand::Rng;
use serde_json::json;
use tokio::time::sleep;

const SIGNATURE_TYPE: &str = "agntcy.dir.sign.v1.Signature";

fn short_id() -> String {
    format!("{:08x}", rand::thread_rng().gen::<u32>())
}

fn gen_records(count: usize, test: &str) -> Vec<Record> {
    (0..count)
        .map(|i| {
            serde_json::from_value(json!({
                "data": {
                    "name": format!("agntcy-{test}-{i}-{}", short_id()),
                    "version": "v3.0.0",
                    "schema_version": "0.7.0",
                    "description": "Research agent for Cisco's marketing strategy.",
                    "authors": ["Cisco Systems"],
                    "created_at": "2025-03-19T17:06:37Z",
                    "skills": [
                        {"name": "natural_language_processing/natural_language_generation/text_completion", "id": 10201},
                        {"name": "natural_language_processing/analytical_reasoning/problem_solving", "id": 10702}
                    ],
                    "locators": [{"type": "docker_image", "url": "https://ghcr.io/agntcy/marketing-strategy"}],
                    "domains": [{"name": "technology/networking", "id": 103}],
                    "modules": []
                }
            }))
            .unwrap()
        })
        .collect()
}

async fn client() -> Client {
    Client::new(Config::from_env().unwrap()).await.unwrap()
}

fn publish_req(refs: &[RecordRef]) -> routing_v1::PublishRequest {
    routing_v1::PublishRequest {
        request: Some(routing_v1::publish_request::Request::RecordRefs(
            routing_v1::RecordRefs { refs: refs.to_vec() },
        )),
    }
}

fn unpublish_req(refs: &[RecordRef]) -> routing_v1::UnpublishRequest {
    routing_v1::UnpublishRequest {
        request: Some(routing_v1::unpublish_request::Request::RecordRefs(
            routing_v1::RecordRefs { refs: refs.to_vec() },
        )),
    }
}

fn signature_referrer(r: &RecordRef) -> PushReferrerRequest {
    serde_json::from_value(json!({
        "recordRef": {"cid": r.cid},
        "type": SIGNATURE_TYPE,
        "data": {"signature": "dGVzdC1zaWduYXR1cmU=", "annotations": {"payload": "test-payload-data"}}
    }))
    .unwrap()
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn push() {
    let refs = client().await.push(gen_records(2, "push")).await.unwrap();
    assert_eq!(refs.len(), 2);
    assert!(refs.iter().all(|r| r.cid.len() == 59), "{refs:?}");
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn pull() {
    let c = client().await;
    let records = gen_records(2, "pull");
    let refs = c.push(records.clone()).await.unwrap();
    let pulled = c.pull(refs).await.unwrap();
    assert_eq!(pulled, records);
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn search_cids() {
    let c = client().await;
    c.push(gen_records(1, "search")).await.unwrap();
    let hits = c
        .search_cids(search_v1::SearchCiDsRequest {
            queries: vec![search_v1::RecordQuery {
                r#type: search_v1::RecordQueryType::SkillId as i32,
                value: "10201".into(),
                negate: false,
            }],
            limit: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!hits.is_empty());
    assert!(hits.iter().all(|h| !h.record_cid.is_empty()));
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn search_annotation() {
    let c = client().await;
    let record: Record = serde_json::from_value(json!({
        "data": {
            "name": format!("agntcy-annotation-{}", short_id()),
            "version": "v3.0.0", "schema_version": "0.8.0",
            "description": "Record with custom annotations.",
            "authors": ["AGNTCY"], "created_at": "2025-03-19T17:06:37Z",
            "annotations": {"key": "value"},
            "skills": [{"name": "natural_language_processing/natural_language_generation/text_completion", "id": 10201}],
            "locators": [], "domains": [{"name": "technology/networking", "id": 103}], "modules": []
        }
    }))
    .unwrap();
    let refs = c.push(vec![record]).await.unwrap();
    assert_eq!(refs.len(), 1);

    let hits = c
        .search_cids(search_v1::SearchCiDsRequest {
            queries: vec![search_v1::RecordQuery {
                r#type: search_v1::RecordQueryType::Annotation as i32,
                value: "key:value".into(),
                negate: false,
            }],
            limit: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(hits.iter().any(|h| h.record_cid == refs[0].cid));
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn search_routing() {
    let c = client().await;
    let refs = c.push(gen_records(1, "searchRouting")).await.unwrap();
    c.publish(publish_req(&refs)).await.unwrap();
    sleep(Duration::from_secs(5)).await;

    c.search_routing(routing_v1::SearchRequest {
        queries: vec![routing_v1::RecordQuery {
            r#type: routing_v1::RecordQueryType::Domain as i32,
            value: "technology/networking".into(),
        }],
        limit: Some(10),
        ..Default::default()
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn delete_referrer() {
    let c = client().await;
    let refs = c.push(gen_records(1, "deleteReferrer")).await.unwrap();

    let pushed = c.push_referrer(vec![signature_referrer(&refs[0])]).await.unwrap();
    assert_eq!(pushed.len(), 1);
    assert!(pushed[0].success, "{:?}", pushed[0].error_message);

    let deleted = c
        .delete_referrer(DeleteReferrerRequest {
            record: Some(refs[0].clone()),
            referrer_ref: pushed[0].referrer_ref.clone(),
            referrer_type: None,
        })
        .await
        .unwrap();
    assert!(!deleted.referrer_refs.is_empty());
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn lookup() {
    let c = client().await;
    let refs = c.push(gen_records(2, "lookup")).await.unwrap();
    let metas = c.lookup(refs.clone()).await.unwrap();
    assert_eq!(metas.len(), 2);
    assert!(metas.iter().zip(&refs).all(|(m, r)| m.cid == r.cid));
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn publish() {
    let c = client().await;
    let refs = c.push(gen_records(1, "publish")).await.unwrap();
    c.publish(publish_req(&refs)).await.unwrap();
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn list() {
    let c = client().await;
    let refs = c.push(gen_records(1, "list")).await.unwrap();
    c.publish(publish_req(&refs)).await.unwrap();
    // allow the publication to be indexed
    sleep(Duration::from_secs(5)).await;

    let listed = c
        .list(routing_v1::ListRequest {
            queries: vec![routing_v1::RecordQuery {
                r#type: routing_v1::RecordQueryType::Domain as i32,
                value: "technology/networking".into(),
            }],
            limit: None,
        })
        .await
        .unwrap();
    assert!(!listed.is_empty());
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn unpublish() {
    let c = client().await;
    let refs = c.push(gen_records(1, "unpublish")).await.unwrap();
    c.publish(publish_req(&refs)).await.unwrap();
    c.unpublish(unpublish_req(&refs)).await.unwrap();
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn delete() {
    let c = client().await;
    let refs = c.push(gen_records(1, "delete")).await.unwrap();
    c.delete(refs.clone()).await.unwrap();
    assert!(c.pull(refs).await.is_err(), "record should be gone");
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn push_referrer() {
    let c = client().await;
    let refs = c.push(gen_records(2, "pushReferrer")).await.unwrap();
    let resp = c
        .push_referrer(refs.iter().map(signature_referrer).collect())
        .await
        .unwrap();
    assert_eq!(resp.len(), 2);
    assert!(resp.iter().all(|r| r.success));
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn pull_referrer() {
    let c = client().await;
    let refs = c.push(gen_records(2, "pullReferrer")).await.unwrap();
    let pushed = c
        .push_referrer(refs.iter().map(signature_referrer).collect())
        .await
        .unwrap();
    assert_eq!(pushed.len(), 2);

    let pulled = c
        .pull_referrer(
            refs.iter()
                .map(|r| PullReferrerRequest {
                    record_ref: Some(r.clone()),
                    referrer_type: Some(SIGNATURE_TYPE.into()),
                    referrer_ref: None,
                })
                .collect(),
        )
        .await
        .unwrap();
    assert_eq!(pulled.len(), 2);
    assert!(pulled.iter().all(|p| p.referrer.is_some()));
}

fn signer_summary(s: &SignerInfo) -> String {
    match &s.r#type {
        Some(signer_info::Type::Key(k)) => format!("key:{}:{}", k.public_key, k.algorithm),
        Some(signer_info::Type::Oidc(o)) => format!("oidc:{}:{}", o.issuer, o.subject),
        None => "none".into(),
    }
}

#[tokio::test]
#[ignore = "requires a live Directory node, dirctl and cosign"]
async fn sign_and_verify() {
    let c = client().await;
    let mut refs = c.push(gen_records(2, "sign_verify")).await.unwrap();

    let key_password = "testing-key";
    let dir = tempfile::tempdir().unwrap();
    let cosign = std::env::var("COSIGN_PATH").unwrap_or_else(|_| "cosign".into());
    let status = std::process::Command::new(cosign)
        .arg("generate-key-pair")
        .current_dir(dir.path())
        .env("COSIGN_PASSWORD", key_password)
        .output()
        .expect("cosign must be installed");
    assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
    let key_path = dir.path().join("cosign.key").to_string_lossy().into_owned();

    let token = std::env::var("OIDC_TOKEN").unwrap_or_default();
    let provider_url = std::env::var("OIDC_PROVIDER_URL").unwrap_or_default();
    let client_id = std::env::var("OIDC_CLIENT_ID").unwrap_or_else(|_| "sigstore".into());
    let with_oidc = !token.is_empty() && !provider_url.is_empty();

    c.sign(
        &serde_json::from_value(json!({
            "recordRef": {"cid": refs[0].cid},
            "provider": {"key": {"privateKey": key_path, "password": base64_of(key_password)}}
        }))
        .unwrap(),
    )
    .await
    .unwrap();

    if with_oidc {
        c.sign(
            &serde_json::from_value(json!({
                "recordRef": {"cid": refs[1].cid},
                "provider": {"oidc": {"idToken": token, "options": {"oidcClientId": client_id, "oidcProviderUrl": provider_url}}}
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    } else {
        refs.pop(); // unsigned record: no OIDC tested
    }

    // Verification is asynchronous (the reconciler caches results).
    sleep(Duration::from_secs(8)).await;

    for (i, r) in refs.iter().enumerate() {
        let local = c
            .verify(sign_v1::VerifyRequest {
                record_ref: Some(r.clone()),
                provider: Some(sign_v1::VerifyRequestProvider {
                    request: Some(sign_v1::verify_request_provider::Request::Any(Default::default())),
                }),
                from_server: false,
            })
            .await
            .unwrap();
        assert!(local.success, "{:?}", local.error_message);
        assert!(!local.signers.is_empty());

        if i == 0 {
            match &local.signers[0].r#type {
                Some(signer_info::Type::Key(k)) => {
                    assert!(!k.public_key.is_empty());
                    assert!(!k.algorithm.is_empty());
                }
                other => panic!("expected key signer, got {other:?}"),
            }
        } else {
            assert!(matches!(local.signers[0].r#type, Some(signer_info::Type::Oidc(_))));
        }

        // The cached server result must match local verification.
        let remote = c
            .verify(sign_v1::VerifyRequest {
                record_ref: Some(r.clone()),
                provider: None,
                from_server: true,
            })
            .await
            .unwrap();
        assert_eq!(remote.success, local.success);
        let summarize = |v: &[SignerInfo]| v.iter().map(signer_summary).collect::<Vec<_>>();
        assert_eq!(summarize(&remote.signers), summarize(&local.signers));
    }

    let err = c
        .sign(
            &serde_json::from_value(json!({
                "recordRef": {"cid": "invalid-cid"},
                "provider": {"key": {"privateKey": "invalid-private-key", "password": ""}}
            }))
            .unwrap(),
        )
        .await
        .unwrap_err();
    // Which check dirctl trips over first (key vs CID) varies by version.
    assert!(matches!(err, agntcy_dir::Error::Dirctl(_)), "{err}");
}

fn base64_of(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn sync() {
    let c = client().await;
    let remote = std::env::var("DIRECTORY_SERVER_PEER1_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8891".into());

    let created = c
        .create_sync(CreateSyncRequest {
            remote_directory_url: remote,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(is_uuid(&created.sync_id), "{}", created.sync_id);

    let listed = c.list_syncs(ListSyncsRequest::default()).await.unwrap();
    assert!(listed.iter().all(|s| is_uuid(&s.sync_id)));

    let got = c
        .get_sync(GetSyncRequest {
            sync_id: created.sync_id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(got.sync_id, created.sync_id);

    c.delete_sync(DeleteSyncRequest {
        sync_id: created.sync_id,
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn listen() {
    let c = client().await;
    let refs = c.push(gen_records(1, "listen")).await.unwrap();

    // Generate events in the background (the JS suite shells out to `dirctl pull`).
    let bg = c.clone();
    let task = tokio::spawn(async move {
        for _ in 0..90 {
            let _ = bg.pull(refs.clone()).await;
            sleep(Duration::from_secs(1)).await;
        }
    });

    let mut events = c.listen(events_v1::ListenRequest::default()).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(20), events.message()).await;
    task.abort();
    assert!(matches!(first, Ok(Ok(Some(_)))), "no event received: {first:?}");
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn publication() {
    let c = client().await;
    let refs = c.push(gen_records(1, "publication")).await.unwrap();

    let created = c.create_publication(publish_req(&refs)).await.unwrap();
    assert!(!created.publication_id.is_empty());

    c.list_publication(routing_v1::ListPublicationsRequest::default())
        .await
        .unwrap();

    let got = c
        .get_publication(routing_v1::GetPublicationRequest {
            publication_id: created.publication_id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(got.publication_id, created.publication_id);
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn resolve() {
    let c = client().await;
    let records = gen_records(1, "resolve");
    let data = serde_json::to_value(records[0].data.as_ref().unwrap()).unwrap();
    let (name, version) = (
        data["name"].as_str().unwrap().to_string(),
        data["version"].as_str().unwrap().to_string(),
    );
    let refs = c.push(records).await.unwrap();

    let by_name = c
        .resolve(identity_v1::ResolveRequest {
            name: name.clone(),
            version: None,
        })
        .await
        .unwrap();
    assert!(!by_name.records.is_empty());
    assert_eq!(by_name.records[0].cid, refs[0].cid);
    assert_eq!(by_name.records[0].name, name);
    assert_eq!(by_name.records[0].version, version);

    let by_version = c
        .resolve(identity_v1::ResolveRequest {
            name,
            version: Some(version),
        })
        .await
        .unwrap();
    assert_eq!(by_version.records.len(), 1);
    assert_eq!(by_version.records[0].cid, refs[0].cid);
}

#[tokio::test]
#[ignore = "requires a live Directory node"]
async fn get_verification_info() {
    let c = client().await;
    let refs = c.push(gen_records(1, "verification")).await.unwrap();

    // unsigned record: unverified, with an explanation
    let info = c
        .get_verification_info(GetVerificationInfoRequest {
            cid: Some(refs[0].cid.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!info.verified);
    assert!(info.error_message.is_some());
}
