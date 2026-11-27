# Rust SDK

The Directory Rust SDK (`agntcy-dir`) is an async [`tokio`](https://tokio.rs) client for the
Directory gRPC API, built on [`tonic`](https://github.com/hyperium/tonic) and
[`prost`](https://github.com/tokio-rs/prost). It offers the same features as the
[Python](dir-sdk-python.md) and [JavaScript / TypeScript](dir-sdk-javascript.md) SDKs, with
snake_case method names.

- Source: [dir-sdk-rust repository on GitHub](https://github.com/agntcy/dir-sdk-rust)
- Package: [agntcy-dir on crates.io](https://crates.io/crates/agntcy-dir)

## Features

| API | Methods |
|-----|---------|
| Store | `push`, `pull`, `lookup`, `delete`, `push_referrer`, `pull_referrer`, `delete_referrer` |
| Search | `search_cids`, `search_records` |
| Routing | `publish`, `unpublish`, `list`, `search_routing` |
| Publication | `create_publication`, `list_publication`, `get_publication` |
| Identity | `resolve`, `get_verification_info` |
| Sync | `create_sync`, `list_syncs`, `get_sync`, `delete_sync` |
| Runtime discovery | `RuntimeService::connect`, `get_workload`, `list_workloads` (separate dir-runtime address) |
| Events | `listen` (returns a `tonic::Streaming`) |
| Signing | `sign` (cosign key or keyless Sigstore OIDC), `verify`. Both run natively with no `dirctl` or `cosign` binary, and signatures are compatible with `dirctl`. |

- Every message is a generated type with protobuf-JSON `serde` support, so records can be built
  from JSON.
- The SDK collects server-streaming RPCs into a `Vec`. `listen` returns the stream instead.
- You don't need `protoc`. The build generates the stubs with the pure-Rust `protox`.

## Prerequisites

- Rust 1.86 or higher
- A running Directory server (see [Quickstart](dir-quickstart.md) or
  [Kubernetes Deployment](dir-deployment-kubernetes.md))
- For SPIFFE authentication modes: a running [SPIRE](https://spiffe.io/docs/latest/spire-about/) agent

## Installation

```bash
cargo add agntcy-dir
cargo add tokio --features macros,rt-multi-thread
cargo add serde_json
```

Or in `Cargo.toml`:

```toml
[dependencies]
agntcy-dir = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
serde_json = "1"
```

## Configuration

### Environment variables

`Config::from_env()` reads the same variables as the other SDKs:

| Variable | Description | Default |
|----------|-------------|---------|
| `DIRECTORY_CLIENT_SERVER_ADDRESS` | Directory server address (`host:port` or URL) | `127.0.0.1:8888` |
| `DIRECTORY_CLIENT_AUTH_MODE` | Authentication mode: `x509`, `jwt`, `tls`, `oidc`, or empty for insecure | `""` |
| `DIRECTORY_CLIENT_SPIFFE_SOCKET_PATH` | SPIFFE Workload API socket path (`x509`, `jwt`) | `""` |
| `DIRECTORY_CLIENT_JWT_AUDIENCE` | JWT audience (`jwt`) | `""` |
| `DIRECTORY_CLIENT_TLS_CA_FILE` | CA certificate file (`tls`; optional for `oidc`) | `""` |
| `DIRECTORY_CLIENT_TLS_CERT_FILE` | Client certificate file (`tls`) | `""` |
| `DIRECTORY_CLIENT_TLS_KEY_FILE` | Client key file (`tls`) | `""` |
| `DIRECTORY_CLIENT_TLS_SERVER_NAME` | SNI / authority override | `""` |
| `DIRECTORY_CLIENT_TLS_SKIP_VERIFY` | Skip certificate verification for OIDC discovery and token calls only | `false` |
| `DIRECTORY_CLIENT_AUTH_TOKEN` | Pre-issued OIDC access token (`oidc`) | `""` |
| `DIRECTORY_CLIENT_OIDC_ISSUER` | OIDC issuer URL | `""` |
| `DIRECTORY_CLIENT_OIDC_CLIENT_ID` | OIDC client ID | `""` |
| `DIRECTORY_CLIENT_OIDC_CLIENT_SECRET` | OIDC client secret | `""` |
| `DIRECTORY_CLIENT_OIDC_REDIRECT_URI` | Proof Key for Code Exchange (PKCE) redirect URI | `http://localhost:8484/callback` |
| `DIRECTORY_CLIENT_OIDC_CALLBACK_PORT` | PKCE callback port | `8484` |
| `DIRECTORY_CLIENT_OIDC_AUTH_TIMEOUT` | Seconds to wait for the browser callback | `300` |
| `DIRECTORY_CLIENT_OIDC_SCOPES` | Comma-separated OIDC scopes | `openid,profile,email` |

```rust
use agntcy_dir::{Client, Config};

#[tokio::main]
async fn main() -> agntcy_dir::Result<()> {
    let client = Client::new(Config::from_env()?).await?;
    Ok(())
}
```

`Config::from_env_with_prefix` reads the variables under a custom prefix instead of
`DIRECTORY_CLIENT_`.

### Direct instantiation

```rust
use agntcy_dir::{AuthMode, Client, Config};

let config = Config {
    server_address: "localhost:8888".into(),
    auth_mode: AuthMode::Insecure,
    ..Config::from_env()?
};
let client = Client::new(config).await?;
```

A `server_address` without a scheme gets `http://` or `https://` based on the auth mode.

## Authentication modes

| `AuthMode` | Value | Transport |
|------------|-------|-----------|
| `Insecure` | `""` | Plaintext, no authentication (local development only) |
| `X509` | `x509` | mTLS with a SPIFFE Verifiable Identity Document (SVID) in X.509 format from the Workload API (recommended for production) |
| `Jwt` | `jwt` | TLS plus a SPIFFE JWT-SVID bearer token from the Workload API |
| `Tls` | `tls` | mTLS with certificate files on disk |
| `Oidc` | `oidc` | TLS plus an OIDC access token |

### Insecure (local development only)

```rust
let config = Config {
    server_address: "localhost:8888".into(),
    auth_mode: AuthMode::Insecure,
    ..Config::from_env()?
};
```

### X.509 / SPIFFE

```rust
let config = Config {
    server_address: "localhost:8888".into(),
    auth_mode: AuthMode::X509,
    spiffe_endpoint_socket: "unix:///run/spire/agent-sockets/api.sock".into(),
    ..Config::from_env()?
};
```

### JWT / SPIFFE

```rust
let config = Config {
    server_address: "localhost:8888".into(),
    auth_mode: AuthMode::Jwt,
    spiffe_endpoint_socket: "unix:///run/spire/agent-sockets/api.sock".into(),
    jwt_audience: "spiffe://example.org/dir-server".into(),
    ..Config::from_env()?
};
```

### TLS (custom CA / mTLS)

The CA, certificate, and key files are all required in this mode.

```rust
let config = Config {
    server_address: "directory.example.com:443".into(),
    auth_mode: AuthMode::Tls,
    tls_ca_file: "/path/to/ca.crt".into(),
    tls_cert_file: "/path/to/client.crt".into(),
    tls_key_file: "/path/to/client.key".into(),
    ..Config::from_env()?
};
```

### OIDC / Bearer token

#### Pre-issued token (CI / scripts)

```rust
let config = Config {
    server_address: "gateway.example.com:443".into(),
    auth_mode: AuthMode::Oidc,
    auth_token: "eyJhbG...".into(),
    ..Config::from_env()?
};
```

#### Interactive login

Run the PKCE flow from the SDK. It opens the browser and caches the token:

```rust
// DIRECTORY_CLIENT_AUTH_MODE=oidc, plus the OIDC issuer and client ID
let client = Client::new(Config::from_env()?).await?;

if !client.has_cached_oauth_token() {
    client.authenticate_oauth_pkce().await?;
}
```

The token cache lives at `$XDG_CONFIG_HOME/dirctl/auth-token.json` (default
`~/.config/dirctl/auth-token.json`). It is file-compatible with `dirctl`, so you can also log in
once with `dirctl auth login` and reuse the cached token:

```bash
dirctl auth login --oidc-issuer=https://dex.example.com --oidc-client-id=dirctl
```

## Usage

### Store: push and pull records

Records are protobuf `Struct`s. Build them from JSON, then pass them in as a `Vec`:

```rust
use agntcy_dir::models::core_v1::Record;
use agntcy_dir::{Client, Config};

#[tokio::main]
async fn main() -> agntcy_dir::Result<()> {
    let client = Client::new(Config::from_env()?).await?;

    let record: Record = serde_json::from_value(serde_json::json!({
        "data": {
            "name": "my-agent",
            "version": "v1.0.0",
            "schema_version": "1.1.0",
            "description": "My example agent",
            "authors": ["AGNTCY"],
            "created_at": "2025-03-19T17:06:37Z",
            "skills": [
                {"name": "language_processing/language_generation/text_completion", "id": 10301}
            ],
            "locators": [
                {"type": "container_image", "urls": ["https://ghcr.io/agntcy/marketing-strategy"]}
            ]
        }
    }))?;

    // Push one or more records
    let refs = client.push(vec![record]).await?;
    println!("CID: {}", refs[0].cid);

    // Pull them back
    let pulled = client.pull(refs.clone()).await?;
    println!("{}", serde_json::to_string_pretty(&pulled[0])?);

    // Metadata only (no content download)
    let metas = client.lookup(refs.clone()).await?;

    // Delete
    client.delete(refs).await?;
    Ok(())
}
```

All store calls are batch calls: they take and return a `Vec`.

### Search

```rust
use agntcy_dir::models::search_v1::{self, RecordQuery, RecordQueryType};

let hits = client
    .search_cids(search_v1::SearchCiDsRequest {
        queries: vec![RecordQuery {
            r#type: RecordQueryType::SkillId as i32,
            value: "10301".into(),
            negate: false,
        }],
        limit: Some(3),
        ..Default::default()
    })
    .await?;

for hit in hits {
    println!("{}", hit.record_cid);
}
```

Use `search_records` to get the complete OASF documents instead of CIDs. Query by annotation
with `RecordQueryType::Annotation` and a value such as `"env:prod"`.

### Routing: publish and discover

```rust
use agntcy_dir::models::routing_v1::{self, publish_request, RecordRefs};

// Publish records to the routing layer
client
    .publish(routing_v1::PublishRequest {
        request: Some(publish_request::Request::RecordRefs(RecordRefs {
            refs: refs.clone(),
        })),
    })
    .await?;

// List published records by skill
let listed = client
    .list(routing_v1::ListRequest {
        queries: vec![routing_v1::RecordQuery {
            r#type: routing_v1::RecordQueryType::Skill as i32,
            value: "reasoning_planning/logical_reasoning/problem_solving".into(),
        }],
        limit: None,
    })
    .await?;

// Unpublish
client
    .unpublish(routing_v1::UnpublishRequest {
        request: Some(routing_v1::unpublish_request::Request::RecordRefs(RecordRefs {
            refs,
        })),
    })
    .await?;
```

`search_routing` queries the routing layer across the network. Use `create_publication`,
`list_publication`, and `get_publication` to manage publication jobs.

### Identity: resolve and verify claims

```rust
use agntcy_dir::models::identity::GetVerificationInfoRequest;
use agntcy_dir::models::identity_v1::ResolveRequest;

// Resolve a name (optionally versioned) to record references
let resolved = client
    .resolve(ResolveRequest {
        name: "my-agent".into(),
        version: Some("v1.0.0".into()),
    })
    .await?;
for record in &resolved.records {
    println!("{} -> {}", record.name, record.cid);
}

// Get the verification result of a record's identity claims
let info = client
    .get_verification_info(GetVerificationInfoRequest {
        cid: Some(resolved.records[0].cid.clone()),
        ..Default::default()
    })
    .await?;
println!("verified: {}", info.verified);
```

### Runtime discovery: find running workloads

`RuntimeService` talks to the runtime discovery API (`agntcy.dir.runtime.v1.DiscoveryService`)
served by [dir-runtime](https://github.com/agntcy/dir-runtime) and `dirctl daemon`. It connects to
dir-runtime's own address, separately from `Client`, so Directory credentials are never sent to it.

```rust
use agntcy_dir::client::services::RuntimeService;
use agntcy_dir::models::runtime_v1::{GetWorkloadRequest, ListWorkloadsRequest};

let runtime = RuntimeService::connect("localhost:8888").await?;

// List workloads, optionally filtered by labels, runtime types and locator protocols
let workloads = runtime
    .list_workloads(ListWorkloadsRequest {
        labels: [("org.agntcy/discover".to_string(), "true".to_string())].into(),
        runtime_types: vec!["kubernetes".into()],
        locator_protocols: vec!["tcp".into()],
        ..Default::default()
    })
    .await?;

// Get one workload by hostname or ID
let workload = runtime
    .get_workload(GetWorkloadRequest { id: workloads[0].id.clone() })
    .await?;
```

### Events: real-time streaming

`listen` returns the `tonic::Streaming` directly, so you consume events as they arrive:

```rust
use agntcy_dir::models::events_v1::ListenRequest;

let mut events = client.listen(ListenRequest::default()).await?;
while let Some(response) = events.message().await? {
    println!("{response:?}");
}
```

### Signing and verification

`sign` signs the record CID and pushes the public key and signature to the store as referrers.

```rust
use agntcy_dir::models::sign_v1::{
    self, sign_request_provider, verify_request_provider,
};

// Sign with a local cosign key (PEM contents, a file path, or `env://VAR`)
client
    .sign(&sign_v1::SignRequest {
        record_ref: Some(refs[0].clone()),
        provider: Some(sign_v1::SignRequestProvider {
            request: Some(sign_request_provider::Request::Key(sign_v1::SignWithKey {
                private_key: "/path/to/cosign.key".into(),
                password: Some(b"key-password".to_vec()),
            })),
        }),
    })
    .await?;

// Verify locally (pulls referrers and verifies in-process)
let result = client
    .verify(sign_v1::VerifyRequest {
        record_ref: Some(refs[0].clone()),
        provider: Some(sign_v1::VerifyRequestProvider {
            request: Some(verify_request_provider::Request::Any(Default::default())),
        }),
        from_server: false,
    })
    .await?;
println!("valid: {}", result.success);

// Verify via the server (uses the server's cached result)
let result = client
    .verify(sign_v1::VerifyRequest {
        record_ref: Some(refs[0].clone()),
        provider: None,
        from_server: true,
    })
    .await?;
```

The SDK accepts keys as inline PEM, a file path, or an `env://VAR` reference. KMS and URL key
references are not supported. Signing keys can be cosign encrypted keys, or plain ECDSA
(P-256, P-384), Ed25519, or RSA PEM keys.

Use `sign_request_provider::Request::Oidc` for keyless signing through Sigstore (Fulcio, Rekor,
and a timestamp authority). To verify against a specific public key, use
`verify_request_provider::Request::Key(sign_v1::VerifyWithKey { public_key })`.

`VerifyResponse` reports a signature that does not verify (`success` and `error_message`).
An `Err` means the SDK could not carry out verification at all.

### Sync

```rust
use agntcy_dir::models::store_v1::{
    CreateSyncRequest, DeleteSyncRequest, GetSyncRequest, ListSyncsRequest,
};

let created = client
    .create_sync(CreateSyncRequest {
        remote_directory_url: "https://remote.example.com".into(),
        ..Default::default()
    })
    .await?;

let syncs = client.list_syncs(ListSyncsRequest::default()).await?;
let info = client
    .get_sync(GetSyncRequest { sync_id: created.sync_id.clone() })
    .await?;
client
    .delete_sync(DeleteSyncRequest { sync_id: created.sync_id })
    .await?;
```

### Raw gRPC clients

For anything the high-level `Client` doesn't wrap, use the generated tonic clients. Each service
exposes one:

```rust
let mut store = client.store_service().client();
```

Generated models live under `agntcy_dir::models`, for example `core_v1`, `routing_v1`,
`search_v1`, `sign_v1`, `store_v1`, `events_v1`, `identity_v1`, and `runtime_v1`.

## Error handling

All methods return `agntcy_dir::Result<T>`. `agntcy_dir::Error` has one variant per failure
class: `Config`, `Rpc`, `Transport`, `Auth`, `OAuth`, `Sign`, `Verify`, `InvalidArgument`, `Io`,
and `Json`. An `Rpc` error carries the operation name and the underlying `tonic::Status`:

```rust
use agntcy_dir::Error;
use tonic::Code;

match client.pull(refs).await {
    Ok(records) => println!("pulled {}", records.len()),
    Err(Error::Rpc { op, source }) => match source.code() {
        Code::NotFound => eprintln!("{op}: record not found"),
        Code::Unavailable => eprintln!("{op}: server unavailable"),
        Code::PermissionDenied | Code::Unauthenticated => {
            eprintln!("{op}: authentication failure")
        }
        code => eprintln!("{op}: gRPC error {code}: {}", source.message()),
    },
    Err(e) => eprintln!("error: {e}"),
}
```

To match on `tonic::Code`, add `tonic` as a dependency of your project.

## Examples

Runnable examples are in the
[`examples/`](https://github.com/agntcy/dir-sdk-rust/tree/main/examples) directory:

```bash
DIRECTORY_CLIENT_SERVER_ADDRESS=localhost:8888 cargo run --example example
```

`example_interactive_oidc` demonstrates the interactive OIDC login.
