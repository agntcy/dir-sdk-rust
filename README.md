# AGNTCY Directory Rust SDK

Rust client for the [AGNTCY Directory](https://github.com/agntcy/dir), feature-equivalent to
[`dir-sdk-javascript`](../dir-sdk-javascript) and [`dir-sdk-python`](../dir-sdk-python).

- async (`tokio`) gRPC client on `tonic`/`prost`, with protobuf‑JSON `serde` support on every message
- every Directory service: store, routing, publication, search, sign/verify, sync, events, identity
- auth modes: insecure, `tls` (mTLS files), `x509` / `jwt` (SPIFFE Workload API), `oidc` (bearer token + interactive PKCE login with `dirctl`-compatible token cache)
- signing and local verification through the `dirctl` CLI (native binary or Docker)
- no `protoc` needed: stubs are generated at build time from the vendored `proto/` tree with the pure-Rust `protox`

## Usage

```toml
[dependencies]
agntcy-dir = { git = "https://github.com/agntcy/dir-sdk-rust" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
serde_json = "1"
```

```rust
use agntcy_dir::models::core_v1::Record;
use agntcy_dir::{Client, Config};

#[tokio::main]
async fn main() -> agntcy_dir::Result<()> {
    let client = Client::new(Config::from_env()?).await?;

    // Records are protobuf Structs; build them from JSON.
    let record: Record = serde_json::from_str(r#"{"data": {"name": "my-agent", "version": "v1.0.0"}}"#)?;

    let refs = client.push(vec![record]).await?;
    let pulled = client.pull(refs.clone()).await?;
    println!("{}", serde_json::to_string_pretty(&pulled[0])?);

    client.delete(refs).await?;
    Ok(())
}
```

More in [`examples/`](examples).

## Configuration

`Config::from_env()` reads the same variables as the other SDKs:

| Variable | Default | |
|---|---|---|
| `DIRECTORY_CLIENT_SERVER_ADDRESS` | `127.0.0.1:8888` | `host:port` or URL |
| `DIRECTORY_CLIENT_AUTH_MODE` | `""` | `""`, `x509`, `jwt`, `tls`, `oidc` |
| `DIRECTORY_CLIENT_SPIFFE_SOCKET_PATH` | | SPIRE agent socket (`x509`, `jwt`) |
| `DIRECTORY_CLIENT_JWT_AUDIENCE` | | audience (`jwt`) |
| `DIRECTORY_CLIENT_TLS_CA_FILE` / `_TLS_CERT_FILE` / `_TLS_KEY_FILE` | | `tls` mode; `_CA_FILE` is optional for `oidc` |
| `DIRECTORY_CLIENT_TLS_SERVER_NAME` | | SNI / authority override |
| `DIRECTORY_CLIENT_TLS_SKIP_VERIFY` | `false` | OIDC discovery/token HTTP calls only |
| `DIRECTORY_CLIENT_AUTH_TOKEN` | | pre-supplied OIDC access token |
| `DIRECTORY_CLIENT_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET` | | PKCE login |
| `DIRECTORY_CLIENT_OIDC_REDIRECT_URI` | `http://localhost:8484/callback` | |
| `DIRECTORY_CLIENT_OIDC_CALLBACK_PORT` | `8484` | |
| `DIRECTORY_CLIENT_OIDC_AUTH_TIMEOUT` | `300` | seconds |
| `DIRECTORY_CLIENT_OIDC_SCOPES` | `openid,profile,email` | comma separated |
| `DIRCTL_PATH` | `dirctl` | binary used to sign / verify locally |
| `DIRCTL_IMAGE`, `DIRCTL_IMAGE_TAG` | | run `dirctl` in Docker instead (exclusive with `DIRCTL_PATH`) |

### OIDC

```rust
let client = Client::new(Config::from_env()?).await?; // AUTH_MODE=oidc
if !client.has_cached_oauth_token() {
    client.authenticate_oauth_pkce().await?; // opens the browser, caches the token
}
```

The cache lives at `$XDG_CONFIG_HOME/dirctl/auth-token.json` (default `~/.config/dirctl/`), shared with `dirctl`.

## API

`Client` methods mirror the other SDKs in snake_case: `push`, `push_referrer`, `pull`, `pull_referrer`,
`lookup`, `delete`, `delete_referrer`, `search_cids`, `search_records`, `list`, `search_routing`,
`publish`, `unpublish`, `create_publication`, `list_publication`, `get_publication`, `sign`, `verify`,
`create_sync`, `list_syncs`, `get_sync`, `delete_sync`, `listen`, `resolve`, `get_verification_info`.
Streaming RPCs are collected into `Vec`s (except `listen`, which returns the `tonic::Streaming`).
Generated models live in `agntcy_dir::models::{core_v1, routing_v1, ...}`; raw gRPC clients are available
through `client.store_service().client()` etc.

## Development

```sh
task test                                     # kind cluster + live Directory node (needs docker, go, helm deps via Taskfile)
cargo test                                   # unit + offline tests only
DIRECTORY_CLIENT_SERVER_ADDRESS=localhost:8888 \
  cargo test --test client -- --ignored      # against a live Directory
```

The API protos are not committed: `task proto:export` runs `buf export` of the pinned `buf.build/agntcy/dir` commit (see `BUF_COMMIT` in the Taskfile) into `proto/`, which `build.rs` compiles. They are shipped inside the published crate, so crates.io users need neither `buf` nor a BSR token. Requires the `buf` CLI (logged in). To pick up API changes, bump `BUF_COMMIT`.

## License

Apache-2.0
