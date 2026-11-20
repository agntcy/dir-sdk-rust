# AGNTCY Directory Rust SDK

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/agntcy/dir-sdk-rust/badge)](https://scorecard.dev/viewer/?uri=github.com/agntcy/dir-sdk-rust)
[![crates.io](https://img.shields.io/crates/v/agntcy-dir)](https://crates.io/crates/agntcy-dir)

Rust client for the [AGNTCY Directory](https://github.com/agntcy/dir): an async (`tokio`) gRPC SDK
with the same features as the Python and JavaScript / TypeScript SDKs.

## Documentation

Installation, configuration, authentication, usage examples and error handling are documented in
one place, the [Rust SDK page](https://docs.agntcy.org/dir/dir-sdk-rust/) of the Directory docs.
Its source is [`docs/dir-sdk-rust.md`](docs/dir-sdk-rust.md), which is published to the docs site
as-is. To change the user documentation, edit that file, not this README.

Runnable examples are in [`examples/`](examples).

## Development

```sh
task test                                     # kind cluster + live Directory node (needs docker, go, helm deps via Taskfile)
cargo test                                   # unit + offline tests only
DIRECTORY_CLIENT_SERVER_ADDRESS=localhost:8888 \
  cargo test --test client -- --ignored      # against a live Directory
DIRCTL_PATH=... COSIGN_PATH=... DIRECTORY_CLIENT_SERVER_ADDRESS=localhost:8888 \
  cargo test --test dirctl_interop -- --ignored  # SDK <-> dirctl signing interoperability (skips if unavailable)
```

The API protos are not committed: `task proto:export` runs `buf export` of the pinned `buf.build/agntcy/dir` release tag (see `BUF_TAG` in the Taskfile) into `proto/`, which `build.rs` compiles. They are shipped inside the published crate, so crates.io users need neither `buf` nor a BSR token. Requires the `buf` CLI (logged in). To pick up API changes, bump `BUF_TAG` to the matching Directory release.

## License

Apache-2.0
