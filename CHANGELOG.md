# Changelog

[agntcy/dir]: https://github.com/agntcy/dir
[agntcy/dir-sdk-rust]: https://github.com/agntcy/dir-sdk-rust

## Unreleased

### Added

- `RuntimeService` (`agntcy.dir.runtime.v1.DiscoveryService`): `get_workload` and `list_workloads` (with all `ListWorkloadsRequest` filters). It connects to dir-runtime's own address with `RuntimeService::connect`, separately from `Client`, so Directory credentials are never sent to it. Models are in `models::runtime_v1`.

## 1.8.1 (2026-10-21)

### Changed

- Signing and local verification are implemented natively (cosign-compatible keys and keyless Sigstore via the `sigstore-*` crates); the `dirctl` CLI / Docker image is no longer needed.
- Breaking: removed `Config::dirctl_path`, `Config::docker_config`, `DockerConfig`, `client::dirctl`, `Error::Dirctl` and the `DIRCTL_PATH` / `DIRCTL_IMAGE` / `DIRCTL_IMAGE_TAG` variables; added `Error::Sign` and `Error::Verify`.
- `dirctl` (release binary, `DIRCTL_VERSION` / `dirctl_image_tag` workflow input) is installed again, but only as a test dependency of the new `tests/dirctl_interop.rs` suite (SDK-signed records verify with `dirctl` and vice versa; byte-identical Ed25519ph signatures).
- The generated gRPC server stubs are now built too (used by the in-process fake Directory in the unit tests).
- Minimum supported Rust version is now 1.86 (required by the `sigstore-*` crates).

## 1.8.0 (2026-10-16)

### Changed

- Track [agntcy/dir][agntcy/dir] `v1.8.0`: the Directory API protos are exported from the `v1.8.0` tag and the client uses the identity service instead of naming.
- Pinned the directory chart and `dirctl` image used in CI to `v1.8.0`, managed by Renovate.
- Pinned GitHub Actions to commit SHAs.
