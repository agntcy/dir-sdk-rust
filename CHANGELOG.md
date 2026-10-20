# Changelog

[agntcy/dir]: https://github.com/agntcy/dir
[agntcy/dir-sdk-rust]: https://github.com/agntcy/dir-sdk-rust

## Unreleased

### Changed

- Signing and local verification are implemented natively (cosign-compatible keys and keyless Sigstore via the `sigstore-*` crates); the `dirctl` CLI / Docker image is no longer needed.
- Breaking: removed `Config::dirctl_path`, `Config::docker_config`, `DockerConfig`, `client::dirctl`, `Error::Dirctl` and the `DIRCTL_PATH` / `DIRCTL_IMAGE` / `DIRCTL_IMAGE_TAG` variables; added `Error::Sign` and `Error::Verify`.
- Minimum supported Rust version is now 1.86 (required by the `sigstore-*` crates).

## 1.8.0 (2026-10-16)

### Changed

- Track [agntcy/dir][agntcy/dir] `v1.8.0`: the Directory API protos are exported from the `v1.8.0` tag and the client uses the identity service instead of naming.
- Pinned the directory chart and `dirctl` image used in CI to `v1.8.0`, managed by Renovate.
- Pinned GitHub Actions to commit SHAs.
