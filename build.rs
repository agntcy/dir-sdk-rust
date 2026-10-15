// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Generates the Directory gRPC stubs (tonic/prost) and protobuf-JSON serde
//! impls (pbjson) from the vendored `proto/` tree. Uses `protox`, a pure-Rust
//! protobuf compiler, so no `protoc` binary is required.

use std::path::PathBuf;

use prost::Message;

const PROTOS: &[&str] = &[
    "agntcy/dir/core/v1/record.proto",
    "agntcy/dir/events/v1/event_service.proto",
    "agntcy/dir/identity/v1/identity_service.proto",
    "agntcy/dir/routing/v1/routing_service.proto",
    "agntcy/dir/routing/v1/publication_service.proto",
    "agntcy/dir/search/v1/search_service.proto",
    "agntcy/dir/sign/v1/sign_service.proto",
    "agntcy/dir/store/v1/store_service.proto",
    "agntcy/dir/store/v1/sync_service.proto",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);

    if !std::path::Path::new("proto/agntcy").is_dir() {
        return Err("proto/ is missing: run `task proto:export` (buf export of buf.build/agntcy/dir)".into());
    }

    let mut fds = protox::compile(PROTOS, ["proto"])?;
    // Validation annotations are only options, never field types, so drop
    // `buf/validate`. Well-known types must stay: prost resolves field types
    // through them (they are emitted via `extern_path`, not generated).
    fds.file.retain(|f| !f.name().starts_with("buf/"));

    let fds_bytes = fds.encode_to_vec();

    tonic_build::configure()
        .build_server(false)
        .compile_well_known_types(true)
        .extern_path(".google.protobuf", "::pbjson_types")
        .compile_fds(fds)?;

    pbjson_build::Builder::new()
        .out_dir(&out_dir)
        .register_descriptors(&fds_bytes)?
        .build(&[".agntcy"])?;

    Ok(())
}
