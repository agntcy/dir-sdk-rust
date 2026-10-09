// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};

/// Maps a [`tonic::Status`] to an [`Error::Rpc`] for `op`.
pub(crate) fn rpc(op: &'static str) -> impl FnOnce(tonic::Status) -> Error {
    Error::rpc(op)
}

/// Drains a server stream into a `Vec`.
pub(crate) async fn collect<T>(op: &'static str, mut stream: tonic::Streaming<T>) -> Result<Vec<T>> {
    let mut out = Vec::new();
    while let Some(item) = stream.message().await.map_err(rpc(op))? {
        out.push(item);
    }
    Ok(out)
}
