// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Error type shared by the whole SDK.

/// Convenient result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors returned by the Directory SDK.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid or incomplete client configuration.
    #[error("{0}")]
    Config(String),

    /// A gRPC call failed. `op` names the SDK operation.
    #[error("{op} failed: {source}")]
    Rpc {
        op: &'static str,
        #[source]
        source: Box<tonic::Status>,
    },

    /// Establishing the gRPC channel failed.
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    /// Authentication failure (missing token, SPIFFE, ...).
    #[error("{0}")]
    Auth(String),

    /// OAuth PKCE flow failure.
    #[error(transparent)]
    OAuth(#[from] crate::client::auth::OAuthPkceError),

    /// A `dirctl` invocation failed.
    #[error("{0}")]
    Dirctl(String),

    /// An argument supplied by the caller was invalid.
    #[error("{0}")]
    InvalidArgument(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub(crate) fn rpc(op: &'static str) -> impl FnOnce(tonic::Status) -> Error {
        move |source| Error::Rpc {
            op,
            source: Box::new(source),
        }
    }
}
