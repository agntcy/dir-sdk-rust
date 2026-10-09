// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! OIDC authentication helpers: PKCE login, token holder and on-disk cache.

mod oauth_pkce;
mod session;
mod token_cache;

pub use oauth_pkce::{
    code_challenge_s256, exchange_authorization_code, fetch_openid_configuration, run_loopback_pkce_login,
    OAuthPkceError, OAuthTokenHolder, OpenIdConfiguration,
};
pub use session::{cached_token_from_response, OAuthSessionManager};
pub use token_cache::{CachedToken, TokenCache, DEFAULT_TOKEN_CACHE_DIR, TOKEN_CACHE_FILE};

use crate::error::Result;

/// Source of a bearer token attached to every outgoing gRPC request.
pub trait TokenProvider: Send + Sync + 'static {
    /// Returns the current bearer token.
    fn access_token(&self) -> Result<String>;
}
