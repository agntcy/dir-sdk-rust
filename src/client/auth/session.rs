// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use chrono::Utc;
use serde_json::Value;

use super::oauth_pkce::{fetch_openid_configuration, run_loopback_pkce_login, OAuthTokenHolder};
use super::token_cache::{CachedToken, TokenCache};
use crate::client::config::{AuthMode, Config};
use crate::error::{Error, Result};

/// Builds a cache entry from an OAuth token response.
pub fn cached_token_from_response(config: &Config, payload: &Value) -> CachedToken {
    let expires_in = match payload.get("expires_in") {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) if !s.is_empty() => s.parse::<f64>().ok(),
        _ => None,
    }
    .filter(|n| n.is_finite());
    let text = |k: &str| payload.get(k).and_then(Value::as_str).unwrap_or_default().to_string();

    CachedToken {
        access_token: text("access_token"),
        token_type: text("token_type"),
        provider: "oidc".into(),
        issuer: config.oidc_issuer.clone(),
        refresh_token: text("refresh_token"),
        expires_at: expires_in.map(|s| Utc::now() + chrono::Duration::milliseconds((s * 1000.0) as i64)),
        created_at: Some(Utc::now()),
        ..Default::default()
    }
}

/// Coordinates OIDC token state with the interactive PKCE flow and the cache.
#[derive(Debug, Clone)]
pub struct OAuthSessionManager {
    config: Config,
    token_cache: TokenCache,
    holder: Option<OAuthTokenHolder>,
}

impl OAuthSessionManager {
    pub fn new(config: &Config) -> Self {
        Self::with_cache(config, TokenCache::new())
    }

    pub fn with_cache(config: &Config, token_cache: TokenCache) -> Self {
        let mut holder = None;
        if config.auth_mode == AuthMode::Oidc {
            let h = OAuthTokenHolder::new();
            if !config.auth_token.is_empty() {
                h.set_tokens(config.auth_token.clone());
            } else if let Some(cached) = token_cache.get_valid_token() {
                h.set_tokens(cached.access_token);
            }
            holder = Some(h);
        }
        Self {
            config: config.clone(),
            token_cache,
            holder,
        }
    }

    /// The token holder, present only in `oidc` auth mode.
    pub fn oauth_holder(&self) -> Option<&OAuthTokenHolder> {
        self.holder.as_ref()
    }

    pub fn has_access_token(&self) -> bool {
        self.holder.as_ref().is_some_and(OAuthTokenHolder::has_access_token)
    }

    /// Runs the browser-based PKCE login, stores the token in memory and in the cache.
    pub async fn authenticate(&self) -> Result<()> {
        let c = &self.config;
        if c.auth_mode != AuthMode::Oidc {
            return Err(Error::Config(
                "authenticate_oauth_pkce() requires auth_mode=oidc".into(),
            ));
        }
        if c.oidc_issuer.is_empty() {
            return Err(Error::Config(
                "oidc_issuer is required for authenticate_oauth_pkce()".into(),
            ));
        }
        if c.oidc_client_id.is_empty() {
            return Err(Error::Config(
                "oidc_client_id is required for authenticate_oauth_pkce()".into(),
            ));
        }
        let holder = self
            .holder
            .as_ref()
            .ok_or_else(|| Error::Auth("OAuth token holder not initialized".into()))?;

        let verify = !c.tls_skip_verify;
        let total = Duration::from_secs_f64(c.oidc_auth_timeout.max(0.0));
        let meta = fetch_openid_configuration(&c.oidc_issuer, verify, total.min(Duration::from_secs(30))).await?;
        let payload = run_loopback_pkce_login(c, Some(meta), verify, total).await?;

        holder.update_from_token_response(&payload)?;
        self.token_cache.save(&cached_token_from_response(c, &payload))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn oidc_config() -> Config {
        Config {
            auth_mode: AuthMode::Oidc,
            oidc_issuer: "https://idp".into(),
            ..Config::default()
        }
    }

    #[test]
    fn token_from_response() {
        let t = cached_token_from_response(
            &oidc_config(),
            &json!({"access_token": "a", "expires_in": "3600", "refresh_token": "r", "token_type": "Bearer"}),
        );
        assert_eq!(
            (t.access_token.as_str(), t.refresh_token.as_str(), t.provider.as_str()),
            ("a", "r", "oidc")
        );
        assert!(t.expires_at.unwrap() > Utc::now());
    }

    #[test]
    fn holder_only_in_oidc_mode_and_prefers_configured_token() {
        let dir = tempfile::tempdir().unwrap();
        let cache = TokenCache::with_dir(dir.path());
        assert!(OAuthSessionManager::with_cache(&Config::default(), cache.clone())
            .oauth_holder()
            .is_none());

        let mut cfg = oidc_config();
        cfg.auth_token = "configured".into();
        let s = OAuthSessionManager::with_cache(&cfg, cache);
        assert!(s.has_access_token());
        assert_eq!(s.oauth_holder().unwrap().get_access_token().unwrap(), "configured");
    }

    #[tokio::test]
    async fn authenticate_validates_config() {
        let dir = tempfile::tempdir().unwrap();
        let cache = TokenCache::with_dir(dir.path());
        let s = OAuthSessionManager::with_cache(&Config::default(), cache.clone());
        assert!(s.authenticate().await.is_err());
        let s = OAuthSessionManager::with_cache(&oidc_config(), cache);
        assert!(s.authenticate().await.is_err()); // missing client id
    }
}
