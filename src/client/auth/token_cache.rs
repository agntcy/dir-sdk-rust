// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! On-disk OIDC token cache (`$XDG_CONFIG_HOME/dirctl/auth-token.json`),
//! file-compatible with `dirctl`.

use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::Result;

pub const DEFAULT_TOKEN_CACHE_DIR: &str = "dirctl";
pub const TOKEN_CACHE_FILE: &str = "auth-token.json";

const DEFAULT_TOKEN_VALIDITY: Duration = Duration::hours(8);
const TOKEN_EXPIRY_BUFFER: Duration = Duration::minutes(5);

#[allow(clippy::ptr_arg)] // serde `skip_serializing_if` passes `&String`
fn is_empty(s: &String) -> bool {
    s.is_empty()
}

/// A cached OIDC token.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CachedToken {
    #[serde(default)]
    pub access_token: String,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub token_type: String,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub provider: String,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub issuer: String,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub refresh_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub user: String,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub user_id: String,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

/// Reads and writes the cached token.
#[derive(Debug, Clone)]
pub struct TokenCache {
    cache_dir: PathBuf,
}

impl TokenCache {
    /// Cache in the default location (`$XDG_CONFIG_HOME` or `~/.config`, then `dirctl/`).
    pub fn new() -> Self {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
            .unwrap_or_else(|| PathBuf::from(".config"));
        Self {
            cache_dir: base.join(DEFAULT_TOKEN_CACHE_DIR),
        }
    }

    pub fn with_dir(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
        }
    }

    pub fn cache_path(&self) -> PathBuf {
        self.cache_dir.join(TOKEN_CACHE_FILE)
    }

    pub fn load(&self) -> Result<Option<CachedToken>> {
        let path = self.cache_path();
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
    }

    pub fn save(&self, token: &CachedToken) -> Result<()> {
        fs::create_dir_all(&self.cache_dir)?;
        set_mode(&self.cache_dir, 0o700);

        let mut token = token.clone();
        token.created_at.get_or_insert_with(Utc::now);
        let path = self.cache_path();
        fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&token)?))?;
        set_mode(&path, 0o600);
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        let path = self.cache_path();
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// A token is valid when it has an access token and is not (about to be) expired.
    pub fn is_valid(&self, token: Option<&CachedToken>) -> bool {
        let Some(token) = token.filter(|t| !t.access_token.is_empty()) else {
            return false;
        };
        let now = Utc::now();
        match token.expires_at {
            None => now < token.created_at.unwrap_or(now) + DEFAULT_TOKEN_VALIDITY,
            Some(exp) => now + TOKEN_EXPIRY_BUFFER < exp,
        }
    }

    /// The cached token if present and still valid. Unreadable caches count as empty.
    pub fn get_valid_token(&self) -> Option<CachedToken> {
        let token = self.load().ok().flatten();
        self.is_valid(token.as_ref()).then_some(token).flatten()
    }
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_mode(_path: &std::path::Path, _mode: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(expires_in: Option<Duration>) -> CachedToken {
        CachedToken {
            access_token: "tok".into(),
            expires_at: expires_in.map(|d| Utc::now() + d),
            ..Default::default()
        }
    }

    #[test]
    fn roundtrip_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let cache = TokenCache::with_dir(dir.path().join("dirctl"));
        assert!(cache.load().unwrap().is_none());

        cache.save(&token(Some(Duration::hours(1)))).unwrap();
        let loaded = cache.load().unwrap().unwrap();
        assert_eq!(loaded.access_token, "tok");
        assert!(loaded.created_at.is_some());
        assert!(cache.get_valid_token().is_some());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(cache.cache_path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        cache.clear().unwrap();
        assert!(cache.load().unwrap().is_none());
    }

    #[test]
    fn validity_rules() {
        let cache = TokenCache::with_dir("unused");
        assert!(!cache.is_valid(None));
        assert!(!cache.is_valid(Some(&CachedToken::default())));
        assert!(cache.is_valid(Some(&token(Some(Duration::hours(1))))));
        // inside the 5 minute safety buffer
        assert!(!cache.is_valid(Some(&token(Some(Duration::minutes(4))))));
        // no expiry: falls back to 8h from creation
        let mut t = token(None);
        t.created_at = Some(Utc::now() - Duration::hours(9));
        assert!(!cache.is_valid(Some(&t)));
        t.created_at = Some(Utc::now() - Duration::hours(1));
        assert!(cache.is_valid(Some(&t)));
    }

    #[test]
    fn dirctl_style_json_loads() {
        let t: CachedToken = serde_json::from_str(
            r#"{"access_token":"a","expires_at":"2099-01-01T00:00:00Z","created_at":"2026-01-01T00:00:00.123Z"}"#,
        )
        .unwrap();
        assert_eq!(t.access_token, "a");
        assert!(t.expires_at.is_some());
    }
}
