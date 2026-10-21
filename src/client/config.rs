// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Client configuration.

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

/// Authentication mode for Directory client connections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthMode {
    /// Plaintext, unauthenticated (`""`).
    #[default]
    Insecure,
    /// mTLS with a SPIFFE X.509-SVID obtained from the Workload API.
    X509,
    /// TLS plus a SPIFFE JWT-SVID bearer token obtained from the Workload API.
    Jwt,
    /// mTLS with certificate files on disk.
    Tls,
    /// TLS plus an OIDC access token (e.g. from the PKCE flow).
    Oidc,
}

impl AuthMode {
    /// Whether this mode talks TLS to the server.
    pub fn uses_tls(self) -> bool {
        !matches!(self, AuthMode::Insecure)
    }
}

impl FromStr for AuthMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim() {
            "" => Ok(AuthMode::Insecure),
            "x509" => Ok(AuthMode::X509),
            "jwt" => Ok(AuthMode::Jwt),
            "tls" => Ok(AuthMode::Tls),
            "oidc" => Ok(AuthMode::Oidc),
            other => Err(Error::Config(format!("Unsupported auth mode: {other}"))),
        }
    }
}

impl fmt::Display for AuthMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AuthMode::Insecure => "",
            AuthMode::X509 => "x509",
            AuthMode::Jwt => "jwt",
            AuthMode::Tls => "tls",
            AuthMode::Oidc => "oidc",
        })
    }
}

/// Configuration for the AGNTCY Directory client.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// `host:port` or a full `http(s)://` URL. A missing scheme is inferred
    /// from [`Config::auth_mode`].
    pub server_address: String,
    pub spiffe_endpoint_socket: String,
    pub auth_mode: AuthMode,
    /// Pre-supplied OIDC access token.
    pub auth_token: String,
    pub jwt_audience: String,
    pub tls_ca_file: String,
    pub tls_cert_file: String,
    pub tls_key_file: String,
    pub tls_server_name: String,
    /// Skip certificate verification for OIDC discovery/token HTTP calls.
    pub tls_skip_verify: bool,
    pub oidc_issuer: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
    pub oidc_redirect_uri: String,
    pub oidc_callback_port: u16,
    /// Seconds to wait for the browser callback.
    pub oidc_auth_timeout: f64,
    pub oidc_scopes: Vec<String>,
}

impl Config {
    pub const DEFAULT_SERVER_ADDRESS: &'static str = "127.0.0.1:8888";
    pub const DEFAULT_OIDC_REDIRECT_URI: &'static str = "http://localhost:8484/callback";
    pub const DEFAULT_OIDC_CALLBACK_PORT: u16 = 8484;
    pub const DEFAULT_OIDC_AUTH_TIMEOUT: f64 = 300.0;
    pub const DEFAULT_ENV_PREFIX: &'static str = "DIRECTORY_CLIENT_";

    fn default_oidc_scopes() -> Vec<String> {
        ["openid", "profile", "email"].iter().map(|s| s.to_string()).collect()
    }

    /// Loads the configuration from `DIRECTORY_CLIENT_*` environment variables.
    pub fn from_env() -> Result<Self> {
        Self::from_env_with_prefix(Self::DEFAULT_ENV_PREFIX)
    }

    /// Like [`Config::from_env`] with a custom variable prefix.
    pub fn from_env_with_prefix(prefix: &str) -> Result<Self> {
        Self::from_lookup(prefix, |k| std::env::var(k).ok())
    }

    /// Loads the configuration through an arbitrary variable lookup.
    pub fn from_lookup(prefix: &str, get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let var = |name: &str| get(&format!("{prefix}{name}"));
        let or = |name: &str, default: &str| var(name).unwrap_or_else(|| default.to_string());

        let oidc_scopes = match var("OIDC_SCOPES") {
            Some(s) if !s.is_empty() => s
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            _ => Self::default_oidc_scopes(),
        };

        Ok(Self {
            server_address: or("SERVER_ADDRESS", Self::DEFAULT_SERVER_ADDRESS),
            spiffe_endpoint_socket: or("SPIFFE_SOCKET_PATH", ""),
            auth_mode: or("AUTH_MODE", "").parse()?,
            auth_token: or("AUTH_TOKEN", ""),
            jwt_audience: or("JWT_AUDIENCE", ""),
            tls_ca_file: or("TLS_CA_FILE", ""),
            tls_cert_file: or("TLS_CERT_FILE", ""),
            tls_key_file: or("TLS_KEY_FILE", ""),
            tls_server_name: or("TLS_SERVER_NAME", ""),
            tls_skip_verify: parse_bool(var("TLS_SKIP_VERIFY").as_deref(), false),
            oidc_issuer: or("OIDC_ISSUER", ""),
            oidc_client_id: or("OIDC_CLIENT_ID", ""),
            oidc_client_secret: or("OIDC_CLIENT_SECRET", ""),
            oidc_redirect_uri: or("OIDC_REDIRECT_URI", Self::DEFAULT_OIDC_REDIRECT_URI),
            oidc_callback_port: parse_num(
                var("OIDC_CALLBACK_PORT"),
                Self::DEFAULT_OIDC_CALLBACK_PORT,
                "OIDC_CALLBACK_PORT",
            )?,
            oidc_auth_timeout: parse_num(
                var("OIDC_AUTH_TIMEOUT"),
                Self::DEFAULT_OIDC_AUTH_TIMEOUT,
                "OIDC_AUTH_TIMEOUT",
            )?,
            oidc_scopes,
        })
    }

    /// The server URL with a scheme: `https://` for any TLS-based auth mode,
    /// `http://` otherwise, unless the address already has one.
    pub fn server_url(&self) -> String {
        let addr = self.server_address.trim();
        if addr.starts_with("http://") || addr.starts_with("https://") {
            addr.to_string()
        } else if self.auth_mode.uses_tls() {
            format!("https://{addr}")
        } else {
            format!("http://{addr}")
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_address: Self::DEFAULT_SERVER_ADDRESS.into(),
            spiffe_endpoint_socket: String::new(),
            auth_mode: AuthMode::Insecure,
            auth_token: String::new(),
            jwt_audience: String::new(),
            tls_ca_file: String::new(),
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls_server_name: String::new(),
            tls_skip_verify: false,
            oidc_issuer: String::new(),
            oidc_client_id: String::new(),
            oidc_client_secret: String::new(),
            oidc_redirect_uri: Self::DEFAULT_OIDC_REDIRECT_URI.into(),
            oidc_callback_port: Self::DEFAULT_OIDC_CALLBACK_PORT,
            oidc_auth_timeout: Self::DEFAULT_OIDC_AUTH_TIMEOUT,
            oidc_scopes: Self::default_oidc_scopes(),
        }
    }
}

fn parse_bool(value: Option<&str>, default: bool) -> bool {
    match value {
        None | Some("") => default,
        Some(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
    }
}

fn parse_num<T: FromStr>(value: Option<String>, default: T, name: &str) -> Result<T> {
    match value {
        None => Ok(default),
        Some(v) if v.is_empty() => Ok(default),
        Some(v) => v
            .trim()
            .parse()
            .map_err(|_| Error::Config(format!("invalid value for {name}: {v:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn defaults() {
        let cfg = Config::from_lookup("DIRECTORY_CLIENT_", lookup(&[])).unwrap();
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.server_url(), "http://127.0.0.1:8888");
    }

    #[test]
    fn env_overrides() {
        let cfg = Config::from_lookup(
            "DIRECTORY_CLIENT_",
            lookup(&[
                ("DIRECTORY_CLIENT_SERVER_ADDRESS", "dir.example.com:443"),
                ("DIRECTORY_CLIENT_AUTH_MODE", "oidc"),
                ("DIRECTORY_CLIENT_TLS_SKIP_VERIFY", "Yes"),
                ("DIRECTORY_CLIENT_OIDC_SCOPES", "openid, email ,"),
                ("DIRECTORY_CLIENT_OIDC_CALLBACK_PORT", "9000"),
            ]),
        )
        .unwrap();
        assert_eq!(cfg.auth_mode, AuthMode::Oidc);
        assert_eq!(cfg.server_url(), "https://dir.example.com:443");
        assert!(cfg.tls_skip_verify);
        assert_eq!(cfg.oidc_scopes, vec!["openid", "email"]);
        assert_eq!(cfg.oidc_callback_port, 9000);
    }

    #[test]
    fn explicit_scheme_is_kept() {
        let cfg = Config {
            server_address: "http://localhost:1".into(),
            auth_mode: AuthMode::Tls,
            ..Config::default()
        };
        assert_eq!(cfg.server_url(), "http://localhost:1");
    }

    #[test]
    fn rejects_unknown_auth_mode() {
        assert!(Config::from_lookup("P_", lookup(&[("P_AUTH_MODE", "bogus")])).is_err());
    }
}
