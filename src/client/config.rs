// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Client configuration.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
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

/// Docker invocation settings for running `dirctl` in a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerConfig {
    pub dirctl_image: String,
    pub dirctl_image_tag: String,
    pub envs: BTreeMap<String, String>,
    pub mounts: Vec<String>,
    pub user: String,
}

impl DockerConfig {
    pub const DEFAULT_DIRCTL_IMAGE: &'static str = "ghcr.io/agntcy/dir-ctl";
    pub const DEFAULT_DIRCTL_IMAGE_TAG: &'static str = "latest";

    /// Full `docker ...` command line up to and including the image name.
    ///
    /// Only `type=bind` mounts whose `src=` exists on the host are kept.
    pub fn command(&self) -> Vec<String> {
        let mut cmd: Vec<String> = [
            "docker",
            "container",
            "run",
            "--name=dir-ctl",
            "--rm",
            "--network",
            "host",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        if !self.user.is_empty() {
            cmd.extend(["--user".to_string(), self.user.clone()]);
        }
        for (k, v) in &self.envs {
            cmd.extend(["--env".to_string(), format!("{k}={v}")]);
        }
        for mount in self.live_mounts() {
            cmd.extend(["--mount".to_string(), mount.clone()]);
        }
        cmd.push(format!("{}:{}", self.dirctl_image, self.dirctl_image_tag));
        cmd
    }

    fn live_mounts(&self) -> impl Iterator<Item = &String> {
        self.mounts.iter().filter(|m| {
            m.starts_with("type=bind")
                && m.split(',')
                    .find_map(|p| p.strip_prefix("src="))
                    .is_some_and(|src| Path::new(src).exists())
        })
    }
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            dirctl_image: Self::DEFAULT_DIRCTL_IMAGE.into(),
            dirctl_image_tag: Self::DEFAULT_DIRCTL_IMAGE_TAG.into(),
            envs: BTreeMap::new(),
            mounts: Vec::new(),
            user: String::new(),
        }
    }
}

/// Configuration for the AGNTCY Directory client.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// `host:port` or a full `http(s)://` URL. A missing scheme is inferred
    /// from [`Config::auth_mode`].
    pub server_address: String,
    /// Path to the `dirctl` binary (used for signing and local verification).
    /// Defaults to `dirctl` from `PATH` when no docker config is set.
    pub dirctl_path: Option<String>,
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
    pub docker_config: Option<DockerConfig>,
}

impl Config {
    pub const DEFAULT_SERVER_ADDRESS: &'static str = "127.0.0.1:8888";
    pub const DEFAULT_DIRCTL_PATH: &'static str = "dirctl";
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

        let dirctl_path = get("DIRCTL_PATH").filter(|s| !s.is_empty());
        let image = get("DIRCTL_IMAGE").filter(|s| !s.is_empty());
        let tag = get("DIRCTL_IMAGE_TAG").filter(|s| !s.is_empty());
        let docker_config = (image.is_some() || tag.is_some()).then(|| DockerConfig {
            dirctl_image: image.unwrap_or_else(|| DockerConfig::DEFAULT_DIRCTL_IMAGE.into()),
            dirctl_image_tag: tag.unwrap_or_else(|| DockerConfig::DEFAULT_DIRCTL_IMAGE_TAG.into()),
            user: "0:0".into(),
            ..DockerConfig::default()
        });
        if dirctl_path.is_some() && docker_config.is_some() {
            return Err(Error::Config(
                "You cannot specify both DIRCTL_PATH and DIRCTL_IMAGE/DIRCTL_IMAGE_TAG.".into(),
            ));
        }

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
            dirctl_path,
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
            docker_config,
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

    /// `host:port` form handed to `dirctl` (it adds a port itself when the
    /// address carries a scheme).
    pub(crate) fn dirctl_server_address(&self) -> String {
        let addr = self.server_address.trim();
        addr.strip_prefix("https://")
            .or_else(|| addr.strip_prefix("http://"))
            .unwrap_or(addr)
            .to_string()
    }

    /// Resolves the program and leading arguments used to run `dirctl`.
    pub fn dirctl_command(&self) -> Vec<String> {
        if let Some(docker) = &self.docker_config {
            return docker.command();
        }
        vec![self
            .dirctl_path
            .clone()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| Self::DEFAULT_DIRCTL_PATH.to_string())]
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_address: Self::DEFAULT_SERVER_ADDRESS.into(),
            dirctl_path: None,
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
            docker_config: None,
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
        assert_eq!(cfg.dirctl_command(), vec!["dirctl"]);
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
                ("DIRCTL_PATH", "/usr/bin/dirctl"),
            ]),
        )
        .unwrap();
        assert_eq!(cfg.auth_mode, AuthMode::Oidc);
        assert_eq!(cfg.server_url(), "https://dir.example.com:443");
        assert!(cfg.tls_skip_verify);
        assert_eq!(cfg.oidc_scopes, vec!["openid", "email"]);
        assert_eq!(cfg.oidc_callback_port, 9000);
        assert_eq!(cfg.dirctl_command(), vec!["/usr/bin/dirctl"]);
    }

    #[test]
    fn explicit_scheme_is_kept() {
        let cfg = Config {
            server_address: "http://localhost:1".into(),
            auth_mode: AuthMode::Tls,
            ..Config::default()
        };
        assert_eq!(cfg.server_url(), "http://localhost:1");
        assert_eq!(cfg.dirctl_server_address(), "localhost:1");
    }

    #[test]
    fn rejects_unknown_auth_mode_and_path_plus_docker() {
        assert!(Config::from_lookup("P_", lookup(&[("P_AUTH_MODE", "bogus")])).is_err());
        assert!(Config::from_lookup("P_", lookup(&[("DIRCTL_PATH", "x"), ("DIRCTL_IMAGE", "y")])).is_err());
    }

    #[test]
    fn docker_command_shape() {
        let mut d = DockerConfig {
            user: "0:0".into(),
            ..DockerConfig::default()
        };
        d.envs.insert("A".into(), "b".into());
        d.mounts.push("type=bind,src=/definitely/not/here,dst=/x".into());
        let cmd = d.command();
        assert_eq!(&cmd[..3], ["docker", "container", "run"]);
        assert!(cmd.contains(&"A=b".to_string()));
        assert!(!cmd.iter().any(|a| a == "--mount"));
        assert_eq!(cmd.last().unwrap(), "ghcr.io/agntcy/dir-ctl:latest");
    }
}
