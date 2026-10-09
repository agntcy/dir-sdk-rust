// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! OAuth 2.0 authorization-code flow with PKCE over a loopback redirect.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use super::TokenProvider;
use crate::client::config::Config;
use crate::error::{Error, Result};

/// Error raised when the OAuth PKCE flow fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct OAuthPkceError(pub String);

fn pkce_err(msg: impl Into<String>) -> OAuthPkceError {
    OAuthPkceError(msg.into())
}

/// Subset of the OpenID provider metadata needed for the flow.
#[derive(Debug, Clone, Deserialize)]
pub struct OpenIdConfiguration {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
}

/// Holds an OAuth access token shared with the gRPC auth interceptor.
#[derive(Debug, Clone, Default)]
pub struct OAuthTokenHolder {
    token: Arc<RwLock<Option<String>>>,
}

impl OAuthTokenHolder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_tokens(&self, access_token: impl Into<String>) {
        *self.token.write().unwrap_or_else(|e| e.into_inner()) = Some(access_token.into());
    }

    /// Stores the `access_token` of an OAuth token response.
    pub fn update_from_token_response(&self, payload: &Value) -> std::result::Result<(), OAuthPkceError> {
        match payload.get("access_token").and_then(Value::as_str) {
            Some(t) if !t.is_empty() => {
                self.set_tokens(t);
                Ok(())
            }
            _ => Err(pkce_err("Token response missing access_token")),
        }
    }

    /// Returns the access token, or an error if none has been set.
    pub fn get_access_token(&self) -> Result<String> {
        self.token
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| {
                Error::Auth(
                    "No OAuth access token: set DIRECTORY_CLIENT_AUTH_TOKEN or call Client::authenticate_oauth_pkce()"
                        .into(),
                )
            })
    }

    pub fn has_access_token(&self) -> bool {
        self.get_access_token().is_ok()
    }
}

impl TokenProvider for OAuthTokenHolder {
    fn access_token(&self) -> Result<String> {
        self.get_access_token()
    }
}

pub(crate) fn normalize_issuer(issuer: &str) -> Result<String> {
    let u = issuer.trim_end_matches('/');
    if !u.starts_with("https://") && !u.starts_with("http://") {
        return Err(Error::Config(
            "oidc_issuer must be an absolute URL (https:// recommended)".into(),
        ));
    }
    Ok(u.to_string())
}

fn http_client(verify: bool, timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify)
        .timeout(timeout)
        .build()
        .map_err(|e| Error::Auth(format!("failed to build HTTP client: {e}")))
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Fetches `<issuer>/.well-known/openid-configuration`.
pub async fn fetch_openid_configuration(issuer: &str, verify: bool, timeout: Duration) -> Result<OpenIdConfiguration> {
    let url = format!("{}/.well-known/openid-configuration", normalize_issuer(issuer)?);
    let resp = http_client(verify, timeout)?
        .get(&url)
        .send()
        .await
        .map_err(|e| pkce_err(format!("OpenID discovery failed: {e}")))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| pkce_err(format!("OpenID discovery failed: {e}")))?;
    if !status.is_success() {
        return Err(pkce_err(format!(
            "OpenID discovery HTTP {}: {}",
            status.as_u16(),
            truncate(&text, 500)
        ))
        .into());
    }
    let data: Value =
        serde_json::from_str(&text).map_err(|_| pkce_err("OpenID discovery response is not valid JSON"))?;
    serde_json::from_value(data)
        .map_err(|_| pkce_err("OpenID configuration missing authorization_endpoint or token_endpoint").into())
}

/// Exchanges an authorization code for tokens at the token endpoint.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_authorization_code(
    token_endpoint: &str,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    code_verifier: &str,
    client_secret: &str,
    verify: bool,
    timeout: Duration,
) -> Result<Value> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];
    if !client_secret.is_empty() {
        form.push(("client_secret", client_secret));
    }
    let resp = http_client(verify, timeout)?
        .post(token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| pkce_err(format!("Token request failed: {e}")))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| pkce_err(format!("Token request failed: {e}")))?;
    let json: Value = serde_json::from_str(&text)
        .map_err(|_| pkce_err(format!("Token response not JSON: {}", truncate(&text, 500))))?;
    if !status.is_success() {
        return Err(pkce_err(format!("Token HTTP {}: {}", status.as_u16(), truncate(&text, 500))).into());
    }
    Ok(json)
}

fn random_b64url(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// RFC 7636 `S256` code challenge for `verifier`.
pub fn code_challenge_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn html_page(message: &str) -> String {
    format!("<!DOCTYPE html><html><body><p>{message} You may close this window.</p></body></html>")
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Reads the request target (`/path?query`) from an HTTP/1.x request.
async fn read_request_target(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf);
    let mut parts = head.lines().next()?.split_whitespace();
    (parts.next()? == "GET").then(|| parts.next().map(String::from))?
}

/// Outcome of the redirect, decided once a request for the redirect path arrives.
enum Callback {
    Code(String),
    Error(String),
}

async fn wait_for_callback(listener: &TcpListener, path: &str, state: &str) -> Callback {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let Some(target) = read_request_target(&mut stream).await else {
            respond(&mut stream, "400 Bad Request", "").await;
            continue;
        };
        let Ok(url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
            respond(&mut stream, "400 Bad Request", "").await;
            continue;
        };
        if url.path() != path {
            // e.g. /favicon.ico — keep waiting for the real redirect.
            respond(&mut stream, "404 Not Found", "Not Found").await;
            continue;
        }
        let q = |k: &str| url.query_pairs().find(|(n, _)| n == k).map(|(_, v)| v.into_owned());

        if let Some(err) = q("error") {
            let desc = q("error_description").unwrap_or_default();
            respond(&mut stream, "200 OK", &html_page("Authorization failed.")).await;
            return Callback::Error(format!("{err}: {desc}"));
        }
        if q("state").as_deref() != Some(state) {
            respond(&mut stream, "200 OK", &html_page("Invalid state.")).await;
            return Callback::Error("state mismatch".into());
        }
        return match q("code") {
            Some(code) if !code.is_empty() => {
                respond(&mut stream, "200 OK", &html_page("Login successful.")).await;
                Callback::Code(code)
            }
            _ => {
                respond(&mut stream, "200 OK", &html_page("Missing code.")).await;
                Callback::Error("missing code".into())
            }
        };
    }
}

/// Runs the interactive PKCE login: opens the browser, waits for the loopback
/// redirect and exchanges the code. Returns the raw token response.
pub async fn run_loopback_pkce_login(
    config: &Config,
    metadata: Option<OpenIdConfiguration>,
    verify: bool,
    timeout: Duration,
) -> Result<Value> {
    if config.oidc_issuer.is_empty() {
        return Err(Error::Config("oidc_issuer is required for OAuth PKCE".into()));
    }
    if config.oidc_client_id.is_empty() {
        return Err(Error::Config("oidc_client_id is required for OAuth PKCE".into()));
    }

    let redirect_uri = config.oidc_redirect_uri.trim().to_string();
    let parsed = Url::parse(&redirect_uri)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .ok_or_else(|| Error::Config("oidc_redirect_uri must be an absolute http(s) URL".into()))?;
    if !matches!(parsed.host_str(), Some("localhost" | "127.0.0.1")) {
        return Err(Error::Config(
            "loopback PKCE requires redirect host localhost or 127.0.0.1".into(),
        ));
    }
    let path = parsed.path().to_string();

    let meta = match metadata {
        Some(m) => m,
        None => fetch_openid_configuration(&config.oidc_issuer, verify, timeout.min(Duration::from_secs(30))).await?,
    };

    let code_verifier = random_b64url(48);
    let state = random_b64url(24);

    let listener = TcpListener::bind(("127.0.0.1", config.oidc_callback_port)).await?;

    let scope = if config.oidc_scopes.is_empty() {
        "openid".to_string()
    } else {
        config.oidc_scopes.join(" ")
    };
    let mut authorize = Url::parse(&meta.authorization_endpoint)
        .map_err(|e| pkce_err(format!("invalid authorization_endpoint: {e}")))?;
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.oidc_client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &scope)
        .append_pair("state", &state)
        .append_pair("code_challenge", &code_challenge_s256(&code_verifier))
        .append_pair("code_challenge_method", "S256");

    if open::that_detached(authorize.as_str()).is_err() {
        eprintln!("Open this URL in your browser to authenticate:\n{authorize}");
    }

    let callback = tokio::time::timeout(timeout, wait_for_callback(&listener, &path, &state))
        .await
        .map_err(|_| pkce_err(format!("OAuth callback timed out after {}s", config.oidc_auth_timeout)))?;
    drop(listener);

    let code = match callback {
        Callback::Code(c) => c,
        Callback::Error(e) => return Err(pkce_err(e).into()),
    };

    exchange_authorization_code(
        &meta.token_endpoint,
        &code,
        &redirect_uri,
        &config.oidc_client_id,
        &code_verifier,
        &config.oidc_client_secret,
        verify,
        timeout.min(Duration::from_secs(30)),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_vector() {
        assert_eq!(
            code_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn issuer_normalization() {
        assert_eq!(
            normalize_issuer("https://idp.example.com//").unwrap(),
            "https://idp.example.com"
        );
        assert!(normalize_issuer("idp.example.com").is_err());
    }

    #[test]
    fn holder_requires_token() {
        let h = OAuthTokenHolder::new();
        assert!(!h.has_access_token());
        assert!(h.update_from_token_response(&serde_json::json!({})).is_err());
        h.update_from_token_response(&serde_json::json!({"access_token": "abc"}))
            .unwrap();
        assert_eq!(h.get_access_token().unwrap(), "abc");
    }

    #[tokio::test]
    async fn callback_extracts_code_and_ignores_other_paths() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { wait_for_callback(&listener, "/callback", "st").await });

        let get = |target: &'static str| async move {
            let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            s.write_all(format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).await.unwrap();
            out
        };
        assert!(get("/favicon.ico").await.starts_with("HTTP/1.1 404"));
        assert!(get("/callback?state=st&code=the-code")
            .await
            .starts_with("HTTP/1.1 200"));
        match server.await.unwrap() {
            Callback::Code(c) => assert_eq!(c, "the-code"),
            Callback::Error(e) => panic!("unexpected error {e}"),
        }
    }
}
