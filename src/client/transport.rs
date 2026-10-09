// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! gRPC channel construction for every supported auth mode.

use std::sync::Arc;

use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::{Request, Status};

use super::auth::{OAuthTokenHolder, TokenProvider};
use super::config::{AuthMode, Config};
use super::spiffe::{certs_to_pem, der_to_pem, JwtSvidSource, WorkloadClient};
use crate::error::{Error, Result};

/// The channel type used by all service clients.
pub type GrpcChannel = InterceptedService<Channel, AuthInterceptor>;

/// Attaches `authorization: Bearer <token>` to outgoing requests when a
/// token provider is configured.
#[derive(Clone, Default)]
pub struct AuthInterceptor {
    provider: Option<Arc<dyn TokenProvider>>,
}

impl AuthInterceptor {
    pub fn none() -> Self {
        Self { provider: None }
    }

    pub fn bearer(provider: Arc<dyn TokenProvider>) -> Self {
        Self {
            provider: Some(provider),
        }
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> std::result::Result<Request<()>, Status> {
        if let Some(provider) = &self.provider {
            let token = provider
                .access_token()
                .map_err(|e| Status::unauthenticated(e.to_string()))?;
            let value: MetadataValue<_> = format!("Bearer {token}")
                .parse()
                .map_err(|_| Status::unauthenticated("access token contains invalid characters"))?;
            req.metadata_mut().insert("authorization", value);
        }
        Ok(req)
    }
}

fn read_file(path: &str, what: &str) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| Error::Config(format!("Failed to read {what} {path}: {e}")))
}

fn base_tls(config: &Config) -> ClientTlsConfig {
    let sn = config.tls_server_name.trim();
    let tls = ClientTlsConfig::new();
    if sn.is_empty() {
        tls
    } else {
        tls.domain_name(sn)
    }
}

/// TLS config trusting `ca_pem`, or the system roots when `None`.
fn tls_with_roots(config: &Config, ca_pem: Option<String>) -> ClientTlsConfig {
    match ca_pem {
        Some(pem) => base_tls(config).ca_certificate(Certificate::from_pem(pem)),
        None => base_tls(config).with_native_roots(),
    }
}

fn endpoint(config: &Config, tls: Option<ClientTlsConfig>) -> Result<Endpoint> {
    let url = config.server_url();
    let mut ep = Endpoint::from_shared(url.clone())
        .map_err(|e| Error::Config(format!("invalid server address {url:?}: {e}")))?;
    // An explicit https:// address needs TLS even in the default mode.
    let tls = tls.or_else(|| url.starts_with("https://").then(|| tls_with_roots(config, None)));
    if let Some(tls) = tls {
        ep = ep.tls_config(tls)?;
    }
    Ok(ep)
}

fn finish(ep: Endpoint, auth: AuthInterceptor) -> GrpcChannel {
    InterceptedService::new(ep.connect_lazy(), auth)
}

fn spiffe_socket<'a>(config: &'a Config, mode: &str) -> Result<&'a str> {
    match config.spiffe_endpoint_socket.as_str() {
        "" => Err(Error::Config(format!(
            "SPIFFE socket path is required for {mode} authentication"
        ))),
        s => Ok(s),
    }
}

/// Creates the gRPC channel for `config.auth_mode`.
///
/// The connection is established lazily on first use. `oidc_holder` must be
/// supplied for [`AuthMode::Oidc`].
pub async fn create_channel(config: &Config, oidc_holder: Option<&OAuthTokenHolder>) -> Result<GrpcChannel> {
    match config.auth_mode {
        AuthMode::Insecure => Ok(finish(endpoint(config, None)?, AuthInterceptor::none())),

        AuthMode::Tls => {
            for (v, what) in [
                (&config.tls_ca_file, "TLS CA file"),
                (&config.tls_cert_file, "TLS certificate file"),
                (&config.tls_key_file, "TLS key file"),
            ] {
                if v.is_empty() {
                    return Err(Error::Config(format!("{what} is required for TLS authentication")));
                }
            }
            let ca = read_file(&config.tls_ca_file, "TLS CA file")?;
            let cert = read_file(&config.tls_cert_file, "TLS certificate file")?;
            let key = read_file(&config.tls_key_file, "TLS key file")?;
            let tls = tls_with_roots(config, Some(ca)).identity(Identity::from_pem(cert, key));
            Ok(finish(endpoint(config, Some(tls))?, AuthInterceptor::none()))
        }

        AuthMode::Oidc => {
            let holder = oidc_holder.ok_or_else(|| Error::Auth("OAuth token holder not initialized".into()))?;
            let ca = (!config.tls_ca_file.is_empty())
                .then(|| read_file(&config.tls_ca_file, "TLS CA file"))
                .transpose()?;
            let tls = tls_with_roots(config, ca);
            Ok(finish(
                endpoint(config, Some(tls))?,
                AuthInterceptor::bearer(Arc::new(holder.clone())),
            ))
        }

        AuthMode::X509 => {
            let socket = spiffe_socket(config, "X.509")?;
            let svid = WorkloadClient::connect(socket).await?.fetch_x509_svid().await?;
            let ca = certs_to_pem(&svid.bundle)?;
            let chain = certs_to_pem(&svid.x509_svid)?;
            let key = der_to_pem(&svid.x509_svid_key, "PRIVATE KEY");
            let tls = tls_with_roots(config, Some(ca)).identity(Identity::from_pem(chain, key));
            Ok(finish(endpoint(config, Some(tls))?, AuthInterceptor::none()))
        }

        AuthMode::Jwt => {
            let socket = spiffe_socket(config, "JWT")?;
            if config.jwt_audience.is_empty() {
                return Err(Error::Config("JWT audience is required for JWT authentication".into()));
            }
            let client = WorkloadClient::connect(socket).await?;
            let bundle = client
                .fetch_x509_bundles()
                .await?
                .into_values()
                .find(|b| !b.is_empty())
                .ok_or_else(|| Error::Auth("Failed to fetch X.509 bundle from SPIRE: no bundles returned".into()))?;
            let tls = tls_with_roots(config, Some(certs_to_pem(&bundle)?));
            let source = JwtSvidSource::start(client, config.jwt_audience.clone()).await?;
            Ok(finish(
                endpoint(config, Some(tls))?,
                AuthInterceptor::bearer(Arc::new(source)),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(&'static str);
    impl TokenProvider for Fixed {
        fn access_token(&self) -> Result<String> {
            Ok(self.0.to_string())
        }
    }

    #[test]
    fn interceptor_sets_bearer_header() {
        let mut i = AuthInterceptor::bearer(Arc::new(Fixed("abc")));
        let req = i.call(Request::new(())).unwrap();
        assert_eq!(req.metadata().get("authorization").unwrap(), "Bearer abc");
    }

    #[test]
    fn interceptor_without_provider_is_a_noop() {
        let req = AuthInterceptor::none().call(Request::new(())).unwrap();
        assert!(req.metadata().get("authorization").is_none());
    }

    #[test]
    fn missing_token_is_unauthenticated() {
        let holder = OAuthTokenHolder::new();
        let mut i = AuthInterceptor::bearer(Arc::new(holder));
        assert_eq!(
            i.call(Request::new(())).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    }

    #[tokio::test]
    async fn config_errors() {
        let cfg = |mode| Config {
            auth_mode: mode,
            ..Config::default()
        };
        assert!(create_channel(&cfg(AuthMode::Tls), None).await.is_err());
        assert!(create_channel(&cfg(AuthMode::X509), None).await.is_err());
        assert!(create_channel(&cfg(AuthMode::Jwt), None).await.is_err());
        assert!(create_channel(&cfg(AuthMode::Oidc), None).await.is_err());
    }

    #[tokio::test]
    async fn insecure_channel_is_lazy() {
        assert!(create_channel(&Config::default(), None).await.is_ok());
    }
}
