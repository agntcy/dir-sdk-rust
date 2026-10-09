// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Minimal SPIFFE Workload API client (X.509-SVID, X.509 bundles, JWT-SVID).
//!
//! The messages mirror the `SpiffeWorkloadAPI` gRPC service from the SPIFFE
//! specification; the service has no protobuf package, hence the bare
//! `/SpiffeWorkloadAPI/...` method paths.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use http::uri::PathAndQuery;
use tonic::transport::Channel;

use crate::client::auth::TokenProvider;
use crate::error::{Error, Result};

#[derive(Clone, PartialEq, prost::Message)]
struct X509svidRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct X509svidResponse {
    #[prost(message, repeated, tag = "1")]
    svids: Vec<X509svid>,
}

/// An X.509-SVID as delivered by the Workload API (all binary fields are DER).
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct X509svid {
    #[prost(string, tag = "1")]
    pub spiffe_id: String,
    /// ASN.1 DER certificate chain, leaf first, concatenated.
    #[prost(bytes = "vec", tag = "2")]
    pub x509_svid: Vec<u8>,
    /// ASN.1 DER PKCS#8 private key.
    #[prost(bytes = "vec", tag = "3")]
    pub x509_svid_key: Vec<u8>,
    /// ASN.1 DER trust bundle certificates, concatenated.
    #[prost(bytes = "vec", tag = "4")]
    pub bundle: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct X509BundlesRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct X509BundlesResponse {
    #[prost(map = "string, bytes", tag = "2")]
    bundles: HashMap<String, Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct JwtsvidRequest {
    #[prost(string, repeated, tag = "1")]
    audience: Vec<String>,
    #[prost(string, tag = "2")]
    spiffe_id: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct JwtsvidResponse {
    #[prost(message, repeated, tag = "1")]
    svids: Vec<Jwtsvid>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Jwtsvid {
    #[prost(string, tag = "1")]
    spiffe_id: String,
    #[prost(string, tag = "2")]
    svid: String,
}

/// Client for the SPIRE agent's Workload API.
#[derive(Clone)]
pub(crate) struct WorkloadClient {
    channel: Channel,
}

impl WorkloadClient {
    /// Connects to the agent at `socket` (`unix:///path` or a plain path).
    #[cfg(unix)]
    pub(crate) async fn connect(socket: &str) -> Result<Self> {
        use hyper_util::rt::TokioIo;
        use tonic::transport::{Endpoint, Uri};

        let path = socket
            .strip_prefix("unix://")
            .or_else(|| socket.strip_prefix("unix:"))
            .unwrap_or(socket)
            .to_string();
        let channel = Endpoint::try_from("http://[::]:50051")
            .map_err(|e| Error::Auth(format!("invalid SPIFFE endpoint: {e}")))?
            .connect_with_connector(tower::service_fn(move |_: Uri| {
                let path = path.clone();
                async move { Ok::<_, std::io::Error>(TokioIo::new(tokio::net::UnixStream::connect(path).await?)) }
            }))
            .await
            .map_err(|e| Error::Auth(format!("failed to connect to the SPIFFE Workload API at {socket}: {e}")))?;
        Ok(Self { channel })
    }

    #[cfg(not(unix))]
    pub(crate) async fn connect(_socket: &str) -> Result<Self> {
        Err(Error::Auth("the SPIFFE Workload API requires a Unix platform".into()))
    }

    fn request<T>(msg: T) -> tonic::Request<T> {
        let mut req = tonic::Request::new(msg);
        req.metadata_mut()
            .insert("workload.spiffe.io", "true".parse().expect("static metadata"));
        req
    }

    async fn grpc(&self) -> Result<tonic::client::Grpc<Channel>> {
        let mut grpc = tonic::client::Grpc::new(self.channel.clone());
        grpc.ready()
            .await
            .map_err(|e| Error::Auth(format!("SPIFFE Workload API not ready: {e}")))?;
        Ok(grpc)
    }

    fn status(op: &str) -> impl FnOnce(tonic::Status) -> Error + '_ {
        move |s| Error::Auth(format!("{op}: {s}"))
    }

    /// Fetches the default X.509-SVID (first message of the update stream).
    pub(crate) async fn fetch_x509_svid(&self) -> Result<X509svid> {
        let op = "failed to fetch X.509-SVID from SPIRE";
        let mut stream = self
            .grpc()
            .await?
            .server_streaming(
                Self::request(X509svidRequest {}),
                PathAndQuery::from_static("/SpiffeWorkloadAPI/FetchX509SVID"),
                tonic::codec::ProstCodec::<X509svidRequest, X509svidResponse>::default(),
            )
            .await
            .map_err(Self::status(op))?
            .into_inner();
        loop {
            match stream.message().await.map_err(Self::status(op))? {
                Some(resp) if !resp.svids.is_empty() => return Ok(resp.svids.into_iter().next().expect("non-empty")),
                Some(_) => continue,
                None => return Err(Error::Auth(format!("{op}: no SVIDs returned"))),
            }
        }
    }

    /// Fetches the X.509 bundles keyed by trust domain (concatenated DER).
    pub(crate) async fn fetch_x509_bundles(&self) -> Result<HashMap<String, Vec<u8>>> {
        let op = "failed to fetch X.509 bundle from SPIRE";
        let mut stream = self
            .grpc()
            .await?
            .server_streaming(
                Self::request(X509BundlesRequest {}),
                PathAndQuery::from_static("/SpiffeWorkloadAPI/FetchX509Bundles"),
                tonic::codec::ProstCodec::<X509BundlesRequest, X509BundlesResponse>::default(),
            )
            .await
            .map_err(Self::status(op))?
            .into_inner();
        loop {
            match stream.message().await.map_err(Self::status(op))? {
                Some(resp) if !resp.bundles.is_empty() => return Ok(resp.bundles),
                Some(_) => continue,
                None => return Err(Error::Auth(format!("{op}: no bundles returned"))),
            }
        }
    }

    /// Fetches a JWT-SVID for `audience` and the default identity.
    pub(crate) async fn fetch_jwt_svid(&self, audience: &str) -> Result<String> {
        let op = "failed to fetch JWT-SVID from SPIRE";
        let resp: JwtsvidResponse = self
            .grpc()
            .await?
            .unary(
                Self::request(JwtsvidRequest {
                    audience: vec![audience.to_string()],
                    spiffe_id: String::new(),
                }),
                PathAndQuery::from_static("/SpiffeWorkloadAPI/FetchJWTSVID"),
                tonic::codec::ProstCodec::<JwtsvidRequest, JwtsvidResponse>::default(),
            )
            .await
            .map_err(Self::status(op))?
            .into_inner();
        resp.svids
            .into_iter()
            .next()
            .map(|s| s.svid)
            .ok_or_else(|| Error::Auth(format!("{op}: no SVIDs returned")))
    }
}

/// PEM-encodes DER bytes with the given label.
pub(crate) fn der_to_pem(der: &[u8], label: &str) -> String {
    let b64 = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Splits concatenated DER `SEQUENCE`s (certificates) into individual items.
pub(crate) fn split_der_sequences(mut data: &[u8]) -> Result<Vec<&[u8]>> {
    let bad = || Error::Auth("malformed DER certificate data from SPIRE".to_string());
    let mut items = Vec::new();
    while !data.is_empty() {
        if data[0] != 0x30 || data.len() < 2 {
            return Err(bad());
        }
        let (header, len) = if data[1] < 0x80 {
            (2usize, data[1] as usize)
        } else {
            let n = (data[1] & 0x7f) as usize;
            if n == 0 || n > 4 || data.len() < 2 + n {
                return Err(bad());
            }
            (
                2 + n,
                data[2..2 + n].iter().fold(0usize, |acc, b| (acc << 8) | *b as usize),
            )
        };
        let total = header.checked_add(len).filter(|t| *t <= data.len()).ok_or_else(bad)?;
        items.push(&data[..total]);
        data = &data[total..];
    }
    Ok(items)
}

/// Concatenated DER certificates → PEM bundle.
pub(crate) fn certs_to_pem(der: &[u8]) -> Result<String> {
    Ok(split_der_sequences(der)?
        .into_iter()
        .map(|c| der_to_pem(c, "CERTIFICATE"))
        .collect())
}

/// Reads the `exp` claim (seconds since the epoch) of a JWT without verifying it.
fn jwt_expiry(token: &str) -> Option<i64> {
    let payload = URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?).ok()?;
    serde_json::from_slice::<serde_json::Value>(&payload)
        .ok()?
        .get("exp")?
        .as_i64()
}

/// A JWT-SVID that is kept fresh by a background task; the current token is
/// attached to every outgoing request.
pub(crate) struct JwtSvidSource {
    token: Arc<RwLock<String>>,
    task: tokio::task::JoinHandle<()>,
}

impl JwtSvidSource {
    pub(crate) async fn start(client: WorkloadClient, audience: String) -> Result<Self> {
        let first = client.fetch_jwt_svid(&audience).await?;
        let token = Arc::new(RwLock::new(first.clone()));

        let shared = token.clone();
        let task = tokio::spawn(async move {
            let mut current = first;
            loop {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs() as i64);
                // Refresh once half of the remaining lifetime has elapsed.
                let wait = jwt_expiry(&current).map_or(60, |exp| ((exp - now) / 2).clamp(1, 3600)) as u64;
                tokio::time::sleep(Duration::from_secs(wait)).await;
                loop {
                    match client.fetch_jwt_svid(&audience).await {
                        Ok(t) => {
                            *shared.write().unwrap_or_else(|e| e.into_inner()) = t.clone();
                            current = t;
                            break;
                        }
                        Err(_) => tokio::time::sleep(Duration::from_secs(5)).await,
                    }
                }
            }
        });
        Ok(Self { token, task })
    }
}

impl TokenProvider for JwtSvidSource {
    fn access_token(&self) -> Result<String> {
        Ok(self.token.read().unwrap_or_else(|e| e.into_inner()).clone())
    }
}

impl Drop for JwtSvidSource {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_concatenated_der() {
        // two fake "certificates": short-form and long-form lengths
        let a = [0x30, 0x02, 0xaa, 0xbb];
        let mut b = vec![0x30, 0x82, 0x01, 0x00];
        b.extend(std::iter::repeat(0u8).take(256));
        let mut all = a.to_vec();
        all.extend(&b);
        let parts = split_der_sequences(&all).unwrap();
        assert_eq!(parts, vec![&a[..], &b[..]]);
        assert!(split_der_sequences(&[0x31, 0x00]).is_err());
        assert!(split_der_sequences(&[0x30, 0x05, 0x00]).is_err());
    }

    #[test]
    fn pem_wraps_at_64() {
        let pem = der_to_pem(&[7u8; 100], "CERTIFICATE");
        let lines: Vec<_> = pem.lines().collect();
        assert_eq!(lines[0], "-----BEGIN CERTIFICATE-----");
        assert_eq!(lines[1].len(), 64);
        assert_eq!(*lines.last().unwrap(), "-----END CERTIFICATE-----");
    }

    #[test]
    fn jwt_expiry_is_parsed() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"exp":1234}"#);
        assert_eq!(jwt_expiry(&format!("h.{payload}.s")), Some(1234));
        assert_eq!(jwt_expiry("garbage"), None);
    }
}
