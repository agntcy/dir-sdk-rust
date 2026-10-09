// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use super::runner::{run_dirctl, DirctlOutput};
use crate::client::config::Config;
use crate::error::{Error, Result};
use crate::models::sign_v1::{self, sign_request_provider::Request};

fn server_env(config: &Config) -> Vec<(String, String)> {
    vec![("DIRECTORY_CLIENT_SERVER_ADDRESS".into(), config.dirctl_server_address())]
}

fn push_opt(args: &mut Vec<String>, flag: &str, value: &str) {
    if !value.is_empty() {
        args.extend([flag.to_string(), value.to_string()]);
    }
}

/// Signs `cid` with a private key (`dirctl sign <cid> --key <key>`).
pub async fn sign_with_key(config: &Config, cid: &str, req: &sign_v1::SignWithKey) -> Result<DirctlOutput> {
    let password = req.password.as_deref().map(String::from_utf8_lossy).unwrap_or_default();
    let mut env = server_env(config);
    env.push(("COSIGN_PASSWORD".into(), password.into_owned()));

    // Inside docker the key file is bind-mounted (read-only) at the container root.
    let (key_arg, mounts) = match (&config.docker_config, Path::new(&req.private_key).file_name()) {
        (Some(_), Some(name)) if Path::new(&req.private_key).is_file() => {
            let dst = format!("/{}", name.to_string_lossy());
            let mount = format!("type=bind,src={},dst={dst},readonly", req.private_key);
            (dst, vec![mount])
        }
        _ => (req.private_key.clone(), vec![]),
    };

    let args = ["sign", cid, "--key", &key_arg].map(String::from);
    run_dirctl(config, &args, &env, &mounts).await
}

/// Signs `cid` using keyless OIDC (`dirctl sign <cid> [--oidc-token ...]`).
pub async fn sign_with_oidc(config: &Config, cid: &str, req: &sign_v1::SignWithOidc) -> Result<DirctlOutput> {
    let mut args = vec!["sign".to_string(), cid.to_string()];
    push_opt(&mut args, "--oidc-token", &req.id_token);
    if let Some(o) = &req.options {
        push_opt(&mut args, "--oidc-provider-url", &o.oidc_provider_url);
        push_opt(&mut args, "--oidc-client-id", &o.oidc_client_id);
        push_opt(&mut args, "--oidc-client-secret", &o.oidc_client_secret);
        if o.skip_tlog {
            args.push("--skip-tlog".into());
        }
        push_opt(&mut args, "--fulcio-url", &o.fulcio_url);
        push_opt(&mut args, "--rekor-url", &o.rekor_url);
        push_opt(&mut args, "--timestamp-url", &o.timestamp_url);
    }
    run_dirctl(config, &args, &server_env(config), &[]).await
}

/// Signs a record through `dirctl`, selecting the method from `req.provider`.
pub async fn sign_record(config: &Config, req: &sign_v1::SignRequest) -> Result<()> {
    let cid = req.record_ref.as_ref().map(|r| r.cid.as_str()).unwrap_or_default();
    match req.provider.as_ref().and_then(|p| p.request.as_ref()) {
        Some(Request::Oidc(oidc)) => sign_with_oidc(config, cid, oidc).await?,
        Some(Request::Key(key)) => sign_with_key(config, cid, key).await?,
        None => return Err(Error::InvalidArgument("unsupported provider was supplied".into())),
    };
    Ok(())
}
