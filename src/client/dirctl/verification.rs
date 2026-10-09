// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use super::runner::run_dirctl;
use crate::client::config::Config;
use crate::error::{Error, Result};
use crate::models::sign_v1::{self, verify_request_provider::Request};

fn push_opt(args: &mut Vec<String>, flag: &str, value: &str) {
    if !value.is_empty() {
        args.extend([flag.to_string(), value.to_string()]);
    }
}

fn push_oidc_options(args: &mut Vec<String>, o: &sign_v1::VerifyOptionsOidc) {
    push_opt(args, "--tuf-mirror-url", &o.tuf_mirror_url);
    push_opt(args, "--trusted-root-path", &o.trusted_root_path);
    for (set, flag) in [
        (o.ignore_tlog, "--ignore-tlog"),
        (o.ignore_tsa, "--ignore-tsa"),
        (o.ignore_sct, "--ignore-sct"),
    ] {
        if set {
            args.push(flag.into());
        }
    }
}

fn base_args(cid: &str, output_path: &str) -> Vec<String> {
    ["verify", cid, "--output-file", output_path].map(String::from).to_vec()
}

async fn run_verify(config: &Config, args: Vec<String>, mounts: &[String]) -> Result<()> {
    let env = [(
        "DIRECTORY_CLIENT_SERVER_ADDRESS".to_string(),
        config.dirctl_server_address(),
    )];
    run_dirctl(config, &args, &env, mounts).await.map(|_| ())
}

/// `dirctl verify <cid> --key <public key>`.
pub async fn verify_with_key(
    config: &Config,
    cid: &str,
    req: &sign_v1::VerifyWithKey,
    output_path: &str,
    mounts: &[String],
) -> Result<()> {
    let mut args = base_args(cid, output_path);
    args.extend(["--key".to_string(), req.public_key.clone()]);
    run_verify(config, args, mounts).await
}

/// `dirctl verify <cid>` accepting any valid signer.
pub async fn verify_with_any(
    config: &Config,
    cid: &str,
    req: Option<&sign_v1::VerifyWithAny>,
    output_path: &str,
    mounts: &[String],
) -> Result<()> {
    let mut args = base_args(cid, output_path);
    if let Some(o) = req.and_then(|r| r.oidc_options.as_ref()) {
        push_oidc_options(&mut args, o);
    }
    run_verify(config, args, mounts).await
}

/// `dirctl verify <cid> --oidc-issuer ... --oidc-subject ...`.
pub async fn verify_with_oidc(
    config: &Config,
    cid: &str,
    req: Option<&sign_v1::VerifyWithOidc>,
    output_path: &str,
    mounts: &[String],
) -> Result<()> {
    let mut args = base_args(cid, output_path);
    if let Some(r) = req {
        push_opt(&mut args, "--oidc-issuer", &r.issuer);
        push_opt(&mut args, "--oidc-subject", &r.subject);
        if let Some(o) = &r.options {
            push_oidc_options(&mut args, o);
        }
    }
    run_verify(config, args, mounts).await
}

/// Verifies a record locally through `dirctl` and parses its JSON report.
pub async fn verify_record(config: &Config, request: &sign_v1::VerifyRequest) -> Result<sign_v1::VerifyResponse> {
    let tmp = tempfile::tempdir()?;
    let output = tmp.path().join("output.json");
    std::fs::File::create(&output)?;

    let host_path = output.to_string_lossy().into_owned();
    // Inside docker the output file is bind-mounted at the container root.
    let (path_arg, mounts) = if config.docker_config.is_some() {
        let name = output
            .file_name()
            .expect("has file name")
            .to_string_lossy()
            .into_owned();
        (
            format!("/{name}"),
            vec![format!("type=bind,src={host_path},dst=/{name}")],
        )
    } else {
        (host_path.clone(), vec![])
    };

    let cid = request.record_ref.as_ref().map(|r| r.cid.as_str()).unwrap_or_default();
    match request.provider.as_ref().and_then(|p| p.request.as_ref()) {
        Some(Request::Oidc(r)) => verify_with_oidc(config, cid, Some(r), &path_arg, &mounts).await?,
        Some(Request::Key(r)) => verify_with_key(config, cid, r, &path_arg, &mounts).await?,
        Some(Request::Any(r)) => verify_with_any(config, cid, Some(r), &path_arg, &mounts).await?,
        None => return Err(Error::InvalidArgument("unsupported provider was supplied".into())),
    }

    let json = std::fs::read_to_string(&output)
        .map_err(|e| Error::Dirctl(format!("verification output file was not readable: {e}")))?;
    serde_json::from_str(&json).map_err(|e| Error::Dirctl(format!("Failed to parse verification response: {e}")))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A stand-in `dirctl` that writes a canned report to `--output-file`.
    fn fake_dirctl(dir: &std::path::Path, report: &str) -> Config {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("dirctl");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = --output-file ] && out=$2; shift; done\nprintf '%s' '{report}' > \"$out\"\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        Config {
            dirctl_path: Some(script.to_string_lossy().into()),
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn parses_dirctl_report() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = fake_dirctl(dir.path(), r#"{"success":true,"signers":[]}"#);
        let req = sign_v1::VerifyRequest {
            record_ref: Some(crate::models::core_v1::RecordRef { cid: "bafy".into() }),
            provider: Some(sign_v1::VerifyRequestProvider {
                request: Some(Request::Any(sign_v1::VerifyWithAny::default())),
            }),
            from_server: false,
        };
        let resp = verify_record(&cfg, &req).await.unwrap();
        assert!(resp.success);
    }

    #[tokio::test]
    async fn requires_provider() {
        let err = verify_record(&Config::default(), &sign_v1::VerifyRequest::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }
}
