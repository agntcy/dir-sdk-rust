// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::client::config::Config;
use crate::error::{Error, Result};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Captured output of a successful `dirctl` run.
#[derive(Debug, Clone, Default)]
pub struct DirctlOutput {
    pub stdout: String,
    pub stderr: String,
}

/// Program + leading arguments for invoking `dirctl` (native binary or
/// `docker run ...`), including docker `--env`/`--mount` flags for `env` and
/// `extra_mounts`.
pub fn build_dirctl_command(config: &Config, env: &[(String, String)], extra_mounts: &[String]) -> Vec<String> {
    match &config.docker_config {
        Some(docker) => {
            let mut docker = docker.clone();
            docker.envs.extend(env.iter().cloned());
            docker.mounts.extend(extra_mounts.iter().cloned());
            docker.command()
        }
        None => config.dirctl_command(),
    }
}

/// Runs `dirctl <args>` and fails on a non-zero exit status.
pub async fn run_dirctl(
    config: &Config,
    args: &[String],
    env: &[(String, String)],
    extra_mounts: &[String],
) -> Result<DirctlOutput> {
    let base = build_dirctl_command(config, env, extra_mounts);
    let (program, base_args) = base.split_first().expect("command is never empty");

    let child = Command::new(program)
        .args(base_args)
        .args(args)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| Error::Dirctl(format!("failed to run {program}: {e}")))?;

    let output = tokio::time::timeout(DEFAULT_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| Error::Dirctl("dirctl command timed out".into()))?
        .map_err(|e| Error::Dirctl(format!("failed to run {program}: {e}")))?;

    let out = DirctlOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    if !output.status.success() {
        let detail = [&out.stderr, &out.stdout]
            .into_iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
            .unwrap_or("no output");
        return Err(Error::Dirctl(format!(
            "dirctl command failed with {}: {detail}",
            output.status
        )));
    }
    Ok(out)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn config_for(program: &str) -> Config {
        Config {
            dirctl_path: Some(program.into()),
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn captures_output_and_env() {
        // `sh -c` stands in for dirctl: args are passed after the program
        let cfg = config_for("sh");
        let out = run_dirctl(
            &cfg,
            &["-c".into(), "echo \"$GREETING\"".into()],
            &[("GREETING".into(), "hello".into())],
            &[],
        )
        .await
        .unwrap();
        assert_eq!(out.stdout.trim(), "hello");
    }

    #[tokio::test]
    async fn non_zero_exit_reports_stderr() {
        let err = run_dirctl(
            &config_for("sh"),
            &["-c".into(), "echo boom >&2; exit 3".into()],
            &[],
            &[],
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("boom"), "{msg}");
    }

    #[tokio::test]
    async fn missing_binary_is_reported() {
        let err = run_dirctl(&config_for("/definitely/not/dirctl"), &[], &[], &[])
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Dirctl(_)));
    }

    #[test]
    fn docker_gets_env_and_mounts() {
        let cfg = Config {
            docker_config: Some(Default::default()),
            ..Config::default()
        };
        let cmd = build_dirctl_command(&cfg, &[("K".into(), "V".into())], &[]);
        assert_eq!(cmd[0], "docker");
        assert!(cmd.contains(&"K=V".to_string()));
    }
}
