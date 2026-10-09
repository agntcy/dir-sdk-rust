// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Signing and local verification are delegated to the `dirctl` CLI (run
//! natively or in Docker), exactly like the other Directory SDKs.

mod runner;
mod signing;
mod verification;

pub use runner::{build_dirctl_command, run_dirctl, DirctlOutput};
pub use signing::{sign_record, sign_with_key, sign_with_oidc};
pub use verification::{verify_record, verify_with_any, verify_with_key, verify_with_oidc};
