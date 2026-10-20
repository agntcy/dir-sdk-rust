// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Native signing and local verification (no `dirctl` / `cosign` binary),
//! a port of the Go SDK's `client/sign.go`, `client/verify.go`,
//! `client/utils/cosign` and `client/utils/verify`.

pub(crate) mod keys;
pub(crate) mod oidc;
pub(crate) mod referrer;
pub(crate) mod verify;
