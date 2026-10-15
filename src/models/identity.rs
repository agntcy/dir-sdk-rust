// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Name-ownership verification result types (projected from identity.v1).

use pbjson_types::Timestamp;

/// Looks up the ownership-claim verification status of a record, by CID or by
/// name (with an optional version).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GetVerificationInfoRequest {
    pub cid: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
}

/// The verified owner of a record's name.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DomainVerification {
    /// The verified owner subject.
    pub domain: String,
    /// How the owner was verified.
    pub method: String,
    /// When the owner was last verified.
    pub verified_at: Option<Timestamp>,
}

/// Details of a verified name.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Verification {
    pub domain: Option<DomainVerification>,
}

/// Result of a name ownership lookup.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GetVerificationInfoResponse {
    pub verified: bool,
    pub verification: Option<Verification>,
    pub error_message: Option<String>,
}
