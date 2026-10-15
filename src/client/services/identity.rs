// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use super::rpc;
use crate::client::transport::GrpcChannel;
use crate::error::Result;
use crate::models::identity::{
    DomainVerification, GetVerificationInfoRequest, GetVerificationInfoResponse, Verification,
};
use crate::models::identity_v1::identity_service_client::IdentityServiceClient;
use crate::models::identity_v1::{
    ClaimVerificationStatus, GetIdentityStatusRequest, GetIdentityStatusResponse, ResolveRequest, ResolveResponse,
};

/// The reported method for a record resolved through a verified owner claim.
const OWNER_CLAIM_METHOD: &str = "owner-claim";

/// Name resolution and ownership verification.
#[derive(Clone)]
pub struct IdentityService {
    client: IdentityServiceClient<GrpcChannel>,
}

impl IdentityService {
    pub(crate) fn new(channel: GrpcChannel) -> Self {
        Self {
            client: IdentityServiceClient::new(channel),
        }
    }

    pub fn client(&self) -> IdentityServiceClient<GrpcChannel> {
        self.client.clone()
    }

    pub async fn resolve(&self, request: ResolveRequest) -> Result<ResolveResponse> {
        Ok(self
            .client()
            .resolve(request)
            .await
            .map_err(rpc("resolve"))?
            .into_inner())
    }

    /// Reports whether a record has a verified owner, projected from its
    /// ownership claim (`identity.v1.GetIdentityStatus`).
    pub async fn get_verification_info(
        &self,
        request: GetVerificationInfoRequest,
    ) -> Result<GetVerificationInfoResponse> {
        let status = self
            .client()
            .get_identity_status(GetIdentityStatusRequest {
                cid: request.cid,
                name: request.name,
                version: request.version,
            })
            .await
            .map_err(rpc("get_verification_info"))?
            .into_inner();
        Ok(verification_info(status))
    }
}

/// Projects the ownership claim result onto the legacy naming result shape.
pub(crate) fn verification_info(status: GetIdentityStatusResponse) -> GetVerificationInfoResponse {
    let Some(owner) = status.owner else {
        return GetVerificationInfoResponse {
            error_message: Some("no verification found".into()),
            ..Default::default()
        };
    };

    if owner.status != ClaimVerificationStatus::Verified as i32 {
        return GetVerificationInfoResponse {
            error_message: Some(
                owner
                    .error
                    .filter(|e| !e.is_empty())
                    .unwrap_or_else(|| "verification failed".into()),
            ),
            ..Default::default()
        };
    }

    GetVerificationInfoResponse {
        verified: true,
        verification: Some(Verification {
            domain: Some(DomainVerification {
                domain: owner.subject,
                method: OWNER_CLAIM_METHOD.into(),
                verified_at: owner.verified_at,
            }),
        }),
        error_message: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::identity_v1::ClaimVerification;

    fn owner(status: ClaimVerificationStatus, error: Option<&str>) -> GetIdentityStatusResponse {
        GetIdentityStatusResponse {
            owner: Some(ClaimVerification {
                subject: "example.com".into(),
                status: status as i32,
                error: error.map(String::from),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn no_owner() {
        let r = verification_info(GetIdentityStatusResponse::default());
        assert!(!r.verified);
        assert_eq!(r.error_message.as_deref(), Some("no verification found"));
    }

    #[test]
    fn failed_owner_uses_error_or_default() {
        let r = verification_info(owner(ClaimVerificationStatus::Failed, Some("bad sig")));
        assert_eq!(r.error_message.as_deref(), Some("bad sig"));
        let r = verification_info(owner(ClaimVerificationStatus::Failed, None));
        assert_eq!(r.error_message.as_deref(), Some("verification failed"));
    }

    #[test]
    fn verified_owner() {
        let r = verification_info(owner(ClaimVerificationStatus::Verified, None));
        assert!(r.verified);
        let d = r.verification.unwrap().domain.unwrap();
        assert_eq!((d.domain.as_str(), d.method.as_str()), ("example.com", "owner-claim"));
    }
}
