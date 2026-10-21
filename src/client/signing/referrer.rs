// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Referrer encoding of signatures and public keys, identical to
//! `Signature.MarshalReferrer` / `PublicKey.MarshalReferrer` in the Go SDK:
//! the referrer `data` is the protobuf-JSON form of the message as a
//! `google.protobuf.Struct`.

use pbjson_types::Struct;

use crate::error::{Error, Result};
use crate::models::core_v1::{RecordRef, RecordReferrer};
use crate::models::sign_v1::{PublicKey, Signature};
use crate::models::store_v1::PushReferrerRequest;

/// Referrer type of [`Signature`] (the protobuf full name, as in Go).
pub const SIGNATURE_REFERRER_TYPE: &str = "agntcy.dir.sign.v1.Signature";
/// Referrer type of [`PublicKey`].
pub const PUBLIC_KEY_REFERRER_TYPE: &str = "agntcy.dir.sign.v1.PublicKey";

fn to_struct<T: serde::Serialize>(msg: &T, what: &str) -> Result<Struct> {
    let value = serde_json::to_value(msg)?;
    if !value.is_object() {
        return Err(Error::Sign(format!("failed to convert {what} to struct")));
    }
    serde_json::from_value(value).map_err(|e| Error::Sign(format!("failed to convert {what} to struct: {e}")))
}

fn from_struct<T: serde::de::DeserializeOwned>(referrer: &RecordReferrer, what: &str) -> Result<T> {
    let data = referrer
        .data
        .as_ref()
        .ok_or_else(|| Error::Verify("referrer or data is nil".into()))?;
    let value = serde_json::to_value(data)?;
    serde_json::from_value(value).map_err(|e| Error::Verify(format!("failed to decode {what} from referrer: {e}")))
}

/// Exports a signature into a push request for `record_ref`.
pub fn signature_to_push_request(record_ref: &RecordRef, signature: &Signature) -> Result<PushReferrerRequest> {
    Ok(PushReferrerRequest {
        record_ref: Some(record_ref.clone()),
        r#type: SIGNATURE_REFERRER_TYPE.into(),
        annotations: Default::default(),
        created_at: String::new(),
        data: Some(to_struct(signature, "signature")?),
    })
}

/// Exports a public key into a push request for `record_ref`.
pub fn public_key_to_push_request(record_ref: &RecordRef, key: &PublicKey) -> Result<PushReferrerRequest> {
    Ok(PushReferrerRequest {
        record_ref: Some(record_ref.clone()),
        r#type: PUBLIC_KEY_REFERRER_TYPE.into(),
        annotations: Default::default(),
        created_at: String::new(),
        data: Some(to_struct(key, "public key")?),
    })
}

/// Loads a [`Signature`] from a referrer.
pub fn signature_from_referrer(referrer: &RecordReferrer) -> Result<Signature> {
    from_struct(referrer, "signature")
}

/// Loads a [`PublicKey`] from a referrer.
pub fn public_key_from_referrer(referrer: &RecordReferrer) -> Result<PublicKey> {
    from_struct(referrer, "public key")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn referrer(req: PushReferrerRequest) -> RecordReferrer {
        RecordReferrer {
            r#type: req.r#type,
            data: req.data,
            ..Default::default()
        }
    }

    #[test]
    fn signature_roundtrip_uses_protojson_field_names() {
        let sig = Signature {
            signature: "c2ln".into(),
            algorithm: "ECDSA-P-256".into(),
            signed_at: "2026-01-01T00:00:00Z".into(),
            ..Default::default()
        };
        let req = signature_to_push_request(&RecordRef { cid: "bafy".into() }, &sig).unwrap();
        assert_eq!(req.r#type, "agntcy.dir.sign.v1.Signature");
        assert!(req.annotations.is_empty() && req.created_at.is_empty());
        // data is the protojson form: camelCase names, default fields omitted
        let json = serde_json::to_value(req.data.as_ref().unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"signedAt": "2026-01-01T00:00:00Z", "algorithm": "ECDSA-P-256", "signature": "c2ln"})
        );
        assert_eq!(signature_from_referrer(&referrer(req)).unwrap(), sig);
    }

    #[test]
    fn public_key_roundtrip() {
        let key = PublicKey { key: "PEM".into() };
        let req = public_key_to_push_request(&RecordRef { cid: "bafy".into() }, &key).unwrap();
        assert_eq!(req.r#type, "agntcy.dir.sign.v1.PublicKey");
        assert_eq!(
            serde_json::to_value(req.data.as_ref().unwrap()).unwrap(),
            serde_json::json!({"key": "PEM"})
        );
        assert_eq!(public_key_from_referrer(&referrer(req)).unwrap(), key);
    }

    #[test]
    fn missing_data_is_an_error() {
        assert!(signature_from_referrer(&RecordReferrer::default()).is_err());
        assert!(public_key_from_referrer(&RecordReferrer::default()).is_err());
    }

    #[test]
    fn only_objects_convert_to_structs() {
        let err = to_struct(&"not an object", "thing").unwrap_err();
        assert!(err.to_string().contains("failed to convert thing to struct"), "{err}");
    }
}
