// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Protobuf models, grouped by API package like the other Directory SDKs
//! (`models::core_v1`, `models::routing_v1`, ...).
//!
//! All messages implement [`serde::Serialize`] / [`serde::Deserialize`]
//! using the canonical protobuf JSON mapping, so a record can be built with
//! `serde_json::from_value::<core_v1::Record>(json)`.

pub mod identity;

pub use crate::proto::agntcy::dir::core::v1 as core_v1;
pub use crate::proto::agntcy::dir::events::v1 as events_v1;
pub use crate::proto::agntcy::dir::identity::v1 as identity_v1;
pub use crate::proto::agntcy::dir::routing::v1 as routing_v1;
pub use crate::proto::agntcy::dir::search::v1 as search_v1;
pub use crate::proto::agntcy::dir::sign::v1 as sign_v1;
pub use crate::proto::agntcy::dir::store::v1 as store_v1;
