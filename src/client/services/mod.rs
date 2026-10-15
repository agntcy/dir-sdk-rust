// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Thin, typed wrappers around the generated gRPC clients. Streaming
//! responses are collected into `Vec`s; every error names the operation.

mod base;
mod events;
mod identity;
mod publication;
mod routing;
mod search;
mod signing;
mod store;
mod sync;

pub(crate) use base::{collect, rpc};
pub use events::EventService;
pub use identity::IdentityService;
pub use publication::PublicationService;
pub use routing::RoutingService;
pub use search::SearchService;
pub use signing::SignService;
pub use store::StoreService;
pub use sync::SyncService;
