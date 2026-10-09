// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Rust SDK for the [AGNTCY Directory](https://github.com/agntcy/dir).
//!
//! ```no_run
//! use agntcy_dir::{Client, Config};
//!
//! # async fn run() -> agntcy_dir::Result<()> {
//! let client = Client::new(Config::from_env()?).await?;
//! let hits = client.list(Default::default()).await?;
//! # Ok(()) }
//! ```

mod proto;

pub mod client;
pub mod error;
pub mod models;

pub use client::auth::{OAuthPkceError, OAuthSessionManager, OAuthTokenHolder};
pub use client::config::{AuthMode, Config, DockerConfig};
pub use client::Client;
pub use error::{Error, Result};
