// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Interactive OIDC login (PKCE in the browser), then a simple authenticated call.
//!
//! ```sh
//! DIRECTORY_CLIENT_SERVER_ADDRESS=dir.example.com:443 \
//! DIRECTORY_CLIENT_AUTH_MODE=oidc \
//! DIRECTORY_CLIENT_OIDC_ISSUER=https://idp.example.com \
//! DIRECTORY_CLIENT_OIDC_CLIENT_ID=my-client \
//! cargo run --example example_interactive_oidc
//! ```

use agntcy_dir::models::routing_v1::ListRequest;
use agntcy_dir::{Client, Config};

#[tokio::main]
async fn main() -> agntcy_dir::Result<()> {
    let client = Client::new(Config::from_env()?).await?;

    if client.has_cached_oauth_token() {
        println!("Using cached or configured access token.");
    } else {
        println!("No token available, starting the browser login...");
        client.authenticate_oauth_pkce().await?;
        println!("Authenticated with OAuth PKCE");
    }

    let listed = client.list(ListRequest::default()).await?;
    println!("Listed {} record(s)", listed.len());
    Ok(())
}
