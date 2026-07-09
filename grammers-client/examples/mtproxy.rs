// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! MTProxy connection example.
//!
//! This example demonstrates how to connect to Telegram through an MTProxy server.
//!
//! Run with:
//! ```sh
//! cargo run --example mtproxy --features mtproxy
//! ```
//!
//! # Configuration
//!
//! You need to set the following environment variables or modify the constants below:
//! - `TELEGRAM_API_ID`: Your API ID (get from https://my.telegram.org)
//! - `MTPROXY_HOST`: MTProxy server hostname or IP
//! - `MTPROXY_PORT`: MTProxy server port (default: 8888)
//! - `MTPROXY_SECRET`: MTProxy secret (hex or base64)

use std::env;
use std::sync::Arc;

use grammers_client::Client;
use grammers_mtsender::{ConnectionParams, MtProxyConfig};
use grammers_session::storages::SqliteSession;
use grammers_tl_types as tl;

/// Example API ID - replace with your own or use environment variable
const API_ID: i32 = 932939; // Example only - get yours at https://my.telegram.org

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    simple_logger::init_with_env()?;

    // Get configuration from environment or use defaults
    let api_id = env::var("TELEGRAM_API_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(API_ID);

    let mtproxy_host = env::var("MTPROXY_HOST")
        .unwrap_or_else(|_| "127.0.0.1".to_string());

    let mtproxy_port = env::var("MTPROXY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8888);

    let mtproxy_secret = env::var("MTPROXY_SECRET")
        .unwrap_or_else(|_| "dd0123456789abcdef0123456789abcdef".to_string());

    // DC ID (optional). Some MTProxy servers support only specific data centers.
    let mtproxy_dc_id = env::var("MTPROXY_DC_ID")
        .ok()
        .and_then(|s| s.parse::<i32>().ok());

    println!("MTProxy Configuration:");
    println!("  API ID: {}", api_id);
    println!("  Proxy: {}:{}", mtproxy_host, mtproxy_port);
    println!("  Secret: {}***", &mtproxy_secret[..8]);
    println!("  DC ID: {:?}", mtproxy_dc_id);

    // Load or create session
    let session = Arc::new(SqliteSession::open("mtproxy.session").await?);

    // Configure connection with MTProxy
    let params = ConnectionParams {
        #[cfg(feature = "mtproxy")]
        mtproxy: Some(MtProxyConfig {
            host: mtproxy_host,
            port: mtproxy_port,
            secret: mtproxy_secret,
            dc_id: mtproxy_dc_id,
        }),
        ..Default::default()
    };

    println!("Connecting to Telegram via MTProxy...");

    // Create sender pool with MTProxy configuration
    let grammers_mtsender::SenderPool { runner, handle, .. } =
        grammers_mtsender::SenderPool::with_configuration(
            Arc::clone(&session),
            api_id,
            params,
        );

    let client = Client::new(handle);
    let pool_task = tokio::spawn(runner.run());

    println!("Connected! Testing connection with ping...");

    // Test connection with ping
    let pong = client.invoke(&tl::functions::Ping { ping_id: 123 }).await?;
    println!("Ping result: {:?}", pong);

    println!("MTProxy connection test successful!");
    println!("\nNote: This example only tests the connection.");
    println!("For full authentication, use the 'dialogs' example with MTProxy configuration.");

    // Pool's `run()` won't finish until all handles are dropped or quit is called.
    drop(client);
    let _ = pool_task.await;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main())
}
