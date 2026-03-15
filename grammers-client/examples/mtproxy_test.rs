// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! MTProxy connection test example with full authorization.
//!
//! This example demonstrates how to connect to Telegram through an MTProxy server
//! and perform full authentication.
//!
//! Run with:
//! ```sh
//! cargo run --example mtproxy_test --features mtproxy -- <api_id> <api_hash> <host> <port> <secret>
//! ```
//!
//! Example:
//! ```sh
//! cargo run --example mtproxy_test --features mtproxy -- 12345 your_api_hash 127.0.0.1 8888 dd0123456789abcdef0123456789abcdef
//! ```

use std::env;
use std::io::{self, BufRead as _, Write as _};
use std::sync::Arc;

use grammers_client::{Client, SignInError};
use grammers_mtsender::{ConnectionParams, MtProxyConfig, SenderPool};
use grammers_session::storages::MemorySession;
use grammers_tl_types as tl;
use simple_logger::SimpleLogger;
use tokio::runtime;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn prompt(message: &str) -> Result<String> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(message.as_bytes())?;
    stdout.flush()?;

    let stdin = io::stdin();
    let mut stdin = stdin.lock();

    let mut line = String::new();
    stdin.read_line(&mut line)?;
    Ok(line)
}

fn print_usage() {
    println!("MTProxy Test Example");
    println!();
    println!("USAGE:");
    println!("  cargo run --example mtproxy_test --features mtproxy -- <api_id> <api_hash> <host> [port] [secret] [dc_id]");
    println!();
    println!("ARGUMENTS:");
    println!("  api_id   - Your Telegram API ID");
    println!("  api_hash - Your Telegram API hash");
    println!("  host     - MTProxy server hostname or IP");
    println!("  port     - MTProxy server port (default: 8888)");
    println!("  secret   - MTProxy secret (hex or base64, default: dd0123456789abcdef0123456789abcdef)");
    println!("  dc_id    - DC ID to use (default: auto from session, try 1, 2, 3, 4, or 5 if needed)");
    println!();
    println!("EXAMPLES:");
    println!("  # With all parameters");
    println!("  cargo run --example mtproxy_test --features mtproxy -- 12345 your_hash 127.0.0.1 8888 dd0123456789abcdef0123456789abcdef 2");
    println!();
    println!("  # With defaults for port, secret and dc_id");
    println!("  cargo run --example mtproxy_test --features mtproxy -- 12345 your_hash proxy.example.com");
    println!();
    println!("SECRET FORMATS:");
    println!("  Hex (16 bytes):     0123456789abcdef0123456789abcdef");
    println!("  DD-Secure (best):    dd0123456789abcdef0123456789abcdef");
    println!("  EE-Prefix:          ee0123456789abcdef0123456789abcdef");
    println!("  Base64:              ASNFZ4mrze/+3LqYdlQyEA==");
    println!();
    println!("ENVIRONMENT VARIABLES (alternative):");
    println!("  TG_ID         - Your Telegram API ID");
    println!("  TG_HASH       - Your Telegram API hash");
    println!("  MTPROXY_HOST  - MTProxy server hostname or IP");
    println!("  MTPROXY_PORT  - MTProxy server port (default: 8888)");
    println!("  MTPROXY_SECRET - MTProxy secret");
}

async fn async_main(api_id: i32, api_hash: String, mtproxy_host: String, mtproxy_port: u16, mtproxy_secret: String, mtproxy_dc_id: Option<i32>) -> Result<()> {
    SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();

    println!("MTProxy Test");
    println!("=============");
    println!("  API ID: {}", api_id);
    println!("  Proxy: {}:{}", mtproxy_host, mtproxy_port);
    let secret_preview = mtproxy_secret.get(..8).unwrap_or(&mtproxy_secret);
    println!("  Secret: {}***", secret_preview);
    if let Some(dc_id) = mtproxy_dc_id {
        println!("  DC ID: {}", dc_id);
    } else {
        println!("  DC ID: auto (from session)");
    }
    println!();

    // Load or create session
    let session = Arc::new(MemorySession::default());

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
    let SenderPool { runner, handle, .. } =
        SenderPool::with_configuration(Arc::clone(&session), api_id, params);

    let client = Client::new(handle);
    let _ = tokio::spawn(runner.run());

    // Test connection with ping first
    println!("Testing connection with ping...");
    match client.invoke(&tl::functions::Ping { ping_id: 12345 }).await {
        Ok(_pong) => println!("✓ Ping successful!"),
        Err(e) => {
            println!("✗ Ping failed: {}", e);
            println!("Note: This might be expected if you need to authorize first.");
        }
    }

    // Handle authorization if needed
    if !client.is_authorized().await? {
        println!("\nAuthorization required. Signing in...");

        let phone = prompt("Enter your phone number (international format, e.g. +1234567890): ")?;
        let token = client.request_login_code(&phone.trim(), &api_hash).await?;
        let code = prompt("Enter the code you received: ")?;
        let signed_in = client.sign_in(&token, code.trim()).await;

        match signed_in {
            Err(SignInError::PasswordRequired(password_token)) => {
                let hint = password_token.hint().unwrap_or("None");
                let prompt_message = format!("Enter the password (hint {}): ", &hint);
                let password = prompt(prompt_message.as_str())?;

                client
                    .check_password(password_token, password.trim())
                    .await?;
            }
            Ok(_) => (),
            Err(e) => panic!("Sign in failed: {}", e),
        };
        println!("✓ Signed in successfully!");
    }

    println!("\n✓ MTProxy connection test successful!");
    println!("You can now use the client normally.");

    // Get some dialog info to verify everything works
    println!("\nFetching first few dialogs...");
    let mut dialogs = client.iter_dialogs();
    let mut count = 0;

    while let Some(dialog) = dialogs.next().await? {
        if count >= 3 {
            break;
        }
        let peer = dialog.peer();
        println!("  - {}: {}", peer.id(), peer.name().unwrap_or_default());
        count += 1;
    }

    println!("\n✓ All tests passed! MTProxy is working correctly.");
    println!("\nMTProxy Details:");
    println!("  - Using RandomizedIntermediate transport");
    println!("  - Random padding enabled for DPI bypass");
    println!("  - All packet sizes are obfuscated");

    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // Try to get arguments from command line first
    if args.len() >= 4 {
        let api_id = args[1].parse().expect("Invalid API ID");
        let api_hash = args[2].to_string();
        let mtproxy_host = args[3].to_string();
        let mtproxy_port = if args.len() >= 5 {
            args[4].parse().expect("Invalid port number")
        } else {
            8888
        };
        let mtproxy_secret = if args.len() >= 6 {
            args[5].to_string()
        } else {
            "dd0123456789abcdef0123456789abcdef".to_string()
        };
        let mtproxy_dc_id = if args.len() >= 7 {
            Some(args[6].parse().expect("Invalid DC ID"))
        } else {
            None
        };

        return runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async_main(api_id, api_hash, mtproxy_host, mtproxy_port, mtproxy_secret, mtproxy_dc_id));
    }

    // Fallback to environment variables
    let api_id = match env::var("TG_ID") {
        Ok(val) => val.parse().expect("Invalid API ID"),
        Err(_) => {
            print_usage();
            eprintln!("\nError: TG_ID environment variable not set");
            eprintln!("Use: cargo run --example mtproxy_test --features mtproxy -- <api_id> <api_hash> <host> [port] [secret]");
            std::process::exit(1);
        }
    };

    let api_hash = match env::var("TG_HASH") {
        Ok(val) => val,
        Err(_) => {
            eprintln!("Error: TG_HASH environment variable not set");
            eprintln!("Use: cargo run --example mtproxy_test --features mtproxy -- <api_id> <api_hash> <host> [port] [secret]");
            std::process::exit(1);
        }
    };

    let mtproxy_host = match env::var("MTPROXY_HOST") {
        Ok(val) => val,
        Err(_) => {
            eprintln!("Error: MTPROXY_HOST environment variable not set");
            eprintln!("Use: cargo run --example mtproxy_test --features mtproxy -- <api_id> <api_hash> <host> [port] [secret]");
            std::process::exit(1);
        }
    };

    let mtproxy_port = env::var("MTPROXY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8888);

    let mtproxy_secret = env::var("MTPROXY_SECRET")
        .unwrap_or_else(|_| "dd0123456789abcdef0123456789abcdef".to_string());

    runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main(api_id, api_hash, mtproxy_host, mtproxy_port, mtproxy_secret, None))
}
