// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! SOCKS5 proxy connection test example.
//!
//! This example demonstrates how to connect to Telegram through a SOCKS5 proxy server.
//!
//! Run with:
//! ```sh
//! cargo run --example proxy_test --features proxy -- <api_id> <api_hash> <proxy_url>
//! ```
//!
//! Example:
//! ```sh
//! cargo run --example proxy_test --features proxy -- 12345 your_api_hash socks5://user:pass@127.0.0.1:1080
//! ```

use std::env;
use std::io::{self, BufRead as _, Write as _};
use std::sync::Arc;

use grammers_client::{Client, SignInError};
use grammers_mtsender::{ConnectionParams, SenderPool};
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
    println!("SOCKS5 Proxy Test Example");
    println!();
    println!("USAGE:");
    println!("  cargo run --example proxy_test --features proxy -- <api_id> <api_hash> <proxy_url>");
    println!();
    println!("ARGUMENTS:");
    println!("  api_id     - Your Telegram API ID");
    println!("  api_hash   - Your Telegram API hash");
    println!("  proxy_url  - SOCKS5 proxy URL (e.g., socks5://user:pass@127.0.0.1:1080)");
    println!();
    println!("EXAMPLES:");
    println!("  # Direct connection (no proxy)");
    println!("  cargo run --example proxy_test --features proxy -- 12345 your_hash socks5://127.0.0.1:1080");
    println!();
    println!("  # With authentication");
    println!("  cargo run --example proxy_test --features proxy -- 12345 your_hash socks5://user:pass@127.0.0.1:1080");
    println!();
    println!("ENVIRONMENT VARIABLES (alternative):");
    println!("  TG_ID        - Your Telegram API ID");
    println!("  TG_HASH      - Your Telegram API hash");
    println!("  SOCKS5_PROXY  - SOCKS5 proxy URL");
}

async fn async_main(api_id: i32, api_hash: String, socks5_proxy: String) -> Result<()> {
    SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();

    println!("SOCKS5 Proxy Test");
    println!("==================");
    println!("  API ID: {}", api_id);
    println!("  Proxy: {}", socks5_proxy);
    println!();

    // Load or create session
    let session = Arc::new(MemorySession::default());

    // Configure connection with SOCKS5 proxy
    let params = ConnectionParams {
        #[cfg(feature = "proxy")]
        proxy_url: Some(socks5_proxy),
        ..Default::default()
    };

    println!("Connecting to Telegram via SOCKS5 proxy...");

    // Create sender pool with proxy configuration
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

    println!("\n✓ SOCKS5 proxy connection test successful!");
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

    println!("\n✓ All tests passed! SOCKS5 proxy is working correctly.");

    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // Try to get arguments from command line first
    if args.len() >= 4 {
        let api_id = args[1].parse().expect("Invalid API ID");
        let api_hash = args[2].to_string();
        let socks5_proxy = args[3].to_string();

        return runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async_main(api_id, api_hash, socks5_proxy));
    }

    // Fallback to environment variables
    let api_id = match env::var("TG_ID") {
        Ok(val) => val.parse().expect("Invalid API ID"),
        Err(_) => {
            print_usage();
            eprintln!("\nError: TG_ID environment variable not set");
            eprintln!("Use: cargo run --example proxy_test --features proxy -- <api_id> <api_hash> <proxy_url>");
            std::process::exit(1);
        }
    };

    let api_hash = match env::var("TG_HASH") {
        Ok(val) => val,
        Err(_) => {
            eprintln!("Error: TG_HASH environment variable not set");
            eprintln!("Use: cargo run --example proxy_test --features proxy -- <api_id> <api_hash> <proxy_url>");
            std::process::exit(1);
        }
    };

    let socks5_proxy = match env::var("SOCKS5_PROXY") {
        Ok(val) => val,
        Err(_) => {
            eprintln!("Error: SOCKS5_PROXY environment variable not set");
            eprintln!("Use: cargo run --example proxy_test --features proxy -- <api_id> <api_hash> <proxy_url>");
            std::process::exit(1);
        }
    };

    runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main(api_id, api_hash, socks5_proxy))
}
