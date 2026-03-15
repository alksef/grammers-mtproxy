// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod mtproxy;
mod tcp;

pub use tcp::NetStream;

/// Represents a socket address which may be proxied.
#[derive(Debug, Clone)]
pub enum ServerAddr {
    /// Socket address whose connection should be proxied via SOCKS5.
    #[cfg(feature = "proxy")]
    Proxied {
        address: std::net::SocketAddr,
        proxy: String,
    },
    /// Proxy address for MTProxy connection.
    #[cfg(feature = "mtproxy")]
    MtProxy {
        /// MTProxy server hostname or IP address
        proxy_host: String,
        /// MTProxy server port
        proxy_port: u16,
        secret: String,
        dc_id: i32,
    },
    /// Direct TCP connection to Telegram server.
    Tcp { address: std::net::SocketAddr },
}

impl ServerAddr {
    /// Get the DC ID if this is an MTProxy address.
    #[cfg(feature = "mtproxy")]
    pub fn dc_id(&self) -> Option<i32> {
        match self {
            Self::MtProxy { dc_id, .. } => Some(*dc_id),
            _ => None,
        }
    }

    /// Get the MTProxy secret if this is an MTProxy address.
    #[cfg(feature = "mtproxy")]
    pub fn secret(&self) -> Option<&str> {
        match self {
            Self::MtProxy { secret, .. } => Some(secret),
            _ => None,
        }
    }
}
