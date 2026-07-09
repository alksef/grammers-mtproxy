// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! FakeTLS stream implementation for MTProxy EE-FakeTLS mode.
//!
//! Implements the gotd/td layered model:
//! ```text
//! FakeTlsStream<S>:
//!   framing: FakeTlsFraming<S>   // TLS-record framing (always on)
//!   obfs2_send: Aes256Ctr        // AES-CTR encrypts outgoing
//!   obfs2_recv: Aes256Ctr        // AES-CTR decrypts incoming
//! ```

pub mod client_hello;
pub mod obfuscator;
pub mod record;
pub mod server_hello;
pub mod framing;

#[cfg(feature = "mtproxy")]
pub mod stream;

#[cfg(feature = "mtproxy")]
pub use stream::FakeTlsStream;
