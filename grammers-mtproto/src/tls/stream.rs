// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! FakeTLS stream — gotd/td layered model.
//!
//! ```text
//! FakeTlsStream<S>:
//!   framing: FakeTlsFraming<S>   // TLS-record framing (always on)
//!   obfs2_send: Aes256Ctr        // AES-CTR encrypts outgoing
//!   obfs2_recv: Aes256Ctr        // AES-CTR decrypts incoming
//! ```

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::client_hello::build_client_hello;
use super::framing::FakeTlsFraming;
use super::obfuscator::Aes256Ctr;
use super::obfuscator::client_handshake;
use super::record::{TLS_DIGEST_LEN, TLS_DIGEST_POS, TLS_RECORD_CHANGE_CIPHER, MAX_TLS_PLAINTEXT_SIZE};
use super::server_hello::validate_server_hello;

pub struct FakeTlsStream<S> {
    framing: FakeTlsFraming<S>,
    obfs2_send: Aes256Ctr,
    obfs2_recv: Aes256Ctr,
    first_prefix: Option<Vec<u8>>,
    ccs_sent: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> FakeTlsStream<S> {
    pub async fn new(
        stream: S,
        secret: &[u8; 16],
        dc_id: i16,
        hostname: &str,
    ) -> io::Result<Self> {
        let mut stream = stream;

        // Step 1: Build and send ClientHello
        let client_hello = build_client_hello(secret, hostname);
        let client_random: [u8; TLS_DIGEST_LEN] = client_hello
            [TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN]
            .try_into()
            .unwrap();

        // build_client_hello returns the full TLS-record including outer header:
        // [0x16, 0x03, 0x01, ...]. Write it as-is.
        stream.write_all(&client_hello).await?;

        // Step 2: Read server response — ServerHello + CCS + Application-noise
        let mut response = Vec::with_capacity(8192);
        loop {
            let header = {
                let mut hdr = [0u8; 5];
                stream.read_exact(&mut hdr).await?;
                hdr
            };

            let record_type = header[0];
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;

            response.extend_from_slice(&header);
            let payload_start = response.len();
            response.resize(payload_start + length, 0);
            stream.read_exact(&mut response[payload_start..payload_start + length]).await?;

            // Check if server handshake is complete (got all 3 records)
            // ServerHello (0x16) + ChangeCipherSpec (0x14) + Application (0x17)
            // We check as we read records
            match record_type {
                0x16 => { /* ServerHello - continue reading */ }
                0x14 => { /* ChangeCipherSpec - continue reading */ }
                0x17 => {
                    // Got all three records, validate
                    break;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected response record type: 0x{:02x}", record_type),
                    ));
                }
            }
        }

        // Validate ServerHello HMAC
        validate_server_hello(&response, &client_random, secret)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Step 3: Generate obfuscated2 init frame
        let (frame, send_cipher, recv_cipher) = client_handshake(secret, dc_id);

        // Step 4: Create framing layer (tdesktop model: CCS + prefix are sent on first write)
        let framing = FakeTlsFraming::new(stream);

        Ok(Self {
            framing,
            obfs2_send: send_cipher,
            obfs2_recv: recv_cipher,
            first_prefix: Some(frame.to_vec()),
            ccs_sent: false,
        })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for FakeTlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.framing).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let after = buf.filled().len();
                if after > before {
                    let filled = buf.filled_mut();
                    let new_data = &mut filled[before..after];
                    self.obfs2_recv.apply_keystream(new_data);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for FakeTlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(prefix) = self.first_prefix.clone() {
            if !self.ccs_sent {
                let ccs = [TLS_RECORD_CHANGE_CIPHER, 0x03, 0x03, 0x00, 0x01, 0x01];
                match Pin::new(self.framing.inner_mut()).poll_write(cx, &ccs) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(_)) => {
                        self.ccs_sent = true;
                    }
                }
            }

            let prefix_len = prefix.len();
            let max_chunk = MAX_TLS_PLAINTEXT_SIZE as usize - prefix_len;
            let chunk = buf.len().min(max_chunk);
            let mut encrypted_chunk = buf[..chunk].to_vec();
            self.obfs2_send.apply_keystream(&mut encrypted_chunk);
            let mut payload = prefix;
            payload.extend_from_slice(&encrypted_chunk);

            match Pin::new(&mut self.framing).poll_write(cx, &payload) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => {
                    self.first_prefix = None;
                    return Poll::Ready(Ok(n.saturating_sub(prefix_len).min(chunk)));
                }
            }
        }

        let mut encrypted = buf.to_vec();
        self.obfs2_send.apply_keystream(&mut encrypted);
        Pin::new(&mut self.framing).poll_write(cx, &encrypted)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.framing).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.framing).poll_shutdown(cx)
    }
}
