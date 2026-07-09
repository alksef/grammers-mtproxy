// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TLS-record framing layer (always on — never switches to raw mode).
//!
//! Wraps all outgoing data in TLS ApplicationData records and
//! strips TLS record headers on incoming data.
//!
//! This is the key difference from the previous failed implementation:
//! framing lives for the entire connection lifetime.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::record::{
    TlsRecordHeader, TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER,
    MAX_TLS_CIPHERTEXT_SIZE, MAX_TLS_PLAINTEXT_SIZE,
};

const HEADER_SIZE: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    Header { offset: usize },
    Payload { length: usize, offset: usize },
    Buffered { pos: usize, len: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteState {
    Idle,
    Writing(usize),
}

pub struct FakeTlsFraming<S> {
    inner: S,
    read_state: ReadState,
    read_buf: Box<[u8]>,
    write_state: WriteState,
}

impl<S: AsyncRead + AsyncWrite + Unpin> FakeTlsFraming<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_state: ReadState::Header { offset: 0 },
            read_buf: vec![0u8; MAX_TLS_CIPHERTEXT_SIZE as usize].into_boxed_slice(),
            write_state: WriteState::Idle,
        }
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for FakeTlsFraming<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            match this.read_state {
                ReadState::Header { offset } => {
                    let mut hdr = [0u8; HEADER_SIZE];
                    if offset < HEADER_SIZE {
                        let mut small = ReadBuf::new(&mut hdr[offset..]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut small) {
                            Poll::Ready(Ok(())) => {
                                let filled = offset + small.filled().len();
                                if filled < HEADER_SIZE {
                                    this.read_state = ReadState::Header { offset: filled };
                                    return Poll::Pending;
                                }
                                let header = TlsRecordHeader::from_bytes(&hdr)
                                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                                let record_type = header.record_type;
                                let length = header.length as usize;

                                if record_type == TLS_RECORD_CHANGE_CIPHER {
                                    if length == 0 {
                                        this.read_state = ReadState::Header { offset: 0 };
                                        continue;
                                    }
                                    // Read and discard CCS payload
                                    let mut discard = vec![0u8; length];
                                    let mut discard_buf = ReadBuf::new(&mut discard);
                                    match Pin::new(&mut this.inner).poll_read(cx, &mut discard_buf) {
                                        Poll::Ready(Ok(())) => {
                                            if discard_buf.filled().len() < length {
                                                this.read_state = ReadState::Payload { length, offset: discard_buf.filled().len() };
                                                return Poll::Pending;
                                            }
                                            this.read_state = ReadState::Header { offset: 0 };
                                            continue;
                                        }
                                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                        Poll::Pending => {
                                            this.read_state = ReadState::Payload { length, offset: 0 };
                                            return Poll::Pending;
                                        }
                                    }
                                }
                                if record_type != TLS_RECORD_APPLICATION {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!("unexpected TLS record type: 0x{:02x}", record_type),
                                    )));
                                }
                                if length == 0 {
                                    this.read_state = ReadState::Header { offset: 0 };
                                    continue;
                                }
                                this.read_state = ReadState::Payload { length, offset: 0 };
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => {
                                this.read_state = ReadState::Header { offset };
                                return Poll::Pending;
                            }
                        }
                    }
                }
                ReadState::Payload { length, offset } => {
                    let to_read = (length - offset).min(this.read_buf.len() - offset);
                    let mut payload_buf = ReadBuf::new(&mut this.read_buf[offset..offset + to_read]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut payload_buf) {
                        Poll::Ready(Ok(())) => {
                            let new_offset = offset + payload_buf.filled().len();
                            if new_offset < length {
                                this.read_state = ReadState::Payload { length, offset: new_offset };
                                return Poll::Pending;
                            }
                            let to_copy = length.min(buf.remaining());
                            buf.put_slice(&this.read_buf[..to_copy]);
                            if to_copy < length {
                                this.read_buf.copy_within(to_copy..length, 0);
                                this.read_state = ReadState::Buffered {
                                    pos: 0,
                                    len: length - to_copy,
                                };
                            } else {
                                this.read_state = ReadState::Header { offset: 0 };
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(e)) => {
                            this.read_state = ReadState::Header { offset: 0 };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Pending => {
                            this.read_state = ReadState::Payload { length, offset };
                            return Poll::Pending;
                        }
                    }
                }
                ReadState::Buffered { pos, len } => {
                    let remaining = len - pos;
                    let to_copy = remaining.min(buf.remaining());
                    buf.put_slice(&this.read_buf[pos..pos + to_copy]);
                    if pos + to_copy >= len {
                        this.read_state = ReadState::Header { offset: 0 };
                    } else {
                        this.read_state = ReadState::Buffered {
                            pos: pos + to_copy,
                            len,
                        };
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for FakeTlsFraming<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // If we're in the middle of writing a record, try to finish it
        if self.write_state != WriteState::Idle {
            return Pin::new(&mut self.inner).poll_flush(cx).map(|r| {
                r.map(|()| {
                    self.write_state = WriteState::Idle;
                    0
                })
            });
        }

        // Determine chunk size — one TLS record at a time
        let chunk = buf.len().min(MAX_TLS_PLAINTEXT_SIZE as usize);
        let header = TlsRecordHeader::new(TLS_RECORD_APPLICATION, chunk as u16);
        let header_bytes = header.to_bytes();

        // Write header + chunk into a single buffer
        let mut frame = Vec::with_capacity(HEADER_SIZE + chunk);
        frame.extend_from_slice(&header_bytes);
        frame.extend_from_slice(&buf[..chunk]);

        self.write_state = WriteState::Writing(chunk);

        match Pin::new(&mut self.inner).poll_write(cx, &frame) {
            Poll::Ready(Ok(_n)) => {
                let chunk_len = chunk;
                self.write_state = WriteState::Idle;
                Poll::Ready(Ok(chunk_len))
            }
            Poll::Ready(Err(e)) => {
                self.write_state = WriteState::Idle;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn test_framing_roundtrip() {
        let (local, remote) = duplex(8192);
        let mut local = FakeTlsFraming::new(local);
        let mut remote = FakeTlsFraming::new(remote);

        let send_data = Arc::new(b"hello world from faketls framing test".to_vec());
        let send_clone = send_data.clone();

        let write_task = tokio::spawn(async move {
            let (_, mut w) = tokio::io::split(&mut local);
            w.write_all(&send_clone).await.unwrap();
        });

        let mut buf = vec![0u8; 256];
        let (mut r, _) = tokio::io::split(&mut remote);
        let n = r.read(&mut buf).await.unwrap();

        write_task.await.unwrap();
        assert_eq!(&buf[..n], send_data.as_slice());
    }

    #[tokio::test]
    async fn test_framing_multiple_records() {
        let (local, remote) = duplex(65536);
        let mut local = FakeTlsFraming::new(local);
        let mut remote = FakeTlsFraming::new(remote);

        let send_data = Arc::new(vec![0xABu8; MAX_TLS_PLAINTEXT_SIZE as usize + 100]);
        let send_clone = send_data.clone();

        let write_task = tokio::spawn(async move {
            let (_, mut w) = tokio::io::split(&mut local);
            w.write_all(&send_clone).await.unwrap();
        });

        let (mut r, _) = tokio::io::split(&mut remote);
        let mut total = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = r.read(&mut buf).await.unwrap();
            total.extend_from_slice(&buf[..n]);
            if total.len() == send_data.len() {
                break;
            }
        }

        write_task.await.unwrap();
        assert_eq!(total, send_data.as_slice());
    }
}
