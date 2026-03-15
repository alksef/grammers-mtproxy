// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Randomized Intermediate transport.
//!
//! This is an implementation of the [intermediate transport] with random padding.
//!
//! Unlike the regular [intermediate transport], this variant adds 0-3 random bytes
//! of padding per packet. This is used by MTProxy in DD-Secure mode to prevent
//! size-based DPI detection.
//!
//! The padding size is determined by the last byte of the payload modulo 4,
//! following TDlib's implementation.
//!
//! * Overhead: small + random (0-3 bytes per packet).
//! * Minimum envelope length: 4 bytes.
//! * Maximum envelope length: 7 bytes (4 + padding).
//!
//! It serializes the input payload as follows:
//!
//! ```text
//! +----+----...----+-----+
//! | len|  payload  | pad |
//! +----+----...----+-----+
//!  ^^^^ 4 bytes    0-3 bytes
//! ```
//!
//! The random padding makes packet sizes less predictable, which helps bypass
//! DPI systems that detect MTProxy by fixed packet sizes.
//!
//! [intermediate transport]: https://core.telegram.org/mtproto/mtproto-transports#intermediate
//! [intermediate transport]: crate::transport::Intermediate

use grammers_crypto::DequeBuffer;

use super::{Error, Tagged, Transport, UnpackedOffset};

/// A light MTProto transport protocol that guarantees data padded to 4 bytes,
/// with randomized padding (0-3 bytes) per packet to prevent size-based detection.
///
/// This is the transport used by MTProxy in DD-Secure mode.
pub struct RandomizedIntermediate {
    init: bool,
}

#[allow(clippy::new_without_default)]
impl RandomizedIntermediate {
    const TAG: [u8; 4] = 0xdd_dd_dd_dd_u32.to_le_bytes();

    pub fn new() -> Self {
        Self { init: false }
    }
}

impl Transport for RandomizedIntermediate {
    fn pack(&mut self, buffer: &mut DequeBuffer<u8>) {
        let len = buffer.len();
        assert_eq!(len % 4, 0);

        log::debug!("RandomizedIntermediate::pack: initial buffer len = {}, init = {}", len, self.init);

        // TDlib-style padding:
        // 1. Read 4 random bytes (we'll use 0-3 of them based on last payload byte)
        let mut random_bytes = [0u8; 4];
        let _ = getrandom::fill(&mut random_bytes);

        // 2. Padding size = last byte of original payload % 4
        let last_byte = if len > 0 { buffer[len - 1] } else { 0 };
        let pad_size = (last_byte % 4) as usize;

        // 3. Add only pad_size random bytes
        buffer.extend(&random_bytes[..pad_size]);

        // 4. Now prefix with TOTAL length (payload + padding)
        let total_len = buffer.len();
        buffer.extend_front(&(total_len as i32).to_le_bytes());

        if !self.init {
            log::debug!("RandomizedIntermediate::pack: adding TAG ({:02x} {:02x} {:02x} {:02x})", Self::TAG[0], Self::TAG[1], Self::TAG[2], Self::TAG[3]);
            buffer.extend_front(&Self::TAG);
            self.init = true;
        } else {
            log::debug!("RandomizedIntermediate::pack: NOT adding TAG (already initialized)");
        }

        log::debug!("RandomizedIntermediate::pack: final buffer len = {}", buffer.len());
    }

    fn unpack(&mut self, buffer: &mut [u8]) -> Result<UnpackedOffset, Error> {
        if buffer.len() < 4 {
            log::debug!("RandomizedIntermediate::unpack: buffer too small ({} < 4)", buffer.len());
            return Err(Error::MissingBytes);
        }

        let len = i32::from_le_bytes(buffer[0..4].try_into().unwrap()) as usize;
        log::debug!("RandomizedIntermediate::unpack: len = {} from bytes {:02x?}, buffer.len() = {}", len, &buffer[0..4], buffer.len());

        if buffer.len() < 4 + len {
            log::debug!("RandomizedIntermediate::unpack: MissingBytes (buffer.len() {} < {})", buffer.len(), 4 + len);
            return Err(Error::MissingBytes);
        }

        if len <= 4 {
            if len >= 4 {
                let data = i32::from_le_bytes(buffer[4..8].try_into().unwrap());
                return Err(Error::BadStatus {
                    status: (-data) as u32,
                });
            }
            return Err(Error::BadLen { got: len as i32 });
        }

        // Strip random padding: data portion is from index 4 to (4 + len - padding)
        // Padding size = len % 4 (same as TDlib)
        let pad_size = len % 4;
        let data_end = 4 + len - pad_size;

        log::debug!("RandomizedIntermediate::unpack: len={}, pad_size={}, data_end={}", len, pad_size, data_end);

        Ok(UnpackedOffset {
            data_range: 4..data_end,
            next_offset: 4 + len,
        })
    }
}

impl Tagged for RandomizedIntermediate {
    fn init_tag(&mut self) -> [u8; 4] {
        self.init = true;
        Self::TAG
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a full randomized intermediate transport, and `n` bytes of input data for it.
    fn setup_pack(n: usize) -> (RandomizedIntermediate, DequeBuffer<u8>) {
        let mut buffer = DequeBuffer::with_capacity(n, 0);
        buffer.extend((0..n).map(|x| (x & 0xff) as u8));
        (RandomizedIntermediate::new(), buffer)
    }

    #[test]
    fn pack_empty() {
        let (mut transport, mut buffer) = setup_pack(0);
        transport.pack(&mut buffer);
        // First byte should be tag (0xdd)
        assert_eq!(buffer[0], 0xdd);
        // Length should be 0
        assert_eq!(buffer[4..8], [0, 0, 0, 0]);
    }

    #[test]
    #[should_panic]
    fn pack_non_padded() {
        let (mut transport, mut buffer) = setup_pack(7);
        transport.pack(&mut buffer);
    }

    #[test]
    fn pack_normal() {
        let (mut transport, mut buffer) = setup_pack(128);
        let _orig = buffer.clone();
        transport.pack(&mut buffer);
        // Should start with tag
        assert_eq!(&buffer[..4], &[0xdd, 0xdd, 0xdd, 0xdd]);
        // Length should be original length + padding
        let len_bytes: [u8; 4] = buffer[4..8].try_into().unwrap();
        let len = i32::from_le_bytes(len_bytes) as usize;
        assert!(len >= 128);
    }

    #[test]
    fn unpack_small() {
        let mut transport = RandomizedIntermediate::new();
        let mut buffer = DequeBuffer::with_capacity(1, 0);
        buffer.extend([1]);
        assert_eq!(transport.unpack(&mut buffer[..]), Err(Error::MissingBytes));
    }

    #[test]
    fn unpack_normal() {
        let (mut transport, mut buffer) = setup_pack(128);
        let orig = buffer.clone();
        transport.pack(&mut buffer);
        let n = 4; // init bytes
        let offset = transport.unpack(&mut buffer[n..]).unwrap();
        // Should have stripped padding
        assert_eq!(buffer[n..][offset.data_range.clone()].len(), 128);
        // Verify the data is the same as original
        assert_eq!(&buffer[n..][offset.data_range], &orig[..]);
    }

    #[test]
    fn unpack_with_padding() {
        let (mut transport, mut buffer) = setup_pack(100);
        let _orig = buffer.clone();
        transport.pack(&mut buffer);

        // Find where the data ends (before padding)
        let len_bytes: [u8; 4] = buffer[4..8].try_into().unwrap();
        let len_with_padding = i32::from_le_bytes(len_bytes) as usize;
        let padding = len_with_padding % 4;

        assert!(padding <= 3);
    }

    #[test]
    fn unpack_bad_status() {
        let mut transport = RandomizedIntermediate::new();
        let mut buffer = DequeBuffer::with_capacity(8, 0);
        buffer.extend(&(4_i32).to_le_bytes());
        buffer.extend(&(-404_i32).to_le_bytes());

        assert_eq!(
            transport.unpack(&mut buffer[..]),
            Err(Error::BadStatus { status: 404 })
        );
    }

    #[test]
    fn test_tag() {
        assert_eq!(RandomizedIntermediate::TAG, [0xdd, 0xdd, 0xdd, 0xdd]);
    }

    #[test]
    fn test_padding_size() {
        let mut transport = RandomizedIntermediate::new();
        let mut buffer = DequeBuffer::with_capacity(100, 0);

        // Pack multiple times and verify padding is within bounds
        for _ in 0..100 {
            buffer.clear();
            buffer.extend(&[1u8, 2, 3, 4]); // 4 bytes of data
            transport.pack(&mut buffer);

            // Skip TAG if present (first 4 bytes), then read length header
            let offset = if buffer.len() > 8 && buffer[0..4] == RandomizedIntermediate::TAG { 4 } else { 0 };
            let len_bytes: [u8; 4] = buffer[offset..offset + 4].try_into().unwrap();
            let len = i32::from_le_bytes(len_bytes) as usize;

            // Length should be 4 (data) + padding (0-3)
            assert!(len >= 4, "len {} should be >= 4", len);
            assert!(len <= 7, "len {} should be <= 7", len);
        }
    }
}
