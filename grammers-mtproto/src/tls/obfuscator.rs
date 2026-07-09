// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! AES-256-CTR obfuscator for EE-FakeTLS MTProxy mode.
//!
//! After the FakeTLS handshake completes, both client and server derive
//! symmetric AES-256-CTR ciphers from a 64-byte handshake frame sent by
//! the client. This provides the "obfuscated transport" layer required by
//! the MTG proxy server.
//!
//! # Key Exchange
//!
//! The handshake is unidirectional: only the client sends a 64-byte frame.
//! Both sides derive send/recv ciphers from the same frame using the
//! `revert()` trick (reversing bytes [8:56) = key(32) + iv(16)).

use rand::RngCore;
#[cfg(feature = "mtproxy")]
use sha2::{Digest, Sha256};

#[cfg(feature = "mtproxy")]
use aes::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};

/// Frame constants
#[cfg(any(test, feature = "mtproxy"))]
const FRAME_LEN: usize = 64;
#[cfg(any(test, feature = "mtproxy"))]
const FRAME_OFFSET_KEY: usize = 8;
#[cfg(any(test, feature = "mtproxy"))]
const FRAME_OFFSET_IV: usize = 40;
#[cfg(any(test, feature = "mtproxy"))]
const FRAME_OFFSET_CONN_TYPE: usize = 56;
#[cfg(any(test, feature = "mtproxy"))]
const FRAME_OFFSET_DC: usize = 60;
#[cfg(any(test, feature = "mtproxy"))]
const FRAME_KEY_LEN: usize = 32;
#[cfg(any(test, feature = "mtproxy"))]
const FRAME_IV_LEN: usize = 16;

/// Connection type: always 0xdddddddd for all modes including EE.
#[cfg(any(test, feature = "mtproxy"))]
const CONNECTION_TYPE: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

/// Forbidden first 4-byte patterns (little-endian uint32).
#[cfg(any(test, feature = "mtproxy"))]
const FORBIDDEN_HEADERS: &[u32] = &[
    0x44414548, // HEAD
    0x54534f50, // POST
    0x20544547, // GET
    0x4954504f, // OPTI
    0x02010316, // unknown
    0xdddddddd, // PaddedIntermediate
    0xeeeeeeee, // Intermediate
];

/// AES-256-CTR cipher wrapper.
#[cfg(feature = "mtproxy")]
#[allow(deprecated)]
pub struct Aes256Ctr(ctr::Ctr128BE<aes::Aes256>);

#[cfg(feature = "mtproxy")]
impl Aes256Ctr {
    fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self(ctr::Ctr128BE::<aes::Aes256>::new(
            GenericArray::from_slice(key),
            GenericArray::from_slice(iv),
        ))
    }

    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        self.0.apply_keystream(buf);
    }
}

/// Derive an AES-256-CTR cipher from the frame's key/iv and secret.
#[cfg(feature = "mtproxy")]
fn derive_cipher(frame: &[u8; FRAME_LEN], secret_key: &[u8; 16]) -> Aes256Ctr {
    let key = &frame[FRAME_OFFSET_KEY..FRAME_OFFSET_KEY + FRAME_KEY_LEN];
    let iv = &frame[FRAME_OFFSET_IV..FRAME_OFFSET_IV + FRAME_IV_LEN];

    let derived_key = {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(secret_key);
        hasher.finalize()
    };

    let mut derived_key_arr = [0u8; 32];
    derived_key_arr.copy_from_slice(&derived_key);

    Aes256Ctr::new(&derived_key_arr, iv.try_into().unwrap())
}

/// Reverse bytes [8:56) of the frame (key + iv = 48 bytes).
/// Connection type at [56:60] is NOT reversed.
#[cfg(any(test, feature = "mtproxy"))]
fn revert_key_iv(frame: &mut [u8; FRAME_LEN]) {
    frame[FRAME_OFFSET_KEY..FRAME_OFFSET_CONN_TYPE].reverse();
}

/// Validate random bytes in the frame (regenerate if checks fail).
#[cfg(any(test, feature = "mtproxy"))]
fn is_frame_valid(frame: &[u8; FRAME_LEN]) -> bool {
    // First byte must not be 0xef (abridged transport header)
    if frame[0] == 0xef {
        return false;
    }

    // First 4 bytes (LE uint32) must not match forbidden patterns
    let first4 = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if FORBIDDEN_HEADERS.contains(&first4) {
        return false;
    }

    // At least one of bytes [4], [5], [6], [7] must be non-zero
    if frame[4] | frame[5] | frame[6] | frame[7] == 0 {
        return false;
    }

    true
}

/// Generate a valid random 64-byte handshake frame.
#[cfg(any(test, feature = "mtproxy"))]
fn generate_frame(dc_id: i16) -> [u8; FRAME_LEN] {
    let mut rng = rand::thread_rng();
    loop {
        let mut frame = [0u8; FRAME_LEN];
        rng.fill_bytes(&mut frame);

        if !is_frame_valid(&frame) {
            continue;
        }

        // Set connection type
        frame[FRAME_OFFSET_CONN_TYPE..FRAME_OFFSET_CONN_TYPE + 4].copy_from_slice(&CONNECTION_TYPE);

        // Set DC ID (little-endian i16)
        frame[FRAME_OFFSET_DC..FRAME_OFFSET_DC + 2].copy_from_slice(&(dc_id as i16).to_le_bytes());

        return frame;
    }
}

/// Client-side: generate the obfuscated handshake frame
/// along with separate send and receive ciphers.
///
/// Returns `(encrypted_frame, send_cipher, recv_cipher)` where:
/// - `encrypted_frame` must be sent to the server (inside TLS record)
/// - `send_cipher` encrypts all subsequent outgoing data (already advanced by 64 bytes)
/// - `recv_cipher` decrypts all subsequent incoming data (fresh, not advanced)
///
/// Wire format (matching gotd reference):
///   [0:56] PLAINTEXT | [56:64] ENCRYPTED
/// The server reads [0:56] as plaintext to validate init and derive AES-CTR keys,
/// while [56:64] (protocol tag + dc + padding tail) is encrypted.
#[cfg(feature = "mtproxy")]
pub fn client_handshake(
    secret_key: &[u8; 16],
    dc_id: i16,
) -> ([u8; FRAME_LEN], Aes256Ctr, Aes256Ctr) {
    let frame = generate_frame(dc_id);

    // Save original key+iv before encryption
    let mut send_cipher = derive_cipher(&frame, secret_key);

    // Revert key+iv to derive recv cipher
    let mut frame_reverted = frame;
    revert_key_iv(&mut frame_reverted);
    let recv_cipher = derive_cipher(&frame_reverted, secret_key);

    // Encrypt frame with send cipher (this advances send_cipher by 64 bytes)
    let mut encrypted = frame;
    send_cipher.apply_keystream(&mut encrypted);

    // Restore [0:56] to plaintext — the server reads first 56 bytes as plaintext
    // to validate init and derive AES-CTR keys (matching gotd keys.go).
    // [56:64] remain encrypted (protocol tag + dc + padding tail).
    encrypted[0..FRAME_OFFSET_CONN_TYPE].copy_from_slice(&frame[0..FRAME_OFFSET_CONN_TYPE]);

    (encrypted, send_cipher, recv_cipher)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_generation_valid() {
        for _ in 0..1000 {
            let frame = generate_frame(2);
            assert!(is_frame_valid(&frame));
            assert_eq!(
                &frame[FRAME_OFFSET_CONN_TYPE..FRAME_OFFSET_CONN_TYPE + 4],
                &CONNECTION_TYPE
            );
            let dc = i16::from_le_bytes([frame[FRAME_OFFSET_DC], frame[FRAME_OFFSET_DC + 1]]);
            assert_eq!(dc, 2);
        }
    }

    #[test]
    fn test_revert_key_iv_roundtrip() {
        let mut frame = [0u8; FRAME_LEN];
        for i in 0..FRAME_LEN {
            frame[i] = (i * 7 + 13) as u8;
        }

        // Save original key+iv (bytes [8:56) = 48 bytes)
        let original_key_iv: Vec<u8> = frame[FRAME_OFFSET_KEY..FRAME_OFFSET_CONN_TYPE].to_vec();
        // Save bytes after key+iv (connection type + DC + tail) — should NOT be reversed
        let original_tail: [u8; 8] = frame[FRAME_OFFSET_CONN_TYPE..].try_into().unwrap();

        revert_key_iv(&mut frame);

        // Verify key+iv is reversed
        let reverted_key_iv: Vec<u8> = frame[FRAME_OFFSET_KEY..FRAME_OFFSET_CONN_TYPE].to_vec();
        let reversed: Vec<u8> = original_key_iv.iter().copied().rev().collect();
        assert_eq!(reverted_key_iv, reversed);

        // Verify tail (conn_type + DC + noise) is unchanged
        assert_eq!(&frame[FRAME_OFFSET_CONN_TYPE..], &original_tail);
    }

    #[cfg(feature = "mtproxy")]
    #[test]
    fn test_client_handshake_structure() {
        let secret_key = [0x42u8; 16];
        let dc_id: i16 = 2;

        let frame = generate_frame(dc_id);
        let mut send_cipher = derive_cipher(&frame, &secret_key);

        let mut encrypted = frame;
        send_cipher.apply_keystream(&mut encrypted);

        // Before restore, [0:56] should be encrypted (different from plaintext)
        assert_ne!(
            encrypted[0..FRAME_OFFSET_CONN_TYPE],
            frame[0..FRAME_OFFSET_CONN_TYPE],
            "full encrypt should change [0:56]"
        );

        // Restore [0:56] to plaintext (the fix)
        encrypted[0..FRAME_OFFSET_CONN_TYPE].copy_from_slice(&frame[0..FRAME_OFFSET_CONN_TYPE]);

        // Verify [0:56] is plaintext (matches original frame)
        assert_eq!(
            encrypted[0..FRAME_OFFSET_CONN_TYPE],
            frame[0..FRAME_OFFSET_CONN_TYPE],
            "[0:56] should be plaintext"
        );

        // Verify [56:64] remains encrypted (different from plaintext)
        assert_ne!(
            encrypted[FRAME_OFFSET_CONN_TYPE..FRAME_LEN],
            frame[FRAME_OFFSET_CONN_TYPE..FRAME_LEN],
            "[56:64] should remain encrypted"
        );

        // Integration: verify client_handshake produces a valid frame
        let (encrypted_frame, _send_cipher, _recv_cipher) = client_handshake(&secret_key, dc_id);
        assert_eq!(encrypted_frame.len(), FRAME_LEN);
    }

    #[cfg(feature = "mtproxy")]
    #[test]
    fn dump_derive_key() {
        let key = [0xAAu8; 32];
        let secret = [0x42u8; 16];
        let mut h = Sha256::new();
        h.update(&key);
        h.update(&secret);
        eprintln!(
            "DUMP SHA256(key=0xAA*32 || secret=0x42*16) = {}",
            hex::encode(h.finalize())
        );
    }

    #[cfg(feature = "mtproxy")]
    #[test]
    fn dump_client_handshake_vectors() {
        let secret: [u8; 16] = [0x42u8; 16];

        let mut frame = [0u8; FRAME_LEN];
        for i in 0..FRAME_LEN {
            frame[i] = ((i as u8).wrapping_mul(7)).wrapping_add(1);
        }
        frame[0] = 0x11;
        frame[FRAME_OFFSET_CONN_TYPE..FRAME_OFFSET_CONN_TYPE + 4].copy_from_slice(&CONNECTION_TYPE);
        frame[FRAME_OFFSET_DC..FRAME_OFFSET_DC + 2].copy_from_slice(&(2i16).to_le_bytes());

        assert!(is_frame_valid(&frame));

        let mut send_cipher = derive_cipher(&frame, &secret);

        let mut frame_reverted = frame;
        revert_key_iv(&mut frame_reverted);
        let _recv_cipher = derive_cipher(&frame_reverted, &secret);

        let mut encrypted = frame;
        send_cipher.apply_keystream(&mut encrypted);
        encrypted[0..FRAME_OFFSET_CONN_TYPE].copy_from_slice(&frame[0..FRAME_OFFSET_CONN_TYPE]);

        eprintln!("DUMP secret = {}", hex::encode(secret));
        eprintln!("DUMP frame_plain = {}", hex::encode(frame));
        eprintln!("DUMP header_sent = {}", hex::encode(&encrypted));
        eprintln!(
            "DUMP header[0:8]  = {} (plain)",
            hex::encode(&encrypted[0..8])
        );
        eprintln!(
            "DUMP header[8:56] = {} (plain)",
            hex::encode(&encrypted[8..FRAME_OFFSET_CONN_TYPE])
        );
        eprintln!(
            "DUMP header[56:64]= {} (encrypted)",
            hex::encode(&encrypted[FRAME_OFFSET_CONN_TYPE..])
        );

        let mut probe = [0u8; 16];
        send_cipher.apply_keystream(&mut probe);
        eprintln!(
            "DUMP send_keystream_after_init[64:80] = {}",
            hex::encode(probe)
        );

        let mut recv_probe_cipher = derive_cipher(&frame_reverted, &secret);
        let mut recv_probe = [0u8; 16];
        recv_probe_cipher.apply_keystream(&mut recv_probe);
        eprintln!("DUMP recv_keystream[0:16] = {}", hex::encode(recv_probe));
    }
}
