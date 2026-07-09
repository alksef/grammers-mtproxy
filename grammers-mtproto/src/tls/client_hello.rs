// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! FakeTLS ClientHello generation with embedded authentication.

use hmac::{Hmac, Mac};
use rand::{RngCore, thread_rng};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

const CLIENT_HELLO_LENGTH: usize = 517;

/// Generate a TLS ClientHello with embedded authentication.
///
/// Structure matches tdesktop FakeTLS implementation for MTG compatibility.
pub fn build_client_hello(secret: &[u8; 16], hostname: &str) -> Vec<u8> {
    let mut session_id = [0u8; 32];
    thread_rng().fill_bytes(&mut session_id);

    let public_key = gen_x25519_key();

    let mut hello = Vec::with_capacity(576);

    // TLS Record Header + Handshake Header + Client Version (11 bytes)
    hello.extend_from_slice(&[
        0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
    ]);

    // Random (32 bytes) — offset 11, will be replaced with HMAC digest
    let random_offset = hello.len();
    hello.extend_from_slice(&[0u8; 32]);

    // Session ID
    hello.push(0x20); // length = 32
    hello.extend_from_slice(&session_id);

    // Cipher Suites (32 bytes) - Exactly match tdesktop rules
    hello.extend_from_slice(&[0x00, 0x20]); // length = 32
    hello.extend_from_slice(&[
        0x1a, 0x1a, // GREASE
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc,
        0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35,
    ]);

    // Compression methods: length=1, method=null
    hello.extend_from_slice(&[0x01, 0x00]);

    // === Extensions ===
    // Extensions total length placeholder
    let ext_total_start = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]);

    // GREASE Extension (type 0x????)
    hello.extend_from_slice(&[0x1a, 0x1a, 0x00, 0x00]);

    // SNI Extension (type 0x0000)
    hello.extend_from_slice(&[0x00, 0x00]); // extension type = SNI
    let sni_ext_start = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]); // SNI data length placeholder
    // Server Name list
    let sni_list_start = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]); // list length placeholder
    hello.push(0x00); // name type = DNS
    let hostname_bytes = hostname.as_bytes();
    hello.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
    hello.extend_from_slice(hostname_bytes);
    // Fix SNI list length (must not include the 2 bytes of the length field itself)
    let sni_list_len = (hello.len() - sni_list_start - 2) as u16;
    hello[sni_list_start..sni_list_start + 2].copy_from_slice(&sni_list_len.to_be_bytes());
    // Fix SNI data length (must not include the 2 bytes of the length field itself)
    let sni_data_len = (hello.len() - sni_ext_start - 2) as u16;
    hello[sni_ext_start..sni_ext_start + 2].copy_from_slice(&sni_data_len.to_be_bytes());

    // Extended Master Secret (type 0x0017)
    hello.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    // Renegotiation Info (type 0xff01)
    hello.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

    // Session Ticket (type 0x0023)
    hello.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);

    // ALPN (type 0x0010) - h2, http/1.1
    // tdesktop: 00 10 00 0e 00 0c 02 68 32 08 68 74 74 70 2f 31 2e 31
    hello.extend_from_slice(&[
        0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f,
        0x31, 0x2e, 0x31,
    ]);

    // Status Request (type 0x0005)
    // tdesktop: 00 05 00 05 01 00 00 00 00
    hello.extend_from_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);

    // Supported Groups (type 0x000a)
    // tdesktop: 00 0a 00 0c 00 0a {grease} 11 ec 00 1d 00 17 00 18
    hello.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x1a, 0x1a, 0x11, 0xec, 0x00, 0x1d, 0x00, 0x17, 0x00,
        0x18,
    ]);

    // Signature Algorithms (type 0x000d)
    hello.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08,
        0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01,
    ]);

    // Key Share (type 0x0033) - X25519
    hello.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    hello.extend_from_slice(&public_key);

    // PSK Key Exchange Modes (type 0x002d)
    hello.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]);

    // Supported Versions (type 0x002b)
    // tdesktop: 00 2b 00 07 06 {grease} 03 04 03 03
    hello.extend_from_slice(&[
        0x00, 0x2b, 0x00, 0x07, 0x06, 0x2a, 0x2a, 0x03, 0x04, 0x03, 0x03,
    ]);

    // Padding extension (type 0x0015)
    hello.extend_from_slice(&[0x00, 0x15]); // type
    let pad_len_start = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]); // length placeholder
    let pad_data_start = hello.len();
    let remaining = CLIENT_HELLO_LENGTH - hello.len();
    if remaining > 0 {
        hello.resize(CLIENT_HELLO_LENGTH, 0);
        let pad_len = (hello.len() - pad_data_start) as u16;
        hello[pad_len_start..pad_len_start + 2].copy_from_slice(&pad_len.to_be_bytes());
    }

    // Fix extensions total length
    let ext_total_len = (hello.len() - ext_total_start - 2) as u16;
    hello[ext_total_start..ext_total_start + 2].copy_from_slice(&ext_total_len.to_be_bytes());

    assert_eq!(hello.len(), CLIENT_HELLO_LENGTH);

    // Compute HMAC-SHA256 over entire ClientHello (with zeroed random)
    hello[random_offset..random_offset + 32].fill(0);
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(&hello);
    let computed = mac.finalize().into_bytes();
    hello[random_offset..random_offset + 32].copy_from_slice(&computed);

    // XOR last 4 bytes of random with timestamp (little-endian)
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let old = u32::from_le_bytes(
        hello[random_offset + 28..random_offset + 32]
            .try_into()
            .unwrap(),
    );
    hello[random_offset + 28..random_offset + 32].copy_from_slice(&(old ^ timestamp).to_le_bytes());

    hello
}

fn gen_x25519_key() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    public.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_size() {
        let secret = [0u8; 16];
        let hello = build_client_hello(&secret, "example.com");
        assert_eq!(hello.len(), CLIENT_HELLO_LENGTH);
    }

    #[test]
    fn test_client_hello_structure() {
        let secret = [0u8; 16];
        let hello = build_client_hello(&secret, "telegram.org");
        assert_eq!(hello[0], 0x16);
        assert_eq!(&hello[1..3], &[0x03, 0x01]);
        assert_eq!(hello[5], 0x01);
    }

    #[test]
    fn test_hostname_present() {
        let secret = [0u8; 16];
        for hostname in &["example.com", "argeiphontes.ru", "telegram.org"] {
            let hello = build_client_hello(&secret, hostname);
            assert!(
                hello
                    .windows(hostname.len())
                    .any(|w| w == hostname.as_bytes()),
                "Hostname {} should be present",
                hostname
            );
        }
    }
}
