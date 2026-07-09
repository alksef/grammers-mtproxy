// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! FakeTLS ServerHello validation.

use hmac::{Hmac, Mac};
use sha2::Sha256;
#[cfg(feature = "mtproxy")]
use subtle::ConstantTimeEq;

use super::record::{
    TLS_DIGEST_LEN, TLS_DIGEST_POS, TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER,
    TLS_RECORD_HANDSHAKE,
};

type HmacSha256 = Hmac<Sha256>;

/// Validate ServerHello response from server.
///
/// Following telemt/MTG algorithm:
/// HMAC = SHA256(client_random + ENTIRE_SERVER_HELLO_RESPONSE, secret)
///
/// Returns the offset after all TLS records (ServerHello + ChangeCipherSpec + ApplicationData).
pub fn validate_server_hello(
    server_hello: &[u8],
    client_random: &[u8; TLS_DIGEST_LEN],
    secret: &[u8; 16],
) -> Result<usize, ServerHelloError> {
    if server_hello.len() < 5 {
        return Err(ServerHelloError::TooShort);
    }

    // Verify it's a ServerHello (0x16)
    if server_hello[0] != TLS_RECORD_HANDSHAKE {
        return Err(ServerHelloError::NotServerHello {
            record_type: server_hello[0],
        });
    }

    // Extract digest from position 11
    let server_digest: [u8; TLS_DIGEST_LEN] = server_hello
        [TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN]
        .try_into()
        .map_err(|_| ServerHelloError::InvalidDigestLength)?;

    // Compute HMAC: SHA256(client_random + ENTIRE_RESPONSE_WITH_ZEROED_SERVER_RANDOM, secret)
    let mut buf = server_hello.to_vec();
    buf[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].fill(0);
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(client_random);
    mac.update(&buf);
    let expected = mac.finalize().into_bytes();

    // Compare (constant-time)
    #[cfg(feature = "mtproxy")]
    {
        if !bool::from(expected.ct_eq(&server_digest)) {
            return Err(ServerHelloError::HmacMismatch);
        }
    }
    #[cfg(not(feature = "mtproxy"))]
    {
        if expected.as_slice() != server_digest.as_slice() {
            return Err(ServerHelloError::HmacMismatch);
        }
    }

    // Skip all TLS records to find offset to actual data
    skip_tls_records(server_hello)
}

/// Skip TLS records to find offset to actual MTProxy data.
///
/// Processes: ServerHello → ChangeCipherSpec → ApplicationData
/// Returns offset after all FakeTLS handshake records.
fn skip_tls_records(data: &[u8]) -> Result<usize, ServerHelloError> {
    let mut offset = 0;

    // ServerHello (already validated above)
    if offset + 5 > data.len() {
        return Err(ServerHelloError::IncompleteRecord {
            record_type: "ServerHello",
        });
    }

    let sh_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    offset += 5 + sh_len;

    // ChangeCipherSpec (type 0x14)
    if offset < data.len() {
        if data[offset] != TLS_RECORD_CHANGE_CIPHER {
            return Err(ServerHelloError::UnexpectedRecord {
                expected: "ChangeCipherSpec (0x14)",
                got: data[offset],
                position: "after ServerHello",
            });
        }

        if offset + 5 > data.len() {
            return Err(ServerHelloError::IncompleteRecord {
                record_type: "ChangeCipherSpec",
            });
        }

        let ccs_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        offset += 5 + ccs_len;
    }

    // ApplicationData (type 0x17)
    if offset < data.len() {
        if data[offset] != TLS_RECORD_APPLICATION {
            return Err(ServerHelloError::UnexpectedRecord {
                expected: "ApplicationData (0x17)",
                got: data[offset],
                position: "after ChangeCipherSpec",
            });
        }

        if offset + 5 > data.len() {
            return Err(ServerHelloError::IncompleteRecord {
                record_type: "ApplicationData",
            });
        }

        let app_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        offset += 5 + app_len;
    }

    Ok(offset)
}

/// ServerHello validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerHelloError {
    TooShort,
    NotServerHello {
        record_type: u8,
    },
    InvalidDigestLength,
    HmacMismatch,
    IncompleteRecord {
        record_type: &'static str,
    },
    UnexpectedRecord {
        expected: &'static str,
        got: u8,
        position: &'static str,
    },
}

impl std::error::Error for ServerHelloError {}

impl std::fmt::Display for ServerHelloError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "ServerHello too short"),
            Self::NotServerHello { record_type } => {
                write!(f, "Not a ServerHello (type: 0x{:02x})", record_type)
            }
            Self::InvalidDigestLength => write!(f, "Invalid digest length"),
            Self::HmacMismatch => write!(f, "ServerHello HMAC verification failed"),
            Self::IncompleteRecord { record_type } => {
                write!(f, "Incomplete {} record", record_type)
            }
            Self::UnexpectedRecord {
                expected,
                got,
                position,
            } => {
                write!(
                    f,
                    "Expected {} at {}, got 0x{:02x}",
                    expected, position, got
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_hello_validation_success() {
        // Mock ServerHello with valid structure
        let client_random = [0u8; 32];

        // Build minimal ServerHello response
        let mut response = Vec::new();

        // ServerHello record (simplified)
        response.extend_from_slice(&[0x16, 0x03, 0x03]); // Handshake, TLS 1.2
        response.extend_from_slice(&[0x00, 0x26]); // Length: 38 bytes (1+3+2+32)

        // ServerHello body (minimal)
        response.push(0x02); // ServerHello
        response.extend_from_slice(&[0x00, 0x00, 0x22]); // Length: 34 bytes (2+32)
        response.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
                                                   // Random (32 bytes) - will contain HMAC
        response.extend_from_slice(&[0u8; 32]);

        // ChangeCipherSpec (6 bytes: header + 1-byte payload)
        response.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

        // ApplicationData
        response.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x10]);
        response.extend_from_slice(&[0u8; 16]);

        // Compute HMAC over entire three-record packet with ServerRandom zeroed
        let mut buf = response.clone();
        buf[11..43].fill(0);
        let mut mac = HmacSha256::new_from_slice(&[0u8; 16]).unwrap();
        mac.update(&client_random);
        mac.update(&buf);
        let hmac_result = mac.finalize().into_bytes();

        // Place HMAC at position 11
        response[11..43].copy_from_slice(&hmac_result);

        let secret = [0u8; 16];
        let result = validate_server_hello(&response, &client_random, &secret);

        let offset = result.expect("ServerHello should be valid");
        // 5 (SH header) + 38 (SH body) + 6 (CCS: 5 header + 1 payload) + 21 (App: 5 header + 16 body) = 70
        assert_eq!(offset, 70);
    }

    #[test]
    fn test_invalid_record_type() {
        let client_random = [0u8; 32];
        let secret = [0u8; 16];

        // Not a handshake record
        let invalid_data = vec![0x17, 0x03, 0x03, 0x00, 0x05]; // ApplicationData

        let result = validate_server_hello(&invalid_data, &client_random, &secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_incomplete_record() {
        let client_random = [0u8; 32];
        let secret = [0u8; 16];

        // Truncated ServerHello
        let truncated = vec![0x16, 0x03, 0x03]; // Only header

        let result = validate_server_hello(&truncated, &client_random, &secret);
        assert!(result.is_err());
    }
}
