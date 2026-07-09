// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TLS record structures and constants for FakeTLS implementation.

use std::fmt;

/// TLS record content types
pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_CHANGE_CIPHER: u8 = 0x14;
pub const TLS_RECORD_APPLICATION: u8 = 0x17;
pub const TLS_RECORD_ALERT: u8 = 0x15;

/// TLS version (1.2 for compatibility)
pub const TLS_VERSION: &[u8; 2] = &[0x03, 0x03];

/// Position of digest in ClientHello (after TLS record + handshake headers)
///
/// Offset calculation:
/// - TLS Record header: 1 (type) + 2 (version) + 2 (length) = 5
/// - Handshake header: 1 (type) + 3 (length) = 4
/// - Client version: 2 bytes
/// - Total: 5 + 4 + 2 = 11
pub const TLS_DIGEST_POS: usize = 11;
pub const TLS_DIGEST_LEN: usize = 32;

/// Maximum TLS record sizes
pub const MAX_TLS_PLAINTEXT_SIZE: u16 = 16384;
pub const MAX_TLS_CIPHERTEXT_SIZE: u16 = 16640;

/// TLS record header (5 bytes)
///
/// ```text
/// struct {
///     ContentType type;       // 1 byte
///     ProtocolVersion version; // 2 bytes
///     uint16 length;          // 2 bytes
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsRecordHeader {
    pub record_type: u8,
    pub version: [u8; 2],
    pub length: u16,
}

impl TlsRecordHeader {
    /// Create a new TLS record header
    pub fn new(record_type: u8, length: u16) -> Self {
        Self {
            record_type,
            version: *TLS_VERSION,
            length,
        }
    }

    /// Parse TLS record header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlsRecordError> {
        if data.len() < 5 {
            return Err(TlsRecordError::InvalidHeader {
                reason: "Header too short",
            });
        }

        let record_type = data[0];
        let version = [data[1], data[2]];
        let length = u16::from_be_bytes([data[3], data[4]]);

        Ok(Self {
            record_type,
            version,
            length,
        })
    }

    /// Encode TLS record header to bytes
    pub fn to_bytes(&self) -> [u8; 5] {
        let mut bytes = [0u8; 5];
        bytes[0] = self.record_type;
        bytes[1] = self.version[0];
        bytes[2] = self.version[1];
        bytes[3..5].copy_from_slice(&self.length.to_be_bytes());
        bytes
    }

    /// Validate the record header
    pub fn validate(&self) -> Result<(), TlsRecordError> {
        // Validate record type
        match self.record_type {
            TLS_RECORD_HANDSHAKE => {
                if !(4..=MAX_TLS_PLAINTEXT_SIZE).contains(&self.length) {
                    return Err(TlsRecordError::InvalidLength {
                        record_type: "Handshake",
                        length: self.length,
                        max: MAX_TLS_PLAINTEXT_SIZE,
                    });
                }
            }
            TLS_RECORD_APPLICATION => {
                if self.length == 0 || self.length > MAX_TLS_CIPHERTEXT_SIZE {
                    return Err(TlsRecordError::InvalidLength {
                        record_type: "Application",
                        length: self.length,
                        max: MAX_TLS_CIPHERTEXT_SIZE,
                    });
                }
            }
            TLS_RECORD_CHANGE_CIPHER => {
                if self.length != 1 {
                    return Err(TlsRecordError::InvalidLength {
                        record_type: "ChangeCipherSpec",
                        length: self.length,
                        max: 1,
                    });
                }
            }
            TLS_RECORD_ALERT => {
                if self.length != 2 {
                    return Err(TlsRecordError::InvalidLength {
                        record_type: "Alert",
                        length: self.length,
                        max: 2,
                    });
                }
            }
            _ => {
                return Err(TlsRecordError::UnknownRecordType {
                    record_type: self.record_type,
                });
            }
        }

        Ok(())
    }
}

/// TLS record errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsRecordError {
    InvalidHeader {
        reason: &'static str,
    },
    InvalidLength {
        record_type: &'static str,
        length: u16,
        max: u16,
    },
    UnknownRecordType {
        record_type: u8,
    },
}

impl fmt::Display for TlsRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeader { reason } => {
                write!(f, "Invalid TLS header: {}", reason)
            }
            Self::InvalidLength {
                record_type,
                length,
                max,
            } => {
                write!(
                    f,
                    "Invalid {} record length: {} (max {})",
                    record_type, length, max
                )
            }
            Self::UnknownRecordType { record_type } => {
                write!(f, "Unknown TLS record type: 0x{:02x}", record_type)
            }
        }
    }
}

impl std::error::Error for TlsRecordError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_header_roundtrip() {
        let original = TlsRecordHeader::new(TLS_RECORD_HANDSHAKE, 100);
        let bytes = original.to_bytes();
        let parsed = TlsRecordHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_record_header_validation() {
        // Valid ApplicationData record
        let app_header = TlsRecordHeader::new(TLS_RECORD_APPLICATION, 1000);
        assert!(app_header.validate().is_ok());

        // Too large ApplicationData
        let too_large = TlsRecordHeader::new(TLS_RECORD_APPLICATION, MAX_TLS_CIPHERTEXT_SIZE + 1);
        assert!(too_large.validate().is_err());

        // Valid ChangeCipherSpec
        let ccs = TlsRecordHeader::new(TLS_RECORD_CHANGE_CIPHER, 1);
        assert!(ccs.validate().is_ok());

        // Invalid ChangeCipherSpec length
        let bad_ccs = TlsRecordHeader::new(TLS_RECORD_CHANGE_CIPHER, 2);
        assert!(bad_ccs.validate().is_err());
    }

    #[test]
    fn test_constants() {
        assert_eq!(TLS_DIGEST_POS, 11);
        assert_eq!(TLS_DIGEST_LEN, 32);
        assert_eq!(TLS_VERSION, &[0x03, 0x03]);
    }
}
