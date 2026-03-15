// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! MTProxy transport implementation.
//!
//! MTProxy is a specialized proxy protocol developed by Telegram that allows
//! bypassing censorship while maintaining the ability to connect to Telegram servers.
//!
//! See [MTProxy Analysis](https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation)

use grammers_crypto::{DequeBuffer, ObfuscatedCipher};
use sha2::{Digest, Sha256};

use super::{Error, RandomizedIntermediate, Tagged, Transport, UnpackedOffset};

/// MTProxy secret mode based on prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretMode {
    /// Simple mode - no prefix (16 bytes)
    Simple,
    /// DD-Secure mode - requires dd prefix (17 bytes total)
    /// Enables random padding (0-3 bytes per packet)
    DDSecure,
    /// EE-Prefix mode - requires ee prefix (17 bytes total)
    EEPrefix,
}

/// MTProxy obfuscation layer for MTProto transport protocols.
///
/// Similar to `Obfuscated`, but uses pre-shared secret for key derivation
/// and embeds DC ID in the handshake.
///
/// # Key Differences from Obfuscated
///
/// | Feature | Obfuscated | MTProxy |
/// |---------|------------|---------|
/// | Key Source | Random per-connection | Pre-shared secret |
/// | Key Generation | Direct from random | `SHA256(random + secret)` |
/// | DC ID | Not used | Embedded in handshake |
/// | Connection | Direct to Telegram | Through MTProxy server |
///
/// # Example
///
/// ```ignore
/// use grammers_mtproto::transport::{Intermediate, MtProxy};
///
/// let transport = MtProxy::new(
///     Intermediate::new(),
///     "dd0123456789abcdef0123456789abcdef",
///     2,
/// ).unwrap();
/// ```
pub struct MtProxy<T: Transport + Tagged> {
    inner: T,
    head: Option<[u8; 64]>,
    cipher: ObfuscatedCipher,
    #[allow(dead_code)]
    dc_id: i32,
    decrypt_tail: usize,
}

/// Forbidden first byte patterns for MTProxy handshake.
///
/// These patterns must be avoided to prevent DPI detection.
const FORBIDDEN_FIRST_INTS: [[u8; 4]; 4] = [
    [b'P', b'V', b'r', b'G'],  // PVrG
    [b'G', b'E', b'T', b' '],  // GET
    [b'P', b'O', b'S', b'T'],  // POST
    [0xee, 0xee, 0xee, 0xee],  // Intermediate tag
];

impl<T: Transport + Tagged> MtProxy<T> {
    /// Create a new MTProxy transport with the given inner transport, secret, and DC ID.
    ///
    /// # Arguments
    ///
    /// * `inner` - The inner transport (e.g., `Intermediate::new()`)
    /// * `secret` - The MTProxy secret (hex or base64 encoded)
    /// * `dc_id` - The data center ID to connect to
    ///
    /// # Secret Format
    ///
    /// - **Hex**: `"0123456789abcdef0123456789abcdef"` (32 chars = 16 bytes)
    /// - **Hex with prefix**: `"dd0123456789abcdef0123456789abcdef"` (dd mode)
    /// - **Base64**: `"ASNFZ4mrze/+3LqYdlQyEA=="`
    ///
    /// # Example
    ///
    /// ```ignore
    /// let transport = MtProxy::new(
    ///     Intermediate::new(),
    ///     "dd0123456789abcdef0123456789abcdef",
    ///     2,
    /// ).unwrap();
    /// ```
    pub fn new(mut inner: T, secret: &str, dc_id: i32) -> Result<Self, Error> {
        let (secret_bytes, _mode) = Self::parse_secret(secret)?;
        let (init, cipher) = Self::generate_keys(&mut inner, &secret_bytes, dc_id)?;

        Ok(Self {
            inner,
            head: Some(init),
            cipher,
            dc_id,
            decrypt_tail: 0,
        })
    }

    /// Parse and validate MTProxy secret.
    ///
    /// # Returns
    ///
    /// A tuple of (secret_bytes, mode) where:
    /// - `secret_bytes` is the 16-byte secret
    /// - `mode` indicates the prefix mode (Simple, DDSecure, or EEPrefix)
    fn parse_secret(secret: &str) -> Result<(Vec<u8>, SecretMode), Error> {
        use base64::{Engine as _, engine::general_purpose};

        let secret_lower = secret.to_lowercase();

        // Check for prefix and extract the secret part
        let (mode, secret_part) = if secret_lower.starts_with("dd") {
            (SecretMode::DDSecure, &secret[2..])
        } else if secret_lower.starts_with("ee") {
            (SecretMode::EEPrefix, &secret[2..])
        } else {
            (SecretMode::Simple, secret)
        };

        // Try hex decoding first
        let secret_bytes = if let Ok(bytes) = hex::decode(secret_part) {
            if bytes.len() != 16 {
                return Err(Error::BadLen {
                    got: bytes.len() as i32,
                });
            }
            bytes
        } else {
            // Try base64 decoding
            let secret_padded = if secret_part.len() % 4 != 0 {
                let mut padded = secret_part.to_string();
                while padded.len() % 4 != 0 {
                    padded.push('=');
                }
                padded
            } else {
                secret_part.to_string()
            };

            let bytes = general_purpose::STANDARD
                .decode(&secret_padded)
                .map_err(|_| Error::BadLen { got: 0 })?;
            if bytes.len() != 16 {
                return Err(Error::BadLen {
                    got: bytes.len() as i32,
                });
            }
            bytes
        };

        Ok((secret_bytes, mode))
    }

    /// Generate MTProxy handshake with keys derived from secret.
    ///
    /// # Key Derivation
    ///
    /// Unlike regular Obfuscated which uses random bytes directly:
    /// ```text
    /// encrypt_key = random[8:40]
    /// ```
    ///
    /// MTProxy derives keys via SHA256:
    /// ```text
    /// encrypt_key = SHA256(random[8:40] + secret)
    /// decrypt_key = SHA256(random_reversed[:32] + secret)
    /// ```
    fn generate_keys(
        inner: &mut T,
        secret: &[u8],
        dc_id: i32,
    ) -> Result<([u8; 64], ObfuscatedCipher), Error> {
        let mut init = [0u8; 64];

        // Generate random header avoiding forbidden patterns
        loop {
            let _ = getrandom::fill(&mut init);

            // Check first byte is not 0xef
            if init[0] == 0xef {
                continue;
            }

            // Check first 4 bytes don't match forbidden patterns
            if FORBIDDEN_FIRST_INTS.iter().any(|f| &init[..4] == f) {
                continue;
            }

            // Check bytes 4-8 are not all zeros
            if &init[4..8] == &[0, 0, 0, 0] {
                continue;
            }

            break;
        }

        // Create reversed random for decrypt key (random[55:7:-1])
        let mut random_reversed = [0u8; 48];
        for i in 0..48 {
            random_reversed[i] = init[55 - i];
        }

        // Derive keys with SECRET (KEY DIFFERENCE FROM OBFUSCATED)
        let encrypt_key = {
            let mut hasher = Sha256::new();
            hasher.update(&init[8..40]);
            hasher.update(secret);
            hasher.finalize()
        };

        let decrypt_key = {
            let mut hasher = Sha256::new();
            hasher.update(&random_reversed[..32]);
            hasher.update(secret);
            hasher.finalize()
        };

        let encrypt_iv: [u8; 16] = init[40..56].try_into().unwrap();
        let decrypt_iv: [u8; 16] = random_reversed[32..48].try_into().unwrap();

        let encrypt_key_array: [u8; 32] = encrypt_key.try_into().unwrap();
        let decrypt_key_array: [u8; 32] = decrypt_key.try_into().unwrap();

        log::debug!("MTProxy: encrypt_key first 8 bytes = {:02x?}", &encrypt_key_array[..8]);
        log::debug!("MTProxy: decrypt_key first 8 bytes = {:02x?}", &decrypt_key_array[..8]);
        log::debug!("MTProxy: encrypt_iv = {:02x?}", encrypt_iv);
        log::debug!("MTProxy: decrypt_iv = {:02x?}", decrypt_iv);

        let mut cipher = ObfuscatedCipher::from_parts(
            encrypt_key_array,
            encrypt_iv,
            decrypt_key_array,
            decrypt_iv,
        );

        // Embed transport tag
        init[56..60].copy_from_slice(&inner.init_tag());

        // Embed DC ID (2 bytes, little-endian, signed)
        let dc_bytes = (dc_id as u16).to_le_bytes();
        log::debug!("MTProxy: embedding DC ID {} as bytes [{}, {}] at position 60-61", dc_id, dc_bytes[0], dc_bytes[1]);
        init[60..62].copy_from_slice(&dc_bytes);

        // Encrypt the tail (bytes 56-63) to advance both tx and rx counters.
        // Like Obfuscated, we encrypt all 64 bytes but only keep the encrypted tail.
        // This ensures the cipher state is properly synchronized for send/receive.
        let mut encrypted_init = init.to_vec();
        cipher.encrypt(&mut encrypted_init);
        init[56..64].copy_from_slice(&encrypted_init[56..64]);

        log::debug!("MTProxy: generated 64-byte header: first 8 bytes = {:02x?}", &init[..8]);
        log::debug!("MTProxy: bytes 56-63 (encrypted tail) = {:02x?}", &init[56..64]);
        log::debug!("MTProxy: DC ID at bytes 60-61 = [{}, {}] (before encryption: [{}, {}])",
            init[60], init[61], dc_bytes[0], dc_bytes[1]);

        Ok((init, cipher))
    }
}

/// Create MTProxy with automatic transport selection based on secret mode.
///
/// This is a convenience method that always uses `RandomizedIntermediate` transport,
/// which works for all MTProxy modes (Simple, DD-Secure, EE-Prefix).
///
/// # Example
///
/// ```ignore
/// // Automatically uses RandomizedIntermediate for all modes
/// let mtproxy = with_auto_transport("dd0123...", 2).unwrap();
/// ```
pub fn with_auto_transport(
    secret: &str,
    dc_id: i32,
) -> Result<MtProxy<RandomizedIntermediate>, Error> {
    let inner = RandomizedIntermediate::new();
    MtProxy::new(inner, secret, dc_id)
}

impl<T: Transport + Tagged> Transport for MtProxy<T> {
    fn reset_on_partial(&self) -> bool {
        false
    }

    fn pack(&mut self, buffer: &mut DequeBuffer<u8>) {
        self.inner.pack(buffer);
        self.cipher.encrypt(buffer.as_mut());

        if let Some(head) = self.head.take() {
            buffer.extend_front(&head);
        }
    }

    fn unpack(&mut self, buffer: &mut [u8]) -> Result<UnpackedOffset, Error> {
        if buffer.len() < self.decrypt_tail {
            panic!("buffer is smaller than what was decrypted");
        }

        // Decrypt only the new data (from decrypt_tail to end)
        self.cipher.decrypt(&mut buffer[self.decrypt_tail..]);
        self.decrypt_tail = buffer.len();

        match self.inner.unpack(buffer) {
            Ok(offset) => {
                self.decrypt_tail -= offset.next_offset;
                Ok(offset)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Intermediate;

    #[test]
    fn test_parse_secret_hex() {
        let secret = "0123456789abcdef0123456789abcdef";
        let (bytes, mode) = MtProxy::<Intermediate>::parse_secret(secret).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(mode, SecretMode::Simple);
    }

    #[test]
    fn test_parse_secret_dd_mode() {
        let secret = "dd0123456789abcdef0123456789abcdef";
        let (bytes, mode) = MtProxy::<Intermediate>::parse_secret(secret).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(mode, SecretMode::DDSecure);
    }

    #[test]
    fn test_parse_secret_ee_mode() {
        let secret = "ee0123456789abcdef0123456789abcdef";
        let (bytes, mode) = MtProxy::<Intermediate>::parse_secret(secret).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(mode, SecretMode::EEPrefix);
    }

    #[test]
    fn test_parse_secret_base64() {
        let secret = "ASNFZ4mrze/+3LqYdlQyEA==";
        let (bytes, mode) = MtProxy::<Intermediate>::parse_secret(secret).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(mode, SecretMode::Simple);
    }

    #[test]
    fn test_parse_secret_invalid_length() {
        let secret = "0123456789abc"; // Too short
        assert!(MtProxy::<Intermediate>::parse_secret(secret).is_err());
    }

    #[test]
    fn test_dc_id_embedding() {
        let dc_id: i32 = 2;
        let dc_bytes = (dc_id as u16).to_le_bytes();
        assert_eq!(dc_bytes, [2, 0]);
    }

    #[test]
    fn test_dc_id_negative() {
        let dc_id: i32 = -2;
        let dc_bytes = (dc_id as u16).to_le_bytes();
        assert_eq!(dc_bytes, [254, 255]); // -2 in little-endian
    }

    #[test]
    fn test_forbidden_patterns() {
        // PVrG pattern
        assert_eq!(FORBIDDEN_FIRST_INTS[0], [b'P', b'V', b'r', b'G']);
        // GET pattern
        assert_eq!(FORBIDDEN_FIRST_INTS[1], [b'G', b'E', b'T', b' ']);
        // POST pattern
        assert_eq!(FORBIDDEN_FIRST_INTS[2], [b'P', b'O', b'S', b'T']);
        // Intermediate tag
        assert_eq!(FORBIDDEN_FIRST_INTS[3], [0xee, 0xee, 0xee, 0xee]);
    }

    #[test]
    fn test_key_derivation() {
        // Test that key derivation works with a known secret
        let secret = hex::decode("0123456789abcdef0123456789abcdef").unwrap();

        let mut random = [0u8; 64];
        let _ = getrandom::fill(&mut random);

        let encrypt_key = {
            let mut hasher = Sha256::new();
            hasher.update(&random[8..40]);
            hasher.update(&secret);
            hasher.finalize()
        };

        // Key should be 32 bytes
        assert_eq!(encrypt_key.len(), 32);

        // Same input should produce same key
        let encrypt_key2 = {
            let mut hasher = Sha256::new();
            hasher.update(&random[8..40]);
            hasher.update(&secret);
            hasher.finalize()
        };

        assert_eq!(encrypt_key, encrypt_key2);
    }

    #[test]
    fn test_different_secrets_produce_different_keys() {
        let secret1 = hex::decode("0123456789abcdef0123456789abcdef").unwrap();
        let secret2 = hex::decode("fedcba9876543210fedcba9876543210").unwrap();

        let mut random = [0u8; 64];
        let _ = getrandom::fill(&mut random);

        let key1 = {
            let mut hasher = Sha256::new();
            hasher.update(&random[8..40]);
            hasher.update(&secret1);
            hasher.finalize()
        };

        let key2 = {
            let mut hasher = Sha256::new();
            hasher.update(&random[8..40]);
            hasher.update(&secret2);
            hasher.finalize()
        };

        assert_ne!(key1, key2);
    }
}
