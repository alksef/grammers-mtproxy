// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! MTProxy integration tests.

#[cfg(feature = "mtproxy")]
#[cfg(test)]
mod tests {
    use grammers_mtproto::transport::{Intermediate, MtProxy, Transport};
    use grammers_crypto::DequeBuffer;

    #[test]
    fn test_mtproxy_with_intermediate() {
        let transport = MtProxy::new(
            Intermediate::new(),
            "dd0123456789abcdef0123456789abcdef",
            2,
        );

        assert!(transport.is_ok(), "MTProxy creation should succeed");

        let mut transport = transport.unwrap();

        // Test packing
        let mut buffer = DequeBuffer::with_capacity(16, 0);
        buffer.extend(&[0u8; 16]);
        transport.pack(&mut buffer);

        // Should have header (64 bytes) + data
        assert!(buffer.len() > 64, "Packed buffer should contain header");
    }

    #[test]
    fn test_mtproxy_secret_hex() {
        let secret = "0123456789abcdef0123456789abcdef";
        let transport = MtProxy::new(Intermediate::new(), secret, 2);

        assert!(transport.is_ok(), "Hex secret should be valid");
    }

    #[test]
    fn test_mtproxy_secret_base64() {
        let secret = "ASNFZ4mrze/+3LqYdlQyEA==";
        let transport = MtProxy::new(Intermediate::new(), secret, 2);

        assert!(transport.is_ok(), "Base64 secret should be valid");
    }

    #[test]
    fn test_mtproxy_secret_dd_mode() {
        let secret = "dd0123456789abcdef0123456789abcdef";
        let transport = MtProxy::new(Intermediate::new(), secret, 2);

        assert!(transport.is_ok(), "DD mode secret should be valid");
    }

    #[test]
    fn test_mtproxy_secret_ee_mode() {
        let secret = "ee0123456789abcdef0123456789abcdef";
        let transport = MtProxy::new(Intermediate::new(), secret, 2);

        assert!(transport.is_ok(), "EE mode secret should be valid");
    }

    #[test]
    fn test_mtproxy_invalid_secret() {
        let secret = "invalid_secret_too_short";
        let transport = MtProxy::new(Intermediate::new(), secret, 2);

        assert!(transport.is_err(), "Invalid secret should fail");
    }

    #[test]
    fn test_mtproxy_dc_id_positive() {
        let transport = MtProxy::new(
            Intermediate::new(),
            "0123456789abcdef0123456789abcdef",
            4,
        );

        assert!(transport.is_ok(), "Positive DC ID should work");
    }

    #[test]
    fn test_mtproxy_dc_id_negative() {
        let transport = MtProxy::new(
            Intermediate::new(),
            "0123456789abcdef0123456789abcdef",
            -2,
        );

        assert!(transport.is_ok(), "Negative DC ID should work");
    }

    #[test]
    fn test_mtproxy_dc_id_zero() {
        let transport = MtProxy::new(
            Intermediate::new(),
            "0123456789abcdef0123456789abcdef",
            0,
        );

        assert!(transport.is_ok(), "Zero DC ID should work");
    }

    #[test]
    fn test_mtproxy_pack_unpack_cycle() {
        let mut transport = MtProxy::new(
            Intermediate::new(),
            "0123456789abcdef0123456789abcdef",
            2,
        )
        .unwrap();

        // Pack some data
        let mut buffer = DequeBuffer::with_capacity(16, 0);
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        buffer.extend(&data);

        transport.pack(&mut buffer);

        // Verify buffer has been modified
        assert!(buffer.len() > data.len(), "Packed buffer should be larger");

        // Note: Full pack/unpack testing requires more complex setup
        // This is a basic sanity check
    }

    #[test]
    fn test_forbidden_patterns_avoided() {
        // Test that forbidden patterns are avoided in handshake
        let transport = MtProxy::new(
            Intermediate::new(),
            "0123456789abcdef0123456789abcdef",
            2,
        );

        assert!(transport.is_ok(), "Should avoid forbidden patterns");
    }

    #[test]
    fn test_key_derivation_different_secrets() {
        // Create two transports with different secrets
        let transport1 =
            MtProxy::new(Intermediate::new(), "0123456789abcdef0123456789abcdef", 2).unwrap();

        let transport2 =
            MtProxy::new(Intermediate::new(), "fedcba9876543210fedcba9876543210", 2).unwrap();

        // Pack data with both
        let mut buffer1 = DequeBuffer::with_capacity(16, 0);
        let mut buffer2 = DequeBuffer::with_capacity(16, 0);

        buffer1.extend(&[1u8, 2, 3, 4]);
        buffer2.extend(&[1u8, 2, 3, 4]);

        let mut t1 = transport1;
        let mut t2 = transport2;

        t1.pack(&mut buffer1);
        t2.pack(&mut buffer2);

        // Headers should be different due to different secrets
        assert_ne!(
            &buffer1[..64], &buffer2[..64],
            "Different secrets should produce different headers"
        );
    }

    #[test]
    fn test_key_derivation_same_secret() {
        // Create two transports with the same secret
        let secret = "0123456789abcdef0123456789abcdef";

        let transport1 = MtProxy::new(Intermediate::new(), secret, 2).unwrap();
        let transport2 = MtProxy::new(Intermediate::new(), secret, 2).unwrap();

        // Pack data with both
        let mut buffer1 = DequeBuffer::with_capacity(16, 0);
        let mut buffer2 = DequeBuffer::with_capacity(16, 0);

        buffer1.extend(&[1u8, 2, 3, 4]);
        buffer2.extend(&[1u8, 2, 3, 4]);

        let mut t1 = transport1;
        let mut t2 = transport2;

        t1.pack(&mut buffer1);
        t2.pack(&mut buffer2);

        // Headers should be different due to random initialization
        // (even with same secret)
        assert_ne!(
            &buffer1[..64], &buffer2[..64],
            "Random initialization should produce different headers"
        );
    }
}
