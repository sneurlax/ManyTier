use alloc::vec::Vec;
use poly1305::Poly1305;
use universal_hash::KeyInit;

/// Compute a Poly1305 MAC over `data` using the given one-time key,
/// returning the first 8 bytes of the 16-byte tag.
///
/// Uses `compute_unpadded` for correct Poly1305 semantics: partial last
/// blocks get the 0x01 high bit at the actual data boundary, NOT zero-padded
/// to 16 bytes. This matches official ZeroTier's Poly1305 implementation.
pub fn compute_mac(one_time_key: &[u8; 32], data: &[u8]) -> [u8; 8] {
    let tag = Poly1305::new(one_time_key.into()).compute_unpadded(data);
    let mut result = [0u8; 8];
    result.copy_from_slice(&tag[..8]);
    result
}

/// Compute a Poly1305 MAC over multiple non-contiguous data slices.
pub fn compute_mac_multi(one_time_key: &[u8; 32], chunks: &[&[u8]]) -> [u8; 8] {
    let mut data = Vec::new();
    for chunk in chunks {
        data.extend_from_slice(chunk);
    }
    let tag = Poly1305::new(one_time_key.into()).compute_unpadded(&data);
    let mut result = [0u8; 8];
    result.copy_from_slice(&tag[..8]);
    result
}

/// Verify a Poly1305 MAC by computing the tag and comparing the first
/// 8 bytes against `expected` in constant time.
pub fn verify_mac(one_time_key: &[u8; 32], data: &[u8], expected: &[u8; 8]) -> bool {
    let computed = compute_mac(one_time_key, data);
    let mut diff = 0u8;
    for i in 0..8 {
        diff |= computed[i] ^ expected[i];
    }
    diff == 0
}

/// Verify a Poly1305 MAC over multiple non-contiguous data slices.
pub fn verify_mac_multi(one_time_key: &[u8; 32], chunks: &[&[u8]], expected: &[u8; 8]) -> bool {
    let computed = compute_mac_multi(one_time_key, chunks);
    let mut diff = 0u8;
    for i in 0..8 {
        diff |= computed[i] ^ expected[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_mac_returns_8_bytes() {
        let key = [0x42u8; 32];
        let data = b"hello world";
        let mac = compute_mac(&key, data);
        assert_eq!(mac.len(), 8);
    }

    #[test]
    fn verify_mac_returns_true_for_valid() {
        let key = [0x42u8; 32];
        let data = b"hello world";
        let mac = compute_mac(&key, data);
        assert!(verify_mac(&key, data, &mac));
    }

    #[test]
    fn verify_mac_returns_false_for_corrupted_data() {
        let key = [0x42u8; 32];
        let data = b"hello world";
        let mac = compute_mac(&key, data);
        let corrupted_data = b"hello worle";
        assert!(!verify_mac(&key, corrupted_data, &mac));
    }

    #[test]
    fn verify_mac_returns_false_for_corrupted_mac() {
        let key = [0x42u8; 32];
        let data = b"hello world";
        let mut mac = compute_mac(&key, data);
        mac[0] ^= 0xff;
        assert!(!verify_mac(&key, data, &mac));
    }

    #[test]
    fn different_keys_produce_different_macs() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let data = b"hello world";
        let mac1 = compute_mac(&key1, data);
        let mac2 = compute_mac(&key2, data);
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn rfc7539_poly1305_test_vector() {
        // RFC 7539 Section 2.5.2
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        // Expected full tag: a8061dc1305136c6c22b8baf0c0127a9
        let expected_first8: [u8; 8] = [0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6];
        let mac = compute_mac(&key, msg);
        assert_eq!(
            mac, expected_first8,
            "Poly1305 should match RFC 7539 test vector"
        );
    }
}
