/// Poly1305 MAC computation and verification for ZeroTier V1 packets.
///
/// ZeroTier uses only the first 8 bytes of the 16-byte Poly1305 tag
/// for packet authentication (stored at packet offset 19..27).
use poly1305::Poly1305;
use universal_hash::{KeyInit, UniversalHash};

/// Compute a Poly1305 MAC over `data` using the given one-time key,
/// returning the first 8 bytes of the 16-byte tag.
///
/// ZeroTier truncates the Poly1305 tag to 8 bytes for the wire format.
pub fn compute_mac(one_time_key: &[u8; 32], data: &[u8]) -> [u8; 8] {
    let mut mac = Poly1305::new(one_time_key.into());
    mac.update_padded(data);
    let tag = mac.finalize();
    let mut result = [0u8; 8];
    result.copy_from_slice(&tag[..8]);
    result
}

/// Verify a Poly1305 MAC by computing the tag and comparing the first
/// 8 bytes against `expected` in constant time.
pub fn verify_mac(one_time_key: &[u8; 32], data: &[u8], expected: &[u8; 8]) -> bool {
    let computed = compute_mac(one_time_key, data);
    // Constant-time comparison to prevent timing attacks
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
}
