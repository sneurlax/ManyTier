use hmac::{Hmac, Mac};
use sha2::Sha384;

type HmacSha384 = Hmac<Sha384>;

fn kbkdf_hmac_sha384(key: &[u8; 48], label: u8) -> [u8; 48] {
    let message: [u8; 13] = [
        0x00, 0x00, 0x00, 0x00, // iter = 0 (u32 BE)
        0x5A, 0x54,  // "ZT"
        label, // b'0' for K0, b'1' for K1
        0x00,  // separator
        0x00,  // context
        0x00, 0x00, 0x01, 0x80, // output length = 384 bits (BE)
    ];

    let mut mac = HmacSha384::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(&message);
    let result = mac.finalize().into_bytes();

    let mut out = [0u8; 48];
    out.copy_from_slice(&result);
    out
}

/// Derive K0 (GMAC polynomial authentication key) from a 48-byte shared secret via KBKDF-HMAC-SHA384.
pub fn derive_k0(shared_secret: &[u8; 48]) -> [u8; 48] {
    kbkdf_hmac_sha384(shared_secret, b'0')
}

/// Derive K1 (AES-ECB tag encrypt/decrypt + AES-CTR payload key) from a 48-byte shared secret via KBKDF-HMAC-SHA384.
pub fn derive_k1(shared_secret: &[u8; 48]) -> [u8; 48] {
    kbkdf_hmac_sha384(shared_secret, b'1')
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;

    const TEST_SECRET: [u8; 48] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
        0x2E, 0x2F, 0x30,
    ];

    #[test]
    fn k0_and_k1_differ() {
        let k0 = derive_k0(&TEST_SECRET);
        let k1 = derive_k1(&TEST_SECRET);
        assert_ne!(k0, k1, "K0 and K1 must differ (different labels)");
    }

    #[test]
    fn output_is_48_bytes() {
        let k0 = derive_k0(&TEST_SECRET);
        let k1 = derive_k1(&TEST_SECRET);
        assert_eq!(k0.len(), 48);
        assert_eq!(k1.len(), 48);
    }

    #[test]
    fn deterministic() {
        let k0a = derive_k0(&TEST_SECRET);
        let k0b = derive_k0(&TEST_SECRET);
        let k1a = derive_k1(&TEST_SECRET);
        let k1b = derive_k1(&TEST_SECRET);
        assert_eq!(k0a, k0b, "K0 must be deterministic");
        assert_eq!(k1a, k1b, "K1 must be deterministic");
    }

    #[test]
    fn message_format_matches_vendor() {
        // Verify the 13-byte KBKDF message for K0 (label=b'0'=0x30)
        let expected_k0_msg: [u8; 13] = [
            0x00, 0x00, 0x00, 0x00, // iter = 0
            0x5A, 0x54, // "ZT"
            0x30, // label = b'0'
            0x00, // separator
            0x00, // context
            0x00, 0x00, 0x01, 0x80, // 384 bits BE
        ];

        // Verify the 13-byte KBKDF message for K1 (label=b'1'=0x31)
        let expected_k1_msg: [u8; 13] = [
            0x00, 0x00, 0x00, 0x00, 0x5A, 0x54, 0x31, // label = b'1'
            0x00, 0x00, 0x00, 0x00, 0x01, 0x80,
        ];

        // Compute expected outputs using the raw HMAC to cross-check
        let mut mac0 = HmacSha384::new_from_slice(&TEST_SECRET).unwrap();
        mac0.update(&expected_k0_msg);
        let expected_k0: [u8; 48] = mac0.finalize().into_bytes().into();

        let mut mac1 = HmacSha384::new_from_slice(&TEST_SECRET).unwrap();
        mac1.update(&expected_k1_msg);
        let expected_k1: [u8; 48] = mac1.finalize().into_bytes().into();

        assert_eq!(
            derive_k0(&TEST_SECRET),
            expected_k0,
            "K0 output must match raw HMAC with vendor message format"
        );
        assert_eq!(
            derive_k1(&TEST_SECRET),
            expected_k1,
            "K1 output must match raw HMAC with vendor message format"
        );
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let mut other_secret = TEST_SECRET;
        other_secret[0] = 0xFF;
        assert_ne!(derive_k0(&TEST_SECRET), derive_k0(&other_secret));
        assert_ne!(derive_k1(&TEST_SECRET), derive_k1(&other_secret));
    }
}
