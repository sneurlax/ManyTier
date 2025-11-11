//! X25519 ECDH key agreement for ZeroTier V1.
//!
//! Wraps x25519-dalek to provide a simple key agreement function
//! that returns the raw shared secret bytes.

/// Perform X25519 Diffie-Hellman key agreement.
///
/// Returns the 32-byte shared secret from the ECDH exchange.
/// Both parties will derive the same shared secret:
/// `key_agree(a_secret, b_public) == key_agree(b_secret, a_public)`
pub fn key_agree(
    our_secret: &x25519_dalek::StaticSecret,
    their_public: &x25519_dalek::PublicKey,
) -> [u8; 32] {
    our_secret.diffie_hellman(their_public).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn ecdh_symmetry() {
        // Generate two key pairs from fixed bytes for determinism
        let a_secret = StaticSecret::from([0x01u8; 32]);
        let a_public = PublicKey::from(&a_secret);
        let b_secret = StaticSecret::from([0x02u8; 32]);
        let b_public = PublicKey::from(&b_secret);

        let shared_ab = key_agree(&a_secret, &b_public);
        let shared_ba = key_agree(&b_secret, &a_public);

        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn different_keys_produce_different_secrets() {
        let a_secret = StaticSecret::from([0x01u8; 32]);
        let b_secret = StaticSecret::from([0x02u8; 32]);
        let c_secret = StaticSecret::from([0x03u8; 32]);
        let b_public = PublicKey::from(&b_secret);
        let c_public = PublicKey::from(&c_secret);

        let shared_ab = key_agree(&a_secret, &b_public);
        let shared_ac = key_agree(&a_secret, &c_public);

        assert_ne!(shared_ab, shared_ac);
    }
}
