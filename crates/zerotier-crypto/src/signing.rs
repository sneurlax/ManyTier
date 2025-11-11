/// Ed25519 signing and verification for ZeroTier V1.
///
/// ZeroTier uses 96-byte signature fields: the standard 64-byte Ed25519
/// signature padded with 32 zero bytes for forward compatibility
/// (per Pitfall 7 in RESEARCH.md).
use crate::error::CryptoError;

/// Sign a message with an Ed25519 signing key.
///
/// Returns a 96-byte array: 64-byte Ed25519 signature + 32 zero-byte padding.
/// The padding is for ZeroTier forward compatibility with potential future
/// signature schemes.
pub fn sign(signing_key: &ed25519_dalek::SigningKey, message: &[u8]) -> [u8; 96] {
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(message);
    let sig_bytes = sig.to_bytes();
    let mut padded = [0u8; 96];
    padded[..64].copy_from_slice(&sig_bytes);
    // bytes 64..96 remain zero (padding)
    padded
}

/// Verify a 96-byte ZeroTier signature against a message and verifying key.
///
/// Extracts the first 64 bytes as the Ed25519 signature and ignores
/// the 32-byte padding.
pub fn verify(
    verifying_key: &ed25519_dalek::VerifyingKey,
    message: &[u8],
    signature: &[u8; 96],
) -> Result<(), CryptoError> {
    use ed25519_dalek::Verifier;
    let sig_bytes: [u8; 64] = signature[..64]
        .try_into()
        .map_err(|_| CryptoError::SignatureError)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(message, &sig)
        .map_err(|_| CryptoError::SignatureError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    #[test]
    fn sign_produces_96_bytes() {
        let key = test_signing_key();
        let sig = sign(&key, b"test message");
        assert_eq!(sig.len(), 96);
    }

    #[test]
    fn sign_padding_is_zeroes() {
        let key = test_signing_key();
        let sig = sign(&key, b"test message");
        assert_eq!(&sig[64..96], &[0u8; 32]);
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let key = test_signing_key();
        let verifying = key.verifying_key();
        let sig = sign(&key, b"test message");
        assert!(verify(&verifying, b"test message", &sig).is_ok());
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let key = test_signing_key();
        let wrong_key = SigningKey::from_bytes(&[0x43u8; 32]);
        let wrong_verifying = wrong_key.verifying_key();
        let sig = sign(&key, b"test message");
        assert!(verify(&wrong_verifying, b"test message", &sig).is_err());
    }

    #[test]
    fn verify_with_wrong_message_fails() {
        let key = test_signing_key();
        let verifying = key.verifying_key();
        let sig = sign(&key, b"test message");
        assert!(verify(&verifying, b"wrong message", &sig).is_err());
    }

    #[test]
    fn verify_with_corrupted_signature_fails() {
        let key = test_signing_key();
        let verifying = key.verifying_key();
        let mut sig = sign(&key, b"test message");
        sig[0] ^= 0xff;
        assert!(verify(&verifying, b"test message", &sig).is_err());
    }
}
