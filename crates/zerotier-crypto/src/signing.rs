/// ZeroTier C25519 signing and verification helpers.
///
/// ZeroTier signs the first 32 bytes of `SHA-512(message)` with Ed25519 and
/// stores that 32-byte digest suffix alongside the 64-byte signature.
use crate::error::CryptoError;
use sha2::Digest;

/// Sign a message with an Ed25519 signing key.
///
/// Returns a 96-byte ZeroTier signature:
/// - bytes `0..64`: Ed25519 signature over `SHA-512(message)[..32]`
/// - bytes `64..96`: `SHA-512(message)[..32]`
pub fn sign(signing_key: &ed25519_dalek::SigningKey, message: &[u8]) -> [u8; 96] {
    use ed25519_dalek::Signer;
    let digest = sha2::Sha512::digest(message);
    let sig = signing_key.sign(&digest[..32]);
    let sig_bytes = sig.to_bytes();
    let mut signature = [0u8; 96];
    signature[..64].copy_from_slice(&sig_bytes);
    signature[64..].copy_from_slice(&digest[..32]);
    signature
}

/// Verify a 96-byte ZeroTier signature against a message and verifying key.
///
/// Verifies both the stored digest suffix and the Ed25519 signature over that
/// 32-byte digest.
pub fn verify(
    verifying_key: &ed25519_dalek::VerifyingKey,
    message: &[u8],
    signature: &[u8; 96],
) -> Result<(), CryptoError> {
    use ed25519_dalek::Verifier;
    let digest = sha2::Sha512::digest(message);
    if signature[64..] != digest[..32] {
        return Err(CryptoError::SignatureError);
    }
    let sig_bytes: [u8; 64] = signature[..64]
        .try_into()
        .map_err(|_| CryptoError::SignatureError)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(&digest[..32], &sig)
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
    fn sign_appends_message_digest_prefix() {
        let key = test_signing_key();
        let sig = sign(&key, b"test message");
        let digest = sha2::Sha512::digest(b"test message");
        assert_eq!(&sig[64..96], &digest[..32]);
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
