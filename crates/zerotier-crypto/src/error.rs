/// Errors from cryptographic operations in the ZeroTier protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Input data has an invalid or unrecognized format.
    InvalidFormat,
    /// The identity type is not supported by this implementation.
    UnsupportedIdentityType,
    /// Key material has an incorrect length.
    InvalidKeyLength,
    /// A ZeroTier address failed validation.
    InvalidAddress,
    /// Proof-of-work check on an identity failed.
    PoWFailed,
    /// MAC verification failed.
    MacVerificationFailed,
    /// An error occurred during encryption.
    EncryptionError,
    /// A digital signature is invalid.
    SignatureError,
    /// Key agreement produced an invalid result.
    KeyAgreementError,
    /// Packet is too short for the requested operation.
    TooShort,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            CryptoError::InvalidFormat => "invalid format",
            CryptoError::UnsupportedIdentityType => "unsupported identity type",
            CryptoError::InvalidKeyLength => "invalid key length",
            CryptoError::InvalidAddress => "invalid address",
            CryptoError::PoWFailed => "proof of work failed",
            CryptoError::MacVerificationFailed => "MAC verification failed",
            CryptoError::EncryptionError => "encryption error",
            CryptoError::SignatureError => "signature error",
            CryptoError::KeyAgreementError => "key agreement error",
            CryptoError::TooShort => "packet too short",
        };
        f.write_str(message)
    }
}
