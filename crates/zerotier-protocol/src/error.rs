use zerotier_crypto::error::CryptoError;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("packet too short: need {need} bytes, got {got}")]
    TooShort { need: usize, got: usize },

    #[error("invalid packet")]
    InvalidPacket,

    #[error("invalid fragment")]
    InvalidFragment,

    #[error("invalid address")]
    InvalidAddress,

    #[error("invalid or unknown verb: {0:#x}")]
    InvalidVerb(u8),

    #[error("fragment reassembly timeout")]
    FragmentTimeout,

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("crypto error: {0}")]
    CryptoError(#[from] CryptoError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_short_error_message() {
        let err = ProtocolError::TooShort { need: 28, got: 10 };
        let msg = alloc::format!("{}", err);
        assert!(msg.contains("28"));
        assert!(msg.contains("10"));
    }

    #[test]
    fn invalid_verb_error_message() {
        let err = ProtocolError::InvalidVerb(0xff);
        let msg = alloc::format!("{}", err);
        assert!(msg.contains("0xff"));
    }

    #[test]
    fn unsupported_version_error_message() {
        let err = ProtocolError::UnsupportedVersion(3);
        let msg = alloc::format!("{}", err);
        assert!(msg.contains("3"));
    }

    #[test]
    fn crypto_error_conversion() {
        let crypto_err = CryptoError::InvalidFormat;
        let proto_err: ProtocolError = crypto_err.into();
        assert!(matches!(proto_err, ProtocolError::CryptoError(_)));
    }

    #[test]
    fn all_variants_exist() {
        // Verify all variants can be constructed
        let _ = ProtocolError::TooShort { need: 0, got: 0 };
        let _ = ProtocolError::InvalidPacket;
        let _ = ProtocolError::InvalidFragment;
        let _ = ProtocolError::InvalidAddress;
        let _ = ProtocolError::InvalidVerb(0);
        let _ = ProtocolError::FragmentTimeout;
        let _ = ProtocolError::UnsupportedVersion(0);
        let _ = ProtocolError::CryptoError(CryptoError::InvalidFormat);
    }
}
