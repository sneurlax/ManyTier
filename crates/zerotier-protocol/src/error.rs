use zerotier_crypto::error::CryptoError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    TooShort { need: usize, got: usize },
    InvalidPacket,
    InvalidFragment,
    InvalidAddress,
    InvalidVerb(u8),
    FragmentTimeout,
    UnsupportedVersion(u8),
    CryptoError(CryptoError),
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProtocolError::TooShort { need, got } => {
                write!(f, "packet too short: need {need} bytes, got {got}")
            }
            ProtocolError::InvalidPacket => f.write_str("invalid packet"),
            ProtocolError::InvalidFragment => f.write_str("invalid fragment"),
            ProtocolError::InvalidAddress => f.write_str("invalid address"),
            ProtocolError::InvalidVerb(verb) => write!(f, "invalid or unknown verb: {verb:#x}"),
            ProtocolError::FragmentTimeout => f.write_str("fragment reassembly timeout"),
            ProtocolError::UnsupportedVersion(version) => {
                write!(f, "unsupported protocol version: {version}")
            }
            ProtocolError::CryptoError(error) => write!(f, "crypto error: {error}"),
        }
    }
}

impl From<CryptoError> for ProtocolError {
    fn from(value: CryptoError) -> Self {
        ProtocolError::CryptoError(value)
    }
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
