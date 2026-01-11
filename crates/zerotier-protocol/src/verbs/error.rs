use crate::error::ProtocolError;
use crate::verb::Verb;
///
use alloc::vec::Vec;

/// ZeroTier V1 error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    None = 0x00,
    InvalidRequest = 0x01,
    BadProtocolVersion = 0x02,
    ObjectNotFound = 0x03,
    IdentityCollision = 0x04,
    UnsupportedOperation = 0x05,
    NeedMembershipCertificate = 0x06,
    NetworkAccessDenied = 0x07,
    UnwantedMulticast = 0x08,
    NetworkAuthenticationRequired = 0x09,
}

impl ErrorCode {
    /// Parse an error code from a raw byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(ErrorCode::None),
            0x01 => Some(ErrorCode::InvalidRequest),
            0x02 => Some(ErrorCode::BadProtocolVersion),
            0x03 => Some(ErrorCode::ObjectNotFound),
            0x04 => Some(ErrorCode::IdentityCollision),
            0x05 => Some(ErrorCode::UnsupportedOperation),
            0x06 => Some(ErrorCode::NeedMembershipCertificate),
            0x07 => Some(ErrorCode::NetworkAccessDenied),
            0x08 => Some(ErrorCode::UnwantedMulticast),
            0x09 => Some(ErrorCode::NetworkAuthenticationRequired),
            _ => None,
        }
    }

    /// Get the raw byte value of this error code.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Debug)]
pub struct ErrorPayload {
    pub in_re_verb: Verb,
    pub in_re_packet_id: u64,
    pub error_code: ErrorCode,
    pub payload: Vec<u8>,
}

impl ErrorPayload {
    /// Serialize this ERROR payload into the given buffer.
    /// Returns the number of bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0] = self.in_re_verb.to_byte();
        buf[1..9].copy_from_slice(&self.in_re_packet_id.to_be_bytes());
        buf[9] = self.error_code.to_byte();
        let payload_len = self.payload.len();
        if payload_len > 0 {
            buf[10..10 + payload_len].copy_from_slice(&self.payload);
        }
        10 + payload_len
    }

    /// Deserialize an ERROR payload from a byte slice.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 10 {
            return Err(ProtocolError::TooShort {
                need: 10,
                got: data.len(),
            });
        }

        let in_re_verb = Verb::from_byte(data[0]).ok_or(ProtocolError::InvalidVerb(data[0]))?;
        let in_re_packet_id = u64::from_be_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]);
        let error_code = ErrorCode::from_byte(data[9]).ok_or(ProtocolError::InvalidPacket)?;
        let payload = if data.len() > 10 {
            data[10..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            in_re_verb,
            in_re_packet_id,
            error_code,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_from_byte_all() {
        assert_eq!(ErrorCode::from_byte(0x00), Some(ErrorCode::None));
        assert_eq!(ErrorCode::from_byte(0x01), Some(ErrorCode::InvalidRequest));
        assert_eq!(
            ErrorCode::from_byte(0x02),
            Some(ErrorCode::BadProtocolVersion)
        );
        assert_eq!(ErrorCode::from_byte(0x03), Some(ErrorCode::ObjectNotFound));
        assert_eq!(
            ErrorCode::from_byte(0x04),
            Some(ErrorCode::IdentityCollision)
        );
        assert_eq!(
            ErrorCode::from_byte(0x05),
            Some(ErrorCode::UnsupportedOperation)
        );
        assert_eq!(
            ErrorCode::from_byte(0x06),
            Some(ErrorCode::NeedMembershipCertificate)
        );
        assert_eq!(
            ErrorCode::from_byte(0x07),
            Some(ErrorCode::NetworkAccessDenied)
        );
        assert_eq!(
            ErrorCode::from_byte(0x08),
            Some(ErrorCode::UnwantedMulticast)
        );
        assert_eq!(
            ErrorCode::from_byte(0x09),
            Some(ErrorCode::NetworkAuthenticationRequired)
        );
        assert_eq!(ErrorCode::from_byte(0x0a), None);
        assert_eq!(ErrorCode::from_byte(0xff), None);
    }

    #[test]
    fn error_payload_roundtrip_no_payload() {
        let err = ErrorPayload {
            in_re_verb: Verb::Hello,
            in_re_packet_id: 0x1234567890ABCDEF,
            error_code: ErrorCode::BadProtocolVersion,
            payload: Vec::new(),
        };

        let mut buf = [0u8; 64];
        let n = err.serialize(&mut buf);
        assert_eq!(n, 10);

        let parsed = ErrorPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.in_re_verb, Verb::Hello);
        assert_eq!(parsed.in_re_packet_id, 0x1234567890ABCDEF);
        assert_eq!(parsed.error_code, ErrorCode::BadProtocolVersion);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn error_payload_roundtrip_with_payload() {
        let err = ErrorPayload {
            in_re_verb: Verb::Whois,
            in_re_packet_id: 42,
            error_code: ErrorCode::ObjectNotFound,
            payload: alloc::vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let mut buf = [0u8; 64];
        let n = err.serialize(&mut buf);
        assert_eq!(n, 14);

        let parsed = ErrorPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.in_re_verb, Verb::Whois);
        assert_eq!(parsed.in_re_packet_id, 42);
        assert_eq!(parsed.error_code, ErrorCode::ObjectNotFound);
        assert_eq!(parsed.payload, alloc::vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn error_payload_wire_layout() {
        let err = ErrorPayload {
            in_re_verb: Verb::Hello,
            in_re_packet_id: 0x0102030405060708,
            error_code: ErrorCode::NetworkAuthenticationRequired,
            payload: Vec::new(),
        };

        let mut buf = [0u8; 64];
        let n = err.serialize(&mut buf);

        assert_eq!(buf[0], Verb::Hello.to_byte()); // in_re_verb
        assert_eq!(
            &buf[1..9],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        ); // packet ID
        assert_eq!(buf[9], 0x09); // NetworkAuthenticationRequired
        assert_eq!(n, 10);
    }

    #[test]
    fn error_deserialize_too_short() {
        let data = [0u8; 9];
        assert!(ErrorPayload::deserialize(&data).is_err());
    }

    #[test]
    fn error_roundtrip_all_codes() {
        let codes = [
            ErrorCode::None,
            ErrorCode::InvalidRequest,
            ErrorCode::BadProtocolVersion,
            ErrorCode::ObjectNotFound,
            ErrorCode::IdentityCollision,
            ErrorCode::UnsupportedOperation,
            ErrorCode::NeedMembershipCertificate,
            ErrorCode::NetworkAccessDenied,
            ErrorCode::UnwantedMulticast,
            ErrorCode::NetworkAuthenticationRequired,
        ];
        for code in codes {
            let err = ErrorPayload {
                in_re_verb: Verb::Hello,
                in_re_packet_id: 1,
                error_code: code,
                payload: Vec::new(),
            };
            let mut buf = [0u8; 64];
            let n = err.serialize(&mut buf);
            let parsed = ErrorPayload::deserialize(&buf[..n]).unwrap();
            assert_eq!(parsed.error_code, code);
        }
    }
}
