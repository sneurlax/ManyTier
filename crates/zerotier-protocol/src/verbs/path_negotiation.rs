use crate::error::ProtocolError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathNegotiationRequestPayload {
    pub utility: i16,
}

impl PathNegotiationRequestPayload {
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0..2].copy_from_slice(&self.utility.to_be_bytes());
        2
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 2 {
            return Err(ProtocolError::TooShort {
                need: 2,
                got: data.len(),
            });
        }
        let utility = i16::from_be_bytes([data[0], data[1]]);
        Ok(PathNegotiationRequestPayload { utility })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_negotiation_roundtrip_positive() {
        let payload = PathNegotiationRequestPayload { utility: 12345 };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 2);
        let parsed = PathNegotiationRequestPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn path_negotiation_roundtrip_negative() {
        let payload = PathNegotiationRequestPayload { utility: -32768 };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        let parsed = PathNegotiationRequestPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.utility, -32768);
    }

    #[test]
    fn path_negotiation_zero() {
        let payload = PathNegotiationRequestPayload { utility: 0 };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        let parsed = PathNegotiationRequestPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.utility, 0);
    }

    #[test]
    fn path_negotiation_too_short() {
        assert!(PathNegotiationRequestPayload::deserialize(&[0]).is_err());
        assert!(PathNegotiationRequestPayload::deserialize(&[]).is_err());
    }
}
