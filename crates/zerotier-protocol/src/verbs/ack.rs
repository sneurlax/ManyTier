use crate::error::ProtocolError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckPayload {
    pub bytes_acked: u32,
}

impl AckPayload {
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0..4].copy_from_slice(&self.bytes_acked.to_be_bytes());
        4
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 4 {
            return Err(ProtocolError::TooShort {
                need: 4,
                got: data.len(),
            });
        }
        let bytes_acked = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        Ok(AckPayload { bytes_acked })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_roundtrip() {
        let payload = AckPayload {
            bytes_acked: 0xDEADBEEF,
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 4);
        let parsed = AckPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn ack_zero() {
        let payload = AckPayload { bytes_acked: 0 };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        let parsed = AckPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.bytes_acked, 0);
    }

    #[test]
    fn ack_too_short() {
        assert!(AckPayload::deserialize(&[0; 3]).is_err());
    }
}
