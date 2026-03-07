extern crate alloc;

use crate::error::ProtocolError;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMessagePayload {
    pub type_id: u64,
    pub data: Vec<u8>,
}

impl UserMessagePayload {
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0..8].copy_from_slice(&self.type_id.to_be_bytes());
        let dlen = self.data.len();
        buf[8..8 + dlen].copy_from_slice(&self.data);
        8 + dlen
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 8 {
            return Err(ProtocolError::TooShort {
                need: 8,
                got: data.len(),
            });
        }
        let type_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let payload_data = data[8..].to_vec();
        Ok(UserMessagePayload {
            type_id,
            data: payload_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn user_message_roundtrip() {
        let payload = UserMessagePayload {
            type_id: 0x1234567890ABCDEF,
            data: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 13);
        let parsed = UserMessagePayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn user_message_empty_data() {
        let payload = UserMessagePayload {
            type_id: 42,
            data: vec![],
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 8);
        let parsed = UserMessagePayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn user_message_too_short() {
        assert!(UserMessagePayload::deserialize(&[0; 7]).is_err());
    }
}
