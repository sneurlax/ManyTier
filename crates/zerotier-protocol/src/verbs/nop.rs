use crate::error::ProtocolError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NopPayload;

impl NopPayload {
    pub fn serialize(&self, _buf: &mut [u8]) -> usize {
        0
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if !data.is_empty() {
            return Err(ProtocolError::InvalidPacket);
        }
        Ok(NopPayload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nop_roundtrip() {
        let payload = NopPayload;
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 0);
        let parsed = NopPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn nop_rejects_nonempty() {
        assert!(NopPayload::deserialize(&[0x01]).is_err());
    }
}
