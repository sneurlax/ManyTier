extern crate alloc;

use crate::error::ProtocolError;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTracePayload {
    pub data: Vec<u8>,
}

impl RemoteTracePayload {
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let dlen = self.data.len();
        buf[..dlen].copy_from_slice(&self.data);
        dlen
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.is_empty() {
            return Err(ProtocolError::TooShort { need: 1, got: 0 });
        }
        Ok(RemoteTracePayload {
            data: data.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn remote_trace_roundtrip() {
        let payload = RemoteTracePayload {
            data: vec![0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00],
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 6);
        let parsed = RemoteTracePayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn remote_trace_single_byte() {
        let payload = RemoteTracePayload { data: vec![0xFF] };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 1);
        let parsed = RemoteTracePayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn remote_trace_empty_rejected() {
        assert!(RemoteTracePayload::deserialize(&[]).is_err());
    }
}
