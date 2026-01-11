/// FRAME (verb 0x06) and EXT_FRAME (verb 0x07) codecs.
///
/// FRAME wire format:
///
/// EXT_FRAME wire format:
use crate::error::ProtocolError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramePayload<'a> {
    pub network_id: u64,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> FramePayload<'a> {
    /// Zero-copy parse from wire bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, ProtocolError> {
        if data.len() < 10 {
            return Err(ProtocolError::TooShort {
                need: 10,
                got: data.len(),
            });
        }
        let network_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let ethertype = u16::from_be_bytes([data[8], data[9]]);
        let payload = &data[10..];

        Ok(FramePayload {
            network_id,
            ethertype,
            payload,
        })
    }

    /// Serialize into buffer, copying payload. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0..8].copy_from_slice(&self.network_id.to_be_bytes());
        buf[8..10].copy_from_slice(&self.ethertype.to_be_bytes());
        let plen = self.payload.len();
        buf[10..10 + plen].copy_from_slice(self.payload);
        10 + plen
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtFramePayload<'a> {
    pub network_id: u64,
    pub flags: u8,
    pub dest_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> ExtFramePayload<'a> {
    /// Zero-copy parse from wire bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, ProtocolError> {
        if data.len() < 23 {
            return Err(ProtocolError::TooShort {
                need: 23,
                got: data.len(),
            });
        }
        let network_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let flags = data[8];
        let mut dest_mac = [0u8; 6];
        dest_mac.copy_from_slice(&data[9..15]);
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&data[15..21]);
        let ethertype = u16::from_be_bytes([data[21], data[22]]);
        let payload = &data[23..];

        Ok(ExtFramePayload {
            network_id,
            flags,
            dest_mac,
            src_mac,
            ethertype,
            payload,
        })
    }

    /// Serialize into buffer, copying payload. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0..8].copy_from_slice(&self.network_id.to_be_bytes());
        buf[8] = self.flags;
        buf[9..15].copy_from_slice(&self.dest_mac);
        buf[15..21].copy_from_slice(&self.src_mac);
        buf[21..23].copy_from_slice(&self.ethertype.to_be_bytes());
        let plen = self.payload.len();
        buf[23..23 + plen].copy_from_slice(self.payload);
        23 + plen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let data = [0xAA; 100];
        let payload = FramePayload {
            network_id: 0x1234567890abcdef,
            ethertype: 0x0800,
            payload: &data,
        };
        let mut buf = [0u8; 256];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 110);
        let parsed = FramePayload::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.network_id, payload.network_id);
        assert_eq!(parsed.ethertype, payload.ethertype);
        assert_eq!(parsed.payload, &data[..]);
    }

    #[test]
    fn frame_empty_payload() {
        let payload = FramePayload {
            network_id: 1,
            ethertype: 0x0806,
            payload: &[],
        };
        let mut buf = [0u8; 32];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 10);
        let parsed = FramePayload::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.payload.len(), 0);
    }

    #[test]
    fn frame_too_short() {
        assert!(FramePayload::parse(&[0; 9]).is_err());
    }

    #[test]
    fn ext_frame_roundtrip() {
        let data = [0xBB; 50];
        let payload = ExtFramePayload {
            network_id: 0xfedcba9876543210,
            flags: 0x01,
            dest_mac: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            src_mac: [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            ethertype: 0x0800,
            payload: &data,
        };
        let mut buf = [0u8; 256];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 73);
        let parsed = ExtFramePayload::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.network_id, payload.network_id);
        assert_eq!(parsed.flags, payload.flags);
        assert_eq!(parsed.dest_mac, payload.dest_mac);
        assert_eq!(parsed.src_mac, payload.src_mac);
        assert_eq!(parsed.ethertype, payload.ethertype);
        assert_eq!(parsed.payload, &data[..]);
    }

    #[test]
    fn ext_frame_too_short() {
        assert!(ExtFramePayload::parse(&[0; 22]).is_err());
    }
}
