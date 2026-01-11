/// RENDEZVOUS verb codec (verb 0x05).
///
use crate::error::ProtocolError;
use crate::inet_address::InetAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousPayload {
    pub flags: u8,
    pub peer_address: [u8; 5],
    pub address: InetAddress,
}

impl RendezvousPayload {
    /// Serialize into buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0] = self.flags;
        buf[1..6].copy_from_slice(&self.peer_address);
        // Write address type, then length byte, then raw address bytes
        match &self.address {
            InetAddress::V4 { ip, port } => {
                buf[6] = 4; // type
                buf[7] = 6; // length: 4 ip + 2 port
                buf[8..12].copy_from_slice(ip);
                buf[12..14].copy_from_slice(&port.to_be_bytes());
                14
            }
            InetAddress::V6 { ip, port } => {
                buf[6] = 6; // type
                buf[7] = 18; // length: 16 ip + 2 port
                buf[8..24].copy_from_slice(ip);
                buf[24..26].copy_from_slice(&port.to_be_bytes());
                26
            }
            InetAddress::Null => {
                buf[6] = 0; // type
                buf[7] = 0; // length
                8
            }
        }
    }

    /// Deserialize from wire bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 8 {
            return Err(ProtocolError::TooShort {
                need: 8,
                got: data.len(),
            });
        }
        let flags = data[0];
        let mut peer_address = [0u8; 5];
        peer_address.copy_from_slice(&data[1..6]);
        let _addr_type = data[6];
        let addr_len = data[7] as usize;

        if data.len() < 8 + addr_len {
            return Err(ProtocolError::TooShort {
                need: 8 + addr_len,
                got: data.len(),
            });
        }

        let address = match addr_len {
            6 => {
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&data[8..12]);
                let port = u16::from_be_bytes([data[12], data[13]]);
                InetAddress::V4 { ip, port }
            }
            18 => {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&data[8..24]);
                let port = u16::from_be_bytes([data[24], data[25]]);
                InetAddress::V6 { ip, port }
            }
            0 => InetAddress::Null,
            _ => return Err(ProtocolError::InvalidPacket),
        };

        Ok(RendezvousPayload {
            flags,
            peer_address,
            address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendezvous_v4_roundtrip() {
        let payload = RendezvousPayload {
            flags: 0x00,
            peer_address: [0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            address: InetAddress::V4 {
                ip: [192, 168, 1, 1],
                port: 9993,
            },
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 14);
        let parsed = RendezvousPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn rendezvous_v6_roundtrip() {
        let payload = RendezvousPayload {
            flags: 0x01,
            peer_address: [0x01, 0x02, 0x03, 0x04, 0x05],
            address: InetAddress::V6 {
                ip: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                port: 443,
            },
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 26);
        let parsed = RendezvousPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn rendezvous_too_short() {
        assert!(RendezvousPayload::deserialize(&[0; 7]).is_err());
    }
}
