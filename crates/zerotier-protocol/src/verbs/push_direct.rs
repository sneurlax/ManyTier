/// PUSH_DIRECT_PATHS verb codec (verb 0x10).
///
extern crate alloc;

use crate::error::ProtocolError;
use crate::inet_address::InetAddress;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPath {
    pub flags: u16,
    pub address: InetAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushDirectPathsPayload {
    pub paths: Vec<DirectPath>,
}

impl PushDirectPathsPayload {
    /// Serialize into buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let count = self.paths.len() as u16;
        buf[0..2].copy_from_slice(&count.to_be_bytes());
        let mut offset = 2;

        for path in &self.paths {
            // flags
            buf[offset..offset + 2].copy_from_slice(&path.flags.to_be_bytes());
            offset += 2;
            // ext characteristics length = 0
            buf[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes());
            offset += 2;
            // address type and data
            match &path.address {
                InetAddress::V4 { ip, port } => {
                    buf[offset] = 4; // addr type
                    offset += 1;
                    buf[offset] = 6; // addr length: 4 ip + 2 port
                    offset += 1;
                    buf[offset..offset + 4].copy_from_slice(ip);
                    offset += 4;
                    buf[offset..offset + 2].copy_from_slice(&port.to_be_bytes());
                    offset += 2;
                }
                InetAddress::V6 { ip, port } => {
                    buf[offset] = 6; // addr type
                    offset += 1;
                    buf[offset] = 18; // addr length: 16 ip + 2 port
                    offset += 1;
                    buf[offset..offset + 16].copy_from_slice(ip);
                    offset += 16;
                    buf[offset..offset + 2].copy_from_slice(&port.to_be_bytes());
                    offset += 2;
                }
                InetAddress::Null => {
                    buf[offset] = 0;
                    offset += 1;
                    buf[offset] = 0;
                    offset += 1;
                }
            }
        }
        offset
    }

    /// Deserialize from wire bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 2 {
            return Err(ProtocolError::TooShort {
                need: 2,
                got: data.len(),
            });
        }
        let path_count = u16::from_be_bytes([data[0], data[1]]) as usize;
        let mut offset = 2;
        let mut paths = Vec::with_capacity(path_count);

        for _ in 0..path_count {
            if offset + 4 > data.len() {
                return Err(ProtocolError::TooShort {
                    need: offset + 4,
                    got: data.len(),
                });
            }
            let flags = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            // skip ext characteristics data
            offset += ext_len;

            if offset + 2 > data.len() {
                return Err(ProtocolError::TooShort {
                    need: offset + 2,
                    got: data.len(),
                });
            }
            let _addr_type = data[offset];
            offset += 1;
            let addr_len = data[offset] as usize;
            offset += 1;

            if offset + addr_len > data.len() {
                return Err(ProtocolError::TooShort {
                    need: offset + addr_len,
                    got: data.len(),
                });
            }

            let address = match addr_len {
                6 => {
                    let mut ip = [0u8; 4];
                    ip.copy_from_slice(&data[offset..offset + 4]);
                    let port = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
                    InetAddress::V4 { ip, port }
                }
                18 => {
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(&data[offset..offset + 16]);
                    let port = u16::from_be_bytes([data[offset + 16], data[offset + 17]]);
                    InetAddress::V6 { ip, port }
                }
                0 => InetAddress::Null,
                _ => return Err(ProtocolError::InvalidPacket),
            };
            offset += addr_len;

            paths.push(DirectPath { flags, address });
        }

        Ok(PushDirectPathsPayload { paths })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn push_direct_paths_roundtrip() {
        let payload = PushDirectPathsPayload {
            paths: vec![
                DirectPath {
                    flags: 0x0001,
                    address: InetAddress::V4 {
                        ip: [10, 0, 0, 1],
                        port: 9993,
                    },
                },
                DirectPath {
                    flags: 0x0000,
                    address: InetAddress::V6 {
                        ip: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                        port: 443,
                    },
                },
            ],
        };
        let mut buf = [0u8; 256];
        let n = payload.serialize(&mut buf);
        let parsed = PushDirectPathsPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn push_direct_paths_empty() {
        let payload = PushDirectPathsPayload { paths: vec![] };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 2);
        let parsed = PushDirectPathsPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.paths.len(), 0);
    }

    #[test]
    fn push_direct_paths_too_short() {
        assert!(PushDirectPathsPayload::deserialize(&[0]).is_err());
    }
}
