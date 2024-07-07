// Network config verb codecs.

extern crate alloc;

use alloc::vec::Vec;
use crate::error::ProtocolError;

/// NETWORK_CONFIG_REQUEST payload.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfigRequestPayload {
    pub network_id: u64,
    pub dict_data: Vec<u8>,
}

impl NetworkConfigRequestPayload {
    /// Serialize into buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0..8].copy_from_slice(&self.network_id.to_be_bytes());
        let dict_len = self.dict_data.len() as u16;
        buf[8..10].copy_from_slice(&dict_len.to_be_bytes());
        buf[10..10 + self.dict_data.len()].copy_from_slice(&self.dict_data);
        10 + self.dict_data.len()
    }

    /// Deserialize from wire bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 10 {
            return Err(ProtocolError::TooShort {
                need: 10,
                got: data.len(),
            });
        }
        let network_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let dict_len = u16::from_be_bytes([data[8], data[9]]) as usize;
        if data.len() < 10 + dict_len {
            return Err(ProtocolError::TooShort {
                need: 10 + dict_len,
                got: data.len(),
            });
        }
        let dict_data = data[10..10 + dict_len].to_vec();
        Ok(NetworkConfigRequestPayload {
            network_id,
            dict_data,
        })
    }
}

/// NETWORK_CONFIG payload.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfigPayload {
    pub network_id: u64,
    pub dict_data: Vec<u8>,
    pub chunk_index: Option<u16>,
    pub total_chunks: Option<u16>,
    pub signature: Option<[u8; 64]>,
}

impl NetworkConfigPayload {
    /// Serialize into buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0..8].copy_from_slice(&self.network_id.to_be_bytes());
        let dict_len = self.dict_data.len() as u16;
        buf[8..10].copy_from_slice(&dict_len.to_be_bytes());
        let dict_end = 10 + self.dict_data.len();
        buf[10..dict_end].copy_from_slice(&self.dict_data);

        let mut offset = dict_end;
        if let (Some(ci), Some(tc), Some(ref sig)) =
            (self.chunk_index, self.total_chunks, &self.signature)
        {
            buf[offset..offset + 2].copy_from_slice(&ci.to_be_bytes());
            offset += 2;
            buf[offset..offset + 2].copy_from_slice(&tc.to_be_bytes());
            offset += 2;
            buf[offset..offset + 64].copy_from_slice(sig);
            offset += 64;
        }
        offset
    }

    /// Deserialize from wire bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 10 {
            return Err(ProtocolError::TooShort {
                need: 10,
                got: data.len(),
            });
        }
        let network_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let dict_len = u16::from_be_bytes([data[8], data[9]]) as usize;
        if data.len() < 10 + dict_len {
            return Err(ProtocolError::TooShort {
                need: 10 + dict_len,
                got: data.len(),
            });
        }
        let dict_data = data[10..10 + dict_len].to_vec();
        let dict_end = 10 + dict_len;

        // Check for optional multipart fields (2+2+64 = 68 bytes)
        let (chunk_index, total_chunks, signature) = if data.len() >= dict_end + 68 {
            let ci = u16::from_be_bytes([data[dict_end], data[dict_end + 1]]);
            let tc = u16::from_be_bytes([data[dict_end + 2], data[dict_end + 3]]);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&data[dict_end + 4..dict_end + 68]);
            (Some(ci), Some(tc), Some(sig))
        } else {
            (None, None, None)
        };

        Ok(NetworkConfigPayload {
            network_id,
            dict_data,
            chunk_index,
            total_chunks,
            signature,
        })
    }
}

/// A single COM qualifier tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComQualifier {
    pub id: u64,
    pub value: u64,
    pub max_delta: u64,
}

/// Certificate of Membership.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateOfMembership {
    pub qualifiers: Vec<ComQualifier>,
    pub signer_address: [u8; 5],
    pub signature: [u8; 96],
}

impl CertificateOfMembership {
    /// Serialize into buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let count = self.qualifiers.len() as u16;
        buf[0..2].copy_from_slice(&count.to_be_bytes());
        let mut offset = 2;

        for q in &self.qualifiers {
            buf[offset..offset + 8].copy_from_slice(&q.id.to_be_bytes());
            offset += 8;
            buf[offset..offset + 8].copy_from_slice(&q.value.to_be_bytes());
            offset += 8;
            buf[offset..offset + 8].copy_from_slice(&q.max_delta.to_be_bytes());
            offset += 8;
        }

        buf[offset..offset + 5].copy_from_slice(&self.signer_address);
        offset += 5;
        buf[offset..offset + 96].copy_from_slice(&self.signature);
        offset += 96;
        offset
    }

    /// Deserialize from wire bytes. Returns the COM and bytes consumed.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), ProtocolError> {
        if data.len() < 2 {
            return Err(ProtocolError::TooShort {
                need: 2,
                got: data.len(),
            });
        }
        let count = u16::from_be_bytes([data[0], data[1]]) as usize;
        let needed = 2 + count * 24 + 5 + 96;
        if data.len() < needed {
            return Err(ProtocolError::TooShort {
                need: needed,
                got: data.len(),
            });
        }

        let mut offset = 2;
        let mut qualifiers = Vec::with_capacity(count);
        for _ in 0..count {
            let id = u64::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            offset += 8;
            let value = u64::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            offset += 8;
            let max_delta = u64::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            offset += 8;
            qualifiers.push(ComQualifier {
                id,
                value,
                max_delta,
            });
        }

        let mut signer_address = [0u8; 5];
        signer_address.copy_from_slice(&data[offset..offset + 5]);
        offset += 5;

        let mut signature = [0u8; 96];
        signature.copy_from_slice(&data[offset..offset + 96]);
        offset += 96;

        Ok((
            CertificateOfMembership {
                qualifiers,
                signer_address,
                signature,
            },
            offset,
        ))
    }
}

/// NETWORK_CREDENTIALS payload (verb 0x0a).
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkCredentialsPayload {
    pub com: Option<CertificateOfMembership>,
        pub capabilities_raw: Vec<u8>,
        pub tags_raw: Vec<u8>,
        pub revocations_raw: Vec<u8>,
        pub coo_raw: Vec<u8>,
}

impl NetworkCredentialsPayload {
    /// Serialize into buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let mut offset = 0;

        // COM section
        if let Some(ref com) = self.com {
            buf[offset] = 1; // has_com
            offset += 1;
            let com_len = com.serialize(&mut buf[offset..]);
            offset += com_len;
        } else {
            buf[offset] = 0; // no COM
            offset += 1;
        }

        // Capabilities raw blob
        let cap_len = self.capabilities_raw.len() as u16;
        buf[offset..offset + 2].copy_from_slice(&cap_len.to_be_bytes());
        offset += 2;
        if !self.capabilities_raw.is_empty() {
            buf[offset..offset + self.capabilities_raw.len()]
                .copy_from_slice(&self.capabilities_raw);
            offset += self.capabilities_raw.len();
        }

        // Tags raw blob
        let tag_len = self.tags_raw.len() as u16;
        buf[offset..offset + 2].copy_from_slice(&tag_len.to_be_bytes());
        offset += 2;
        if !self.tags_raw.is_empty() {
            buf[offset..offset + self.tags_raw.len()].copy_from_slice(&self.tags_raw);
            offset += self.tags_raw.len();
        }

        // Revocations raw blob
        let rev_len = self.revocations_raw.len() as u16;
        buf[offset..offset + 2].copy_from_slice(&rev_len.to_be_bytes());
        offset += 2;
        if !self.revocations_raw.is_empty() {
            buf[offset..offset + self.revocations_raw.len()]
                .copy_from_slice(&self.revocations_raw);
            offset += self.revocations_raw.len();
        }

        // COO raw blob
        let coo_len = self.coo_raw.len() as u16;
        buf[offset..offset + 2].copy_from_slice(&coo_len.to_be_bytes());
        offset += 2;
        if !self.coo_raw.is_empty() {
            buf[offset..offset + self.coo_raw.len()].copy_from_slice(&self.coo_raw);
            offset += self.coo_raw.len();
        }

        offset
    }

    /// Deserialize from wire bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.is_empty() {
            return Err(ProtocolError::TooShort {
                need: 1,
                got: 0,
            });
        }

        let mut offset = 0;

        // COM section
        let has_com = data[offset];
        offset += 1;
        let com = if has_com != 0 {
            let (com, consumed) = CertificateOfMembership::deserialize(&data[offset..])?;
            offset += consumed;
            Some(com)
        } else {
            None
        };

        // Read raw section: u16 length prefix then raw bytes
        fn read_raw_section(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, ProtocolError> {
            if *offset + 2 > data.len() {
                return Err(ProtocolError::TooShort {
                    need: *offset + 2,
                    got: data.len(),
                });
            }
            let len = u16::from_be_bytes([data[*offset], data[*offset + 1]]) as usize;
            *offset += 2;
            if *offset + len > data.len() {
                return Err(ProtocolError::TooShort {
                    need: *offset + len,
                    got: data.len(),
                });
            }
            let raw = data[*offset..*offset + len].to_vec();
            *offset += len;
            Ok(raw)
        }

        let capabilities_raw = read_raw_section(data, &mut offset)?;
        let tags_raw = read_raw_section(data, &mut offset)?;
        let revocations_raw = read_raw_section(data, &mut offset)?;
        let coo_raw = read_raw_section(data, &mut offset)?;

        Ok(NetworkCredentialsPayload {
            com,
            capabilities_raw,
            tags_raw,
            revocations_raw,
            coo_raw,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn network_config_request_roundtrip() {
        let payload = NetworkConfigRequestPayload {
            network_id: 0x1234567890abcdef,
            dict_data: vec![0x61, 0x3d, 0x62, 0x0a], // "a=b\n"
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 14);
        let parsed = NetworkConfigRequestPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn network_config_request_empty_dict() {
        let payload = NetworkConfigRequestPayload {
            network_id: 1,
            dict_data: vec![],
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 10);
        let parsed = NetworkConfigRequestPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn network_config_request_too_short() {
        assert!(NetworkConfigRequestPayload::deserialize(&[0; 9]).is_err());
    }

    #[test]
    fn network_config_single_chunk() {
        let payload = NetworkConfigPayload {
            network_id: 0xfedcba9876543210,
            dict_data: vec![1, 2, 3, 4, 5],
            chunk_index: None,
            total_chunks: None,
            signature: None,
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        assert_eq!(n, 15); // 8 + 2 + 5
        let parsed = NetworkConfigPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn network_config_multipart() {
        let mut sig = [0u8; 64];
        for (i, b) in sig.iter_mut().enumerate() {
            *b = i as u8;
        }
        let payload = NetworkConfigPayload {
            network_id: 0x1122334455667788,
            dict_data: vec![0xAA, 0xBB],
            chunk_index: Some(0),
            total_chunks: Some(3),
            signature: Some(sig),
        };
        let mut buf = [0u8; 256];
        let n = payload.serialize(&mut buf);
        // 8 + 2 + 2 + 2 + 2 + 64 = 80
        assert_eq!(n, 80);
        let parsed = NetworkConfigPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn com_roundtrip() {
        let mut sig = [0u8; 96];
        for (i, b) in sig.iter_mut().enumerate() {
            *b = (i * 3) as u8;
        }
        let com = CertificateOfMembership {
            qualifiers: vec![
                ComQualifier {
                    id: 0,
                    value: 0x1234567890abcdef,
                    max_delta: 0,
                },
                ComQualifier {
                    id: 1,
                    value: 1000,
                    max_delta: 100,
                },
                ComQualifier {
                    id: 2,
                    value: 0xdeadbeef,
                    max_delta: 0xffffffffffffffff,
                },
            ],
            signer_address: [0xa0, 0xb1, 0xc2, 0xd3, 0xe4],
            signature: sig,
        };
        let mut buf = [0u8; 512];
        let n = com.serialize(&mut buf);
        // 2 + 3*24 + 5 + 96 = 175
        assert_eq!(n, 175);
        let (parsed, consumed) = CertificateOfMembership::deserialize(&buf[..n]).unwrap();
        assert_eq!(consumed, n);
        assert_eq!(parsed, com);
    }

    #[test]
    fn com_96_byte_signature() {
        let mut sig = [0xAA; 96];
        sig[0] = 0x01;
        sig[95] = 0xFF;
        let com = CertificateOfMembership {
            qualifiers: vec![],
            signer_address: [0x11, 0x22, 0x33, 0x44, 0x55],
            signature: sig,
        };
        let mut buf = [0u8; 256];
        let n = com.serialize(&mut buf);
        // 2 + 0 + 5 + 96 = 103
        assert_eq!(n, 103);
        let (parsed, _) = CertificateOfMembership::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.signature[0], 0x01);
        assert_eq!(parsed.signature[95], 0xFF);
        assert_eq!(parsed.signature.len(), 96);
    }

    #[test]
    fn network_credentials_with_com() {
        let mut sig = [0u8; 96];
        sig[0] = 0xDE;
        let com = CertificateOfMembership {
            qualifiers: vec![ComQualifier {
                id: 0,
                value: 42,
                max_delta: 10,
            }],
            signer_address: [0x01, 0x02, 0x03, 0x04, 0x05],
            signature: sig,
        };
        let payload = NetworkCredentialsPayload {
            com: Some(com),
            capabilities_raw: vec![0x01, 0x02],
            tags_raw: vec![],
            revocations_raw: vec![0xAA],
            coo_raw: vec![],
        };
        let mut buf = [0u8; 512];
        let n = payload.serialize(&mut buf);
        let parsed = NetworkCredentialsPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn network_credentials_without_com() {
        let payload = NetworkCredentialsPayload {
            com: None,
            capabilities_raw: vec![],
            tags_raw: vec![],
            revocations_raw: vec![],
            coo_raw: vec![],
        };
        let mut buf = [0u8; 64];
        let n = payload.serialize(&mut buf);
        // 1 (has_com=0) + 4*2 (section lengths) = 9
        assert_eq!(n, 9);
        let parsed = NetworkCredentialsPayload::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn network_credentials_too_short() {
        assert!(NetworkCredentialsPayload::deserialize(&[]).is_err());
    }
}
