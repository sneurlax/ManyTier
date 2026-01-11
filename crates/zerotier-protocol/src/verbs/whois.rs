use crate::error::ProtocolError;
use crate::identity_wire;
///
/// WHOIS request: sequence of 5-byte ZeroTier addresses.
/// WHOIS response (OK(WHOIS)): sequence of serialized identities.
use alloc::vec::Vec;
use zerotier_crypto::identity::Identity;

/// WHOIS request payload: a list of 5-byte ZeroTier addresses to look up.
#[derive(Debug, Clone)]
pub struct WhoisRequest {
    pub addresses: Vec<[u8; 5]>,
}

impl WhoisRequest {
    /// Serialize the WHOIS request into the given buffer.
    /// Returns the number of bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        for addr in &self.addresses {
            buf[pos..pos + 5].copy_from_slice(addr);
            pos += 5;
        }
        pos
    }

    /// Deserialize a WHOIS request from the given data.
    /// Parses as many complete 5-byte addresses as are present.
    /// Any trailing partial address bytes are ignored.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        // See ZeroTierOne 1.14.2 node/IncomingPacket.cpp:714-717.
        let count = data.len() / 5;
        let mut addresses = Vec::with_capacity(count);
        for i in 0..count {
            let mut addr = [0u8; 5];
            addr.copy_from_slice(&data[i * 5..(i + 1) * 5]);
            addresses.push(addr);
        }

        Ok(Self { addresses })
    }
}

/// WHOIS response payload: a list of identities.
#[derive(Debug)]
pub struct WhoisResponse {
    pub identities: Vec<Identity>,
}

impl WhoisResponse {
    /// Serialize the WHOIS response into the given buffer.
    /// Returns the number of bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        for id in &self.identities {
            let n = identity_wire::serialize_identity_public(id, &mut buf[pos..]);
            pos += n;
        }
        pos
    }

    /// Deserialize a WHOIS response from the given data.
    /// Repeatedly deserializes identities until data is exhausted.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        let mut identities = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let (id, consumed) = identity_wire::deserialize_identity(&data[pos..])?;
            identities.push(id);
            pos += consumed;
        }

        Ok(Self { identities })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerotier_crypto::identity::{Address, PublicKey};

    fn stub_identity_with_addr(addr_bytes: [u8; 5]) -> Identity {
        let address = Address::new(addr_bytes).unwrap();
        let mut pk_bytes = [0u8; 64];
        for (i, b) in pk_bytes.iter_mut().enumerate() {
            *b = (i + addr_bytes[0] as usize) as u8;
        }
        let public_key = PublicKey::from_bytes(&pk_bytes).unwrap();
        Identity {
            address,
            public_key,
            secret: None,
        }
    }

    #[test]
    fn whois_request_one_address() {
        let req = WhoisRequest {
            addresses: alloc::vec![[0xa0, 0xb1, 0xc2, 0xd3, 0xe4]],
        };
        let mut buf = [0u8; 64];
        let n = req.serialize(&mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], &[0xa0, 0xb1, 0xc2, 0xd3, 0xe4]);
    }

    #[test]
    fn whois_request_three_addresses() {
        let req = WhoisRequest {
            addresses: alloc::vec![
                [0x01, 0x02, 0x03, 0x04, 0x05],
                [0x11, 0x12, 0x13, 0x14, 0x15],
                [0x21, 0x22, 0x23, 0x24, 0x25],
            ],
        };
        let mut buf = [0u8; 64];
        let n = req.serialize(&mut buf);
        assert_eq!(n, 15);
    }

    #[test]
    fn whois_request_roundtrip() {
        let req = WhoisRequest {
            addresses: alloc::vec![
                [0xa0, 0xb1, 0xc2, 0xd3, 0xe4],
                [0x10, 0x20, 0x30, 0x40, 0x50],
                [0x55, 0x66, 0x77, 0x88, 0x99],
            ],
        };
        let mut buf = [0u8; 64];
        let n = req.serialize(&mut buf);

        let parsed = WhoisRequest::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.addresses.len(), 3);
        assert_eq!(parsed.addresses[0], [0xa0, 0xb1, 0xc2, 0xd3, 0xe4]);
        assert_eq!(parsed.addresses[1], [0x10, 0x20, 0x30, 0x40, 0x50]);
        assert_eq!(parsed.addresses[2], [0x55, 0x66, 0x77, 0x88, 0x99]);
    }

    #[test]
    fn whois_request_empty() {
        let req = WhoisRequest {
            addresses: alloc::vec![],
        };
        let mut buf = [0u8; 64];
        let n = req.serialize(&mut buf);
        assert_eq!(n, 0);

        let parsed = WhoisRequest::deserialize(&buf[..n]).unwrap();
        assert!(parsed.addresses.is_empty());
    }

    #[test]
    fn whois_request_ignores_trailing_partial_address() {
        let data = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xff, 0xee];
        let parsed = WhoisRequest::deserialize(&data).unwrap();

        assert_eq!(
            parsed.addresses,
            alloc::vec![[0xa0, 0xb1, 0xc2, 0xd3, 0xe4]]
        );
    }

    #[test]
    fn whois_request_short_trailing_bytes_parse_as_empty() {
        let parsed = WhoisRequest::deserialize(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        assert!(parsed.addresses.is_empty());
    }

    #[test]
    fn whois_response_roundtrip() {
        let addr1 = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let addr2 = [0x10, 0x20, 0x30, 0x40, 0x50];
        let id1 = stub_identity_with_addr(addr1);
        let id2 = stub_identity_with_addr(addr2);

        let resp = WhoisResponse {
            identities: alloc::vec![id1, id2],
        };
        let mut buf = [0u8; 256];
        let n = resp.serialize(&mut buf);
        assert_eq!(n, 71 * 2);

        let parsed = WhoisResponse::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.identities.len(), 2);
        assert_eq!(parsed.identities[0].address, Address::new(addr1).unwrap());
        assert_eq!(parsed.identities[1].address, Address::new(addr2).unwrap());
    }

    #[test]
    fn whois_response_empty() {
        let parsed = WhoisResponse::deserialize(&[]).unwrap();
        assert!(parsed.identities.is_empty());
    }
}
