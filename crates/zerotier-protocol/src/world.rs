// World (Planet/Moon) binary format parser.
/// Binary format:

use alloc::vec::Vec;
use zerotier_crypto::identity::Identity;

use crate::constants::*;
use crate::error::ProtocolError;
use crate::identity_wire;
use crate::inet_address::InetAddress;

pub const WORLD_START_SENTINEL: [u8; 8] = [0x7f; 8];

pub const WORLD_END_SENTINEL: [u8; 8] = [0xf7; 8];

/// Minimum world binary size: 8 (start) + 1 (type) + 8 (id) + 8 (ts) + 64 (signing key) + 96 (sig) + 1 (root count) + 8 (end) = 194.
const WORLD_MIN_SIZE: usize = 194;

/// Default planet binary extracted from official ZeroTier installation.
/// Contains the official ZeroTier root server identities and endpoints.
/// Override at runtime via config file or CLI flag.
pub const DEFAULT_PLANET: &[u8] = include_bytes!("../../../tests/fixtures/planet.bin");

/// World type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorldType {
    /// Null/unknown world type.
    Null,
    /// Planet: global root server definition.
    Planet,
    /// Moon: custom root server definition.
    Moon,
}

impl WorldType {
    /// Convert a wire byte to a WorldType.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(WorldType::Null),
            1 => Some(WorldType::Planet),
            127 => Some(WorldType::Moon),
            _ => None,
        }
    }

    /// Convert to wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            WorldType::Null => 0,
            WorldType::Planet => 1,
            WorldType::Moon => 127,
        }
    }
}

/// A root server entry in a world definition.
#[derive(Debug)]
pub struct WorldRoot {
    pub identity: Identity,
    pub endpoints: Vec<InetAddress>,
}

/// A world definition (planet or moon).
#[derive(Debug)]
pub struct World {
    pub world_type: WorldType,
    /// Unique world identifier.
    pub id: u64,
    pub timestamp: u64,
    pub signing_key: [u8; 64],
    pub signature: [u8; 96],
    /// Root servers in this world.
    pub roots: Vec<WorldRoot>,
    /// Optional dictionary data (Moon-only, for future use).
    pub dict_data: Option<Vec<u8>>,
}

impl World {
    /// Deserialize a world definition from binary format.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < WORLD_MIN_SIZE {
            return Err(ProtocolError::TooShort {
                need: WORLD_MIN_SIZE,
                got: data.len(),
            });
        }

        // Check start sentinel
        if data[0..8] != WORLD_START_SENTINEL {
            return Err(ProtocolError::InvalidPacket);
        }

        // Check end sentinel
        if data[data.len() - 8..] != WORLD_END_SENTINEL {
            return Err(ProtocolError::InvalidPacket);
        }

        // Parse type
        let world_type = WorldType::from_byte(data[8]).ok_or(ProtocolError::InvalidPacket)?;

        // Parse world ID (u64 BE)
        let id = u64::from_be_bytes([
            data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
        ]);

        // Parse timestamp (u64 BE)
        let timestamp = u64::from_be_bytes([
            data[17], data[18], data[19], data[20], data[21], data[22], data[23], data[24],
        ]);

        // Copy signing key (64 bytes at offset 25)
        let mut signing_key = [0u8; 64];
        signing_key.copy_from_slice(&data[25..89]);

        // Copy signature (96 bytes at offset 89)
        let mut signature = [0u8; 96];
        signature.copy_from_slice(&data[89..185]);

        // Parse root count
        let root_count = data[185] as usize;
        if root_count > WORLD_MAX_ROOTS {
            return Err(ProtocolError::InvalidPacket);
        }

        let mut pos = 186;
        let end_pos = data.len() - 8; // before end sentinel

        let mut roots = Vec::with_capacity(root_count);
        for _ in 0..root_count {
            if pos >= end_pos {
                return Err(ProtocolError::TooShort {
                    need: pos + 1,
                    got: end_pos,
                });
            }

            // Deserialize identity
            let (identity, id_consumed) = identity_wire::deserialize_identity(&data[pos..])?;
            pos += id_consumed;

            if pos >= end_pos {
                return Err(ProtocolError::TooShort {
                    need: pos + 1,
                    got: end_pos,
                });
            }

            // Endpoint count
            let ep_count = data[pos] as usize;
            if ep_count > WORLD_MAX_ENDPOINTS_PER_ROOT {
                return Err(ProtocolError::InvalidPacket);
            }
            pos += 1;

            let mut endpoints = Vec::with_capacity(ep_count);
            for _ in 0..ep_count {
                if pos >= end_pos {
                    return Err(ProtocolError::TooShort {
                        need: pos + 1,
                        got: end_pos,
                    });
                }
                let (addr, addr_consumed) = InetAddress::deserialize(&data[pos..end_pos])?;
                endpoints.push(addr);
                pos += addr_consumed;
            }

            roots.push(WorldRoot {
                identity,
                endpoints,
            });
        }

        // Moon dict_data
        let dict_data = if world_type == WorldType::Moon {
            if pos + 2 > end_pos {
                return Err(ProtocolError::TooShort {
                    need: pos + 2,
                    got: end_pos,
                });
            }
            let dict_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if pos + dict_len > end_pos {
                return Err(ProtocolError::TooShort {
                    need: pos + dict_len,
                    got: end_pos,
                });
            }
            let dict = data[pos..pos + dict_len].to_vec();
            pos += dict_len;
            let _ = pos; // suppress unused warning
            Some(dict)
        } else {
            None
        };

        Ok(World {
            world_type,
            id,
            timestamp,
            signing_key,
            signature,
            roots,
            dict_data,
        })
    }

    /// Serialize this world definition to binary format.
    ///
    /// Returns the number of bytes written, or an error if the buffer is too small.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, ProtocolError> {
        let mut pos = 0;

        // Start sentinel
        buf[pos..pos + 8].copy_from_slice(&WORLD_START_SENTINEL);
        pos += 8;

        // Type
        buf[pos] = self.world_type.to_byte();
        pos += 1;

        // World ID
        buf[pos..pos + 8].copy_from_slice(&self.id.to_be_bytes());
        pos += 8;

        // Timestamp
        buf[pos..pos + 8].copy_from_slice(&self.timestamp.to_be_bytes());
        pos += 8;

        // Signing key
        buf[pos..pos + 64].copy_from_slice(&self.signing_key);
        pos += 64;

        // Signature
        buf[pos..pos + 96].copy_from_slice(&self.signature);
        pos += 96;

        // Root count
        buf[pos] = self.roots.len() as u8;
        pos += 1;

        // Roots
        for root in &self.roots {
            let id_written = identity_wire::serialize_identity_public(&root.identity, &mut buf[pos..]);
            pos += id_written;

            buf[pos] = root.endpoints.len() as u8;
            pos += 1;

            for ep in &root.endpoints {
                let ep_written = ep.serialize(&mut buf[pos..]);
                pos += ep_written;
            }
        }

        // Moon dict_data
        if self.world_type == WorldType::Moon {
            if let Some(ref dict) = self.dict_data {
                buf[pos..pos + 2].copy_from_slice(&(dict.len() as u16).to_be_bytes());
                pos += 2;
                buf[pos..pos + dict.len()].copy_from_slice(dict);
                pos += dict.len();
            } else {
                buf[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
                pos += 2;
            }
        }

        // End sentinel
        buf[pos..pos + 8].copy_from_slice(&WORLD_END_SENTINEL);
        pos += 8;

        Ok(pos)
    }

    /// Serialize the signed portion of this world definition.
    ///
    /// The signed portion includes everything between the sentinels except the
    /// signature itself: type + id + timestamp + signing_key + roots.
    /// Returns the number of bytes written.
    pub fn signed_portion(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;

        // Type
        buf[pos] = self.world_type.to_byte();
        pos += 1;

        // World ID
        buf[pos..pos + 8].copy_from_slice(&self.id.to_be_bytes());
        pos += 8;

        // Timestamp
        buf[pos..pos + 8].copy_from_slice(&self.timestamp.to_be_bytes());
        pos += 8;

        // Signing key
        buf[pos..pos + 64].copy_from_slice(&self.signing_key);
        pos += 64;

        // Root count
        buf[pos] = self.roots.len() as u8;
        pos += 1;

        // Roots
        for root in &self.roots {
            let id_written = identity_wire::serialize_identity_public(&root.identity, &mut buf[pos..]);
            pos += id_written;

            buf[pos] = root.endpoints.len() as u8;
            pos += 1;

            for ep in &root.endpoints {
                let ep_written = ep.serialize(&mut buf[pos..]);
                pos += ep_written;
            }
        }

        // Moon dict_data in signed portion
        if self.world_type == WorldType::Moon {
            if let Some(ref dict) = self.dict_data {
                buf[pos..pos + 2].copy_from_slice(&(dict.len() as u16).to_be_bytes());
                pos += 2;
                buf[pos..pos + dict.len()].copy_from_slice(dict);
                pos += dict.len();
            } else {
                buf[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
                pos += 2;
            }
        }

        pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use zerotier_crypto::identity::{Address, PublicKey};

    fn fixture_identity(addr_byte: u8) -> Identity {
        let address = Address::new([0xa0, 0xb1, 0xc2, 0xd3, addr_byte]).unwrap();
        let mut pk_bytes = [0u8; 64];
        for (i, b) in pk_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(addr_byte);
        }
        let public_key = PublicKey::from_bytes(&pk_bytes).unwrap();
        Identity {
            address,
            public_key,
            secret: None,
        }
    }

    fn new_test_world(world_type: WorldType, root_count: usize, ep_count: usize) -> World {
        let mut roots = Vec::new();
        for i in 0..root_count {
            let identity = fixture_identity(0xe0 + i as u8);
            let mut endpoints = Vec::new();
            for j in 0..ep_count {
                endpoints.push(InetAddress::V4 {
                    ip: [192, 168, i as u8, j as u8],
                    port: 9993,
                });
            }
            roots.push(WorldRoot {
                identity,
                endpoints,
            });
        }

        World {
            world_type,
            id: 149604618,
            timestamp: 1000000,
            signing_key: [0xAA; 64],
            signature: [0xBB; 96],
            roots,
            dict_data: None,
        }
    }

    #[test]
    fn deserialize_bad_start_sentinel_returns_err() {
        let mut data = [0u8; 200];
        // Wrong start sentinel
        data[0..8].copy_from_slice(&[0x00; 8]);
        // Correct end sentinel
        data[192..200].copy_from_slice(&WORLD_END_SENTINEL);
        assert!(World::deserialize(&data).is_err());
    }

    #[test]
    fn deserialize_bad_end_sentinel_returns_err() {
        let mut data = [0u8; 200];
        // Correct start sentinel
        data[0..8].copy_from_slice(&WORLD_START_SENTINEL);
        // Wrong end sentinel
        data[192..200].copy_from_slice(&[0x00; 8]);
        // Type = planet, 0 roots
        data[8] = WORLD_TYPE_PLANET;
        data[185] = 0; // 0 roots
        assert!(World::deserialize(&data).is_err());
    }

    #[test]
    fn deserialize_type_planet() {
        let world = new_test_world(WorldType::Planet, 0, 0);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();
        let parsed = World::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.world_type, WorldType::Planet);
    }

    #[test]
    fn deserialize_type_moon() {
        let mut world = new_test_world(WorldType::Moon, 0, 0);
        world.dict_data = Some(vec![]);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();
        let parsed = World::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.world_type, WorldType::Moon);
    }

    #[test]
    fn roundtrip_planet_2_roots_2_endpoints() {
        let world = new_test_world(WorldType::Planet, 2, 2);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();

        let parsed = World::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.world_type, world.world_type);
        assert_eq!(parsed.id, world.id);
        assert_eq!(parsed.timestamp, world.timestamp);
        assert_eq!(parsed.signing_key, world.signing_key);
        assert_eq!(parsed.signature, world.signature);
        assert_eq!(parsed.roots.len(), 2);
        for (orig, parsed_root) in world.roots.iter().zip(parsed.roots.iter()) {
            assert_eq!(orig.identity.address, parsed_root.identity.address);
            assert_eq!(orig.identity.public_key, parsed_root.identity.public_key);
            assert_eq!(orig.endpoints, parsed_root.endpoints);
        }
        assert!(parsed.dict_data.is_none());

        // Byte-for-byte round-trip
        let mut buf2 = [0u8; 2048];
        let n2 = parsed.serialize(&mut buf2).unwrap();
        assert_eq!(n, n2);
        assert_eq!(&buf[..n], &buf2[..n2]);
    }

    #[test]
    fn roundtrip_zero_roots() {
        let world = new_test_world(WorldType::Planet, 0, 0);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();
        let parsed = World::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.roots.len(), 0);
    }

    #[test]
    fn roundtrip_moon_with_dict_data() {
        let mut world = new_test_world(WorldType::Moon, 1, 1);
        world.dict_data = Some(vec![0x01, 0x02, 0x03, 0x04]);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();

        let parsed = World::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.world_type, WorldType::Moon);
        assert_eq!(parsed.dict_data, Some(vec![0x01, 0x02, 0x03, 0x04]));

        // Byte-for-byte round-trip
        let mut buf2 = [0u8; 2048];
        let n2 = parsed.serialize(&mut buf2).unwrap();
        assert_eq!(n, n2);
        assert_eq!(&buf[..n], &buf2[..n2]);
    }

    #[test]
    fn root_identity_parseable() {
        let world = new_test_world(WorldType::Planet, 1, 1);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();
        let parsed = World::deserialize(&buf[..n]).unwrap();
        // Identity was successfully parsed via identity_wire::deserialize_identity
        assert_eq!(parsed.roots[0].identity.address, world.roots[0].identity.address);
        assert_eq!(parsed.roots[0].identity.public_key, world.roots[0].identity.public_key);
    }

    #[test]
    fn root_endpoints_parseable() {
        let world = new_test_world(WorldType::Planet, 1, 2);
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();
        let parsed = World::deserialize(&buf[..n]).unwrap();
        assert_eq!(parsed.roots[0].endpoints.len(), 2);
        assert_eq!(parsed.roots[0].endpoints, world.roots[0].endpoints);
    }

    #[test]
    fn default_planet_parses() {
        let world = World::deserialize(DEFAULT_PLANET).expect("default planet should parse");
        assert_eq!(world.world_type, WorldType::Planet);
        assert_eq!(world.id, WORLD_ID_EARTH); // 149604618
        assert!(!world.roots.is_empty(), "planet must have at least one root");
        for root in &world.roots {
            assert!(!root.endpoints.is_empty(), "each root must have endpoints");
        }
    }

    #[test]
    fn default_planet_has_4_roots() {
        let world = World::deserialize(DEFAULT_PLANET).unwrap();
        assert_eq!(world.roots.len(), 4);
    }

    #[test]
    fn too_short_data_returns_err() {
        let data = [0u8; 10];
        assert!(World::deserialize(&data).is_err());
    }

    #[test]
    fn world_type_from_byte() {
        assert_eq!(WorldType::from_byte(0), Some(WorldType::Null));
        assert_eq!(WorldType::from_byte(1), Some(WorldType::Planet));
        assert_eq!(WorldType::from_byte(127), Some(WorldType::Moon));
        assert_eq!(WorldType::from_byte(2), None);
        assert_eq!(WorldType::from_byte(255), None);
    }

    #[test]
    fn world_type_to_byte() {
        assert_eq!(WorldType::Null.to_byte(), 0);
        assert_eq!(WorldType::Planet.to_byte(), 1);
        assert_eq!(WorldType::Moon.to_byte(), 127);
    }

    #[test]
    fn signed_portion_excludes_sentinels_and_signature() {
        let world = new_test_world(WorldType::Planet, 1, 1);
        let mut buf = [0u8; 2048];
        let n = world.signed_portion(&mut buf);
        // signed_portion should NOT contain sentinels or signature
        // It should start with the type byte
        assert_eq!(buf[0], WORLD_TYPE_PLANET);
        // It should contain type(1) + id(8) + ts(8) + signing_key(64) + root_count(1) + root data
        assert!(n > 82); // at minimum type+id+ts+key+count
    }
}
