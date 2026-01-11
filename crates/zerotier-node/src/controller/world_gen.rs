//! Moon and planet world file generation.
//!
//! Generates signed World binaries for custom root server definitions.
//! Uses the existing World struct from zerotier-protocol for serialization,
//! and the Ed25519 signing from zerotier-crypto for signature generation.

extern crate alloc;

use alloc::vec::Vec;
use zerotier_crypto::signing;
use zerotier_protocol::world::{World, WorldRoot, WorldType};

/// Generate a moon world file binary.
///
/// A moon is a custom root definition (world_type = 0x7f / 127).
/// It contains root server identities and their stable endpoints.
///
/// The signing key's public half (x25519 + ed25519) is embedded as the
/// `signing_key` field in the World header. The caller must provide the
/// 64-byte combined public key separately since ed25519_dalek::SigningKey
/// only gives the 32-byte ed25519 verifying key, not the x25519 portion.
pub fn generate_moon(
    moon_id: u64,
    timestamp: u64,
    roots: Vec<WorldRoot>,
    signing_key: &ed25519_dalek::SigningKey,
    public_key_bytes: &[u8; 64],
) -> Vec<u8> {
    generate_world(
        WorldType::Moon,
        moon_id,
        timestamp,
        roots,
        signing_key,
        public_key_bytes,
        Some(Vec::new()),
    )
}

/// Generate a planet world file binary.
///
/// A planet is the root-of-roots definition (world_type = 0x01 / 1).
pub fn generate_planet(
    planet_id: u64,
    timestamp: u64,
    roots: Vec<WorldRoot>,
    signing_key: &ed25519_dalek::SigningKey,
    public_key_bytes: &[u8; 64],
) -> Vec<u8> {
    generate_world(
        WorldType::Planet,
        planet_id,
        timestamp,
        roots,
        signing_key,
        public_key_bytes,
        None,
    )
}

/// Internal: generate a signed world binary of the given type.
fn generate_world(
    world_type: WorldType,
    id: u64,
    timestamp: u64,
    roots: Vec<WorldRoot>,
    signing_key: &ed25519_dalek::SigningKey,
    public_key_bytes: &[u8; 64],
    dict_data: Option<Vec<u8>>,
) -> Vec<u8> {
    // Build the World struct with a placeholder signature
    let mut world = World {
        world_type,
        id,
        timestamp,
        signing_key: *public_key_bytes,
        signature: [0u8; 96],
        roots,
        dict_data,
    };

    // Compute signature over the signed portion
    let mut sign_buf = [0u8; 4096];
    let sign_len = world.signed_portion(&mut sign_buf);
    let signature = signing::sign(signing_key, &sign_buf[..sign_len]);
    world.signature = signature;

    // Serialize the complete world binary
    let mut out_buf = [0u8; 8192];
    let n = world
        .serialize(&mut out_buf)
        .expect("world serialization buffer too small");
    out_buf[..n].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerotier_crypto::identity::{Address, Identity, PublicKey};
    use zerotier_crypto::signing;
    use zerotier_protocol::inet_address::InetAddress;

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32])
    }

    fn test_public_key_bytes() -> [u8; 64] {
        // 32 bytes x25519 (fake) + 32 bytes ed25519 verifying key
        let signing = test_signing_key();
        let vk = signing.verifying_key();
        let mut pk = [0u8; 64];
        pk[..32].copy_from_slice(&[0xAA; 32]); // fake x25519
        pk[32..64].copy_from_slice(vk.as_bytes());
        pk
    }

    fn test_root() -> WorldRoot {
        let address = Address::new([0xa0, 0xb1, 0xc2, 0xd3, 0xe4]).unwrap();
        let mut pk_bytes = [0u8; 64];
        for (i, b) in pk_bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let public_key = PublicKey::from_bytes(&pk_bytes).unwrap();
        let identity = Identity {
            address,
            public_key,
            secret: None,
        };
        WorldRoot {
            identity,
            endpoints: alloc::vec![InetAddress::V4 {
                ip: [192, 168, 1, 1],
                port: 9993,
            }],
        }
    }

    #[test]
    fn generate_planet_roundtrips() {
        let sk = test_signing_key();
        let pk = test_public_key_bytes();
        let roots = alloc::vec![test_root()];
        let planet_bytes = generate_planet(149604618, 1000000, roots, &sk, &pk);

        // Should be parseable
        let world = World::deserialize(&planet_bytes).expect("planet should parse");
        assert_eq!(world.world_type, WorldType::Planet);
        assert_eq!(world.id, 149604618);
        assert_eq!(world.timestamp, 1000000);
        assert_eq!(world.roots.len(), 1);
        assert!(world.dict_data.is_none());
    }

    #[test]
    fn generate_moon_roundtrips() {
        let sk = test_signing_key();
        let pk = test_public_key_bytes();
        let roots = alloc::vec![test_root()];
        let moon_bytes = generate_moon(42, 2000000, roots, &sk, &pk);

        let world = World::deserialize(&moon_bytes).expect("moon should parse");
        assert_eq!(world.world_type, WorldType::Moon);
        assert_eq!(world.id, 42);
        assert_eq!(world.timestamp, 2000000);
        assert_eq!(world.roots.len(), 1);
        // Moon has empty dict_data
        assert_eq!(world.dict_data, Some(alloc::vec![]));
    }

    #[test]
    fn generate_planet_signature_verifies() {
        let sk = test_signing_key();
        let pk = test_public_key_bytes();
        let roots = alloc::vec![test_root()];
        let planet_bytes = generate_planet(149604618, 1000000, roots, &sk, &pk);

        let world = World::deserialize(&planet_bytes).unwrap();

        // Re-compute signed portion and verify
        let mut sign_buf = [0u8; 4096];
        let sign_len = world.signed_portion(&mut sign_buf);
        let vk = sk.verifying_key();
        assert!(
            signing::verify(&vk, &sign_buf[..sign_len], &world.signature).is_ok(),
            "signature should verify"
        );
    }
}
