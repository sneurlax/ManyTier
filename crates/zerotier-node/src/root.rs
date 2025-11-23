/// Root server communication .
///
/// Handles building HELLO packets (cipher suite 0, MAC only) for root server
/// bootstrapping and WHOIS requests (cipher suite 1, encrypted) for address
/// resolution.
extern crate alloc;

use zerotier_crypto::identity::Identity;
use zerotier_crypto::salsa;
use zerotier_protocol::constants::*;
use zerotier_protocol::inet_address::InetAddress;
use zerotier_protocol::verb::Verb;
use zerotier_protocol::verbs::hello::HelloPayload;
use zerotier_protocol::verbs::ok::OkPayload;
use zerotier_protocol::verbs::rendezvous::RendezvousPayload;
use zerotier_protocol::verbs::whois::WhoisRequest;
use zerotier_protocol::ProtocolError;

/// Root server communication manager.
///
/// Builds HELLO and WHOIS packets for bootstrapping and address resolution.
#[derive(Debug)]
pub struct RootManager {
    /// Counter for tracking HELLO retries.
    pub last_hello_sent: u64,
}

impl RootManager {
    pub fn new() -> Self {
        RootManager { last_hello_sent: 0 }
    }

    /// Build a HELLO packet to send to a root server.
    ///
    /// HELLO uses cipher suite 0 (MAC only, no encryption per Pitfall 1).
    /// The shared_secret is used only for MAC computation, not encryption.
    pub fn build_hello(
        our_identity: &Identity,
        dest_address: &[u8; 5],
        dest_physical: core::net::SocketAddr,
        now_ms: u64,
        shared_secret: &[u8; 32],
        buf: &mut [u8],
        planet_world_timestamp: u64,
    ) -> Result<(usize, u64), ProtocolError> {
        if buf.len() < ZT_PROTO_MIN_PACKET_LENGTH + 128 {
            return Err(ProtocolError::TooShort {
                need: ZT_PROTO_MIN_PACKET_LENGTH + 128,
                got: buf.len(),
            });
        }

        // Generate packet ID from timestamp (used as IV)
        let packet_id = now_ms;
        buf[0..8].copy_from_slice(&packet_id.to_be_bytes());

        // Destination address
        buf[8..13].copy_from_slice(dest_address);

        // Source address
        buf[13..18].copy_from_slice(our_identity.address.as_bytes());

        // Flags byte: cipher suite 0 (bits 3-5 = 000), hop count 0 (bits 0-2 = 000)
        // cipher_suite_0 = no payload encryption, MAC only
        buf[18] = CIPHER_SUITE_C25519_POLY1305_NONE << 3;

        // MAC field (bytes 19..27) - will be set by armor
        buf[19..27].copy_from_slice(&[0u8; 8]);

        // Verb byte: HELLO (0x01)
        buf[27] = Verb::Hello.to_byte();

        // Build HELLO payload after the header (offset 28)
        let dest_inet = InetAddress::from_socket_addr(dest_physical);
        let mut hello = HelloPayload::new(
            Identity {
                address: our_identity.address,
                public_key: our_identity.public_key.clone(),
                secret: None, // Don't include secret in outgoing packets
            },
            now_ms,
            dest_inet,
        );
        hello.planet_world_timestamp = planet_world_timestamp;

        let payload_len = hello.serialize(&mut buf[28..])?;
        let moon_count_offset = 28 + payload_len;
        buf[moon_count_offset..moon_count_offset + 2].copy_from_slice(&0u16.to_be_bytes());
        let total_len = moon_count_offset + 2;

        salsa::crypt_packet_field(shared_secret, &mut buf[..total_len], moon_count_offset, 2)
            .map_err(ProtocolError::CryptoError)?;

        // Armor: cipher suite 0 = MAC only, no encryption
        salsa::armor_packet(shared_secret, &mut buf[..total_len], false)
            .map_err(ProtocolError::CryptoError)?;

        Ok((total_len, packet_id))
    }

    /// Build a WHOIS request packet.
    ///
    /// WHOIS uses cipher suite 1 (Salsa20/12 + Poly1305) -- requires active session with root.
    pub fn build_whois(
        our_identity: &Identity,
        dest_address: &[u8; 5],
        addresses: &[[u8; 5]],
        shared_secret: &[u8; 32],
        now_ms: u64,
        buf: &mut [u8],
    ) -> Result<(usize, u64), ProtocolError> {
        if buf.len() < ZT_PROTO_MIN_PACKET_LENGTH + addresses.len() * 5 {
            return Err(ProtocolError::TooShort {
                need: ZT_PROTO_MIN_PACKET_LENGTH + addresses.len() * 5,
                got: buf.len(),
            });
        }

        // Packet ID
        let packet_id = now_ms;
        buf[0..8].copy_from_slice(&packet_id.to_be_bytes());

        // Destination
        buf[8..13].copy_from_slice(dest_address);

        // Source
        buf[13..18].copy_from_slice(our_identity.address.as_bytes());

        // Flags: cipher suite 1 (Salsa20/12 + Poly1305), hop count 0
        buf[18] = CIPHER_SUITE_C25519_POLY1305_SALSA2012 << 3;

        // MAC placeholder
        buf[19..27].copy_from_slice(&[0u8; 8]);

        // Verb: WHOIS
        buf[27] = Verb::Whois.to_byte();

        // WHOIS payload: list of 5-byte addresses
        let whois = WhoisRequest {
            addresses: addresses.to_vec(),
        };
        let payload_len = whois.serialize(&mut buf[28..]);
        let total_len = 28 + payload_len;

        // Armor with encryption (cipher suite 1)
        salsa::armor_packet(shared_secret, &mut buf[..total_len], true)
            .map_err(ProtocolError::CryptoError)?;

        Ok((total_len, packet_id))
    }

    /// Build an OK(HELLO) response packet.
    pub fn build_ok_hello(
        our_identity: &Identity,
        dest_address: &[u8; 5],
        in_re_packet_id: u64,
        timestamp_echo: u64,
        shared_secret: &[u8; 32],
        now_ms: u64,
        use_unmangled_null: bool,
        buf: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        if buf.len() < ZT_PROTO_MIN_PACKET_LENGTH + 32 {
            return Err(ProtocolError::TooShort {
                need: ZT_PROTO_MIN_PACKET_LENGTH + 32,
                got: buf.len(),
            });
        }

        let packet_id = now_ms;
        buf[0..8].copy_from_slice(&packet_id.to_be_bytes());
        buf[8..13].copy_from_slice(dest_address);
        buf[13..18].copy_from_slice(our_identity.address.as_bytes());

        // Cipher suite 1 for OK responses
        buf[18] = CIPHER_SUITE_C25519_POLY1305_SALSA2012 << 3;
        buf[19..27].copy_from_slice(&[0u8; 8]);
        buf[27] = Verb::Ok.to_byte();

        // OK payload
        let ok = OkPayload {
            in_re_verb: Verb::Hello,
            in_re_packet_id,
            sub_payload: zerotier_protocol::verbs::ok::OkSubPayload::Hello {
                timestamp_echo,
                protocol_version: ZT_PROTO_VERSION,
                major_version: 0,
                minor_version: 1,
                revision: 0,
                world_update: None,
            },
        };

        let payload_len = ok.serialize(&mut buf[28..])?;
        let total_len = 28 + payload_len;

        if use_unmangled_null {
            salsa::armor_packet_unmangled(&[0u8; 32], &mut buf[..total_len], false)
                .map_err(ProtocolError::CryptoError)?;
        } else {
            salsa::armor_packet(shared_secret, &mut buf[..total_len], true)
                .map_err(ProtocolError::CryptoError)?;
        }

        Ok(total_len)
    }

    /// Build a RENDEZVOUS packet telling `dest` to contact `target_peer` at `target_address`.
    ///
    /// RENDEZVOUS uses cipher suite 1 (encrypted) since we have an active session with the peer.
    /// The root sends RENDEZVOUS to both peers to trigger mutual hole-punching.
    pub fn build_rendezvous(
        our_identity: &Identity,
        dest_address: &[u8; 5],
        target_peer_address: &[u8; 5],
        target_physical: InetAddress,
        shared_secret: &[u8; 32],
        now_ms: u64,
        buf: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        if buf.len() < ZT_PROTO_MIN_PACKET_LENGTH + 32 {
            return Err(ProtocolError::TooShort {
                need: ZT_PROTO_MIN_PACKET_LENGTH + 32,
                got: buf.len(),
            });
        }

        let packet_id = now_ms;
        buf[0..8].copy_from_slice(&packet_id.to_be_bytes());
        buf[8..13].copy_from_slice(dest_address);
        buf[13..18].copy_from_slice(our_identity.address.as_bytes());

        // Cipher suite 1 (encrypted)
        buf[18] = CIPHER_SUITE_C25519_POLY1305_SALSA2012 << 3;
        buf[19..27].copy_from_slice(&[0u8; 8]);
        buf[27] = Verb::Rendezvous.to_byte();

        let rendezvous = RendezvousPayload {
            flags: 0,
            peer_address: *target_peer_address,
            address: target_physical,
        };

        let payload_len = rendezvous.serialize(&mut buf[28..]);
        let total_len = 28 + payload_len;

        salsa::armor_packet(shared_secret, &mut buf[..total_len], true)
            .map_err(ProtocolError::CryptoError)?;

        Ok(total_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerotier_crypto::identity::{Address, PublicKey};
    use zerotier_protocol::PacketHeader;

    fn build_test_identity() -> Identity {
        let address = Address::new([0xa0, 0xb1, 0xc2, 0xd3, 0xe4]).unwrap();
        let pk = PublicKey::from_bytes(&[0x42u8; 64]).unwrap();
        Identity {
            address,
            public_key: pk,
            secret: None,
        }
    }

    fn test_shared_secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(0x42);
        }
        s
    }

    #[test]
    fn build_hello_produces_valid_packet() {
        let id = build_test_identity();
        let dest = [0x01, 0x02, 0x03, 0x04, 0x05];
        let dest_phys: core::net::SocketAddr = "192.168.1.1:9993".parse().unwrap();
        let secret = test_shared_secret();
        let mut buf = [0u8; 512];

        let (len, _packet_id) =
            RootManager::build_hello(&id, &dest, dest_phys, 1000, &secret, &mut buf, 0).unwrap();

        assert!(len >= ZT_PROTO_MIN_PACKET_LENGTH);

        // Parse header -- verb is encrypted (cipher suite 0 = MAC only, verb is NOT encrypted)
        // Actually cipher suite 0 means no encryption so verb is plaintext
        // But armor_packet with encrypt_payload=false doesn't encrypt verb+payload
        // However, the verb byte IS part of the payload area (offset 27+)
        // For cipher suite 0, armor_packet(false) does NOT encrypt, so verb is readable.
        // But the MAC overwrites bytes 19..27.
        // We can read dest/source from the header
        let hdr = PacketHeader::from_bytes(&buf[..len]).unwrap();
        assert_eq!(hdr.dest, dest);
        assert_eq!(hdr.source_address(), *id.address.as_bytes());
        // Cipher suite 0
        assert_eq!(hdr.cipher_suite(), CIPHER_SUITE_C25519_POLY1305_NONE);
        // Verb is Hello (not encrypted for cipher suite 0)
        assert_eq!(hdr.verb_id(), Verb::Hello.to_byte());
    }

    #[test]
    fn build_whois_uses_cipher_suite_1() {
        let id = build_test_identity();
        let dest = [0x01, 0x02, 0x03, 0x04, 0x05];
        let secret = test_shared_secret();
        let addresses = [[0x11, 0x22, 0x33, 0x44, 0x55]];
        let mut buf = [0u8; 512];

        let (len, _) =
            RootManager::build_whois(&id, &dest, &addresses, &secret, 2000, &mut buf).unwrap();

        assert!(len >= ZT_PROTO_MIN_PACKET_LENGTH);

        let hdr = PacketHeader::from_bytes(&buf[..len]).unwrap();
        assert_eq!(hdr.cipher_suite(), CIPHER_SUITE_C25519_POLY1305_SALSA2012);
    }

    #[test]
    fn build_hello_too_small_buffer() {
        let id = build_test_identity();
        let dest = [0x01, 0x02, 0x03, 0x04, 0x05];
        let dest_phys: core::net::SocketAddr = "192.168.1.1:9993".parse().unwrap();
        let secret = test_shared_secret();
        let mut buf = [0u8; 10];

        assert!(
            RootManager::build_hello(&id, &dest, dest_phys, 1000, &secret, &mut buf, 0).is_err()
        );
    }
}
