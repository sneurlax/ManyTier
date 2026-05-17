//! ZeroTier network rules engine.
//!
//! Provides types and serialization for match/action rules, tags, and capabilities
//! that are included in NetworkConfig dictionaries (R, TAG, CAP keys).
//!
//! Binary format per rule entry:
//! - `u8 type_and_flags`: bits 0-5 = rule type, bit 6 = OR flag, bit 7 = NOT flag
//! - `u8 value_length`: length of value data in bytes
//! - `[u8; value_length]`: type-specific value data

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

/// A single ZeroTier network rule (match condition or action).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    pub rule_type: u8,
    pub not_flag: bool,
    pub or_flag: bool,
    pub value: Vec<u8>,
}

/// A tag assigned to a network member.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Tag {
    pub id: u32,
    pub value: u32,
}

/// A capability granted to a network member, containing its own rule chain.
///
/// This is the network-level *definition*; a member gains the capability by
/// having its `id` listed in that member's assigned capability IDs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Capability {
    pub id: u32,
    pub rules: Vec<Rule>,
}

// ---------------------------------------------------------------------------
// Rule type constants (from ZeroTier source)
// ---------------------------------------------------------------------------

/// Actions
pub const ACTION_DROP: u8 = 0x00;
pub const ACTION_ACCEPT: u8 = 0x01;
pub const ACTION_TEE: u8 = 0x02;
pub const ACTION_WATCH: u8 = 0x03;
pub const ACTION_REDIRECT: u8 = 0x04;
pub const ACTION_BREAK: u8 = 0x05;

/// Match conditions
pub const MATCH_SOURCE_ZEROTIER_ADDRESS: u8 = 0x18;
pub const MATCH_DEST_ZEROTIER_ADDRESS: u8 = 0x19;
pub const MATCH_VLAN_ID: u8 = 0x1a;
pub const MATCH_VLAN_PCP: u8 = 0x1b;
pub const MATCH_VLAN_DEI: u8 = 0x1c;
pub const MATCH_MAC_SOURCE: u8 = 0x20;
pub const MATCH_MAC_DEST: u8 = 0x21;
pub const MATCH_IPV4_SOURCE: u8 = 0x22;
pub const MATCH_IPV4_DEST: u8 = 0x23;
pub const MATCH_IPV6_SOURCE: u8 = 0x24;
pub const MATCH_IPV6_DEST: u8 = 0x25;
pub const MATCH_IP_TOS: u8 = 0x26;
pub const MATCH_IP_PROTOCOL: u8 = 0x27;
pub const MATCH_ETHERTYPE: u8 = 0x28;
pub const MATCH_ICMP_TYPE: u8 = 0x29;
pub const MATCH_IP_SOURCE_PORT_RANGE: u8 = 0x2a;
pub const MATCH_IP_DEST_PORT_RANGE: u8 = 0x2b;
pub const MATCH_CHARACTERISTICS: u8 = 0x2c;
pub const MATCH_FRAME_SIZE_RANGE: u8 = 0x2d;
pub const MATCH_RANDOM: u8 = 0x2e;
pub const MATCH_TAGS_DIFFERENCE: u8 = 0x30;
pub const MATCH_TAGS_BITWISE_AND: u8 = 0x31;
pub const MATCH_TAGS_BITWISE_OR: u8 = 0x32;
pub const MATCH_TAGS_BITWISE_XOR: u8 = 0x33;
pub const MATCH_TAGS_EQUAL: u8 = 0x34;
pub const MATCH_INTEGER_RANGE: u8 = 0x3f;

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serialize a list of rules into binary format (R dictionary key).
///
/// Each rule is encoded as:
/// - `u8`: type_and_flags (bits 0-5 = type, bit 6 = OR, bit 7 = NOT)
/// - `u8`: value length
/// - `[u8]`: value bytes
pub fn serialize_rules(rules: &[Rule]) -> Vec<u8> {
    let mut buf = Vec::new();
    for rule in rules {
        let type_byte = (rule.rule_type & 0x3F)
            | if rule.or_flag { 0x40 } else { 0 }
            | if rule.not_flag { 0x80 } else { 0 };
        buf.push(type_byte);
        buf.push(rule.value.len() as u8);
        buf.extend_from_slice(&rule.value);
    }
    buf
}

/// Create the default allow-all rule set (single ACTION_ACCEPT).
pub fn default_allow_all() -> Vec<Rule> {
    vec![Rule {
        rule_type: ACTION_ACCEPT,
        not_flag: false,
        or_flag: false,
        value: vec![],
    }]
}

/// Serialize tags for the TAG dictionary key.
///
/// Format per tag:
/// - network_id: u64 BE
/// - timestamp: u64 BE
/// - tag_id: u32 BE
/// - tag_value: u32 BE
/// - issued_to: 5 bytes (ZeroTier address)
/// - signature: 96 bytes (stub: all zeros until controller signing is wired)
pub fn serialize_tags(
    tags: &[Tag],
    network_id: u64,
    issued_to: &[u8; 5],
    timestamp: u64,
) -> Vec<u8> {
    // Per-tag size: 8 + 8 + 4 + 4 + 5 + 96 = 125 bytes
    let mut buf = Vec::with_capacity(tags.len() * 125);
    for tag in tags {
        buf.extend_from_slice(&network_id.to_be_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(&tag.id.to_be_bytes());
        buf.extend_from_slice(&tag.value.to_be_bytes());
        buf.extend_from_slice(issued_to);
        // Stub signature (96 bytes of zeros)
        buf.extend_from_slice(&[0u8; 96]);
    }
    buf
}

/// Serialize capabilities for the CAP dictionary key.
///
/// Format per capability:
/// - network_id: u64 BE
/// - timestamp: u64 BE
/// - cap_id: u32 BE
/// - rule_count: u16 BE
/// - rules: serialized rule chain (same format as R key)
/// - issued_to: 5 bytes (ZeroTier address)
/// - signature: 96 bytes (stub: all zeros until controller signing is wired)
pub fn serialize_capabilities(
    caps: &[Capability],
    network_id: u64,
    issued_to: &[u8; 5],
    timestamp: u64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    for cap in caps {
        buf.extend_from_slice(&network_id.to_be_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(&cap.id.to_be_bytes());
        buf.extend_from_slice(&(cap.rules.len() as u16).to_be_bytes());
        buf.extend_from_slice(&serialize_rules(&cap.rules));
        buf.extend_from_slice(issued_to);
        // Stub signature (96 bytes of zeros)
        buf.extend_from_slice(&[0u8; 96]);
    }
    buf
}

/// Serialize tags for the TAG dictionary key, signed with the controller's key.
///
/// Same layout as [`serialize_tags`], except the trailing 96-byte signature is
/// computed via [`zerotier_crypto::signing::sign`] (the same Ed25519 +
/// SHA-512-digest-suffix scheme already used for the Certificate of
/// Membership) over the preceding `network_id || timestamp || tag_id ||
/// tag_value || issued_to` bytes.
///
/// This canonical signed layout follows this codebase's existing COM-signing
/// convention but has not been byte-verified against a real official
/// `zerotier-one` peer the way the COM and HELLO formats were: treat it as
/// unverified until an interop rerun confirms an official client accepts it.
pub fn serialize_tags_signed(
    tags: &[Tag],
    network_id: u64,
    issued_to: &[u8; 5],
    timestamp: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(tags.len() * 125);
    for tag in tags {
        let mut signed_data = Vec::with_capacity(29);
        signed_data.extend_from_slice(&network_id.to_be_bytes());
        signed_data.extend_from_slice(&timestamp.to_be_bytes());
        signed_data.extend_from_slice(&tag.id.to_be_bytes());
        signed_data.extend_from_slice(&tag.value.to_be_bytes());
        signed_data.extend_from_slice(issued_to);

        let signature = zerotier_crypto::signing::sign(signing_key, &signed_data);

        buf.extend_from_slice(&signed_data);
        buf.extend_from_slice(&signature);
    }
    buf
}

/// Serialize capabilities for the CAP dictionary key, signed with the controller's key.
///
/// Same layout as [`serialize_capabilities`], except the trailing 96-byte
/// signature is computed via [`zerotier_crypto::signing::sign`] over the
/// preceding `network_id || timestamp || cap_id || rule_count || rules ||
/// issued_to` bytes. See [`serialize_tags_signed`] for the same
/// not-yet-interop-verified caveat.
pub fn serialize_capabilities_signed(
    caps: &[Capability],
    network_id: u64,
    issued_to: &[u8; 5],
    timestamp: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> Vec<u8> {
    let mut buf = Vec::new();
    for cap in caps {
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&network_id.to_be_bytes());
        signed_data.extend_from_slice(&timestamp.to_be_bytes());
        signed_data.extend_from_slice(&cap.id.to_be_bytes());
        signed_data.extend_from_slice(&(cap.rules.len() as u16).to_be_bytes());
        signed_data.extend_from_slice(&serialize_rules(&cap.rules));
        signed_data.extend_from_slice(issued_to);

        let signature = zerotier_crypto::signing::sign(signing_key, &signed_data);

        buf.extend_from_slice(&signed_data);
        buf.extend_from_slice(&signature);
    }
    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_allow_all_serializes_to_accept() {
        let rules = default_allow_all();
        let bytes = serialize_rules(&rules);
        assert_eq!(bytes, vec![0x01, 0x00]);
    }

    #[test]
    fn serialize_ethertype_match_then_accept() {
        // Match ethertype 0x0800 (IPv4), then accept
        let rules = vec![
            Rule {
                rule_type: MATCH_ETHERTYPE,
                not_flag: false,
                or_flag: false,
                value: vec![0x08, 0x00], // ethertype as u16 BE
            },
            Rule {
                rule_type: ACTION_ACCEPT,
                not_flag: false,
                or_flag: false,
                value: vec![],
            },
        ];
        let bytes = serialize_rules(&rules);
        // First rule: type=0x28, len=2, value=[0x08, 0x00]
        // Second rule: type=0x01, len=0
        assert_eq!(bytes, vec![0x28, 0x02, 0x08, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn serialize_rules_with_not_and_or_flags() {
        let rules = vec![
            Rule {
                rule_type: MATCH_IP_PROTOCOL,
                not_flag: true,
                or_flag: false,
                value: vec![0x06], // TCP
            },
            Rule {
                rule_type: MATCH_IP_PROTOCOL,
                not_flag: false,
                or_flag: true,
                value: vec![0x11], // UDP
            },
            Rule {
                rule_type: ACTION_DROP,
                not_flag: false,
                or_flag: false,
                value: vec![],
            },
        ];
        let bytes = serialize_rules(&rules);

        // First rule: type=0x27 | NOT(0x80) = 0xA7, len=1, value=0x06
        assert_eq!(bytes[0], 0xA7);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[2], 0x06);

        // Second rule: type=0x27 | OR(0x40) = 0x67, len=1, value=0x11
        assert_eq!(bytes[3], 0x67);
        assert_eq!(bytes[4], 0x01);
        assert_eq!(bytes[5], 0x11);

        // Third rule: type=0x00, len=0
        assert_eq!(bytes[6], 0x00);
        assert_eq!(bytes[7], 0x00);
    }

    #[test]
    fn serialize_tags_format() {
        let tags = vec![Tag { id: 1, value: 100 }, Tag { id: 2, value: 200 }];
        let network_id = 0xff00001234560001u64;
        let issued_to = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let timestamp = 1000000u64;

        let bytes = serialize_tags(&tags, network_id, &issued_to, timestamp);

        // Each tag: 8 + 8 + 4 + 4 + 5 + 96 = 125 bytes
        assert_eq!(bytes.len(), 250);

        // First tag: check network_id
        assert_eq!(
            u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            network_id
        );
        // First tag: check timestamp
        assert_eq!(
            u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            timestamp
        );
        // First tag: check id
        assert_eq!(u32::from_be_bytes(bytes[16..20].try_into().unwrap()), 1);
        // First tag: check value
        assert_eq!(u32::from_be_bytes(bytes[20..24].try_into().unwrap()), 100);
        // First tag: check issued_to
        assert_eq!(&bytes[24..29], &issued_to);
        // First tag: signature is stub zeros
        assert!(bytes[29..125].iter().all(|&b| b == 0));
    }

    #[test]
    fn serialize_capabilities_format() {
        let caps = vec![Capability {
            id: 42,
            rules: vec![Rule {
                rule_type: ACTION_ACCEPT,
                not_flag: false,
                or_flag: false,
                value: vec![],
            }],
        }];
        let network_id = 0xff00001234560001u64;
        let issued_to = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let timestamp = 1000000u64;

        let bytes = serialize_capabilities(&caps, network_id, &issued_to, timestamp);

        // Header: 8 + 8 + 4 + 2 = 22 bytes
        // Rules: 2 bytes (accept = [0x01, 0x00])
        // Footer: 5 + 96 = 101 bytes
        // Total: 22 + 2 + 101 = 125 bytes
        assert_eq!(bytes.len(), 125);

        // Check cap_id
        assert_eq!(u32::from_be_bytes(bytes[16..20].try_into().unwrap()), 42);
        // Check rule_count
        assert_eq!(u16::from_be_bytes(bytes[20..22].try_into().unwrap()), 1);
        // Check rules
        assert_eq!(&bytes[22..24], &[0x01, 0x00]);
    }

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn serialize_tags_signed_produces_nonzero_verifiable_signature() {
        let tags = vec![Tag { id: 1, value: 100 }];
        let network_id = 0xff00001234560001u64;
        let issued_to = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let timestamp = 1000000u64;
        let signing_key = test_signing_key();

        let bytes = serialize_tags_signed(&tags, network_id, &issued_to, timestamp, &signing_key);
        assert_eq!(bytes.len(), 125);

        let signed_data = &bytes[0..29];
        let signature: [u8; 96] = bytes[29..125].try_into().unwrap();
        assert!(!signature.iter().all(|&b| b == 0));
        assert!(zerotier_crypto::signing::verify(
            &signing_key.verifying_key(),
            signed_data,
            &signature
        )
        .is_ok());
    }

    #[test]
    fn serialize_capabilities_signed_produces_nonzero_verifiable_signature() {
        let caps = vec![Capability {
            id: 42,
            rules: vec![Rule {
                rule_type: ACTION_ACCEPT,
                not_flag: false,
                or_flag: false,
                value: vec![],
            }],
        }];
        let network_id = 0xff00001234560001u64;
        let issued_to = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let timestamp = 1000000u64;
        let signing_key = test_signing_key();

        let bytes =
            serialize_capabilities_signed(&caps, network_id, &issued_to, timestamp, &signing_key);
        assert_eq!(bytes.len(), 125);

        let signed_data = &bytes[0..29];
        let signature: [u8; 96] = bytes[29..125].try_into().unwrap();
        assert!(!signature.iter().all(|&b| b == 0));
        assert!(zerotier_crypto::signing::verify(
            &signing_key.verifying_key(),
            signed_data,
            &signature
        )
        .is_ok());
    }
}
