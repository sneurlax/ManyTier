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

use alloc::string::String;
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

/// A network-level tag *definition*: the name and allowed value space for a
/// tag ID. Members carry tag *assignments* (`Tag { id, value }`) that should
/// reference one of these definitions, but the controller does not enforce
/// that binding -- it is metadata for operators/UIs, matching official's
/// `network.conf` "tags" schema.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TagDefinition {
    pub id: u32,
    pub name: String,
    /// Default value assigned to members that don't have this tag explicitly set.
    pub default: Option<u32>,
    /// Named enum values for this tag, e.g. `[("admin", 1), ("user", 2)]`.
    pub enums: Vec<(String, u32)>,
}

// ---------------------------------------------------------------------------
// Rule type constants (from ZeroTier source)
// ---------------------------------------------------------------------------

/// Actions (numeric values verified 2026-07-03 against upstream
/// `include/ZeroTierOne.h` `ZT_VirtualNetworkRuleType` at ZeroTierOne tag
/// `1.14.2` -- the previous MATCH_MAC_SOURCE..MATCH_INTEGER_RANGE values
/// below this comment were wrong by a systematic offset and would have
/// mis-encoded any non-default rule on the wire).
pub const ACTION_DROP: u8 = 0x00;
pub const ACTION_ACCEPT: u8 = 0x01;
pub const ACTION_TEE: u8 = 0x02;
pub const ACTION_WATCH: u8 = 0x03;
pub const ACTION_REDIRECT: u8 = 0x04;
pub const ACTION_BREAK: u8 = 0x05;
pub const ACTION_PRIORITY: u8 = 0x06;

/// Match conditions
pub const MATCH_SOURCE_ZEROTIER_ADDRESS: u8 = 0x18;
pub const MATCH_DEST_ZEROTIER_ADDRESS: u8 = 0x19;
pub const MATCH_VLAN_ID: u8 = 0x1a;
pub const MATCH_VLAN_PCP: u8 = 0x1b;
pub const MATCH_VLAN_DEI: u8 = 0x1c;
pub const MATCH_MAC_SOURCE: u8 = 0x1d;
pub const MATCH_MAC_DEST: u8 = 0x1e;
pub const MATCH_IPV4_SOURCE: u8 = 0x1f;
pub const MATCH_IPV4_DEST: u8 = 0x20;
pub const MATCH_IPV6_SOURCE: u8 = 0x21;
pub const MATCH_IPV6_DEST: u8 = 0x22;
pub const MATCH_IP_TOS: u8 = 0x23;
pub const MATCH_IP_PROTOCOL: u8 = 0x24;
pub const MATCH_ETHERTYPE: u8 = 0x25;
pub const MATCH_ICMP: u8 = 0x26;
pub const MATCH_IP_SOURCE_PORT_RANGE: u8 = 0x27;
pub const MATCH_IP_DEST_PORT_RANGE: u8 = 0x28;
pub const MATCH_CHARACTERISTICS: u8 = 0x29;
pub const MATCH_FRAME_SIZE_RANGE: u8 = 0x2a;
pub const MATCH_RANDOM: u8 = 0x2b;
pub const MATCH_TAGS_DIFFERENCE: u8 = 0x2c;
pub const MATCH_TAGS_BITWISE_AND: u8 = 0x2d;
pub const MATCH_TAGS_BITWISE_OR: u8 = 0x2e;
pub const MATCH_TAGS_BITWISE_XOR: u8 = 0x2f;
pub const MATCH_TAGS_EQUAL: u8 = 0x30;
pub const MATCH_TAG_SENDER: u8 = 0x31;
pub const MATCH_TAG_RECEIVER: u8 = 0x32;
pub const MATCH_INTEGER_RANGE: u8 = 0x33;

/// Map a rule-type byte (masked to bits 0-5) to official's symbolic REST name,
/// e.g. `ACTION_ACCEPT`, `MATCH_IP_PROTOCOL`. Unknown values return `"UNKNOWN"`.
pub fn rule_type_name(rule_type: u8) -> &'static str {
    match rule_type & 0x3F {
        ACTION_DROP => "ACTION_DROP",
        ACTION_ACCEPT => "ACTION_ACCEPT",
        ACTION_TEE => "ACTION_TEE",
        ACTION_WATCH => "ACTION_WATCH",
        ACTION_REDIRECT => "ACTION_REDIRECT",
        ACTION_BREAK => "ACTION_BREAK",
        ACTION_PRIORITY => "ACTION_PRIORITY",
        MATCH_SOURCE_ZEROTIER_ADDRESS => "MATCH_SOURCE_ZEROTIER_ADDRESS",
        MATCH_DEST_ZEROTIER_ADDRESS => "MATCH_DEST_ZEROTIER_ADDRESS",
        MATCH_VLAN_ID => "MATCH_VLAN_ID",
        MATCH_VLAN_PCP => "MATCH_VLAN_PCP",
        MATCH_VLAN_DEI => "MATCH_VLAN_DEI",
        MATCH_MAC_SOURCE => "MATCH_MAC_SOURCE",
        MATCH_MAC_DEST => "MATCH_MAC_DEST",
        MATCH_IPV4_SOURCE => "MATCH_IPV4_SOURCE",
        MATCH_IPV4_DEST => "MATCH_IPV4_DEST",
        MATCH_IPV6_SOURCE => "MATCH_IPV6_SOURCE",
        MATCH_IPV6_DEST => "MATCH_IPV6_DEST",
        MATCH_IP_TOS => "MATCH_IP_TOS",
        MATCH_IP_PROTOCOL => "MATCH_IP_PROTOCOL",
        MATCH_ETHERTYPE => "MATCH_ETHERTYPE",
        MATCH_ICMP => "MATCH_ICMP",
        MATCH_IP_SOURCE_PORT_RANGE => "MATCH_IP_SOURCE_PORT_RANGE",
        MATCH_IP_DEST_PORT_RANGE => "MATCH_IP_DEST_PORT_RANGE",
        MATCH_CHARACTERISTICS => "MATCH_CHARACTERISTICS",
        MATCH_FRAME_SIZE_RANGE => "MATCH_FRAME_SIZE_RANGE",
        MATCH_RANDOM => "MATCH_RANDOM",
        MATCH_TAGS_DIFFERENCE => "MATCH_TAGS_DIFFERENCE",
        MATCH_TAGS_BITWISE_AND => "MATCH_TAGS_BITWISE_AND",
        MATCH_TAGS_BITWISE_OR => "MATCH_TAGS_BITWISE_OR",
        MATCH_TAGS_BITWISE_XOR => "MATCH_TAGS_BITWISE_XOR",
        MATCH_TAGS_EQUAL => "MATCH_TAGS_EQUAL",
        MATCH_TAG_SENDER => "MATCH_TAG_SENDER",
        MATCH_TAG_RECEIVER => "MATCH_TAG_RECEIVER",
        MATCH_INTEGER_RANGE => "MATCH_INTEGER_RANGE",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Signature type byte for an Ed25519 signature (upstream `Tag.hpp`/`Capability.hpp`).
const SIGNATURE_TYPE_ED25519: u8 = 1;

/// Length in bytes of the combined Ed25519 + digest-suffix signature (upstream `ZT_C25519_SIGNATURE_LEN`).
const SIGNATURE_LEN: usize = 96;

/// Marker upstream wraps around the "for signing" byte range of Tag/Capability
/// (`0x7f7f7f7f7f7f7f7f` in `Tag.hpp`/`Capability.hpp` `serialize(..., forSign=true)`).
const SIGN_MARKER: u64 = 0x7f7f_7f7f_7f7f_7f7f;

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
/// Matches the wire layout of upstream `Tag::serialize` (`node/Tag.hpp`,
/// verified against the ZeroTier 1.14.2 source):
/// - network_id: u64 BE
/// - timestamp: i64 BE
/// - tag_id: u32 BE
/// - tag_value: u32 BE
/// - issued_to: 5 bytes (ZeroTier address)
/// - signed_by: 5 bytes (ZeroTier address; zero here: stub is unsigned)
/// - signature_type: u8 (0 == none, so a deserializer skips `signature_len` bytes)
/// - signature_len: u16 BE
/// - signature: `signature_len` bytes (stub: all zeros until controller signing is wired)
/// - additional_fields_len: u16 BE (currently always 0)
pub fn serialize_tags(
    tags: &[Tag],
    network_id: u64,
    issued_to: &[u8; 5],
    timestamp: u64,
) -> Vec<u8> {
    // Per-tag size: 8 + 8 + 4 + 4 + 5 + 5 + 1 + 2 + 96 + 2 = 135 bytes
    let mut buf = Vec::with_capacity(tags.len() * 135);
    for tag in tags {
        buf.extend_from_slice(&network_id.to_be_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(&tag.id.to_be_bytes());
        buf.extend_from_slice(&tag.value.to_be_bytes());
        buf.extend_from_slice(issued_to);
        buf.extend_from_slice(&[0u8; 5]); // signed_by (none)
        buf.push(0); // signature_type: none
        buf.extend_from_slice(&(SIGNATURE_LEN as u16).to_be_bytes());
        buf.extend_from_slice(&[0u8; SIGNATURE_LEN]); // stub signature
        buf.extend_from_slice(&0u16.to_be_bytes()); // additional_fields_len
    }
    buf
}

/// Serialize capabilities for the CAP dictionary key.
///
/// Matches the wire layout of upstream `Capability::serialize`
/// (`node/Capability.hpp`, verified against the ZeroTier 1.14.2 source):
/// - network_id: u64 BE
/// - timestamp: i64 BE
/// - cap_id: u32 BE
/// - rule_count: u16 BE
/// - rules: serialized rule chain (same per-rule `type_and_flags, value_len,
///   value` format as the R key, which matches upstream's `serializeRules`)
/// - max_custody_chain_length: u8 (always 1: ManyTier issues non-transferable
///   capabilities directly, no chain-of-custody hand-off)
/// - custody chain: terminated immediately by a 5-byte zero `to` address,
///   since this stub issues no signature
/// - additional_fields_len: u16 BE (currently always 0)
pub fn serialize_capabilities(
    caps: &[Capability],
    network_id: u64,
    _issued_to: &[u8; 5],
    timestamp: u64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    for cap in caps {
        buf.extend_from_slice(&network_id.to_be_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(&cap.id.to_be_bytes());
        buf.extend_from_slice(&(cap.rules.len() as u16).to_be_bytes());
        buf.extend_from_slice(&serialize_rules(&cap.rules));
        buf.push(1); // max_custody_chain_length
        buf.extend_from_slice(&[0u8; 5]); // terminate custody chain (unsigned)
        buf.extend_from_slice(&0u16.to_be_bytes()); // additional_fields_len
    }
    buf
}

/// Serialize tags for the TAG dictionary key, signed with the controller's key.
///
/// Byte-verified against upstream `Tag::serialize`/`Tag::sign` (`node/Tag.hpp`,
/// ZeroTier 1.14.2 source): the signed range is `0x7f7f7f7f7f7f7f7f ||
/// network_id || timestamp || tag_id || tag_value || issued_to || signed_by ||
/// additional_fields_len(0) || 0x7f7f7f7f7f7f7f7f`, signed via
/// [`zerotier_crypto::signing::sign`] (the same Ed25519 + SHA-512-digest-suffix
/// scheme already used for the Certificate of Membership). The wire form then
/// carries `network_id || timestamp || tag_id || tag_value || issued_to ||
/// signed_by || signature_type(1) || signature_len(96) || signature ||
/// additional_fields_len(0)`: see [`serialize_tags`] for the unsigned layout
/// this mirrors. `signed_by` is the controller's own ZeroTier address (the
/// public counterpart of `signing_key`).
///
/// This is now byte-format-verified against the upstream source rather than
/// guessed, but: like the rest of this module: has not been confirmed by
/// running a real official `zerotier-one` peer against it the way COM and
/// HELLO were during v1.3-v1.7 interop work.
pub fn serialize_tags_signed(
    tags: &[Tag],
    network_id: u64,
    issued_to: &[u8; 5],
    signed_by: &[u8; 5],
    timestamp: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(tags.len() * 135);
    for tag in tags {
        let mut signed_data = Vec::with_capacity(48);
        signed_data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
        signed_data.extend_from_slice(&network_id.to_be_bytes());
        signed_data.extend_from_slice(&timestamp.to_be_bytes());
        signed_data.extend_from_slice(&tag.id.to_be_bytes());
        signed_data.extend_from_slice(&tag.value.to_be_bytes());
        signed_data.extend_from_slice(issued_to);
        signed_data.extend_from_slice(signed_by);
        signed_data.extend_from_slice(&0u16.to_be_bytes()); // additional_fields_len
        signed_data.extend_from_slice(&SIGN_MARKER.to_be_bytes());

        let signature = zerotier_crypto::signing::sign(signing_key, &signed_data);

        buf.extend_from_slice(&network_id.to_be_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(&tag.id.to_be_bytes());
        buf.extend_from_slice(&tag.value.to_be_bytes());
        buf.extend_from_slice(issued_to);
        buf.extend_from_slice(signed_by);
        buf.push(SIGNATURE_TYPE_ED25519);
        buf.extend_from_slice(&(SIGNATURE_LEN as u16).to_be_bytes());
        buf.extend_from_slice(&signature);
        buf.extend_from_slice(&0u16.to_be_bytes()); // additional_fields_len
    }
    buf
}

/// Serialize capabilities for the CAP dictionary key, signed with the controller's key.
///
/// Byte-verified against upstream `Capability::serialize`/`Capability::sign`
/// (`node/Capability.hpp`, ZeroTier 1.14.2 source): the signed range is
/// `0x7f7f7f7f7f7f7f7f || network_id || timestamp || cap_id || rule_count ||
/// rules || max_custody_chain_length(1) || additional_fields_len(0) ||
/// 0x7f7f7f7f7f7f7f7f`, signed via [`zerotier_crypto::signing::sign`]. The
/// wire form then appends a single custody-chain entry: `to(issued_to) ||
/// from(signed_by) || signature_type(1) || signature_len(96) || signature`
///: followed by the zero-address chain terminator and
/// `additional_fields_len(0)`. ManyTier only ever issues a capability
/// directly (`max_custody_chain_length` is always 1, one custody entry),
/// never a transferable multi-hop chain. See [`serialize_tags_signed`] for
/// the same not-yet-live-interop-verified caveat.
pub fn serialize_capabilities_signed(
    caps: &[Capability],
    network_id: u64,
    issued_to: &[u8; 5],
    signed_by: &[u8; 5],
    timestamp: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> Vec<u8> {
    let mut buf = Vec::new();
    for cap in caps {
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
        signed_data.extend_from_slice(&network_id.to_be_bytes());
        signed_data.extend_from_slice(&timestamp.to_be_bytes());
        signed_data.extend_from_slice(&cap.id.to_be_bytes());
        signed_data.extend_from_slice(&(cap.rules.len() as u16).to_be_bytes());
        signed_data.extend_from_slice(&serialize_rules(&cap.rules));
        signed_data.push(1); // max_custody_chain_length
        signed_data.extend_from_slice(&0u16.to_be_bytes()); // additional_fields_len
        signed_data.extend_from_slice(&SIGN_MARKER.to_be_bytes());

        let signature = zerotier_crypto::signing::sign(signing_key, &signed_data);

        buf.extend_from_slice(&network_id.to_be_bytes());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(&cap.id.to_be_bytes());
        buf.extend_from_slice(&(cap.rules.len() as u16).to_be_bytes());
        buf.extend_from_slice(&serialize_rules(&cap.rules));
        buf.push(1); // max_custody_chain_length
        buf.extend_from_slice(issued_to); // custody[0].to
        buf.extend_from_slice(signed_by); // custody[0].from
        buf.push(SIGNATURE_TYPE_ED25519);
        buf.extend_from_slice(&(SIGNATURE_LEN as u16).to_be_bytes());
        buf.extend_from_slice(&signature);
        buf.extend_from_slice(&[0u8; 5]); // terminate custody chain
        buf.extend_from_slice(&0u16.to_be_bytes()); // additional_fields_len
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
    fn rule_type_name_covers_actions_and_matches() {
        assert_eq!(rule_type_name(ACTION_ACCEPT), "ACTION_ACCEPT");
        assert_eq!(rule_type_name(ACTION_DROP), "ACTION_DROP");
        assert_eq!(rule_type_name(MATCH_IP_PROTOCOL), "MATCH_IP_PROTOCOL");
        assert_eq!(rule_type_name(MATCH_INTEGER_RANGE), "MATCH_INTEGER_RANGE");
        // NOT/OR flag bits (0x80/0x40) must be masked off before lookup.
        assert_eq!(rule_type_name(MATCH_ETHERTYPE | 0x80), "MATCH_ETHERTYPE");
        assert_eq!(rule_type_name(0x3e), "UNKNOWN");
    }

    #[test]
    fn rule_type_constants_match_upstream_zt_virtualnetworkruletype() {
        // Pinned against `include/ZeroTierOne.h` `ZT_VirtualNetworkRuleType` at
        // ZeroTierOne tag 1.14.2, fetched 2026-07-03. A prior version of these
        // constants (MATCH_MAC_SOURCE and beyond) used a wrong systematic
        // offset that would have mis-encoded non-default rules on the wire.
        assert_eq!(ACTION_DROP, 0);
        assert_eq!(ACTION_ACCEPT, 1);
        assert_eq!(ACTION_TEE, 2);
        assert_eq!(ACTION_WATCH, 3);
        assert_eq!(ACTION_REDIRECT, 4);
        assert_eq!(ACTION_BREAK, 5);
        assert_eq!(ACTION_PRIORITY, 6);
        assert_eq!(MATCH_SOURCE_ZEROTIER_ADDRESS, 24);
        assert_eq!(MATCH_DEST_ZEROTIER_ADDRESS, 25);
        assert_eq!(MATCH_VLAN_ID, 26);
        assert_eq!(MATCH_VLAN_PCP, 27);
        assert_eq!(MATCH_VLAN_DEI, 28);
        assert_eq!(MATCH_MAC_SOURCE, 29);
        assert_eq!(MATCH_MAC_DEST, 30);
        assert_eq!(MATCH_IPV4_SOURCE, 31);
        assert_eq!(MATCH_IPV4_DEST, 32);
        assert_eq!(MATCH_IPV6_SOURCE, 33);
        assert_eq!(MATCH_IPV6_DEST, 34);
        assert_eq!(MATCH_IP_TOS, 35);
        assert_eq!(MATCH_IP_PROTOCOL, 36);
        assert_eq!(MATCH_ETHERTYPE, 37);
        assert_eq!(MATCH_ICMP, 38);
        assert_eq!(MATCH_IP_SOURCE_PORT_RANGE, 39);
        assert_eq!(MATCH_IP_DEST_PORT_RANGE, 40);
        assert_eq!(MATCH_CHARACTERISTICS, 41);
        assert_eq!(MATCH_FRAME_SIZE_RANGE, 42);
        assert_eq!(MATCH_RANDOM, 43);
        assert_eq!(MATCH_TAGS_DIFFERENCE, 44);
        assert_eq!(MATCH_TAGS_BITWISE_AND, 45);
        assert_eq!(MATCH_TAGS_BITWISE_OR, 46);
        assert_eq!(MATCH_TAGS_BITWISE_XOR, 47);
        assert_eq!(MATCH_TAGS_EQUAL, 48);
        assert_eq!(MATCH_TAG_SENDER, 49);
        assert_eq!(MATCH_TAG_RECEIVER, 50);
        assert_eq!(MATCH_INTEGER_RANGE, 51);
    }

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
        // First rule: type=0x25, len=2, value=[0x08, 0x00]
        // Second rule: type=0x01, len=0
        assert_eq!(bytes, vec![0x25, 0x02, 0x08, 0x00, 0x01, 0x00]);
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

        // First rule: type=0x24 | NOT(0x80) = 0xA4, len=1, value=0x06
        assert_eq!(bytes[0], 0xA4);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[2], 0x06);

        // Second rule: type=0x24 | OR(0x40) = 0x64, len=1, value=0x11
        assert_eq!(bytes[3], 0x64);
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

        // Each tag: 8 + 8 + 4 + 4 + 5 + 5 + 1 + 2 + 96 + 2 = 135 bytes
        assert_eq!(bytes.len(), 270);

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
        // First tag: signed_by is zero (unsigned stub)
        assert_eq!(&bytes[29..34], &[0u8; 5]);
        // First tag: signature_type is 0 (none)
        assert_eq!(bytes[34], 0);
        // First tag: signature_len is 96
        assert_eq!(u16::from_be_bytes(bytes[35..37].try_into().unwrap()), 96);
        // First tag: stub signature is zeros
        assert!(bytes[37..133].iter().all(|&b| b == 0));
        // First tag: additional_fields_len is 0
        assert_eq!(u16::from_be_bytes(bytes[133..135].try_into().unwrap()), 0);
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
        // max_custody_chain_length: 1 byte
        // Terminator: 5 bytes (zero 'to': unsigned stub)
        // additional_fields_len: 2 bytes
        // Total: 22 + 2 + 1 + 5 + 2 = 32 bytes
        assert_eq!(bytes.len(), 32);

        // Check cap_id
        assert_eq!(u32::from_be_bytes(bytes[16..20].try_into().unwrap()), 42);
        // Check rule_count
        assert_eq!(u16::from_be_bytes(bytes[20..22].try_into().unwrap()), 1);
        // Check rules
        assert_eq!(&bytes[22..24], &[0x01, 0x00]);
        // max_custody_chain_length
        assert_eq!(bytes[24], 1);
        // Terminator ('to' == 0)
        assert_eq!(&bytes[25..30], &[0u8; 5]);
        // additional_fields_len
        assert_eq!(u16::from_be_bytes(bytes[30..32].try_into().unwrap()), 0);
    }

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn serialize_tags_signed_produces_nonzero_verifiable_signature() {
        let tags = vec![Tag { id: 1, value: 100 }];
        let network_id = 0xff00001234560001u64;
        let issued_to = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let signed_by = [0x11, 0x22, 0x33, 0x44, 0x55];
        let timestamp = 1000000u64;
        let signing_key = test_signing_key();

        let bytes = serialize_tags_signed(
            &tags,
            network_id,
            &issued_to,
            &signed_by,
            timestamp,
            &signing_key,
        );
        assert_eq!(bytes.len(), 135);

        // network_id || timestamp || id || value || issued_to || signed_by
        assert_eq!(&bytes[24..29], &issued_to);
        assert_eq!(&bytes[29..34], &signed_by);
        assert_eq!(bytes[34], SIGNATURE_TYPE_ED25519);
        assert_eq!(u16::from_be_bytes(bytes[35..37].try_into().unwrap()), 96);
        let signature: [u8; 96] = bytes[37..133].try_into().unwrap();
        assert_eq!(u16::from_be_bytes(bytes[133..135].try_into().unwrap()), 0);
        assert!(!signature.iter().all(|&b| b == 0));

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
        signed_data.extend_from_slice(&bytes[0..34]);
        signed_data.extend_from_slice(&0u16.to_be_bytes());
        signed_data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
        assert!(zerotier_crypto::signing::verify(
            &signing_key.verifying_key(),
            &signed_data,
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
        let signed_by = [0x11, 0x22, 0x33, 0x44, 0x55];
        let timestamp = 1000000u64;
        let signing_key = test_signing_key();

        let bytes = serialize_capabilities_signed(
            &caps,
            network_id,
            &issued_to,
            &signed_by,
            timestamp,
            &signing_key,
        );
        // Header (22) + rules (2) + max_custody_chain_length (1) + to (5) +
        // from (5) + sig_type (1) + sig_len (2) + sig (96) + terminator (5) +
        // additional_fields_len (2) = 141 bytes
        assert_eq!(bytes.len(), 141);

        assert_eq!(bytes[24], 1); // max_custody_chain_length
        assert_eq!(&bytes[25..30], &issued_to);
        assert_eq!(&bytes[30..35], &signed_by);
        assert_eq!(bytes[35], SIGNATURE_TYPE_ED25519);
        assert_eq!(u16::from_be_bytes(bytes[36..38].try_into().unwrap()), 96);
        let signature: [u8; 96] = bytes[38..134].try_into().unwrap();
        assert_eq!(&bytes[134..139], &[0u8; 5]); // chain terminator
        assert_eq!(u16::from_be_bytes(bytes[139..141].try_into().unwrap()), 0);
        assert!(!signature.iter().all(|&b| b == 0));

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
        signed_data.extend_from_slice(&bytes[0..25]);
        signed_data.extend_from_slice(&0u16.to_be_bytes());
        signed_data.extend_from_slice(&SIGN_MARKER.to_be_bytes());
        assert!(zerotier_crypto::signing::verify(
            &signing_key.verifying_key(),
            &signed_data,
            &signature
        )
        .is_ok());
    }
}
