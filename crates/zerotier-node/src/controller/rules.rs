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
// Per-rule-type field decomposition
// ---------------------------------------------------------------------------

/// A rule's `value` bytes decoded into official's typed per-rule-type fields
/// (matching the field names/shapes `EmbeddedNetworkController.cpp`'s
/// `_renderRule`/`_parseRule` expose over JSON), rather than the raw wire
/// blob. Byte layouts verified 2026-07-03 against upstream `Capability.hpp`
/// `serializeRules`/`deserializeRules` at ZeroTierOne tag `1.14.2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleFields {
    /// `ACTION_TEE` / `ACTION_WATCH` / `ACTION_REDIRECT`. `length` is only
    /// meaningful for TEE/WATCH; REDIRECT always encodes it as 0.
    Forward {
        address: u64,
        flags: u32,
        length: u16,
    },
    /// `MATCH_SOURCE_ZEROTIER_ADDRESS` / `MATCH_DEST_ZEROTIER_ADDRESS`.
    ZtAddress(u64),
    VlanId(u16),
    VlanPcp(u8),
    VlanDei(u8),
    /// `MATCH_MAC_SOURCE` / `MATCH_MAC_DEST`.
    Mac([u8; 6]),
    /// `MATCH_IPV4_SOURCE` / `MATCH_IPV4_DEST`.
    Ipv4 {
        ip: [u8; 4],
        mask: u8,
    },
    /// `MATCH_IPV6_SOURCE` / `MATCH_IPV6_DEST`.
    Ipv6 {
        ip: [u8; 16],
        mask: u8,
    },
    IpTos {
        mask: u8,
        start: u8,
        end: u8,
    },
    IpProtocol(u8),
    EtherType(u16),
    Icmp {
        icmp_type: u8,
        icmp_code: Option<u8>,
    },
    /// `MATCH_IP_SOURCE_PORT_RANGE` / `MATCH_IP_DEST_PORT_RANGE`.
    PortRange {
        start: u16,
        end: u16,
    },
    Characteristics(u64),
    FrameSizeRange {
        start: u16,
        end: u16,
    },
    RandomProbability(u32),
    /// `MATCH_TAGS_*` / `MATCH_TAG_SENDER` / `MATCH_TAG_RECEIVER`.
    Tag {
        id: u32,
        value: u32,
    },
    /// `end` is the absolute range end (already `start + delta`, matching the
    /// wire and official's JSON -- not the raw in-memory delta).
    IntegerRange {
        start: u64,
        end: u64,
        idx: u16,
        little: bool,
        bits: u8,
    },
}

/// Decode a rule's `value` bytes into typed fields for the rule's type.
/// Returns `None` for rule types with no value payload (e.g. `ACTION_DROP`,
/// `ACTION_ACCEPT`, `ACTION_BREAK`, `ACTION_PRIORITY`), unknown rule types,
/// or a `value` shorter than the type's fixed layout requires.
pub fn decode_rule_fields(rule_type: u8, value: &[u8]) -> Option<RuleFields> {
    fn u16_be(b: &[u8]) -> u16 {
        u16::from_be_bytes([b[0], b[1]])
    }
    fn u32_be(b: &[u8]) -> u32 {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }
    fn u64_be(b: &[u8]) -> u64 {
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }

    match rule_type & 0x3F {
        ACTION_TEE | ACTION_WATCH | ACTION_REDIRECT if value.len() >= 14 => {
            Some(RuleFields::Forward {
                address: u64_be(&value[0..8]),
                flags: u32_be(&value[8..12]),
                length: u16_be(&value[12..14]),
            })
        }
        MATCH_SOURCE_ZEROTIER_ADDRESS | MATCH_DEST_ZEROTIER_ADDRESS if value.len() >= 5 => {
            let addr = (value[0] as u64) << 32
                | (value[1] as u64) << 24
                | (value[2] as u64) << 16
                | (value[3] as u64) << 8
                | value[4] as u64;
            Some(RuleFields::ZtAddress(addr))
        }
        MATCH_VLAN_ID if value.len() >= 2 => Some(RuleFields::VlanId(u16_be(&value[0..2]))),
        MATCH_VLAN_PCP if !value.is_empty() => Some(RuleFields::VlanPcp(value[0])),
        MATCH_VLAN_DEI if !value.is_empty() => Some(RuleFields::VlanDei(value[0])),
        MATCH_MAC_SOURCE | MATCH_MAC_DEST if value.len() >= 6 => {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&value[0..6]);
            Some(RuleFields::Mac(mac))
        }
        MATCH_IPV4_SOURCE | MATCH_IPV4_DEST if value.len() >= 5 => {
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&value[0..4]);
            Some(RuleFields::Ipv4 { ip, mask: value[4] })
        }
        MATCH_IPV6_SOURCE | MATCH_IPV6_DEST if value.len() >= 17 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&value[0..16]);
            Some(RuleFields::Ipv6 {
                ip,
                mask: value[16],
            })
        }
        MATCH_IP_TOS if value.len() >= 3 => Some(RuleFields::IpTos {
            mask: value[0],
            start: value[1],
            end: value[2],
        }),
        MATCH_IP_PROTOCOL if !value.is_empty() => Some(RuleFields::IpProtocol(value[0])),
        MATCH_ETHERTYPE if value.len() >= 2 => Some(RuleFields::EtherType(u16_be(&value[0..2]))),
        MATCH_ICMP if value.len() >= 3 => Some(RuleFields::Icmp {
            icmp_type: value[0],
            icmp_code: if value[2] & 0x01 != 0 {
                Some(value[1])
            } else {
                None
            },
        }),
        MATCH_IP_SOURCE_PORT_RANGE | MATCH_IP_DEST_PORT_RANGE if value.len() >= 4 => {
            Some(RuleFields::PortRange {
                start: u16_be(&value[0..2]),
                end: u16_be(&value[2..4]),
            })
        }
        MATCH_CHARACTERISTICS if value.len() >= 8 => {
            Some(RuleFields::Characteristics(u64_be(&value[0..8])))
        }
        MATCH_FRAME_SIZE_RANGE if value.len() >= 4 => Some(RuleFields::FrameSizeRange {
            start: u16_be(&value[0..2]),
            end: u16_be(&value[2..4]),
        }),
        MATCH_RANDOM if value.len() >= 4 => {
            Some(RuleFields::RandomProbability(u32_be(&value[0..4])))
        }
        MATCH_TAGS_DIFFERENCE
        | MATCH_TAGS_BITWISE_AND
        | MATCH_TAGS_BITWISE_OR
        | MATCH_TAGS_BITWISE_XOR
        | MATCH_TAGS_EQUAL
        | MATCH_TAG_SENDER
        | MATCH_TAG_RECEIVER
            if value.len() >= 8 =>
        {
            Some(RuleFields::Tag {
                id: u32_be(&value[0..4]),
                value: u32_be(&value[4..8]),
            })
        }
        MATCH_INTEGER_RANGE if value.len() >= 19 => {
            let format = value[18];
            Some(RuleFields::IntegerRange {
                start: u64_be(&value[0..8]),
                end: u64_be(&value[8..16]),
                idx: u16_be(&value[16..18]),
                little: format & 0x80 != 0,
                bits: (format & 0x3F) + 1,
            })
        }
        _ => None,
    }
}

/// Encode typed rule fields back into wire-format `value` bytes, the inverse
/// of [`decode_rule_fields`].
pub fn encode_rule_fields(fields: &RuleFields) -> Vec<u8> {
    let mut buf = Vec::new();
    match *fields {
        RuleFields::Forward {
            address,
            flags,
            length,
        } => {
            buf.extend_from_slice(&address.to_be_bytes());
            buf.extend_from_slice(&flags.to_be_bytes());
            buf.extend_from_slice(&length.to_be_bytes());
        }
        RuleFields::ZtAddress(addr) => {
            let b = addr.to_be_bytes();
            buf.extend_from_slice(&b[3..8]);
        }
        RuleFields::VlanId(v) => buf.extend_from_slice(&v.to_be_bytes()),
        RuleFields::VlanPcp(v) => buf.push(v),
        RuleFields::VlanDei(v) => buf.push(v),
        RuleFields::Mac(mac) => buf.extend_from_slice(&mac),
        RuleFields::Ipv4 { ip, mask } => {
            buf.extend_from_slice(&ip);
            buf.push(mask);
        }
        RuleFields::Ipv6 { ip, mask } => {
            buf.extend_from_slice(&ip);
            buf.push(mask);
        }
        RuleFields::IpTos { mask, start, end } => {
            buf.push(mask);
            buf.push(start);
            buf.push(end);
        }
        RuleFields::IpProtocol(v) => buf.push(v),
        RuleFields::EtherType(v) => buf.extend_from_slice(&v.to_be_bytes()),
        RuleFields::Icmp {
            icmp_type,
            icmp_code,
        } => {
            buf.push(icmp_type);
            buf.push(icmp_code.unwrap_or(0));
            buf.push(if icmp_code.is_some() { 0x01 } else { 0x00 });
        }
        RuleFields::PortRange { start, end } => {
            buf.extend_from_slice(&start.to_be_bytes());
            buf.extend_from_slice(&end.to_be_bytes());
        }
        RuleFields::Characteristics(v) => buf.extend_from_slice(&v.to_be_bytes()),
        RuleFields::FrameSizeRange { start, end } => {
            buf.extend_from_slice(&start.to_be_bytes());
            buf.extend_from_slice(&end.to_be_bytes());
        }
        RuleFields::RandomProbability(v) => buf.extend_from_slice(&v.to_be_bytes()),
        RuleFields::Tag { id, value } => {
            buf.extend_from_slice(&id.to_be_bytes());
            buf.extend_from_slice(&value.to_be_bytes());
        }
        RuleFields::IntegerRange {
            start,
            end,
            idx,
            little,
            bits,
        } => {
            buf.extend_from_slice(&start.to_be_bytes());
            buf.extend_from_slice(&end.to_be_bytes());
            buf.extend_from_slice(&idx.to_be_bytes());
            let format = ((bits - 1) & 0x3F) | if little { 0x80 } else { 0 };
            buf.push(format);
        }
    }
    buf
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
    fn decode_rule_fields_returns_none_for_valueless_types() {
        assert_eq!(decode_rule_fields(ACTION_DROP, &[]), None);
        assert_eq!(decode_rule_fields(ACTION_ACCEPT, &[]), None);
        assert_eq!(decode_rule_fields(ACTION_BREAK, &[]), None);
        assert_eq!(decode_rule_fields(ACTION_PRIORITY, &[]), None);
        assert_eq!(decode_rule_fields(0x3e, &[1, 2, 3]), None);
    }

    #[test]
    fn decode_rule_fields_ip_protocol_and_ethertype_match_upstream_byte_widths() {
        // MATCH_ETHERTYPE: single u16 BE (matches
        // serialize_ethertype_match_then_accept's [0x08, 0x00] fixture).
        assert_eq!(
            decode_rule_fields(MATCH_ETHERTYPE, &[0x08, 0x00]),
            Some(RuleFields::EtherType(0x0800))
        );
        assert_eq!(
            decode_rule_fields(MATCH_IP_PROTOCOL, &[6]),
            Some(RuleFields::IpProtocol(6))
        );
    }

    #[test]
    fn rule_fields_round_trip_through_encode_decode_for_every_type() {
        let cases = [
            (
                ACTION_TEE,
                RuleFields::Forward {
                    address: 0x0102030405,
                    flags: 7,
                    length: 200,
                },
            ),
            (
                MATCH_SOURCE_ZEROTIER_ADDRESS,
                RuleFields::ZtAddress(0x8899aabbcc),
            ),
            (MATCH_VLAN_ID, RuleFields::VlanId(42)),
            (MATCH_VLAN_PCP, RuleFields::VlanPcp(3)),
            (MATCH_VLAN_DEI, RuleFields::VlanDei(1)),
            (
                MATCH_MAC_SOURCE,
                RuleFields::Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            ),
            (
                MATCH_IPV4_SOURCE,
                RuleFields::Ipv4 {
                    ip: [10, 0, 0, 1],
                    mask: 24,
                },
            ),
            (
                MATCH_IPV6_SOURCE,
                RuleFields::Ipv6 {
                    ip: [0xfd; 16],
                    mask: 64,
                },
            ),
            (
                MATCH_IP_TOS,
                RuleFields::IpTos {
                    mask: 0xff,
                    start: 1,
                    end: 2,
                },
            ),
            (MATCH_IP_PROTOCOL, RuleFields::IpProtocol(17)),
            (MATCH_ETHERTYPE, RuleFields::EtherType(0x86dd)),
            (
                MATCH_ICMP,
                RuleFields::Icmp {
                    icmp_type: 8,
                    icmp_code: Some(0),
                },
            ),
            (
                MATCH_ICMP,
                RuleFields::Icmp {
                    icmp_type: 8,
                    icmp_code: None,
                },
            ),
            (
                MATCH_IP_SOURCE_PORT_RANGE,
                RuleFields::PortRange {
                    start: 1024,
                    end: 2048,
                },
            ),
            (
                MATCH_CHARACTERISTICS,
                RuleFields::Characteristics(0xdead_beef_1234_5678),
            ),
            (
                MATCH_FRAME_SIZE_RANGE,
                RuleFields::FrameSizeRange {
                    start: 64,
                    end: 1500,
                },
            ),
            (MATCH_RANDOM, RuleFields::RandomProbability(0x7fff_ffff)),
            (
                MATCH_TAGS_EQUAL,
                RuleFields::Tag {
                    id: 9,
                    value: 12345,
                },
            ),
            (
                MATCH_INTEGER_RANGE,
                RuleFields::IntegerRange {
                    start: 100,
                    end: 200,
                    idx: 4,
                    little: true,
                    bits: 32,
                },
            ),
        ];
        for (rule_type, fields) in cases {
            let encoded = encode_rule_fields(&fields);
            let decoded = decode_rule_fields(rule_type, &encoded);
            assert_eq!(
                decoded,
                Some(fields),
                "round-trip mismatch for rule_type {rule_type:#x}"
            );
        }
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
