/// Static network configuration deserialization from JSON.
///
/// This module is gated behind `#[cfg(feature = "native")]` since it uses
/// serde_json which requires std. The `NetworkMembership` type in network.rs
/// stays no_std.
///
/// Used for test setups and static network configurations where no controller
/// is available (e.g., Shadow VL2 tests with pre-generated configs).

extern crate std;
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

use crate::ethernet;
use crate::network::{NetworkMember, NetworkMembership, Route};
use zerotier_protocol::verbs::network_config::{CertificateOfMembership, ComQualifier};

/// Top-level static network configuration.
#[derive(Debug, Deserialize)]
pub struct StaticNetworkConfig {
    #[serde(rename = "networkId")]
    pub network_id: String,
    pub mtu: u16,
    pub members: Vec<StaticMemberConfig>,
    pub com: StaticComConfig,
    pub routes: Vec<StaticRouteConfig>,
    #[serde(rename = "multicastLimit", default)]
    pub multicast_limit: u32,
}

/// A member entry in the static config.
#[derive(Debug, Deserialize)]
pub struct StaticMemberConfig {
    pub address: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    #[serde(default = "default_true")]
    pub authorized: bool,
}

fn default_true() -> bool {
    true
}

/// COM configuration in the static config.
#[derive(Debug, Deserialize)]
pub struct StaticComConfig {
    pub qualifiers: Vec<StaticQualifierConfig>,
    #[serde(rename = "signerAddress")]
    pub signer_address: String,
    pub signature: String,
}

/// A qualifier entry in the static COM config.
#[derive(Debug, Deserialize)]
pub struct StaticQualifierConfig {
    pub id: u64,
    pub value: serde_json::Value,
    #[serde(rename = "maxDelta")]
    pub max_delta: u64,
}

/// A route entry in the static config.
#[derive(Debug, Deserialize)]
pub struct StaticRouteConfig {
    pub target: String,
}

/// Error type for config loading.
#[derive(Debug)]
pub enum ConfigError {
    Json(serde_json::Error),
    InvalidHex(String),
    InvalidAddress(String),
    InvalidIp(String),
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigError::Json(e) => write!(f, "JSON error: {e}"),
            ConfigError::InvalidHex(s) => write!(f, "invalid hex: {s}"),
            ConfigError::InvalidAddress(s) => write!(f, "invalid address: {s}"),
            ConfigError::InvalidIp(s) => write!(f, "invalid IP: {s}"),
        }
    }
}

/// Load a static network config from JSON bytes.
pub fn load_from_json(json: &[u8]) -> Result<StaticNetworkConfig, ConfigError> {
    serde_json::from_slice(json).map_err(ConfigError::Json)
}

/// Parse a hex string into a 5-byte ZT address.
fn parse_zt_address(hex: &str) -> Result<[u8; 5], ConfigError> {
    if hex.len() != 10 {
        return Err(ConfigError::InvalidAddress(hex.into()));
    }
    let mut addr = [0u8; 5];
    for (i, byte) in addr.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| ConfigError::InvalidHex(hex.into()))?;
    }
    Ok(addr)
}

/// Parse a hex string into raw bytes.
fn parse_hex_bytes(hex: &str) -> Result<Vec<u8>, ConfigError> {
    if hex.len() % 2 != 0 {
        return Err(ConfigError::InvalidHex(hex.into()));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        bytes.push(
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| ConfigError::InvalidHex(hex.into()))?,
        );
    }
    Ok(bytes)
}

/// Parse "ip/prefix" into (ip, prefix_len).
fn parse_ipv4_cidr(s: &str) -> Result<(Ipv4Addr, u8), ConfigError> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err(ConfigError::InvalidIp(s.into()));
    }
    let ip: Ipv4Addr = parts[0].parse().map_err(|_| ConfigError::InvalidIp(s.into()))?;
    let prefix: u8 = parts[1].parse().map_err(|_| ConfigError::InvalidIp(s.into()))?;
    Ok((ip, prefix))
}

fn parse_ipv6_cidr(s: &str) -> Result<(Ipv6Addr, u8), ConfigError> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err(ConfigError::InvalidIp(s.into()));
    }
    let ip: Ipv6Addr = parts[0].parse().map_err(|_| ConfigError::InvalidIp(s.into()))?;
    let prefix: u8 = parts[1].parse().map_err(|_| ConfigError::InvalidIp(s.into()))?;
    Ok((ip, prefix))
}

impl NetworkMembership {
    /// Build a NetworkMembership from a static config.
    pub fn from_static_config(
        config: &StaticNetworkConfig,
        _our_zt_address: &[u8; 5],
    ) -> Result<Self, ConfigError> {
        // Parse network ID from hex
        let network_id = u64::from_str_radix(&config.network_id, 16)
            .map_err(|_| ConfigError::InvalidHex(config.network_id.clone()))?;

        let mut members = Vec::with_capacity(config.members.len());
        for mc in &config.members {
            let zt_address = parse_zt_address(&mc.address)?;
            let mac = ethernet::derive_mac(&zt_address, network_id);
            let ipv4 = mc.ipv4.as_deref().map(parse_ipv4_cidr).transpose()?;
            let ipv6 = mc.ipv6.as_deref().map(parse_ipv6_cidr).transpose()?;
            members.push(NetworkMember {
                zt_address,
                mac,
                ipv4,
                ipv6,
                authorized: mc.authorized,
            });
        }

        // Parse COM
        let mut qualifiers = Vec::new();
        for qc in &config.com.qualifiers {
            let value = match &qc.value {
                serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
                serde_json::Value::String(s) => {
                    u64::from_str_radix(s.as_str(), 16)
                        .map_err(|_| ConfigError::InvalidHex(s.clone()))?
                }
                _ => 0,
            };
            qualifiers.push(ComQualifier {
                id: qc.id,
                value,
                max_delta: qc.max_delta,
            });
        }

        let signer_address = parse_zt_address(&config.com.signer_address)?;
        let sig_bytes = parse_hex_bytes(&config.com.signature)?;
        let mut signature = [0u8; 96];
        let copy_len = sig_bytes.len().min(96);
        signature[..copy_len].copy_from_slice(&sig_bytes[..copy_len]);

        let our_com = Some(CertificateOfMembership {
            qualifiers,
            signer_address,
            signature,
        });

        let routes = config
            .routes
            .iter()
            .map(|r| Route {
                target: r.target.clone(),
            })
            .collect();

        Ok(NetworkMembership {
            network_id,
            members,
            our_com,
            peer_coms: Vec::new(),
            mtu: config.mtu,
            routes,
            last_config_request: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_JSON: &[u8] = br#"{
        "networkId": "ff00000000abcdef",
        "mtu": 2800,
        "members": [
            {
                "address": "a0b1c2d3e4",
                "ipv4": "10.147.20.1/24",
                "ipv6": "fd00::1/64",
                "authorized": true
            },
            {
                "address": "f0e1d2c3b4",
                "ipv4": "10.147.20.2/24",
                "authorized": true
            }
        ],
        "com": {
            "qualifiers": [
                {"id": 0, "value": 1711500000000, "maxDelta": 360000},
                {"id": 1, "value": "ff00000000abcdef", "maxDelta": 0},
                {"id": 2, "value": "00a0b1c2d3e4", "maxDelta": 0}
            ],
            "signerAddress": "a0b1c2d3e4",
            "signature": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        },
        "routes": [
            {"target": "10.147.20.0/24"},
            {"target": "fd00::/64"}
        ],
        "multicastLimit": 32
    }"#;

    #[test]
    fn load_from_json_parses_valid_config() {
        let config = load_from_json(TEST_JSON).unwrap();
        assert_eq!(config.network_id, "ff00000000abcdef");
        assert_eq!(config.mtu, 2800);
        assert_eq!(config.members.len(), 2);
        assert_eq!(config.routes.len(), 2);
        assert_eq!(config.multicast_limit, 32);
    }

    #[test]
    fn load_from_json_rejects_invalid() {
        assert!(load_from_json(b"not json").is_err());
    }

    #[test]
    fn from_static_config_builds_membership() {
        let config = load_from_json(TEST_JSON).unwrap();
        let our_addr = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let membership = NetworkMembership::from_static_config(&config, &our_addr).unwrap();

        assert_eq!(membership.network_id, 0xff00000000abcdef);
        assert_eq!(membership.mtu, 2800);
        assert_eq!(membership.members.len(), 2);
        assert_eq!(membership.routes.len(), 2);
        assert!(membership.our_com.is_some());

        // Verify first member
        let m1 = &membership.members[0];
        assert_eq!(m1.zt_address, [0xa0, 0xb1, 0xc2, 0xd3, 0xe4]);
        assert_eq!(m1.ipv4, Some((Ipv4Addr::new(10, 147, 20, 1), 24)));
        assert!(m1.authorized);

        // Verify MAC was derived
        let expected_mac = ethernet::derive_mac(&[0xa0, 0xb1, 0xc2, 0xd3, 0xe4], 0xff00000000abcdef);
        assert_eq!(m1.mac, expected_mac);
    }

    #[test]
    fn from_static_config_ip_lookups_work() {
        let config = load_from_json(TEST_JSON).unwrap();
        let our_addr = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let membership = NetworkMembership::from_static_config(&config, &our_addr).unwrap();

        // IPv4 lookup
        let found = membership.lookup_ipv4(Ipv4Addr::new(10, 147, 20, 1));
        assert!(found.is_some());
        assert_eq!(found.unwrap().zt_address, [0xa0, 0xb1, 0xc2, 0xd3, 0xe4]);

        // IPv4 not found
        assert!(membership.lookup_ipv4(Ipv4Addr::new(10, 0, 0, 99)).is_none());

        // MAC lookup
        let mac = ethernet::derive_mac(&[0xf0, 0xe1, 0xd2, 0xc3, 0xb4], 0xff00000000abcdef);
        let found = membership.lookup_mac(&mac);
        assert!(found.is_some());
        assert_eq!(found.unwrap().zt_address, [0xf0, 0xe1, 0xd2, 0xc3, 0xb4]);
    }

    #[test]
    fn from_static_config_com_qualifiers_parsed() {
        let config = load_from_json(TEST_JSON).unwrap();
        let our_addr = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let membership = NetworkMembership::from_static_config(&config, &our_addr).unwrap();

        let com = membership.our_com.as_ref().unwrap();
        assert_eq!(com.qualifiers.len(), 3);
        assert_eq!(com.qualifiers[0].id, 0);
        assert_eq!(com.qualifiers[0].value, 1711500000000);
        assert_eq!(com.qualifiers[0].max_delta, 360000);
        assert_eq!(com.qualifiers[1].id, 1);
        assert_eq!(com.qualifiers[1].value, 0xff00000000abcdef);
        assert_eq!(com.signer_address, [0xa0, 0xb1, 0xc2, 0xd3, 0xe4]);
    }
}
