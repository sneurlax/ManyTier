/// Static test network config generator with Ed25519-signed COMs.
///
/// Generates JSON config files for Shadow VL2 tests where each member gets
/// their own Certificate of Membership with correct `issued_to` value (qualifier
/// ID 2) signed by a controller identity's Ed25519 key.
///
/// Design decisions:
/// - Per-member COM in the JSON (each member has their own `com` field)
/// - Qualifiers sorted by ID: 0 (timestamp), 1 (network_id), 2 (issued_to)
/// - 96-byte ZeroTier compound signature (64 Ed25519 + 32 zero padding)
/// - Signature computed over canonical big-endian byte representation
use serde::Serialize;

/// Top-level static network configuration.
#[derive(Serialize)]
pub struct TestNetworkConfig {
    #[serde(rename = "networkId")]
    pub network_id: String,
    pub mtu: u16,
    pub members: Vec<TestMemberConfig>,
    pub routes: Vec<TestRouteConfig>,
    #[serde(rename = "multicastLimit")]
    pub multicast_limit: u32,
    /// Shared COM template (for backward compat with existing config parser).
    /// Each member also has their own per-member COM in the generated output,
    pub com: TestComConfig,
}

/// A member entry with per-member COM.
#[derive(Serialize)]
pub struct TestMemberConfig {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    pub authorized: bool,
    pub com: TestComConfig,
}

/// COM configuration.
#[derive(Serialize, Clone)]
pub struct TestComConfig {
    pub qualifiers: Vec<TestQualifierConfig>,
    #[serde(rename = "signerAddress")]
    pub signer_address: String,
    pub signature: String,
}

/// A qualifier entry.
#[derive(Serialize, Clone)]
pub struct TestQualifierConfig {
    pub id: u64,
    pub value: serde_json::Value,
    #[serde(rename = "maxDelta")]
    pub max_delta: u64,
}

/// A route entry.
#[derive(Serialize)]
pub struct TestRouteConfig {
    pub target: String,
}

/// Encode 5 bytes as 10-char lowercase hex.
fn hex_encode_address(addr: &[u8; 5]) -> String {
    let mut s = String::with_capacity(10);
    for b in addr {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Encode arbitrary bytes as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Build the canonical signed data for a COM.
///
/// Qualifiers sorted by ID ascending, each serialized as:
/// id(u64 BE) + value(u64 BE) + max_delta(u64 BE)
fn build_com_signed_data(timestamp: u64, network_id: u64, issued_to: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(3 * 24); // 3 qualifiers * 24 bytes each

    // Qualifier 0: timestamp
    data.extend_from_slice(&0u64.to_be_bytes());
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(&360000u64.to_be_bytes());

    // Qualifier 1: network_id
    data.extend_from_slice(&1u64.to_be_bytes());
    data.extend_from_slice(&network_id.to_be_bytes());
    data.extend_from_slice(&0u64.to_be_bytes());

    // Qualifier 2: issued_to
    data.extend_from_slice(&2u64.to_be_bytes());
    data.extend_from_slice(&issued_to.to_be_bytes());
    data.extend_from_slice(&0u64.to_be_bytes());

    data
}

/// Convert a 5-byte ZT address to u64 (zero-padded in high bytes).
fn zt_address_to_u64(addr: &[u8; 5]) -> u64 {
    (addr[0] as u64) << 32
        | (addr[1] as u64) << 24
        | (addr[2] as u64) << 16
        | (addr[3] as u64) << 8
        | (addr[4] as u64)
}

/// Generate static test network configuration JSON with per-member signed COMs.
///
/// # Arguments
/// - `controller_signing_key`: Ed25519 key used to sign COMs (simulates controller)
/// - `controller_address`: 5-byte ZT address of the controller/signer
/// - `member_addresses`: Vec of (zt_address_bytes, "ipv4/prefix", "ipv6/prefix")
/// - `network_id`: 64-bit network ID
///
/// Each member receives their own COM with:
/// - Qualifier 0 (timestamp): current timestamp, max_delta=360000 (6 min)
/// - Qualifier 1 (network_id): exact match (max_delta=0)
/// - Qualifier 2 (issued_to): member's ZT address as u64, exact match (max_delta=0)
///
/// The signature is computed via `zerotier_crypto::signing::sign` over the canonical
/// qualifier bytes (sorted by ID, each as id+value+max_delta in BE).
pub fn generate_test_config(
    controller_signing_key: &ed25519_dalek::SigningKey,
    controller_address: &[u8; 5],
    member_addresses: &[([u8; 5], &str, &str)],
    network_id: u64,
) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let signer_address_hex = hex_encode_address(controller_address);
    let network_id_hex = format!("{:016x}", network_id);

    let mut members = Vec::with_capacity(member_addresses.len());
    let mut first_com = None;

    for (zt_addr, ipv4, ipv6) in member_addresses {
        let issued_to = zt_address_to_u64(zt_addr);
        let signed_data = build_com_signed_data(timestamp, network_id, issued_to);
        let signature = zerotier_crypto::signing::sign(controller_signing_key, &signed_data);
        let signature_hex = hex_encode(&signature);

        let com = TestComConfig {
            qualifiers: vec![
                TestQualifierConfig {
                    id: 0,
                    value: serde_json::Value::Number(serde_json::Number::from(timestamp)),
                    max_delta: 360000,
                },
                TestQualifierConfig {
                    id: 1,
                    value: serde_json::Value::String(network_id_hex.clone()),
                    max_delta: 0,
                },
                TestQualifierConfig {
                    id: 2,
                    value: serde_json::Value::String(format!("{:012x}", issued_to)),
                    max_delta: 0,
                },
            ],
            signer_address: signer_address_hex.clone(),
            signature: signature_hex,
        };

        if first_com.is_none() {
            first_com = Some(com.clone());
        }

        let ipv4_opt = if ipv4.is_empty() {
            None
        } else {
            Some(ipv4.to_string())
        };
        let ipv6_opt = if ipv6.is_empty() {
            None
        } else {
            Some(ipv6.to_string())
        };

        members.push(TestMemberConfig {
            address: hex_encode_address(zt_addr),
            ipv4: ipv4_opt,
            ipv6: ipv6_opt,
            authorized: true,
            com,
        });
    }

    let config = TestNetworkConfig {
        network_id: network_id_hex,
        mtu: 2800,
        members,
        routes: vec![
            TestRouteConfig {
                target: "10.147.20.0/24".to_string(),
            },
            TestRouteConfig {
                target: "fd00::/64".to_string(),
            },
        ],
        multicast_limit: 32,
        com: first_com.expect("at least one member required"),
    };

    serde_json::to_string_pretty(&config).expect("JSON serialization failed")
}

/// Generate a config file and write it to disk, returning the JSON string.
///
/// This is the convenience wrapper called from shadow-node setup.
#[allow(dead_code)] // used by a subset of the test binaries that include this module
pub fn generate_test_config_to_file(
    controller_signing_key: &ed25519_dalek::SigningKey,
    controller_address: &[u8; 5],
    member_addresses: &[([u8; 5], &str, &str)],
    network_id: u64,
    output_path: &std::path::Path,
) -> String {
    let json = generate_test_config(
        controller_signing_key,
        controller_address,
        member_addresses,
        network_id,
    );
    std::fs::write(output_path, &json).expect("failed to write config file");
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_json_with_signed_coms() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let controller_addr = [0x01, 0x02, 0x03, 0x04, 0x05];
        let members = vec![
            (
                [0xa0, 0xb1, 0xc2, 0xd3, 0xe4],
                "10.147.20.1/24",
                "fd00::1/64",
            ),
            (
                [0xf0, 0xe1, 0xd2, 0xc3, 0xb4],
                "10.147.20.2/24",
                "fd00::2/64",
            ),
        ];

        let json =
            generate_test_config(&signing_key, &controller_addr, &members, 0xff00000000abcdef);

        // Parse it back
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["networkId"], "ff00000000abcdef");
        assert_eq!(v["mtu"], 2800);
        assert_eq!(v["members"].as_array().unwrap().len(), 2);

        // Each member has their own COM
        let m0 = &v["members"][0];
        assert!(m0["com"]["signature"].as_str().unwrap().len() == 192); // 96 bytes = 192 hex
        assert_eq!(m0["com"]["qualifiers"].as_array().unwrap().len(), 3);

        let m1 = &v["members"][1];
        assert!(m1["com"]["signature"].as_str().unwrap().len() == 192);

        // Signatures should differ because issued_to differs
        assert_ne!(
            m0["com"]["signature"].as_str().unwrap(),
            m1["com"]["signature"].as_str().unwrap(),
        );

        // Verify that signer_address matches controller
        assert_eq!(m0["com"]["signerAddress"], "0102030405");
    }

    #[test]
    fn com_signature_is_verifiable() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let controller_addr = [0x01, 0x02, 0x03, 0x04, 0x05];
        let zt_addr = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let network_id = 0xff00000000abcdef_u64;

        let members = vec![(zt_addr, "10.147.20.1/24", "fd00::1/64")];

        let json = generate_test_config(&signing_key, &controller_addr, &members, network_id);

        // Parse the config and verify the COM signature
        let config: zerotier_node::network_config::StaticNetworkConfig =
            serde_json::from_str(&json).unwrap();
        let membership =
            zerotier_node::network::NetworkMembership::from_static_config(&config, &zt_addr)
                .unwrap();

        let com = membership.our_com.as_ref().unwrap();

        // Use the existing com_verify_signature function
        assert!(
            zerotier_node::network::com_verify_signature(com, &verifying_key),
            "COM signature verification failed"
        );
    }

    #[test]
    fn qualifier_ids_are_correct() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let controller_addr = [0x01, 0x02, 0x03, 0x04, 0x05];
        let members = vec![([0xa0, 0xb1, 0xc2, 0xd3, 0xe4], "10.147.20.1/24", "")];

        let json =
            generate_test_config(&signing_key, &controller_addr, &members, 0xff00000000abcdef);

        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let quals = v["members"][0]["com"]["qualifiers"].as_array().unwrap();
        assert_eq!(quals[0]["id"], 0);
        assert_eq!(quals[0]["maxDelta"], 360000);
        assert_eq!(quals[1]["id"], 1);
        assert_eq!(quals[1]["maxDelta"], 0);
        assert_eq!(quals[2]["id"], 2);
        assert_eq!(quals[2]["maxDelta"], 0);
    }
}
