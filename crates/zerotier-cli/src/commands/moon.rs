//! `manytier moon generate` -- create a signed moon world file.
//!
//! Offline command: it reads a secret identity and endpoint list and writes a
//! `.moon` file, without talking to a running service. The moon world ID is
//! the root identity's ZeroTier address (matching official ZeroTier's
//! convention), unless overridden.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use zerotier_crypto::identity::Identity;
use zerotier_node::controller::world_gen::generate_moon;
use zerotier_protocol::inet_address::InetAddress;
use zerotier_protocol::world::WorldRoot;

pub fn generate(
    identity_path: &str,
    endpoints: &[String],
    output: Option<&str>,
    moon_id: Option<&str>,
) -> anyhow::Result<()> {
    let identity_str = std::fs::read_to_string(identity_path)
        .with_context(|| format!("failed to read identity from {identity_path}"))?;
    let identity = Identity::parse(identity_str.trim())
        .map_err(|e| anyhow::anyhow!("failed to parse identity: {e:?}"))?;
    let secret = identity
        .secret
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("moon generation requires a SECRET identity (identity.secret), got a public-only identity"))?;

    if endpoints.is_empty() {
        anyhow::bail!("at least one --endpoint <ip:port> is required");
    }
    let inet_endpoints: Vec<InetAddress> = endpoints
        .iter()
        .map(|e| {
            let sock: SocketAddr = e
                .parse()
                .with_context(|| format!("invalid endpoint '{e}' (expected ip:port)"))?;
            Ok(match sock {
                SocketAddr::V4(v4) => InetAddress::V4 {
                    ip: v4.ip().octets(),
                    port: v4.port(),
                },
                SocketAddr::V6(v6) => InetAddress::V6 {
                    ip: v6.ip().octets(),
                    port: v6.port(),
                },
            })
        })
        .collect::<anyhow::Result<_>>()?;

    let addr = identity.address.as_bytes();
    let default_moon_id =
        u64::from_be_bytes([0, 0, 0, addr[0], addr[1], addr[2], addr[3], addr[4]]);
    let moon_id = match moon_id {
        Some(id) => u64::from_str_radix(id, 16).context("invalid --moon-id (expected hex)")?,
        None => default_moon_id,
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis() as u64;

    // 64-byte world signing key: [x25519 dh (32) | ed25519 verifying (32)],
    // matching the identity public key layout.
    let mut public_key_bytes = [0u8; 64];
    public_key_bytes[..32].copy_from_slice(&identity.public_key.dh);
    public_key_bytes[32..].copy_from_slice(&identity.public_key.signing);

    let root = WorldRoot {
        identity: Identity {
            address: identity.address,
            public_key: identity.public_key.clone(),
            secret: None,
        },
        endpoints: inet_endpoints,
    };

    let moon_bytes = generate_moon(
        moon_id,
        timestamp,
        vec![root],
        &secret.signing,
        &public_key_bytes,
    );

    let output_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{moon_id:016x}.moon")));
    std::fs::write(&output_path, &moon_bytes)
        .with_context(|| format!("failed to write {}", output_path.display()))?;

    println!("moon generated: {}", output_path.display());
    println!("moon id:        {moon_id:016x}");
    println!(
        "root address:   {:02x}{:02x}{:02x}{:02x}{:02x}",
        addr[0], addr[1], addr[2], addr[3], addr[4]
    );
    println!("endpoints:      {}", endpoints.join(", "));
    println!();
    println!("To orbit from another node:");
    println!(
        "  1. copy {} into that node's {{data-dir}}/moons.d/",
        output_path.display()
    );
    println!("  2. manytier orbit {moon_id:016x}   (or restart the service)");
    Ok(())
}
