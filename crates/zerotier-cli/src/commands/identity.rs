//! `manytier identity generate|show` -- offline identity management.

use zerotier_crypto::identity::Identity;

/// Generate a new identity and write to identity.secret / identity.public.
pub fn generate() -> anyhow::Result<()> {
    let mut rng = GetrandomRng;
    let identity =
        Identity::generate(&mut rng).map_err(|e| anyhow::anyhow!("identity generation failed: {:?}", e))?;

    // Write secret identity
    let secret_str = identity
        .to_secret_string()
        .ok_or_else(|| anyhow::anyhow!("generated identity has no secret key"))?;
    std::fs::write("identity.secret", &secret_str)?;

    // Write public identity
    let public_str = identity.to_public_string();
    std::fs::write("identity.public", &public_str)?;

    println!("{}", identity.address.to_hex());
    Ok(())
}

/// Show existing identity from identity.secret file.
pub fn show() -> anyhow::Result<()> {
    let secret_str = std::fs::read_to_string("identity.secret")
        .or_else(|_| std::fs::read_to_string("/var/lib/manytier/identity.secret"))?;
    let identity = Identity::parse(secret_str.trim())
        .map_err(|e| anyhow::anyhow!("failed to parse identity: {:?}", e))?;
    println!("{}", identity.address.to_hex());
    Ok(())
}

/// RNG wrapper using getrandom::fill directly to bridge rand_core version conflicts.
///
/// The dalek crates use rand_core 0.6 transitively while our workspace uses 0.9.
/// This wrapper implements rand_core::RngCore using getrandom::fill to avoid
/// version-mismatch trait bound errors with OsRng.
struct GetrandomRng;

impl rand_core::RngCore for GetrandomRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).expect("getrandom failed");
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("getrandom failed");
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("getrandom failed");
    }
}

impl rand_core::CryptoRng for GetrandomRng {}
