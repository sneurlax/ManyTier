#![no_main]

use libfuzzer_sys::fuzz_target;
use zerotier_crypto::identity::{Address, Identity, PublicKey, SecretKey};
use zerotier_protocol::identity_wire;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = Identity::parse(&text);
    let _ = Address::from_hex(&text);
    let _ = PublicKey::from_hex(&text);

    if data.len() >= 64 {
        let _ = PublicKey::from_bytes(&data[..64]);
        let _ = SecretKey::from_bytes(&data[..64]);
    }

    let _ = identity_wire::deserialize_identity(data);
});
