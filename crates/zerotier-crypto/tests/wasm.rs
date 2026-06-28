//! Smoke tests run under `wasm-pack test --node` to prove zerotier-crypto
//! works when compiled to wasm32-unknown-unknown, not just that it
//! compiles.
#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;
use zerotier_crypto::salsa::{armor_packet, crypt_packet_field, dearmor_packet};

fn make_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 32) as u8);
    }
    out
}

fn make_packet(seed: u64, payload_len: usize) -> (Vec<u8>, [u8; 48]) {
    let payload = make_bytes(seed, payload_len);
    let secret: [u8; 48] = make_bytes(seed ^ 0xfeed_beef, 48).try_into().unwrap();
    let mut packet = vec![0u8; 28 + payload.len()];
    packet[0..8].copy_from_slice(&seed.to_be_bytes());
    packet[8..13].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    packet[13..18].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]);
    packet[18] = 0x08;
    packet[27] = 0x05;
    packet[28..].copy_from_slice(&payload);
    (packet, secret)
}

#[wasm_bindgen_test]
fn armor_roundtrips_in_wasm() {
    let (mut packet, secret) = make_packet(42, 64);
    let original = packet.clone();
    armor_packet(&secret, &mut packet, true).unwrap();
    dearmor_packet(&secret, &mut packet).unwrap();
    assert_eq!(&packet[28..], &original[28..]);
    assert_eq!(packet[27], original[27]);
}

#[wasm_bindgen_test]
fn crypt_packet_field_roundtrips_in_wasm() {
    let (mut packet, secret) = make_packet(7, 32);
    let original = packet.clone();
    let field_len = packet.len().saturating_sub(27).min(32);
    crypt_packet_field(&secret, &mut packet, 27, field_len).unwrap();
    assert_ne!(packet, original);
    crypt_packet_field(&secret, &mut packet, 27, field_len).unwrap();
    assert_eq!(packet, original);
}
