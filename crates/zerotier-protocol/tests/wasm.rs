//! Smoke tests run under `wasm-pack test --node` to prove zerotier-protocol
//! works when compiled to wasm32-unknown-unknown, not just that it
//! compiles.
#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;
use zerotier_protocol::header::PacketHeader;
use zerotier_protocol::verbs::whois::{WhoisRequest, WhoisResponse};

#[wasm_bindgen_test]
fn packet_header_parses_in_wasm() {
    let dest = [0x01, 0x02, 0x03, 0x04, 0x05];
    let source = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
    let mut buf = [0u8; 28];
    buf[0..8].copy_from_slice(&0xDEADBEEFCAFEBABEu64.to_be_bytes());
    buf[8..13].copy_from_slice(&dest);
    buf[13..18].copy_from_slice(&source);
    buf[18] = 0b01_001_010;
    buf[27] = 0x81;

    let hdr = PacketHeader::from_bytes(&buf).unwrap();
    assert_eq!(hdr.dest_address(), dest);
    assert_eq!(hdr.source_address(), source);
    assert_eq!(hdr.cipher_suite(), 1);
    assert_eq!(hdr.hops(), 2);
    assert!(hdr.is_fragmented());
    assert_eq!(hdr.verb_id(), 0x01);
    assert!(hdr.is_compressed());
    assert_eq!(hdr.packet_id(), 0xDEADBEEFCAFEBABE);
}

#[wasm_bindgen_test]
fn whois_request_roundtrips_in_wasm() {
    let req = WhoisRequest {
        addresses: vec![[1, 2, 3, 4, 5], [6, 7, 8, 9, 10]],
    };
    let mut buf = [0u8; 10];
    let n = req.serialize(&mut buf);
    assert_eq!(n, 10);

    let parsed = WhoisRequest::deserialize(&buf).unwrap();
    assert_eq!(parsed.addresses, req.addresses);
}

#[wasm_bindgen_test]
fn whois_response_parses_empty_in_wasm() {
    let parsed = WhoisResponse::deserialize(&[]).unwrap();
    assert!(parsed.identities.is_empty());
}
