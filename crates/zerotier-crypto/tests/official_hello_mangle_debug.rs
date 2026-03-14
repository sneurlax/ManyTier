// Brute-force MAC-variant debug harness; the parameter sweeps intentionally
// take one argument per axis.
#![allow(clippy::too_many_arguments)]

use std::fs;

use cipher::{KeyIvInit, StreamCipher};
use poly1305::Poly1305;
use salsa20::{Salsa12, Salsa20};
use sha2::{Digest, Sha512};
use universal_hash::{KeyInit as _, UniversalHash};
use zerotier_crypto::identity::Identity;
use zerotier_crypto::salsa::{
    PACKET_IV_LEN, PACKET_IV_OFFSET, PACKET_MAC_LEN, PACKET_MAC_OFFSET, PACKET_MIN_LEN,
    PACKET_VERB_OFFSET,
};

#[derive(Clone, Copy, Debug)]
enum SizeEndian {
    Le,
    Be,
}

#[derive(Clone, Copy, Debug)]
enum CipherKind {
    Salsa12,
    Salsa20,
}

fn derive_key(
    shared_secret: &[u8; 32],
    packet: &[u8],
    xor_len: usize,
    zero_mac_for_xor: bool,
    mask_flags: bool,
    size_xor_pos: Option<usize>,
    size_endian: SizeEndian,
    size_sub: usize,
) -> [u8; 32] {
    let mut key = *shared_secret;

    let xor_len = xor_len.min(32).min(packet.len());
    if xor_len > 0 {
        let mut tmp: [u8; 32] = [0u8; 32];
        tmp[..xor_len].copy_from_slice(&packet[..xor_len]);
        if zero_mac_for_xor && xor_len > PACKET_MAC_OFFSET {
            let end = xor_len.min(PACKET_MAC_OFFSET + PACKET_MAC_LEN);
            for b in &mut tmp[PACKET_MAC_OFFSET..end] {
                *b = 0;
            }
        }
        if mask_flags && xor_len > 18 {
            tmp[18] &= 0xf8;
        }
        for i in 0..xor_len {
            key[i] ^= tmp[i];
        }
    }

    if let Some(pos) = size_xor_pos {
        if pos + 1 < 32 {
            let size_value = packet.len().saturating_sub(size_sub) as u16;
            let (b0, b1) = match size_endian {
                SizeEndian::Le => (size_value as u8, (size_value >> 8) as u8),
                SizeEndian::Be => ((size_value >> 8) as u8, size_value as u8),
            };
            key[pos] ^= b0;
            key[pos + 1] ^= b1;
        }
    }

    key
}

#[derive(Clone, Copy, Debug)]
enum MacVerbInclusion {
    IncludeVerb,
    ExcludeVerb,
}

/// Which Poly1305 finalization mode to use.
#[derive(Clone, Copy, Debug)]
enum PolyMode {
    /// `update_padded`: zero-pads partial blocks to 16 bytes
    UpdatePadded,
    /// `compute_unpadded`: adds 0x01 high bit at data boundary (correct per RFC)
    ComputeUnpadded,
}

/// Which header prefix to include before the payload in the MAC data.
#[derive(Clone, Copy, Debug)]
enum MacPrefix {
    /// No prefix: MAC only covers payload (what ManyTier's armor_packet does)
    None,
    /// Prefix with packet[0..MAC_OFFSET] (bytes 0-18, header before MAC field)
    HeaderBeforeMac,
    /// Prefix with full header[0..VERB_OFFSET] with MAC field zeroed
    HeaderWithZeroMac,
}

fn compute_mac_full(
    packet: &[u8],
    key: &[u8; 32],
    cipher: CipherKind,
    poly_key_offset: usize,
    mac_prefix: MacPrefix,
    mask_nonce: bool,
    verb_inclusion: MacVerbInclusion,
    poly_mode: PolyMode,
) -> [u8; 16] {
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]);
    if mask_nonce {
        nonce[7] &= 0xf8;
    }

    let mut poly_stream = vec![0u8; poly_key_offset + 32];
    match cipher {
        CipherKind::Salsa12 => {
            let mut c = Salsa12::new(key.into(), &nonce.into());
            c.apply_keystream(&mut poly_stream);
        }
        CipherKind::Salsa20 => {
            let mut c = Salsa20::new(key.into(), &nonce.into());
            c.apply_keystream(&mut poly_stream);
        }
    }
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_stream[poly_key_offset..poly_key_offset + 32]);

    let mut data = Vec::new();

    match mac_prefix {
        MacPrefix::None => {}
        MacPrefix::HeaderBeforeMac => {
            data.extend_from_slice(&packet[0..PACKET_MAC_OFFSET]);
        }
        MacPrefix::HeaderWithZeroMac => {
            let mut prefix = packet[0..PACKET_VERB_OFFSET].to_vec();
            prefix[PACKET_MAC_OFFSET..PACKET_MAC_OFFSET + PACKET_MAC_LEN].fill(0);
            data.extend_from_slice(&prefix);
        }
    }

    let payload_start = match verb_inclusion {
        MacVerbInclusion::IncludeVerb => PACKET_VERB_OFFSET,
        MacVerbInclusion::ExcludeVerb => PACKET_VERB_OFFSET + 1,
    };
    if packet.len() > payload_start {
        data.extend_from_slice(&packet[payload_start..]);
    }

    let tag = match poly_mode {
        PolyMode::UpdatePadded => {
            let mut mac = Poly1305::new((&poly_key).into());
            mac.update_padded(&data);
            mac.finalize()
        }
        PolyMode::ComputeUnpadded => Poly1305::new((&poly_key).into()).compute_unpadded(&data),
    };
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    out
}

#[test]
#[ignore]
fn debug_mangle_variants_against_official_hello() {
    let packet_path = std::env::var("MANYTIER_DEBUG_OFFICIAL_HELLO_PACKET")
        .expect("set MANYTIER_DEBUG_OFFICIAL_HELLO_PACKET to a captured rx-hello-*.bin");
    let our_identity_secret_path = std::env::var("MANYTIER_DEBUG_OUR_IDENTITY_SECRET")
        .expect("set MANYTIER_DEBUG_OUR_IDENTITY_SECRET to ManyTier identity.secret");
    let official_identity_public_path = std::env::var("MANYTIER_DEBUG_OFFICIAL_IDENTITY_PUBLIC")
        .expect("set MANYTIER_DEBUG_OFFICIAL_IDENTITY_PUBLIC to official identity.public");

    let packet = fs::read(packet_path).expect("failed to read packet");
    assert!(packet.len() >= PACKET_MIN_LEN);

    let mut saved_mac = [0u8; 8];
    saved_mac.copy_from_slice(&packet[PACKET_MAC_OFFSET..PACKET_MAC_OFFSET + PACKET_MAC_LEN]);

    let our_id_s = fs::read_to_string(our_identity_secret_path).expect("read identity.secret");
    let our_id = Identity::parse(our_id_s.trim()).expect("parse identity.secret");
    let our_secret = our_id
        .secret
        .as_ref()
        .expect("identity.secret must contain secret");

    let official_pub_s =
        fs::read_to_string(official_identity_public_path).expect("read identity.public");
    let official_pub = Identity::parse(official_pub_s.trim()).expect("parse identity.public");

    let their_pub = x25519_dalek::PublicKey::from(official_pub.public_key.dh);
    let raw = our_secret.dh.diffie_hellman(&their_pub).to_bytes();
    let digest = Sha512::digest(raw);
    let mut digest_first = [0u8; 32];
    digest_first.copy_from_slice(&digest[..32]);
    let mut digest_last = [0u8; 32];
    digest_last.copy_from_slice(&digest[32..64]);
    let mut raw_xor_digest_first = [0u8; 32];
    let mut raw_xor_digest_last = [0u8; 32];
    for i in 0..32 {
        raw_xor_digest_first[i] = raw[i] ^ digest_first[i];
        raw_xor_digest_last[i] = raw[i] ^ digest_last[i];
    }

    let secret_candidates: [(&str, [u8; 32]); 6] = [
        ("raw", raw),
        ("sha512_first", digest_first),
        ("sha512_last", digest_last),
        ("raw_xor_sha512_first", raw_xor_digest_first),
        ("raw_xor_sha512_last", raw_xor_digest_last),
        ("null", [0u8; 32]),
    ];

    let xor_lens = [18usize, 19, 27, 28, 29, 32];
    let size_xor_pos = [None, Some(19usize), Some(20usize), Some(21usize)];
    let size_subs = [0usize, 16, 27, 28];
    let poly_offsets = [0usize, 32];

    let mut match_count = 0u64;
    let mut total_count = 0u64;

    for (secret_label, shared_secret) in secret_candidates {
        for &cipher in &[CipherKind::Salsa12, CipherKind::Salsa20] {
            for &xor_len in &xor_lens {
                for zero_mac_for_xor in [false, true] {
                    for mask_flags in [false, true] {
                        for &size_pos in &size_xor_pos {
                            for &size_endian in &[SizeEndian::Le, SizeEndian::Be] {
                                for &size_sub in &size_subs {
                                    let key = derive_key(
                                        &shared_secret,
                                        &packet,
                                        xor_len,
                                        zero_mac_for_xor,
                                        mask_flags,
                                        size_pos,
                                        size_endian,
                                        size_sub,
                                    );
                                    for &poly_offset in &poly_offsets {
                                        for mac_prefix in [
                                            MacPrefix::None,
                                            MacPrefix::HeaderBeforeMac,
                                            MacPrefix::HeaderWithZeroMac,
                                        ] {
                                            for mask_nonce in [false, true] {
                                                for verb_inclusion in [
                                                    MacVerbInclusion::IncludeVerb,
                                                    MacVerbInclusion::ExcludeVerb,
                                                ] {
                                                    for poly_mode in [
                                                        PolyMode::UpdatePadded,
                                                        PolyMode::ComputeUnpadded,
                                                    ] {
                                                        total_count += 1;
                                                        let tag = compute_mac_full(
                                                            &packet,
                                                            &key,
                                                            cipher,
                                                            poly_offset,
                                                            mac_prefix,
                                                            mask_nonce,
                                                            verb_inclusion,
                                                            poly_mode,
                                                        );
                                                        let candidates: [[u8; 8]; 4] = [
                                                            tag[0..8].try_into().unwrap(),
                                                            tag[8..16].try_into().unwrap(),
                                                            {
                                                                let mut b: [u8; 8] =
                                                                    tag[0..8].try_into().unwrap();
                                                                b.reverse();
                                                                b
                                                            },
                                                            {
                                                                let mut b: [u8; 8] =
                                                                    tag[8..16].try_into().unwrap();
                                                                b.reverse();
                                                                b
                                                            },
                                                        ];
                                                        if candidates
                                                            .iter()
                                                            .any(|c| c == &saved_mac)
                                                        {
                                                            match_count += 1;
                                                            eprintln!(
                                                            "MATCH: secret={secret_label} cipher={cipher:?} xor_len={xor_len} zero_mac_for_xor={zero_mac_for_xor} mask_flags={mask_flags} size_pos={size_pos:?} size_endian={size_endian:?} size_sub={size_sub} poly_offset={poly_offset} mac_prefix={mac_prefix:?} mask_nonce={mask_nonce} verb_inclusion={verb_inclusion:?} poly_mode={poly_mode:?} tag={}",
                                                            tag.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                                                        );
                                                            // Don't return immediately: collect all matches
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    eprintln!("Tested {} variants total", total_count);
    if match_count > 0 {
        eprintln!("Found {} matches!", match_count);
    } else {
        panic!(
            "no variants matched saved MAC for this packet (len={})",
            packet.len()
        );
    }
}

/// Decrypt the official HELLO's encrypted section to reveal moon count and COR.
#[test]
#[ignore]
fn decrypt_official_hello_encrypted_section() {
    let packet_path = std::env::var("MANYTIER_DEBUG_OFFICIAL_HELLO_PACKET")
        .expect("set MANYTIER_DEBUG_OFFICIAL_HELLO_PACKET to a captured rx-hello-*.bin");
    let our_identity_secret_path = std::env::var("MANYTIER_DEBUG_OUR_IDENTITY_SECRET")
        .expect("set MANYTIER_DEBUG_OUR_IDENTITY_SECRET to ManyTier identity.secret");
    let official_identity_public_path = std::env::var("MANYTIER_DEBUG_OFFICIAL_IDENTITY_PUBLIC")
        .expect("set MANYTIER_DEBUG_OFFICIAL_IDENTITY_PUBLIC to official identity.public");

    let packet = fs::read(packet_path).expect("failed to read packet");
    let packet_len = packet.len();

    let our_id_s = fs::read_to_string(our_identity_secret_path).expect("read identity.secret");
    let our_id = Identity::parse(our_id_s.trim()).expect("parse identity.secret");
    let our_secret = our_id
        .secret
        .as_ref()
        .expect("identity.secret must contain secret");

    let official_pub_s =
        fs::read_to_string(official_identity_public_path).expect("read identity.public");
    let official_pub = Identity::parse(official_pub_s.trim()).expect("parse identity.public");

    let shared_secret = zerotier_crypto::key_agreement::key_agree(
        &our_secret.dh,
        &x25519_dalek::PublicKey::from(official_pub.public_key.dh),
    );

    // Try different encrypted section start offsets.
    // The official code might encrypt from the planet info section, not just the moon count.
    // Possible starts: 119 (before planet world_id), 135 (after planet info)
    // Also try null key
    let null_key = [0u8; 48];
    for (key_label, key) in [("shared_secret", &shared_secret), ("null", &null_key)] {
        for encrypted_start in [119usize, 135] {
            let encrypted_len = packet_len - encrypted_start;
            let mut test_pkt = packet.clone();

            eprintln!(
                "\n--- Trying key={} encrypted_start={} ---",
                key_label, encrypted_start
            );
            eprintln!(
                "Encrypted section ({} bytes at offset {}): {}",
                encrypted_len,
                encrypted_start,
                test_pkt[encrypted_start..]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );

            // Decrypt the entire encrypted section
            zerotier_crypto::salsa::crypt_packet_field(
                key,
                &mut test_pkt,
                encrypted_start,
                encrypted_len,
            )
            .unwrap();

            eprintln!(
                "Decrypted section ({} bytes): {}",
                encrypted_len,
                test_pkt[encrypted_start..]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );

            if encrypted_start == 119 {
                // If encrypted from planet info position:
                let wid = u64::from_be_bytes(test_pkt[119..127].try_into().unwrap());
                let wts = u64::from_be_bytes(test_pkt[127..135].try_into().unwrap());
                let mc = u16::from_be_bytes([test_pkt[135], test_pkt[136]]);
                eprintln!("  planet_world_id: {} (0x{:016x})", wid, wid);
                eprintln!("  planet_world_ts: {} (0x{:016x})", wts, wts);
                eprintln!("  moon_count: {}", mc);
                if mc == 0 && 137 < packet_len {
                    eprintln!(
                        "  After moons ({} bytes): {}",
                        packet_len - 137,
                        test_pkt[137..]
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<String>()
                    );
                }
            } else {
                let mc = u16::from_be_bytes([test_pkt[135], test_pkt[136]]);
                eprintln!("  moon_count: {}", mc);
            }
        } // end for encrypted_start
    } // end for key
}

/// Verify that ManyTier's actual `dearmor_packet` can verify the official HELLO.
///
/// This uses the same captured packet and identities as the brute-force test,
/// but calls ManyTier's production code path instead of the test's own
/// re-implementation.
#[test]
#[ignore]
fn dearmor_official_hello_with_manytier_code() {
    let packet_path = std::env::var("MANYTIER_DEBUG_OFFICIAL_HELLO_PACKET")
        .expect("set MANYTIER_DEBUG_OFFICIAL_HELLO_PACKET to a captured rx-hello-*.bin");
    let our_identity_secret_path = std::env::var("MANYTIER_DEBUG_OUR_IDENTITY_SECRET")
        .expect("set MANYTIER_DEBUG_OUR_IDENTITY_SECRET to ManyTier identity.secret");
    let official_identity_public_path = std::env::var("MANYTIER_DEBUG_OFFICIAL_IDENTITY_PUBLIC")
        .expect("set MANYTIER_DEBUG_OFFICIAL_IDENTITY_PUBLIC to official identity.public");

    let mut packet = fs::read(packet_path).expect("failed to read packet");
    assert!(packet.len() >= PACKET_MIN_LEN);

    let our_id_s = fs::read_to_string(our_identity_secret_path).expect("read identity.secret");
    let our_id = Identity::parse(our_id_s.trim()).expect("parse identity.secret");
    let our_secret = our_id
        .secret
        .as_ref()
        .expect("identity.secret must contain secret");

    let official_pub_s =
        fs::read_to_string(official_identity_public_path).expect("read identity.public");
    let official_pub = Identity::parse(official_pub_s.trim()).expect("parse identity.public");

    // Derive shared secret the same way ManyTier's node does
    let shared_secret = zerotier_crypto::key_agreement::key_agree(
        &our_secret.dh,
        &x25519_dalek::PublicKey::from(official_pub.public_key.dh),
    );

    eprintln!(
        "Shared secret (first 8): {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        shared_secret[0],
        shared_secret[1],
        shared_secret[2],
        shared_secret[3],
        shared_secret[4],
        shared_secret[5],
        shared_secret[6],
        shared_secret[7]
    );
    eprintln!(
        "Packet len: {}, saved MAC: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        packet.len(),
        packet[PACKET_MAC_OFFSET],
        packet[PACKET_MAC_OFFSET + 1],
        packet[PACKET_MAC_OFFSET + 2],
        packet[PACKET_MAC_OFFSET + 3],
        packet[PACKET_MAC_OFFSET + 4],
        packet[PACKET_MAC_OFFSET + 5],
        packet[PACKET_MAC_OFFSET + 6],
        packet[PACKET_MAC_OFFSET + 7]
    );

    let result = zerotier_crypto::salsa::dearmor_packet(&shared_secret, &mut packet);
    match result {
        Ok(()) => eprintln!("SUCCESS: ManyTier dearmor_packet verified official HELLO MAC"),
        Err(e) => panic!(
            "FAILED: ManyTier dearmor_packet rejected official HELLO: {:?}",
            e
        ),
    }
}

// ---------------------------------------------------------------------------
// Side-by-side HELLO layout decoder + diff.
//
// Consumes two ground-truth packets:
//   MANYTIER_DEBUG_MANYTIER_TX_HELLO : a real ManyTier tx HELLO (from the
//      MANYTIER_DUMP_UDP=1 path wired in Task 1).
//   MANYTIER_DEBUG_OFFICIAL_RX_HELLO : a real captured official HELLO from
//      the 2026-04-11 privileged run (629 bytes).
//
// Parses the plaintext 27-byte packet header of both, prints field-by-field
// annotations with offsets, then hex-dumps the entire payload past offset 27
// with 16 bytes per line. ManyTier's known plaintext HELLO fields (version,
// version triple, timestamp, sender identity, dest_inet, moon count, COR
// trailer) are annotated inline where possible so the reader can see exactly
// where the two diverge.
//
// The official HELLO's payload is encrypted under cipher suite 1 so the
// decoder gracefully marks the payload as "opaque (cipher_suite=1)" and
// dumps it as raw hex. The point of this test is NOT to decrypt the official
// payload: that would require the shared secret with the sending root. The
// point is to expose the STRUCTURAL divergence (cipher suite bit, verb high
// flags, total size, trailing bytes) so Task 3 can cross-reference upstream
// source with concrete offsets.
//
// Output is printed to stderr AND written to
// tests/shadow/artifacts/hello-diff-<TIMESTAMP>.txt for offline review.

fn hex_dump_with_offsets(bytes: &[u8], start_offset: usize, out: &mut String) {
    use std::fmt::Write as _;
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let line_off = start_offset + i * 16;
        let hex: String = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        let _ = writeln!(out, "  {:04x}  {:<48}  |{}|", line_off, hex, ascii);
    }
}

fn decode_header(label: &str, bytes: &[u8], out: &mut String) {
    use std::fmt::Write as _;
    let _ = writeln!(out, "=== {} ({} bytes) ===", label, bytes.len());
    if bytes.len() < 28 {
        let _ = writeln!(out, "  <packet too short to have a verb byte>");
        return;
    }
    let packet_id = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
    let dest: [u8; 5] = bytes[8..13].try_into().unwrap();
    let src: [u8; 5] = bytes[13..18].try_into().unwrap();
    let flags = bytes[18];
    let cipher_suite = flags & 0x38; // bits 3..=5
    let hops = flags & 0x07;
    let fragment = flags & 0x40;
    let mac_hex: String = bytes[19..27].iter().map(|b| format!("{:02x}", b)).collect();
    let verb = bytes[27];
    let verb_id = verb & 0x1f;
    let verb_high = verb & 0xe0;

    let _ = writeln!(
        out,
        "  offset  0..8   : packet_id       = 0x{:016x}",
        packet_id
    );
    let _ = writeln!(
        out,
        "  offset  8..13  : dest_addr       = {:02x}{:02x}{:02x}{:02x}{:02x}",
        dest[0], dest[1], dest[2], dest[3], dest[4]
    );
    let _ = writeln!(
        out,
        "  offset 13..18  : src_addr        = {:02x}{:02x}{:02x}{:02x}{:02x}",
        src[0], src[1], src[2], src[3], src[4]
    );
    let _ = writeln!(
        out,
        "  offset 18      : flags           = 0x{:02x}  (cipher_suite={}, hops={}, fragment_bit={})",
        flags,
        cipher_suite >> 3,
        hops,
        if fragment != 0 { 1 } else { 0 }
    );
    let _ = writeln!(out, "  offset 19..27  : mac             = {}", mac_hex);
    let _ = writeln!(
        out,
        "  offset 27      : verb+high_flags = 0x{:02x}  (verb_id=0x{:02x}, high_flags=0x{:02x})",
        verb, verb_id, verb_high
    );
    if verb_high != 0 {
        let _ = writeln!(
            out,
            "                                  (0x20=bit5 {}, 0x40=bit6 {}, 0x80=bit7 {})",
            if verb_high & 0x20 != 0 {
                "SET"
            } else {
                "unset"
            },
            if verb_high & 0x40 != 0 {
                "SET"
            } else {
                "unset"
            },
            if verb_high & 0x80 != 0 {
                "SET"
            } else {
                "unset"
            }
        );
    }
}

fn decode_manytier_hello_payload(bytes: &[u8], out: &mut String) {
    use std::fmt::Write as _;
    // ManyTier HELLO layout past the 27-byte header (see crates/zerotier-node/src/root.rs::build_hello):
    //   offset 28     : protocol version (1 byte)
    //   offset 29     : major version    (1 byte)
    //   offset 30     : minor version    (1 byte)
    //   offset 31..33 : revision         (2 bytes BE)
    //   offset 33..41 : timestamp ms     (8 bytes BE)
    //   offset 41..N  : sender Identity.serialize()  (variable)
    //   offset N..M   : InetAddress (dest_inet)       (variable)
    //   offset M..M+2 : moon_count u16 BE             (2 bytes)
    //   offset M+2..  : (moon records if any)
    //   offset end-2  : COR trailer (2 bytes 0x00 0x00)
    if bytes.len() < 41 {
        let _ = writeln!(out, "  <payload too short for ManyTier HELLO header>");
        return;
    }
    let proto = bytes[28];
    let major = bytes[29];
    let minor = bytes[30];
    let rev = u16::from_be_bytes([bytes[31], bytes[32]]);
    let ts = u64::from_be_bytes(bytes[33..41].try_into().unwrap());
    let _ = writeln!(out, "  offset 28      : proto_version   = 0x{:02x}", proto);
    let _ = writeln!(out, "  offset 29      : major           = {}", major);
    let _ = writeln!(out, "  offset 30      : minor           = {}", minor);
    let _ = writeln!(out, "  offset 31..33  : revision        = {}", rev);
    let _ = writeln!(out, "  offset 33..41  : timestamp_ms    = {}", ts);
    let _ = writeln!(
        out,
        "  offset 41..    : identity + dest_inet + moon_count + COR (opaque to this decoder)"
    );
    let _ = writeln!(out, "  ---- raw payload dump from offset 28 ----");
    hex_dump_with_offsets(&bytes[28..], 28, out);
}

fn decode_official_hello_payload(bytes: &[u8], cipher_suite: u8, out: &mut String) {
    use std::fmt::Write as _;
    if bytes.len() < 28 {
        let _ = writeln!(out, "  <payload missing>");
        return;
    }
    if cipher_suite == 1 {
        let _ = writeln!(
            out,
            "  payload is OPAQUE: cipher_suite=1 means bytes 28..end are Salsa20/12-encrypted"
        );
        let _ = writeln!(
            out,
            "  (decrypting would require the shared secret with the sender, which is not available here)"
        );
    } else {
        let _ = writeln!(
            out,
            "  payload cipher_suite={}: raw bytes are plaintext per upstream",
            cipher_suite
        );
    }
    let _ = writeln!(out, "  ---- raw payload dump from offset 28 ----");
    hex_dump_with_offsets(&bytes[28..], 28, out);
}

#[test]
#[ignore]
fn decode_and_diff_hello_layouts() {
    use std::fmt::Write as _;

    let manytier_path = std::env::var("MANYTIER_DEBUG_MANYTIER_TX_HELLO").expect(
        "set MANYTIER_DEBUG_MANYTIER_TX_HELLO to a ManyTier tx HELLO (tx-hello-*.bin); produced by running \
         the M2M fallback test with MANYTIER_DUMP_UDP=1 (already wired in tests/shadow/harness.rs)",
    );
    let official_path = std::env::var("MANYTIER_DEBUG_OFFICIAL_RX_HELLO").expect(
        "set MANYTIER_DEBUG_OFFICIAL_RX_HELLO to a captured official HELLO (rx-hello-*.bin); a real 629-byte \
         capture lives at tests/shadow/artifacts/run-20260411T120644/host-assisted-fallback/manytier-controller/manytier-data/udp-dumps/",
    );

    let manytier_pkt = fs::read(&manytier_path).unwrap_or_else(|e| {
        panic!(
            "failed to read ManyTier tx HELLO at {}: {}",
            manytier_path, e
        )
    });
    let official_pkt = fs::read(&official_path).unwrap_or_else(|e| {
        panic!(
            "failed to read official rx HELLO at {}: {}",
            official_path, e
        )
    });

    let mut out = String::new();
    let _ = writeln!(out, "Side-by-side HELLO layout diff");
    let _ = writeln!(out, "ManyTier tx HELLO source: {}", manytier_path);
    let _ = writeln!(out, "Official rx HELLO source: {}", official_path);
    let _ = writeln!(out);

    // --- ManyTier header + payload ---
    decode_header("ManyTier tx HELLO", &manytier_pkt, &mut out);
    decode_manytier_hello_payload(&manytier_pkt, &mut out);
    let _ = writeln!(out);

    // --- Official header + payload ---
    decode_header("Official rx HELLO", &official_pkt, &mut out);
    let official_cipher_suite = if official_pkt.len() >= 19 {
        (official_pkt[18] & 0x38) >> 3
    } else {
        0
    };
    decode_official_hello_payload(&official_pkt, official_cipher_suite, &mut out);
    let _ = writeln!(out);

    // --- Summary ---
    let _ = writeln!(out, "=== Summary ===");
    let _ = writeln!(out, "ManyTier total: {} bytes", manytier_pkt.len());
    let _ = writeln!(out, "Official total: {} bytes", official_pkt.len());
    let delta = official_pkt.len() as isize - manytier_pkt.len() as isize;
    let _ = writeln!(out, "delta: {} bytes (official minus ManyTier)", delta);
    let _ = writeln!(
        out,
        "structural divergences observed (unknown: see 17-10-UPSTREAM-HELLO.md for upstream citations):"
    );
    if manytier_pkt.len() >= 28 && official_pkt.len() >= 28 {
        let mt_flags = manytier_pkt[18];
        let of_flags = official_pkt[18];
        if (mt_flags & 0x38) != (of_flags & 0x38) {
            let _ = writeln!(
                out,
                "  - cipher_suite differs: ManyTier=0x{:02x} ({}), Official=0x{:02x} ({})",
                mt_flags & 0x38,
                (mt_flags & 0x38) >> 3,
                of_flags & 0x38,
                (of_flags & 0x38) >> 3
            );
        }
        let mt_verb_high = manytier_pkt[27] & 0xe0;
        let of_verb_high = official_pkt[27] & 0xe0;
        if mt_verb_high != of_verb_high {
            let _ = writeln!(
                out,
                "  - verb high flags differ: ManyTier=0x{:02x}, Official=0x{:02x}",
                mt_verb_high, of_verb_high
            );
        }
        if manytier_pkt.len() != official_pkt.len() {
            let _ = writeln!(
                out,
                "  - total size differs by {} bytes: ManyTier is missing trailing field(s)",
                delta
            );
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "unknown: the {} bytes of payload past ManyTier's HELLO must be identified from upstream ZT 1.14.2 source in Task 3",
        delta.max(0)
    );

    // Write the diff to a timestamped file under tests/shadow/artifacts/.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let artifact_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests/shadow/artifacts");
    let _ = fs::create_dir_all(&artifact_dir);
    let diff_path = artifact_dir.join(format!("hello-diff-{}.txt", ts));
    fs::write(&diff_path, &out).expect("failed to write hello-diff file");

    // Also echo to stderr for interactive runs.
    eprintln!("{}", out);
    eprintln!("--- wrote diff to {} ---", diff_path.display());
}
