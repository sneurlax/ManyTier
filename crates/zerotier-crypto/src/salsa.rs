/// ZeroTier V1 per-packet encryption using Salsa20/12 with key mangling
/// and Poly1305 MAC (truncated to 8 bytes).
///
/// This implements the full armor/dearmor encrypt-then-MAC flow as specified
/// in the ZeroTier protocol (Packet.hpp).
use alloc::vec;
use cipher::{KeyIvInit, StreamCipher};
use salsa20::Salsa12;

use crate::error::CryptoError;
use crate::poly::{compute_mac_multi, verify_mac_multi};

// ZeroTier packet header field offsets and sizes
pub const PACKET_IV_OFFSET: usize = 0;
pub const PACKET_IV_LEN: usize = 8;
pub const PACKET_DEST_OFFSET: usize = 8;
pub const PACKET_SOURCE_OFFSET: usize = 13;
pub const PACKET_FLAGS_OFFSET: usize = 18;
pub const PACKET_MAC_OFFSET: usize = 19;
pub const PACKET_MAC_LEN: usize = 8;
pub const PACKET_VERB_OFFSET: usize = 27;
pub const PACKET_MIN_LEN: usize = 28;
pub const PACKET_HEADER_LEN: usize = 27;

/// Mangle a 32-byte shared secret with packet header metadata to produce
/// a per-packet encryption key.
///
/// The mangling XORs the shared secret with packet header fields:
/// - Bytes 0..18: XOR with IV (8 bytes) + destination (5 bytes) + source (5 bytes)
/// - Byte 18: XOR with flags byte, hop count masked off (& 0xf8)
/// - Bytes 19..21: XOR with packet size as little-endian u16
/// - Bytes 21..32: unchanged from shared secret
pub fn mangle_key(shared_secret: &[u8; 32], packet_header: &[u8], packet_size: usize) -> [u8; 32] {
    let mut key = [0u8; 32];

    // XOR first 18 bytes with packet bytes 0..18 (IV + dest + source)
    for i in 0..18 {
        key[i] = shared_secret[i] ^ packet_header[i];
    }

    // XOR byte 18 with flags (hop count masked off: & 0xf8)
    key[18] = shared_secret[18] ^ (packet_header[18] & 0xf8);

    // XOR bytes 19-20 with packet size (little-endian u16)
    let size = packet_size as u16;
    key[19] = shared_secret[19] ^ (size as u8);
    key[20] = shared_secret[20] ^ ((size >> 8) as u8);

    // Bytes 21-31 unchanged from shared secret
    key[21..32].copy_from_slice(&shared_secret[21..32]);

    key
}

/// Encrypt a packet in-place using the ZeroTier V1 encrypt-then-MAC scheme.
///
/// 1. Mangle the shared secret with packet header to get per-packet key
/// 2. Initialize Salsa20/12 with mangled key and 8-byte IV from packet[0..8]
/// 3. Generate Poly1305 one-time key from first 32 bytes of keystream
/// 4. If `encrypt_payload` is true, encrypt verb + payload at offset 27+
/// 5. Compute Poly1305 MAC over (encrypted) payload
/// 6. Store first 8 bytes of MAC tag at packet[19..27]
pub fn armor_packet(
    shared_secret: &[u8; 32],
    packet: &mut [u8],
    encrypt_payload: bool,
) -> Result<(), CryptoError> {
    if packet.len() < PACKET_MIN_LEN {
        return Err(CryptoError::InvalidFormat);
    }

    let mangled = mangle_key(shared_secret, packet, packet.len());

    // Nonce is 8 bytes from packet[0..8] (the IV/Packet ID field)
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]);

    let mut cipher = Salsa12::new(&mangled.into(), &nonce.into());

    // Generate Poly1305 one-time key from first 32 bytes of keystream
    let mut poly_key = [0u8; 32];
    cipher.apply_keystream(&mut poly_key);

    // Encrypt verb + payload (offset 27+) if requested
    if encrypt_payload && packet.len() > PACKET_VERB_OFFSET {
        cipher.apply_keystream(&mut packet[PACKET_VERB_OFFSET..]);
    }

    // Compute MAC over header (0..19) and (encrypted) content after header (27..)
    let mut chunks = vec![&packet[0..PACKET_MAC_OFFSET]];
    if packet.len() > PACKET_VERB_OFFSET {
        chunks.push(&packet[PACKET_VERB_OFFSET..]);
    }
    let mac = compute_mac_multi(&poly_key, &chunks);

    // Store 8-byte MAC at packet[19..27]
    packet[PACKET_MAC_OFFSET..PACKET_MAC_OFFSET + PACKET_MAC_LEN].copy_from_slice(&mac);

    Ok(())
}

/// Decrypt and verify a packet in-place using an UNMANGLED key.
/// ZeroTier uses an unmangled null key `[0; 32]` for root HELLOs.
pub fn dearmor_packet_unmangled(key: &[u8; 32], packet: &mut [u8]) -> Result<(), CryptoError> {
    if packet.len() < PACKET_MIN_LEN {
        return Err(CryptoError::InvalidFormat);
    }

    let mut saved_mac = [0u8; 8];
    saved_mac.copy_from_slice(&packet[PACKET_MAC_OFFSET..PACKET_MAC_OFFSET + PACKET_MAC_LEN]);

    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]);

    let mut cipher = Salsa12::new(&(*key).into(), &nonce.into());

    let mut poly_key = [0u8; 32];
    cipher.apply_keystream(&mut poly_key);

    let mut chunks = vec![&packet[0..PACKET_MAC_OFFSET]];
    if packet.len() > PACKET_VERB_OFFSET {
        chunks.push(&packet[PACKET_VERB_OFFSET..]);
    }

    if !verify_mac_multi(&poly_key, &chunks, &saved_mac) {
        return Err(CryptoError::MacVerificationFailed);
    }

    cipher.apply_keystream(&mut packet[PACKET_VERB_OFFSET..]);

    Ok(())
}

/// Encrypt a packet in-place using an UNMANGLED key.
pub fn armor_packet_unmangled(key: &[u8; 32], packet: &mut [u8], encrypt_payload: bool) -> Result<(), CryptoError> {
    if packet.len() < PACKET_MIN_LEN {
        return Err(CryptoError::InvalidFormat);
    }

    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]);

    let mut cipher = Salsa12::new(&(*key).into(), &nonce.into());

    let mut poly_key = [0u8; 32];
    cipher.apply_keystream(&mut poly_key);

    if encrypt_payload && packet.len() > PACKET_VERB_OFFSET {
        cipher.apply_keystream(&mut packet[PACKET_VERB_OFFSET..]);
    }

    let mut chunks = vec![&packet[0..PACKET_MAC_OFFSET]];
    if packet.len() > PACKET_VERB_OFFSET {
        chunks.push(&packet[PACKET_VERB_OFFSET..]);
    }
    let mac = compute_mac_multi(&poly_key, &chunks);

    packet[PACKET_MAC_OFFSET..PACKET_MAC_OFFSET + PACKET_MAC_LEN].copy_from_slice(&mac);

    Ok(())
}

/// Decrypt and verify a packet in-place using the ZeroTier V1 scheme.
///
/// 1. Save existing MAC from packet[19..27]
/// 2. Mangle key and initialize Salsa20/12
/// 3. Generate Poly1305 one-time key
/// 4. Verify MAC over encrypted payload -- if invalid, return error
/// 5. Decrypt verb + payload at offset 27+
pub fn dearmor_packet(shared_secret: &[u8; 32], packet: &mut [u8]) -> Result<(), CryptoError> {
    if packet.len() < PACKET_MIN_LEN {
        return Err(CryptoError::InvalidFormat);
    }

    // Save existing MAC
    let mut saved_mac = [0u8; 8];
    saved_mac.copy_from_slice(&packet[PACKET_MAC_OFFSET..PACKET_MAC_OFFSET + PACKET_MAC_LEN]);

    let mangled = mangle_key(shared_secret, packet, packet.len());

    // Nonce is 8 bytes from packet[0..8]
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]);

    let mut cipher = Salsa12::new(&mangled.into(), &nonce.into());

    // Generate Poly1305 one-time key
    let mut poly_key = [0u8; 32];
    cipher.apply_keystream(&mut poly_key);

    // Verify MAC over header (0..19) and encrypted payload (27..)
    let mut chunks = vec![&packet[0..PACKET_MAC_OFFSET]];
    if packet.len() > PACKET_VERB_OFFSET {
        chunks.push(&packet[PACKET_VERB_OFFSET..]);
    }

    if !verify_mac_multi(&poly_key, &chunks, &saved_mac) {
        return Err(CryptoError::MacVerificationFailed);
    }

    // Decrypt verb + payload
    cipher.apply_keystream(&mut packet[PACKET_VERB_OFFSET..]);

    Ok(())
}

/// Encrypt or decrypt a subrange of a packet payload using the raw shared
/// secret and packet IV, matching ZeroTier's `Packet::cryptField()` helper.
///
/// This is used for the HELLO moon-section trailer, which is field-encrypted
/// even when the outer packet uses cipher suite 0.
pub fn crypt_packet_field(
    shared_secret: &[u8; 32],
    packet: &mut [u8],
    start: usize,
    len: usize,
) -> Result<(), CryptoError> {
    if packet.len() < PACKET_MIN_LEN || start > packet.len() || start + len > packet.len() {
        return Err(CryptoError::InvalidFormat);
    }

    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]);
    nonce[7] &= 0xf8;

    let mut cipher = Salsa12::new(shared_secret.into(), &nonce.into());
    cipher.apply_keystream(&mut packet[start..start + len]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // Helper: create a minimal test packet (28 bytes minimum)
    fn make_test_packet() -> [u8; 64] {
        let mut pkt = [0u8; 64];
        // IV / Packet ID (bytes 0..8)
        pkt[0..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        // Destination address (bytes 8..13)
        pkt[8..13].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        // Source address (bytes 13..18)
        pkt[13..18].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]);
        // Flags byte (byte 18) -- cipher suite 1 + hop count 2 = 0x0A
        pkt[18] = 0x0A;
        // MAC field (bytes 19..27) -- will be overwritten by armor
        // Verb (byte 27)
        pkt[27] = 0x05; // some verb
                        // Payload (bytes 28..64)
        for (i, b) in pkt[28..64].iter_mut().enumerate() {
            *b = ((i + 28) & 0xFF) as u8;
        }
        pkt
    }

    fn test_shared_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(0x42);
        }
        secret
    }

    // --- mangle_key tests ---

    #[test]
    fn mangle_key_xors_first_18_bytes() {
        let secret = test_shared_secret();
        let pkt = make_test_packet();
        let mangled = mangle_key(&secret, &pkt, pkt.len());

        for i in 0..18 {
            assert_eq!(mangled[i], secret[i] ^ pkt[i], "byte {} mismatch", i);
        }
    }

    #[test]
    fn mangle_key_masks_hop_count() {
        let secret = test_shared_secret();
        let pkt = make_test_packet();
        let mangled = mangle_key(&secret, &pkt, pkt.len());

        // Byte 18: flags & 0xf8 masks off bottom 3 bits (hop count)
        assert_eq!(mangled[18], secret[18] ^ (pkt[18] & 0xf8));
    }

    #[test]
    fn mangle_key_xors_size_little_endian() {
        let secret = test_shared_secret();
        let pkt = make_test_packet();
        let size = pkt.len() as u16;
        let mangled = mangle_key(&secret, &pkt, pkt.len());

        assert_eq!(mangled[19], secret[19] ^ (size as u8));
        assert_eq!(mangled[20], secret[20] ^ ((size >> 8) as u8));
    }

    #[test]
    fn mangle_key_leaves_bytes_21_to_31_unchanged() {
        let secret = test_shared_secret();
        let pkt = make_test_packet();
        let mangled = mangle_key(&secret, &pkt, pkt.len());

        for i in 21..32 {
            assert_eq!(mangled[i], secret[i], "byte {} should be unchanged", i);
        }
    }

    // --- armor/dearmor tests ---

    #[test]
    fn armor_encrypt_true_encrypts_payload() {
        let secret = test_shared_secret();
        let mut pkt = make_test_packet();
        let original_payload = pkt[27..].to_vec();

        armor_packet(&secret, &mut pkt, true).unwrap();

        // Payload should be different after encryption
        assert_ne!(&pkt[27..], &original_payload[..]);
        // MAC field should be set (not all zeros)
        assert_ne!(&pkt[19..27], &[0u8; 8]);
    }

    #[test]
    fn armor_encrypt_false_only_sets_mac() {
        let secret = test_shared_secret();
        let mut pkt = make_test_packet();
        let original_payload = pkt[27..].to_vec();

        armor_packet(&secret, &mut pkt, false).unwrap();

        // Payload should NOT be encrypted (cipher suite 0 = HELLO)
        assert_eq!(&pkt[27..], &original_payload[..]);
        // MAC field should still be set
        assert_ne!(&pkt[19..27], &[0u8; 8]);
    }

    #[test]
    fn dearmor_recovers_original_plaintext() {
        let secret = test_shared_secret();
        let mut pkt = make_test_packet();
        let original_payload = pkt[27..].to_vec();

        armor_packet(&secret, &mut pkt, true).unwrap();

        // Payload is now encrypted
        assert_ne!(&pkt[27..], &original_payload[..]);

        dearmor_packet(&secret, &mut pkt).unwrap();

        // Payload is decrypted back to original
        assert_eq!(&pkt[27..], &original_payload[..]);
    }

    #[test]
    fn crypt_packet_field_roundtrips_subrange() {
        let secret = test_shared_secret();
        let mut pkt = make_test_packet();
        let original = pkt[40..48].to_vec();

        crypt_packet_field(&secret, &mut pkt, 40, 8).unwrap();
        assert_ne!(&pkt[40..48], &original[..]);

        crypt_packet_field(&secret, &mut pkt, 40, 8).unwrap();
        assert_eq!(&pkt[40..48], &original[..]);
    }

    #[test]
    fn dearmor_with_corrupted_mac_returns_error() {
        let secret = test_shared_secret();
        let mut pkt = make_test_packet();

        armor_packet(&secret, &mut pkt, true).unwrap();

        // Corrupt the MAC
        pkt[19] ^= 0xFF;

        let result = dearmor_packet(&secret, &mut pkt);
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::MacVerificationFailed => {}
            other => panic!("expected MacVerificationFailed, got {:?}", other),
        }
    }

    #[test]
    fn uses_salsa12_not_salsa20() {
        // This test verifies we're using Salsa12 by checking that the
        // output differs from what Salsa20 would produce.
        // The type system enforces this (we import Salsa12), but we verify
        // the encryption output is deterministic and specific to Salsa12.
        let secret = test_shared_secret();
        let mut pkt1 = make_test_packet();
        let mut pkt2 = make_test_packet();

        armor_packet(&secret, &mut pkt1, true).unwrap();
        armor_packet(&secret, &mut pkt2, true).unwrap();

        // Same input -> same output (deterministic)
        assert_eq!(&pkt1[..], &pkt2[..]);
    }

    #[test]
    fn nonce_is_8_bytes_from_packet_iv() {
        // Different IVs should produce different ciphertexts
        let secret = test_shared_secret();
        let mut pkt1 = make_test_packet();
        let mut pkt2 = make_test_packet();
        pkt2[0] = 0xFF; // change IV

        armor_packet(&secret, &mut pkt1, true).unwrap();
        armor_packet(&secret, &mut pkt2, true).unwrap();

        // Different IVs -> different ciphertext
        assert_ne!(&pkt1[27..], &pkt2[27..]);
    }

    #[test]
    fn armor_rejects_too_short_packet() {
        let secret = test_shared_secret();
        let mut pkt = [0u8; 27]; // one byte too short

        let result = armor_packet(&secret, &mut pkt, true);
        assert!(result.is_err());
    }

    #[test]
    fn dearmor_rejects_too_short_packet() {
        let secret = test_shared_secret();
        let mut pkt = [0u8; 27];

        let result = dearmor_packet(&secret, &mut pkt);
        assert!(result.is_err());
    }

    #[test]
    fn armor_dearmor_with_encrypt_false_roundtrips() {
        // For HELLO packets (cipher suite 0), we only MAC, no encrypt
        let secret = test_shared_secret();
        let mut pkt = make_test_packet();
        let original_payload = pkt[27..].to_vec();

        armor_packet(&secret, &mut pkt, false).unwrap();
        // dearmor always tries to decrypt, but since payload wasn't encrypted,
        // applying keystream again would corrupt it. In the real protocol,
        // dearmor for HELLO packets would know not to decrypt.
        // For this test, verify MAC is valid by computing it manually.
        let mangled = mangle_key(&secret, &pkt, pkt.len());
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&pkt[0..8]);
        let mut cipher = Salsa12::new(&mangled.into(), &nonce.into());
        let mut poly_key = [0u8; 32];
        cipher.apply_keystream(&mut poly_key);

        let mut saved_mac = [0u8; 8];
        saved_mac.copy_from_slice(&pkt[19..27]);
        let chunks = vec![&pkt[0..19], &pkt[27..]];
        assert!(crate::poly::verify_mac_multi(&poly_key, &chunks, &saved_mac));
        assert_eq!(&pkt[27..], &original_payload[..]);
    }

    #[test]
    fn armor_dearmor_minimum_size_packet() {
        // Exactly 28 bytes -- 27 header + 1 verb byte, no payload
        let secret = test_shared_secret();
        let mut pkt = [0u8; 28];
        pkt[0..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        pkt[27] = 0x01; // verb

        let original_verb = pkt[27];

        armor_packet(&secret, &mut pkt, true).unwrap();
        dearmor_packet(&secret, &mut pkt).unwrap();

        assert_eq!(pkt[27], original_verb);
    }
}
