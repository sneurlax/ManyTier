use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use ghash::{universal_hash::UniversalHash, GHash};

use crate::error::CryptoError;
use crate::salsa::{
    PACKET_IV_LEN, PACKET_IV_OFFSET, PACKET_MAC_LEN, PACKET_MAC_OFFSET, PACKET_MIN_LEN,
    PACKET_VERB_OFFSET,
};

/// AES-CTR encryption with manual 32-bit-only counter increment.
/// The counter occupies the least-significant 32 bits of `nonce_counter`
/// and does NOT overflow into the upper bits.
fn aes_ctr_encrypt(cipher: &Aes256, nonce_counter: &mut [u8; 16], data: &mut [u8]) {
    let mut block = aes::Block::default();
    for chunk in data.chunks_mut(16) {
        block.copy_from_slice(nonce_counter);
        cipher.encrypt_block(&mut block);

        for (d, k) in chunk.iter_mut().zip(block.iter()) {
            *d ^= k;
        }

        // Increment only the least-significant 32 bits (big-endian at bytes 12..16)
        let ctr = u32::from_be_bytes([
            nonce_counter[12],
            nonce_counter[13],
            nonce_counter[14],
            nonce_counter[15],
        ]);
        let new_ctr = ctr.wrapping_add(1);
        nonce_counter[12..16].copy_from_slice(&new_ctr.to_be_bytes());
    }
}

/// Compute GMAC over (IV || AAD || data), returning the 8-byte truncated tag.
///
/// GMAC construction:
/// 1. Derive GHash key H = AES-ECB(K0_first_16, 0^128): standard GMAC
/// 2. Start with 96-bit IV: [packet_iv(8) | 0x00 0x00 0x00 0x00]: 64-bit IV padded to 96 bits
///    Then the GHASH initial block J0 = IV || 0x00000001 (standard GCM J0)
/// 3. Feed AAD into GHASH, pad to 16-byte boundary with zeros
/// 4. Feed data into GHASH, pad to 16-byte boundary with zeros
/// 5. Feed length block: [AAD_len_bits(64) || data_len_bits(64)]
/// 6. XOR GHASH result with AES-ECB(K0_first_16, J0) to get GMAC tag
/// 7. XOR upper and lower 64-bit halves -> 8-byte shortened MAC
fn gmac_compute(k0: &[u8; 32], iv: &[u8; 8], aad: &[u8], data: &[u8]) -> [u8; 8] {
    let cipher = Aes256::new(k0.into());

    // Derive H = AES(K0, 0^128)
    let mut h_block = aes::Block::default(); // all zeros
    cipher.encrypt_block(&mut h_block);

    let mut ghash = GHash::new(&h_block);

    // Feed AAD into GHASH (auto-padded to 16-byte blocks by ghash crate's update)
    // ghash crate processes full blocks; we need to manually pad partial blocks
    feed_padded(&mut ghash, aad);

    // Feed data into GHASH
    feed_padded(&mut ghash, data);

    // Feed the length block: [aad_bits_be(8) || data_bits_be(8)]
    let aad_bits = (aad.len() as u64) * 8;
    let data_bits = (data.len() as u64) * 8;
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&data_bits.to_be_bytes());
    ghash.update(&[len_block.into()]);

    // GHASH result
    let ghash_result = ghash.finalize();
    let ghash_bytes: [u8; 16] = ghash_result.into();

    // J0 = IV(8) || 0x00 0x00 0x00 0x00 || 0x00 0x00 0x00 0x01
    let mut j0 = aes::Block::default();
    j0[0..8].copy_from_slice(iv);
    // bytes 8..12 are zero (IV padding)
    j0[15] = 0x01; // counter = 1

    // GMAC tag = GHASH XOR AES(K0, J0)
    cipher.encrypt_block(&mut j0);
    let j0_bytes: [u8; 16] = j0.into();

    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = ghash_bytes[i] ^ j0_bytes[i];
    }

    // XOR upper and lower 64-bit halves -> 8-byte shortened MAC
    // Use native byte order for the XOR, matching vendor behavior
    let upper = u64::from_ne_bytes(tag[0..8].try_into().unwrap());
    let lower = u64::from_ne_bytes(tag[8..16].try_into().unwrap());
    let shortened = upper ^ lower;
    shortened.to_ne_bytes()
}

/// Feed data into GHASH, padding the final partial block with zeros.
fn feed_padded(ghash: &mut GHash, data: &[u8]) {
    let full_blocks = data.len() / 16;
    for i in 0..full_blocks {
        let block: [u8; 16] = data[i * 16..(i + 1) * 16].try_into().unwrap();
        ghash.update(&[block.into()]);
    }
    let remainder = data.len() % 16;
    if remainder > 0 {
        let mut padded = [0u8; 16];
        padded[..remainder].copy_from_slice(&data[full_blocks * 16..]);
        ghash.update(&[padded.into()]);
    }
}

/// AES-GMAC-SIV encrypt (two-pass): ZeroTier cipher suite 3.
///
/// Packet layout: [IV(8) | dest(5) | source(5) | flags(1) | MAC(8) | verb+payload...]
///
/// K0: first 32 bytes of KBKDF output: used for GMAC authentication
/// K1: first 32 bytes of separate KBKDF output: used for AES-ECB tag and AES-CTR payload
pub fn armor_packet(
    k0: &[u8; 32],
    k1: &[u8; 32],
    packet: &mut [u8],
    aad: &[u8],
) -> Result<(), CryptoError> {
    if packet.len() < PACKET_MIN_LEN {
        return Err(CryptoError::TooShort);
    }

    let payload_start = PACKET_VERB_OFFSET;
    let payload_len = packet.len() - payload_start;

    // Save the original 8-byte IV
    let mut original_iv = [0u8; 8];
    original_iv.copy_from_slice(&packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]);

    // Pass 1: Compute GMAC over plaintext payload
    let mac = gmac_compute(k0, &original_iv, aad, &packet[payload_start..]);

    // Store MAC in header
    packet[PACKET_MAC_OFFSET..PACKET_MAC_OFFSET + PACKET_MAC_LEN].copy_from_slice(&mac);

    // Build 16-byte tag block: [original_IV(8) | shortened_MAC(8)]
    let mut tag_block = [0u8; 16];
    tag_block[0..8].copy_from_slice(&original_iv);
    tag_block[8..16].copy_from_slice(&mac);

    // AES-ECB encrypt tag block with K1
    let k1_cipher = Aes256::new(k1.into());
    let mut aes_block: aes::Block = tag_block.into();
    k1_cipher.encrypt_block(&mut aes_block);
    let encrypted_tag: [u8; 16] = aes_block.into();

    // Store encrypted IV and MAC back into packet header
    packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]
        .copy_from_slice(&encrypted_tag[0..8]);
    packet[PACKET_MAC_OFFSET..PACKET_MAC_OFFSET + PACKET_MAC_LEN]
        .copy_from_slice(&encrypted_tag[8..16]);

    // Build CTR nonce from the encrypted IV:
    // [encrypted_IV(8) | 0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00]
    // Mask bit 63 (MSB of lower 32-bit counter) to zero
    let mut nonce_counter = [0u8; 16];
    nonce_counter[0..8].copy_from_slice(&encrypted_tag[0..8]);
    // Mask: 0xffffffff7fffffff in big-endian -> bit 31 of byte offset 4..8
    // Byte 4 bit 7 (MSB) must be cleared
    nonce_counter[4] &= 0x7f;

    // Pass 2: AES-CTR encrypt payload with K1
    if payload_len > 0 {
        aes_ctr_encrypt(&k1_cipher, &mut nonce_counter, &mut packet[payload_start..]);
    }

    Ok(())
}

/// AES-GMAC-SIV decrypt (single-pass): ZeroTier cipher suite 3.
///
/// Returns Ok(true) if MAC is valid, Ok(false) if MAC mismatch.
pub fn dearmor_packet(
    k0: &[u8; 32],
    k1: &[u8; 32],
    packet: &mut [u8],
    aad: &[u8],
) -> Result<bool, CryptoError> {
    if packet.len() < PACKET_MIN_LEN {
        return Err(CryptoError::TooShort);
    }

    let payload_start = PACKET_VERB_OFFSET;
    let payload_len = packet.len() - payload_start;

    // Read encrypted [IV(8) | MAC(8)] from packet header
    let mut encrypted_tag = [0u8; 16];
    encrypted_tag[0..8]
        .copy_from_slice(&packet[PACKET_IV_OFFSET..PACKET_IV_OFFSET + PACKET_IV_LEN]);
    encrypted_tag[8..16]
        .copy_from_slice(&packet[PACKET_MAC_OFFSET..PACKET_MAC_OFFSET + PACKET_MAC_LEN]);

    // AES-ECB decrypt to recover [original_IV | original_MAC]
    let k1_cipher = Aes256::new(k1.into());
    let mut aes_block: aes::Block = encrypted_tag.into();
    k1_cipher.decrypt_block(&mut aes_block);
    let decrypted_tag: [u8; 16] = aes_block.into();

    let mut original_iv = [0u8; 8];
    original_iv.copy_from_slice(&decrypted_tag[0..8]);
    let mut original_mac = [0u8; 8];
    original_mac.copy_from_slice(&decrypted_tag[8..16]);

    // Build CTR nonce from the still-encrypted IV
    let mut nonce_counter = [0u8; 16];
    nonce_counter[0..8].copy_from_slice(&encrypted_tag[0..8]);
    nonce_counter[4] &= 0x7f; // mask bit 63

    // AES-CTR decrypt payload with K1
    if payload_len > 0 {
        aes_ctr_encrypt(&k1_cipher, &mut nonce_counter, &mut packet[payload_start..]);
    }

    // Compute GMAC over decrypted plaintext
    let computed_mac = gmac_compute(k0, &original_iv, aad, &packet[payload_start..]);

    // Constant-time compare MACs
    let mut diff = 0u8;
    for i in 0..8 {
        diff |= computed_mac[i] ^ original_mac[i];
    }

    Ok(diff == 0)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;

    fn make_test_packet(payload: &[u8]) -> alloc::vec::Vec<u8> {
        let mut packet = alloc::vec![0u8; PACKET_MIN_LEN + payload.len()];
        // Set a recognizable IV
        packet[0..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        // dest (5 bytes)
        packet[8..13].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        // source (5 bytes)
        packet[13..18].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]);
        // flags
        packet[18] = 0x20;
        // MAC starts zeroed
        // verb
        packet[27] = 0x05;
        // payload
        if !payload.is_empty() {
            packet[28..].copy_from_slice(payload);
        }
        packet
    }

    const TEST_K0: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];

    const TEST_K1: [u8; 32] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
        0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
        0x3E, 0x3F,
    ];

    #[test]
    fn roundtrip_basic() {
        let payload = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let mut packet = make_test_packet(&payload);
        let original = packet.clone();
        let aad = &[];

        armor_packet(&TEST_K0, &TEST_K1, &mut packet, aad).unwrap();
        // Ciphertext should differ from plaintext
        assert_ne!(
            &packet[PACKET_VERB_OFFSET..],
            &original[PACKET_VERB_OFFSET..]
        );

        let valid = dearmor_packet(&TEST_K0, &TEST_K1, &mut packet, aad).unwrap();
        assert!(valid, "MAC should verify after roundtrip");
        // Payload (verb+data) should match original
        assert_eq!(
            &packet[PACKET_VERB_OFFSET..],
            &original[PACKET_VERB_OFFSET..]
        );
    }

    #[test]
    fn roundtrip_with_aad() {
        let payload = [0x42; 64];
        let aad = [0xFF; 32];
        let mut packet = make_test_packet(&payload);
        let original = packet.clone();

        armor_packet(&TEST_K0, &TEST_K1, &mut packet, &aad).unwrap();
        let valid = dearmor_packet(&TEST_K0, &TEST_K1, &mut packet, &aad).unwrap();
        assert!(valid);
        assert_eq!(
            &packet[PACKET_VERB_OFFSET..],
            &original[PACKET_VERB_OFFSET..]
        );
    }

    #[test]
    fn roundtrip_empty_payload() {
        // Minimum packet: header only, no payload beyond verb byte
        let mut packet = make_test_packet(&[]);
        let original = packet.clone();
        let aad = &[];

        armor_packet(&TEST_K0, &TEST_K1, &mut packet, aad).unwrap();
        let valid = dearmor_packet(&TEST_K0, &TEST_K1, &mut packet, aad).unwrap();
        assert!(valid);
        assert_eq!(
            &packet[PACKET_VERB_OFFSET..],
            &original[PACKET_VERB_OFFSET..]
        );
    }

    #[test]
    fn roundtrip_single_byte_payload() {
        let mut packet = make_test_packet(&[0x42]);
        let original = packet.clone();
        let aad = &[];

        armor_packet(&TEST_K0, &TEST_K1, &mut packet, aad).unwrap();
        let valid = dearmor_packet(&TEST_K0, &TEST_K1, &mut packet, aad).unwrap();
        assert!(valid);
        assert_eq!(
            &packet[PACKET_VERB_OFFSET..],
            &original[PACKET_VERB_OFFSET..]
        );
    }

    #[test]
    fn mac_corruption_detected() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut packet = make_test_packet(&payload);
        let aad = &[];

        armor_packet(&TEST_K0, &TEST_K1, &mut packet, aad).unwrap();
        // Flip a bit in the MAC field
        packet[PACKET_MAC_OFFSET] ^= 0x01;

        let valid = dearmor_packet(&TEST_K0, &TEST_K1, &mut packet, aad).unwrap();
        assert!(!valid, "MAC corruption should be detected");
    }

    #[test]
    fn payload_corruption_detected() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut packet = make_test_packet(&payload);
        let aad = &[];

        armor_packet(&TEST_K0, &TEST_K1, &mut packet, aad).unwrap();
        // Flip a bit in the ciphertext
        let last = packet.len() - 1;
        packet[last] ^= 0x01;

        let valid = dearmor_packet(&TEST_K0, &TEST_K1, &mut packet, aad).unwrap();
        assert!(!valid, "Payload corruption should be detected");
    }

    #[test]
    fn determinism() {
        let payload = [0xCA, 0xFE, 0xBA, 0xBE];
        let mut packet1 = make_test_packet(&payload);
        let mut packet2 = make_test_packet(&payload);
        let aad = &[];

        armor_packet(&TEST_K0, &TEST_K1, &mut packet1, aad).unwrap();
        armor_packet(&TEST_K0, &TEST_K1, &mut packet2, aad).unwrap();
        assert_eq!(
            packet1, packet2,
            "Same keys + IV + plaintext must produce same ciphertext"
        );
    }

    #[test]
    fn packet_too_short() {
        let mut packet = [0u8; 10]; // way below PACKET_MIN_LEN (28)
        let result = armor_packet(&TEST_K0, &TEST_K1, &mut packet, &[]);
        assert_eq!(result, Err(CryptoError::TooShort));

        let result = dearmor_packet(&TEST_K0, &TEST_K1, &mut packet, &[]);
        assert_eq!(result, Err(CryptoError::TooShort));
    }

    #[test]
    fn wrong_aad_rejected() {
        let payload = [0x42; 32];
        let mut packet = make_test_packet(&payload);

        armor_packet(&TEST_K0, &TEST_K1, &mut packet, &[0x01]).unwrap();
        let valid = dearmor_packet(&TEST_K0, &TEST_K1, &mut packet, &[0x02]).unwrap();
        assert!(!valid, "Wrong AAD should cause MAC mismatch");
    }

    #[test]
    fn wrong_key_rejected() {
        let payload = [0x42; 32];
        let mut packet = make_test_packet(&payload);

        armor_packet(&TEST_K0, &TEST_K1, &mut packet, &[]).unwrap();

        let mut wrong_k0 = TEST_K0;
        wrong_k0[0] ^= 0xFF;
        let valid = dearmor_packet(&wrong_k0, &TEST_K1, &mut packet, &[]).unwrap();
        assert!(!valid, "Wrong K0 should cause MAC mismatch");
    }

    #[test]
    fn large_payload_roundtrip() {
        let payload = [0xAB; 1024];
        let mut packet = make_test_packet(&payload);
        let original = packet.clone();
        let aad = [0xCD; 64];

        armor_packet(&TEST_K0, &TEST_K1, &mut packet, &aad).unwrap();
        let valid = dearmor_packet(&TEST_K0, &TEST_K1, &mut packet, &aad).unwrap();
        assert!(valid);
        assert_eq!(
            &packet[PACKET_VERB_OFFSET..],
            &original[PACKET_VERB_OFFSET..]
        );
    }
}
