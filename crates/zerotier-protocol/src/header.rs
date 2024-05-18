// Packet and fragment header types for ZeroTier V1 wire format.
use zerocopy::{AsBytes, FromBytes, FromZeroes, Unaligned};

use crate::constants;

/// 28-byte packet header: [IV:8][Dest:5][Src:5][Flags:1][MAC:8][Verb:1]
/// Flags byte: FFCCCHHH (2 flag bits, 3 cipher suite, 3 hop count)
#[derive(FromBytes, FromZeroes, AsBytes, Unaligned)]
#[repr(C, packed)]
pub struct PacketHeader {
    pub iv: [u8; 8],
    pub dest: [u8; 5],
    pub source: [u8; 5],
    pub flags: u8,
    pub mac: [u8; 8],
    pub verb: u8,
}

impl PacketHeader {
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        PacketHeader::ref_from_prefix(data).ok().map(|(hdr, _)| hdr)
    }

    pub fn cipher_suite(&self) -> u8 {
        (self.flags >> 3) & 0x07
    }

    pub fn hops(&self) -> u8 {
        self.flags & 0x07
    }

    pub fn is_fragmented(&self) -> bool {
        self.flags & constants::FLAG_FRAGMENTED != 0
    }

    pub fn verb_id(&self) -> u8 {
        self.verb & 0x1f
    }

    pub fn is_compressed(&self) -> bool {
        self.verb & constants::VERB_FLAG_COMPRESSED != 0
    }

    pub fn dest_address(&self) -> [u8; 5] {
        self.dest
    }

    pub fn source_address(&self) -> [u8; 5] {
        self.source
    }

    pub fn packet_id(&self) -> u64 {
        u64::from_be_bytes(self.iv)
    }
}

/// 16-byte fragment header. Identified by byte 13 == 0xff.
#[derive(FromBytes, FromZeroes, AsBytes, Unaligned)]
#[repr(C, packed)]
pub struct FragmentHeader {
    pub packet_id: [u8; 8],
    pub dest: [u8; 5],
    pub indicator: u8,
    /// Upper 4 bits = total, lower 4 = index.
    pub fragment_info: u8,
    pub hops: u8,
}

impl FragmentHeader {
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        FragmentHeader::ref_from_prefix(data).ok().map(|(hdr, _)| hdr)
    }

    pub fn total_fragments(&self) -> u8 {
        (self.fragment_info >> 4) & 0x0f
    }

    pub fn fragment_number(&self) -> u8 {
        self.fragment_info & 0x0f
    }

    pub fn packet_id_u64(&self) -> u64 {
        u64::from_be_bytes(self.packet_id)
    }
}

/// Check if raw buffer is a fragment (byte 13 == 0xff).
pub fn is_fragment(data: &[u8]) -> bool {
    data.len() >= 16 && data[13] == constants::FRAGMENT_INDICATOR
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_header(
        iv: u64,
        dest: [u8; 5],
        source: [u8; 5],
        flags: u8,
        mac: [u8; 8],
        verb: u8,
    ) -> [u8; 28] {
        let mut buf = [0u8; 28];
        buf[0..8].copy_from_slice(&iv.to_be_bytes());
        buf[8..13].copy_from_slice(&dest);
        buf[13..18].copy_from_slice(&source);
        buf[18] = flags;
        buf[19..27].copy_from_slice(&mac);
        buf[27] = verb;
        buf
    }

    #[test]
    fn packet_header_from_28_bytes() {
        let dest = [0x01, 0x02, 0x03, 0x04, 0x05];
        let source = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        let mac = [0xaa; 8];
        let buf = build_header(0xDEADBEEFCAFEBABE, dest, source, 0b01_001_010, mac, 0x81);
        let hdr = PacketHeader::from_bytes(&buf).unwrap();
        assert_eq!(hdr.dest_address(), dest);
        assert_eq!(hdr.source_address(), source);
        assert_eq!(hdr.cipher_suite(), 1); // bits 3-5
        assert_eq!(hdr.hops(), 2); // bits 0-2
        assert!(hdr.is_fragmented()); // bit 6 set
        assert_eq!(hdr.verb_id(), 0x01); // Hello
        assert!(hdr.is_compressed()); // bit 7 set on verb
        assert_eq!(hdr.packet_id(), 0xDEADBEEFCAFEBABE);
    }

    #[test]
    fn packet_header_from_27_bytes_returns_none() {
        let buf = [0u8; 27];
        assert!(PacketHeader::from_bytes(&buf).is_none());
    }

    #[test]
    fn packet_header_from_larger_buffer() {
        let mut buf = [0u8; 64];
        buf[27] = 0x06; // FRAME verb
        let hdr = PacketHeader::from_bytes(&buf).unwrap();
        assert_eq!(hdr.verb_id(), 0x06);
    }

    #[test]
    fn fragment_header_from_16_bytes() {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&0x1234567890ABCDEFu64.to_be_bytes());
        buf[8..13].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]);
        buf[13] = 0xff; // indicator
        buf[14] = 0x53; // total=5, number=3
        buf[15] = 0x01; // hops=1

        let frag = FragmentHeader::from_bytes(&buf).unwrap();
        assert_eq!(frag.packet_id_u64(), 0x1234567890ABCDEF);
        assert_eq!(frag.total_fragments(), 5);
        assert_eq!(frag.fragment_number(), 3);
        assert_eq!(frag.hops, 1);
        assert_eq!(frag.indicator, 0xff);
    }

    #[test]
    fn fragment_header_from_15_bytes_returns_none() {
        let buf = [0u8; 15];
        assert!(FragmentHeader::from_bytes(&buf).is_none());
    }

    #[test]
    fn is_fragment_detects_fragment_indicator() {
        let mut buf = [0u8; 16];
        buf[13] = 0xff;
        assert!(is_fragment(&buf));
    }

    #[test]
    fn is_fragment_rejects_non_fragment() {
        let mut buf = [0u8; 16];
        buf[13] = 0x00;
        assert!(!is_fragment(&buf));
    }

    #[test]
    fn is_fragment_rejects_short_buffer() {
        let buf = [0xff; 15]; // too short even with 0xff everywhere
        assert!(!is_fragment(&buf));
    }

    #[test]
    fn cipher_suite_extraction() {
        // flags = 0b00_101_000 => cipher=5, hops=0
        let buf = build_header(0, [0; 5], [0; 5], 0b00_101_000, [0; 8], 0);
        let hdr = PacketHeader::from_bytes(&buf).unwrap();
        assert_eq!(hdr.cipher_suite(), 5);
        assert_eq!(hdr.hops(), 0);
    }

    #[test]
    fn hops_extraction() {
        // flags = 0b00_000_111 => cipher=0, hops=7
        let buf = build_header(0, [0; 5], [0; 5], 0b00_000_111, [0; 8], 0);
        let hdr = PacketHeader::from_bytes(&buf).unwrap();
        assert_eq!(hdr.hops(), 7);
        assert_eq!(hdr.cipher_suite(), 0);
    }
}
