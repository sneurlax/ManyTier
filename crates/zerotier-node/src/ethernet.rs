/// Ethernet frame parsing, virtual MAC derivation, and ethertype constants.
///
/// The virtual MAC derivation algorithm is a direct port of ZeroTierOne
/// MAC::fromAddress() from MAC.hpp. It uses XOR (not hashing) to produce
/// deterministic, locally-administered unicast MACs from a ZeroTier address
/// and network ID.

extern crate alloc;

/// Ethertype: IPv4
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// Ethertype: IPv6
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

pub const ETHERTYPE_ARP: u16 = 0x0806;

/// Derive a virtual MAC address from a ZeroTier address and network ID.
///
/// Direct port of ZeroTierOne MAC::fromAddress():
/// - First octet: locally-administered (bit 1 set), unicast (bit 0 clear)
/// - Avoids 0x52 first octet (KVM/libvirt conflict)
/// - Remaining bytes: ZT address XOR'd with network ID bytes
pub fn derive_mac(zt_address: &[u8; 5], network_id: u64) -> [u8; 6] {
    // First octet: locally-administered unicast
    let first = {
        let a = ((network_id as u8) & 0xfe) | 0x02;
        if a == 0x52 { 0x32 } else { a }
    };

    // ZT address as u64 in lower 5 bytes
    let zt_val = u64::from_be_bytes([
        0, 0, 0, zt_address[0], zt_address[1],
        zt_address[2], zt_address[3], zt_address[4],
    ]);

    // XOR network_id bytes into address bytes
    let mut m: u64 = (first as u64) << 40;
    m |= zt_val;
    m ^= ((network_id >> 8) & 0xff) << 32;
    m ^= ((network_id >> 16) & 0xff) << 24;
    m ^= ((network_id >> 24) & 0xff) << 16;
    m ^= ((network_id >> 32) & 0xff) << 8;
    m ^= (network_id >> 40) & 0xff;

    [
        (m >> 40) as u8,
        (m >> 32) as u8,
        (m >> 24) as u8,
        (m >> 16) as u8,
        (m >> 8) as u8,
        m as u8,
    ]
}

/// Parsed Ethernet frame (14-byte header + payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    pub dest_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    /// Parse an Ethernet frame from raw bytes.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }
        let mut dest_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dest_mac.copy_from_slice(&data[0..6]);
        src_mac.copy_from_slice(&data[6..12]);
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        Some(EthernetFrame {
            dest_mac,
            src_mac,
            ethertype,
            payload: &data[14..],
        })
    }

    /// Serialize this frame into a buffer.
    ///
    /// Writes the 14-byte Ethernet header followed by the payload.
    /// Returns the total number of bytes written.
    ///
    /// # Panics
    ///
    /// Panics if `buf` is too small to hold header + payload.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let total = 14 + self.payload.len();
        buf[0..6].copy_from_slice(&self.dest_mac);
        buf[6..12].copy_from_slice(&self.src_mac);
        buf[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
        buf[14..total].copy_from_slice(self.payload);
        total
    }

    /// Returns true if this is an ARP frame (ethertype 0x0806).
    pub fn is_arp(&self) -> bool {
        self.ethertype == ETHERTYPE_ARP
    }

    /// Returns true if this is an IPv4 frame (ethertype 0x0800).
    pub fn is_ipv4(&self) -> bool {
        self.ethertype == ETHERTYPE_IPV4
    }

    /// Returns true if this is an IPv6 frame (ethertype 0x86DD).
    pub fn is_ipv6(&self) -> bool {
        self.ethertype == ETHERTYPE_IPV6
    }

    /// Returns true if the destination MAC is a multicast address.
    ///
    /// The group address bit (bit 0 of the first octet) being set indicates multicast.
    pub fn is_multicast(&self) -> bool {
        self.dest_mac[0] & 0x01 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === derive_mac tests ===

    #[test]
    fn derive_mac_locally_administered_unicast() {
        let mac = derive_mac(&[0xa0, 0xb1, 0xc2, 0xd3, 0xe4], 0xff00000000abcdef);
        // First octet: locally-administered bit set (bit 1), unicast (bit 0 clear)
        assert_eq!(mac[0] & 0x02, 0x02, "locally-administered bit must be set");
        assert_eq!(mac[0] & 0x01, 0x00, "unicast bit must be clear");
    }

    #[test]
    fn derive_mac_avoids_0x52() {
        // Find a network_id where ((network_id as u8) & 0xfe) | 0x02 == 0x52
        // 0x52 = 0b01010010. (x & 0xfe) | 0x02 = 0x52 means x & 0xfe = 0x50, so x = 0x50 or 0x51
        let mac = derive_mac(&[0x00, 0x00, 0x00, 0x00, 0x00], 0x0000000000000050);
        assert_ne!(mac[0], 0x52, "must avoid 0x52 (KVM/libvirt conflict)");
        assert_eq!(mac[0], 0x32, "should use 0x32 instead of 0x52");
    }

    #[test]
    fn derive_mac_produces_6_bytes() {
        let mac = derive_mac(&[0xa0, 0xb1, 0xc2, 0xd3, 0xe4], 0xff00000000abcdef);
        assert_eq!(mac.len(), 6);
    }

    #[test]
    fn derive_mac_deterministic() {
        let mac1 = derive_mac(&[0xa0, 0xb1, 0xc2, 0xd3, 0xe4], 0xff00000000abcdef);
        let mac2 = derive_mac(&[0xa0, 0xb1, 0xc2, 0xd3, 0xe4], 0xff00000000abcdef);
        assert_eq!(mac1, mac2, "same inputs must produce same MAC");
    }

    #[test]
    fn derive_mac_different_network_different_mac() {
        let mac1 = derive_mac(&[0xa0, 0xb1, 0xc2, 0xd3, 0xe4], 0xff00000000abcdef);
        let mac2 = derive_mac(&[0xa0, 0xb1, 0xc2, 0xd3, 0xe4], 0xee11111111abcdef);
        assert_ne!(mac1, mac2, "different networks must produce different MACs");
    }

    #[test]
    fn derive_mac_different_address_different_mac() {
        let mac1 = derive_mac(&[0x01, 0x02, 0x03, 0x04, 0x05], 0xff00000000abcdef);
        let mac2 = derive_mac(&[0x05, 0x04, 0x03, 0x02, 0x01], 0xff00000000abcdef);
        assert_ne!(mac1, mac2, "different addresses must produce different MACs");
    }

    // === EthernetFrame::parse tests ===

    #[test]
    fn parse_valid_frame() {
        let mut data = [0u8; 18];
        // dest MAC
        data[0..6].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        // src MAC
        data[6..12].copy_from_slice(&[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        // ethertype: IPv4
        data[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        // payload
        data[14..18].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let frame = EthernetFrame::parse(&data).unwrap();
        assert_eq!(frame.dest_mac, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(frame.src_mac, [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        assert_eq!(frame.ethertype, 0x0800);
        assert_eq!(frame.payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_too_short() {
        assert!(EthernetFrame::parse(&[0u8; 13]).is_none());
        assert!(EthernetFrame::parse(&[]).is_none());
    }

    #[test]
    fn parse_exactly_14_bytes() {
        let data = [0u8; 14];
        let frame = EthernetFrame::parse(&data).unwrap();
        assert!(frame.payload.is_empty());
    }

    // === Ethertype detection tests ===

    #[test]
    fn is_arp_true() {
        let mut data = [0u8; 14];
        data[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        let frame = EthernetFrame::parse(&data).unwrap();
        assert!(frame.is_arp());
        assert!(!frame.is_ipv4());
        assert!(!frame.is_ipv6());
    }

    #[test]
    fn is_ipv4_true() {
        let mut data = [0u8; 14];
        data[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let frame = EthernetFrame::parse(&data).unwrap();
        assert!(frame.is_ipv4());
        assert!(!frame.is_arp());
    }

    #[test]
    fn is_ipv6_true() {
        let mut data = [0u8; 14];
        data[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        let frame = EthernetFrame::parse(&data).unwrap();
        assert!(frame.is_ipv6());
        assert!(!frame.is_arp());
    }

    // === Multicast detection ===

    #[test]
    fn is_multicast_true() {
        let mut data = [0u8; 14];
        data[0] = 0x01; // group bit set
        let frame = EthernetFrame::parse(&data).unwrap();
        assert!(frame.is_multicast());
    }

    #[test]
    fn is_multicast_false() {
        let mut data = [0u8; 14];
        data[0] = 0x00; // group bit clear
        let frame = EthernetFrame::parse(&data).unwrap();
        assert!(!frame.is_multicast());
    }

    // === Serialize tests ===

    #[test]
    fn serialize_roundtrip() {
        let frame = EthernetFrame {
            dest_mac: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            src_mac: [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            ethertype: ETHERTYPE_ARP,
            payload: &[0xCA, 0xFE],
        };
        let mut buf = [0u8; 64];
        let n = frame.serialize(&mut buf);
        assert_eq!(n, 16); // 14 + 2

        let parsed = EthernetFrame::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.dest_mac, frame.dest_mac);
        assert_eq!(parsed.src_mac, frame.src_mac);
        assert_eq!(parsed.ethertype, frame.ethertype);
        assert_eq!(parsed.payload, frame.payload);
    }

    // === Ethertype constant values ===

    #[test]
    fn ethertype_constants() {
        assert_eq!(ETHERTYPE_ARP, 0x0806);
        assert_eq!(ETHERTYPE_IPV4, 0x0800);
        assert_eq!(ETHERTYPE_IPV6, 0x86DD);
    }
}
