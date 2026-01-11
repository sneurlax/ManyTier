/// ARP packet parsing, reply generation, and interception for the VL2 layer.
///
/// ARP requests arriving as EXT_FRAME payloads (ethertype 0x0806) on the virtual
/// network are resolved locally from the member table, preventing broadcast flooding.
extern crate alloc;

use core::net::Ipv4Addr;

use crate::network::NetworkMembership;

/// ARP operation codes.
pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;

/// Parsed ARP packet (IPv4-over-Ethernet, 28 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket {
    pub hw_type: u16,
    pub proto_type: u16,
    pub hw_len: u8,
    pub proto_len: u8,
    pub operation: u16,
    pub sender_hw: [u8; 6],
    pub sender_proto: [u8; 4],
    pub target_hw: [u8; 6],
    pub target_proto: [u8; 4],
}

impl ArpPacket {
    /// Parse an ARP packet from raw bytes.
    /// IPv4-over-Ethernet (hw_type=0x0001, proto_type=0x0800, hw_len=6, proto_len=4).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 28 {
            return None;
        }

        let hw_type = u16::from_be_bytes([data[0], data[1]]);
        let proto_type = u16::from_be_bytes([data[2], data[3]]);
        let hw_len = data[4];
        let proto_len = data[5];

        // Validate IPv4-over-Ethernet
        if hw_type != 0x0001 || proto_type != 0x0800 || hw_len != 6 || proto_len != 4 {
            return None;
        }

        let operation = u16::from_be_bytes([data[6], data[7]]);

        let mut sender_hw = [0u8; 6];
        sender_hw.copy_from_slice(&data[8..14]);

        let mut sender_proto = [0u8; 4];
        sender_proto.copy_from_slice(&data[14..18]);

        let mut target_hw = [0u8; 6];
        target_hw.copy_from_slice(&data[18..24]);

        let mut target_proto = [0u8; 4];
        target_proto.copy_from_slice(&data[24..28]);

        Some(ArpPacket {
            hw_type,
            proto_type,
            hw_len,
            proto_len,
            operation,
            sender_hw,
            sender_proto,
            target_hw,
            target_proto,
        })
    }

    /// Serialize this ARP packet into a buffer.
    ///
    /// Writes exactly 28 bytes. Panics if `buf` is shorter than 28 bytes.
    /// Returns the number of bytes written (always 28).
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0..2].copy_from_slice(&self.hw_type.to_be_bytes());
        buf[2..4].copy_from_slice(&self.proto_type.to_be_bytes());
        buf[4] = self.hw_len;
        buf[5] = self.proto_len;
        buf[6..8].copy_from_slice(&self.operation.to_be_bytes());
        buf[8..14].copy_from_slice(&self.sender_hw);
        buf[14..18].copy_from_slice(&self.sender_proto);
        buf[18..24].copy_from_slice(&self.target_hw);
        buf[24..28].copy_from_slice(&self.target_proto);
        28
    }
}

/// Handle an ARP request by resolving it from the network membership table.
///
/// If `arp.operation` is not a request (1), returns `None`.
/// If the target IP is found in the membership table, returns an ARP reply
/// with the target's virtual MAC. Otherwise returns `None` (the frame should
/// be sent as multicast).
pub fn handle_arp_request(arp: &ArpPacket, membership: &NetworkMembership) -> Option<ArpPacket> {
    if arp.operation != ARP_OP_REQUEST {
        return None;
    }

    let target_ip = Ipv4Addr::new(
        arp.target_proto[0],
        arp.target_proto[1],
        arp.target_proto[2],
        arp.target_proto[3],
    );

    let member = membership.lookup_ipv4(target_ip)?;

    Some(ArpPacket {
        hw_type: 0x0001,
        proto_type: 0x0800,
        hw_len: 6,
        proto_len: 4,
        operation: ARP_OP_REPLY,
        sender_hw: member.mac,
        sender_proto: arp.target_proto,
        target_hw: arp.sender_hw,
        target_proto: arp.sender_proto,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet;
    use crate::network::{NetworkMember, NetworkMembership};
    use core::net::Ipv4Addr;

    fn make_membership_with_member(ip: Ipv4Addr) -> (NetworkMembership, [u8; 6]) {
        let zt_addr = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let network_id = 0xff00000000abcdef_u64;
        let mac = ethernet::derive_mac(&zt_addr, network_id);
        let mut membership = NetworkMembership::new(network_id, 2800);
        membership.members.push(NetworkMember {
            zt_address: zt_addr,
            mac,
            ipv4: Some((ip, 24)),
            ipv6: None,
            authorized: true,
        });
        (membership, mac)
    }

    fn make_arp_request(sender_hw: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> ArpPacket {
        ArpPacket {
            hw_type: 0x0001,
            proto_type: 0x0800,
            hw_len: 6,
            proto_len: 4,
            operation: ARP_OP_REQUEST,
            sender_hw,
            sender_proto: sender_ip,
            target_hw: [0x00; 6],
            target_proto: target_ip,
        }
    }

    // === ArpPacket::parse tests ===

    #[test]
    fn parse_valid_arp() {
        let mut data = [0u8; 28];
        // hw_type = 0x0001 (Ethernet)
        data[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        // proto_type = 0x0800 (IPv4)
        data[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        data[4] = 6; // hw_len
        data[5] = 4; // proto_len
                     // operation = 1 (request)
        data[6..8].copy_from_slice(&1u16.to_be_bytes());
        // sender hw
        data[8..14].copy_from_slice(&[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        // sender proto (10.0.0.1)
        data[14..18].copy_from_slice(&[10, 0, 0, 1]);
        // target hw
        data[18..24].copy_from_slice(&[0x00; 6]);
        // target proto (10.0.0.2)
        data[24..28].copy_from_slice(&[10, 0, 0, 2]);

        let arp = ArpPacket::parse(&data).unwrap();
        assert_eq!(arp.hw_type, 0x0001);
        assert_eq!(arp.proto_type, 0x0800);
        assert_eq!(arp.hw_len, 6);
        assert_eq!(arp.proto_len, 4);
        assert_eq!(arp.operation, 1);
        assert_eq!(arp.sender_hw, [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        assert_eq!(arp.sender_proto, [10, 0, 0, 1]);
        assert_eq!(arp.target_hw, [0x00; 6]);
        assert_eq!(arp.target_proto, [10, 0, 0, 2]);
    }

    #[test]
    fn parse_too_short() {
        assert!(ArpPacket::parse(&[0u8; 27]).is_none());
        assert!(ArpPacket::parse(&[]).is_none());
    }

    #[test]
    fn parse_wrong_hw_type() {
        let mut data = [0u8; 28];
        data[0..2].copy_from_slice(&0x0006u16.to_be_bytes()); // wrong hw_type
        data[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        data[4] = 6;
        data[5] = 4;
        assert!(ArpPacket::parse(&data).is_none());
    }

    #[test]
    fn parse_wrong_proto_type() {
        let mut data = [0u8; 28];
        data[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        data[2..4].copy_from_slice(&0x86DDu16.to_be_bytes()); // IPv6, not IPv4
        data[4] = 6;
        data[5] = 4;
        assert!(ArpPacket::parse(&data).is_none());
    }

    // === serialize tests ===

    #[test]
    fn serialize_roundtrip() {
        let arp = ArpPacket {
            hw_type: 0x0001,
            proto_type: 0x0800,
            hw_len: 6,
            proto_len: 4,
            operation: ARP_OP_REPLY,
            sender_hw: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            sender_proto: [192, 168, 1, 1],
            target_hw: [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            target_proto: [192, 168, 1, 2],
        };
        let mut buf = [0u8; 28];
        let n = arp.serialize(&mut buf);
        assert_eq!(n, 28);

        let parsed = ArpPacket::parse(&buf).unwrap();
        assert_eq!(parsed, arp);
    }

    #[test]
    fn serialize_is_exactly_28_bytes() {
        let arp = make_arp_request([0x01; 6], [10, 0, 0, 1], [10, 0, 0, 2]);
        let mut buf = [0xFFu8; 64];
        let n = arp.serialize(&mut buf);
        assert_eq!(n, 28);
        // Bytes after 28 should be untouched
        assert_eq!(buf[28], 0xFF);
    }

    // === handle_arp_request tests ===

    #[test]
    fn handle_arp_request_known_ip() {
        let target_ip = Ipv4Addr::new(10, 147, 20, 1);
        let (membership, target_mac) = make_membership_with_member(target_ip);

        let sender_hw = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let request = make_arp_request(sender_hw, [10, 147, 20, 2], [10, 147, 20, 1]);

        let reply = handle_arp_request(&request, &membership).unwrap();
        assert_eq!(reply.operation, ARP_OP_REPLY);
        assert_eq!(reply.sender_hw, target_mac);
        assert_eq!(reply.sender_proto, [10, 147, 20, 1]);
        assert_eq!(reply.target_hw, sender_hw);
        assert_eq!(reply.target_proto, [10, 147, 20, 2]);
    }

    #[test]
    fn handle_arp_request_unknown_ip() {
        let (membership, _) = make_membership_with_member(Ipv4Addr::new(10, 147, 20, 1));
        let request = make_arp_request([0x01; 6], [10, 0, 0, 1], [10, 147, 20, 99]);
        assert!(handle_arp_request(&request, &membership).is_none());
    }

    #[test]
    fn handle_arp_non_request_ignored() {
        let (membership, _) = make_membership_with_member(Ipv4Addr::new(10, 147, 20, 1));
        let mut arp = make_arp_request([0x01; 6], [10, 0, 0, 1], [10, 147, 20, 1]);
        arp.operation = ARP_OP_REPLY; // Not a request
        assert!(handle_arp_request(&arp, &membership).is_none());
    }

    #[test]
    fn handle_arp_reply_fields_correct() {
        let target_ip = Ipv4Addr::new(10, 147, 20, 1);
        let (membership, _) = make_membership_with_member(target_ip);

        let request = make_arp_request([0xAA; 6], [10, 147, 20, 5], [10, 147, 20, 1]);
        let reply = handle_arp_request(&request, &membership).unwrap();

        assert_eq!(reply.hw_type, 0x0001);
        assert_eq!(reply.proto_type, 0x0800);
        assert_eq!(reply.hw_len, 6);
        assert_eq!(reply.proto_len, 4);
    }
}
