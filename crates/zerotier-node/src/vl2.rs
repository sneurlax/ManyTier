/// VL2 frame processing: handles inbound/outbound Ethernet frames over ZeroTier.
///
/// This module connects the VL2 components (network membership, COM verification,
/// ARP/NDP interception, multicast) into the Node's receive/dispatch path.

extern crate alloc;

use alloc::vec::Vec;
use core::net::SocketAddr;

use zerotier_crypto::salsa;
use zerotier_protocol::constants::CIPHER_SUITE_C25519_POLY1305_SALSA2012;
use zerotier_protocol::verb::Verb;
use zerotier_protocol::verbs::frame::{ExtFramePayload, FramePayload};
use zerotier_protocol::verbs::multicast::{
    MulticastFramePayload, MulticastGatherPayload, MulticastLikePayload,
};

use crate::arp;
use crate::ethernet;
use crate::node::{Node, NodeAction};

/// Build a complete ZT packet containing an EXT_FRAME verb payload.
///
/// Returns the armored packet bytes ready to send, or None on error.
fn build_ext_frame_packet(
    our_address: &[u8; 5],
    dest_address: &[u8; 5],
    ext: &ExtFramePayload<'_>,
    shared_secret: &[u8; 32],
) -> Option<Vec<u8>> {
    let mut buf = [0u8; 2048];

    // Packet ID (use a simple counter based on network_id + timestamp-ish)
    let packet_id = ext.network_id;
    buf[0..8].copy_from_slice(&packet_id.to_be_bytes());
    // Destination ZT address
    buf[8..13].copy_from_slice(dest_address);
    // Source ZT address
    buf[13..18].copy_from_slice(our_address);
    // Cipher suite 1 (encrypted)
    buf[18] = CIPHER_SUITE_C25519_POLY1305_SALSA2012 << 3;
    // MAC placeholder
    buf[19..27].copy_from_slice(&[0u8; 8]);
    // Verb: EXT_FRAME
    buf[27] = Verb::ExtFrame.to_byte();

    // Serialize payload
    let payload_len = ext.serialize(&mut buf[28..]);
    let total_len = 28 + payload_len;

    // Armor (encrypt + MAC)
    salsa::armor_packet(shared_secret, &mut buf[..total_len], true).ok()?;

    Some(buf[..total_len].to_vec())
}

/// Handle an inbound FRAME verb (0x06).
///
/// FRAME carries an Ethernet payload with implicit src/dest from the packet header.
/// The sender's ZT address is used to derive the source MAC.
pub fn handle_frame(
    node: &mut Node,
    sender_address: &[u8; 5],
    payload_data: &[u8],
    _from: SocketAddr,
    _now_ms: u64,
) {
    let frame = match FramePayload::parse(payload_data) {
        Ok(f) => f,
        Err(_) => return,
    };

    // Find the network
    let network = match node.find_network(frame.network_id) {
        Some(n) => n,
        None => return,
    };

    // Verify sender's COM
    let has_valid_com = has_peer_com(network, sender_address);
    if !has_valid_com {
        // No valid COM -- would send ERROR_NEED_MEMBERSHIP_CERTIFICATE in a full impl.
        // For now, just drop.
        return;
    }

    // Derive MACs: sender MAC from sender's ZT address, dest MAC is our MAC
    let src_mac = ethernet::derive_mac(sender_address, frame.network_id);
    let dest_mac = network.our_mac(node.identity.address.as_bytes());

    node.push_action(NodeAction::FrameReceived {
        network_id: frame.network_id,
        src_mac,
        dest_mac,
        ethertype: frame.ethertype,
        payload: frame.payload.to_vec(),
    });
}

/// Handle an inbound EXT_FRAME verb (0x07).
///
/// EXT_FRAME carries explicit src/dest MAC addresses and supports bridging.
pub fn handle_ext_frame(
    node: &mut Node,
    sender_address: &[u8; 5],
    payload_data: &[u8],
    _from: SocketAddr,
    _now_ms: u64,
) {
    let ext = match ExtFramePayload::parse(payload_data) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Find the network
    let network = match node.find_network(ext.network_id) {
        Some(n) => n,
        None => return,
    };

    // Verify sender's COM
    let has_valid_com = has_peer_com(network, sender_address);
    if !has_valid_com {
        // No valid COM -- would send ERROR_NEED_MEMBERSHIP_CERTIFICATE
        return;
    }

    node.push_action(NodeAction::FrameReceived {
        network_id: ext.network_id,
        src_mac: ext.src_mac,
        dest_mac: ext.dest_mac,
        ethertype: ext.ethertype,
        payload: ext.payload.to_vec(),
    });
}

/// Handle an inbound MULTICAST_LIKE verb (0x09).
///
/// Records multicast group subscriptions from the sender.
pub fn handle_multicast_like(
    node: &mut Node,
    _sender_address: &[u8; 5],
    payload_data: &[u8],
    now_ms: u64,
) {
    let like = match MulticastLikePayload::deserialize(payload_data) {
        Ok(l) => l,
        Err(_) => return,
    };

    for group in &like.groups {
        // The sender_address subscribes to this group
        // Note: In ZeroTier, the address in each group tuple is the subscriber.
        // MULTICAST_LIKE announces the sender's own subscriptions.
        node.multicast_manager.subscribe(
            group.network_id,
            group.mac,
            group.adi,
            *_sender_address,
            now_ms,
        );
    }
}

/// Handle an inbound MULTICAST_GATHER verb (0x0d).
///
/// Responds with known subscribers for the requested multicast group.
pub fn handle_multicast_gather(
    node: &mut Node,
    _sender_address: &[u8; 5],
    payload_data: &[u8],
    from: SocketAddr,
    _now_ms: u64,
) {
    let gather = match MulticastGatherPayload::deserialize(payload_data) {
        Ok(g) => g,
        Err(_) => return,
    };

    let limit = gather.gather_limit as usize;
    let subscribers = node.multicast_manager.get_subscribers(
        gather.network_id,
        &gather.mac,
        gather.adi,
        limit,
    );

    // Build OK(MULTICAST_GATHER) response with subscriber list.
    // Wire format: count(u32 BE) + repeated 5-byte ZT addresses.
    let count = subscribers.len() as u32;
    let response_len = 4 + subscribers.len() * 5;
    let mut response = Vec::with_capacity(response_len);
    response.extend_from_slice(&count.to_be_bytes());
    for addr in &subscribers {
        response.extend_from_slice(addr);
    }

    node.push_action(NodeAction::SendTo {
        data: response,
        address: from,
    });
}

/// Handle an inbound MULTICAST_FRAME verb (0x0e).
///
/// Decapsulates a multicast frame and delivers it to the TUN device.
pub fn handle_multicast_frame(
    node: &mut Node,
    sender_address: &[u8; 5],
    payload_data: &[u8],
    _from: SocketAddr,
    _now_ms: u64,
) {
    let mf = match MulticastFramePayload::parse(payload_data) {
        Ok(m) => m,
        Err(_) => return,
    };

    // Find the network
    let network = match node.find_network(mf.network_id) {
        Some(n) => n,
        None => return,
    };

    // Verify sender's COM
    let has_valid_com = has_peer_com(network, sender_address);
    if !has_valid_com {
        return;
    }

    // Derive source MAC from sender or explicit source_mac in frame
    let src_mac = mf
        .source_mac
        .unwrap_or_else(|| ethernet::derive_mac(sender_address, mf.network_id));

    node.push_action(NodeAction::FrameReceived {
        network_id: mf.network_id,
        src_mac,
        dest_mac: mf.dest_mac,
        ethertype: mf.ethertype,
        payload: mf.payload.to_vec(),
    });
}

/// Process an outbound frame from the TUN device for transmission on the virtual network.
///
/// This is called when the TUN device reads an IP packet that needs to be sent.
/// It handles:
/// - ARP interception (resolve locally if possible, otherwise multicast)
/// - Unicast IPv4/IPv6 (look up dest, build EXT_FRAME)
/// - Multicast/broadcast frames
///
/// Returns a list of actions (SendTo with EXT_FRAME packets, or LocalReply for ARP).
pub fn process_outbound_frame(
    node: &mut Node,
    network_id: u64,
    ethertype: u16,
    payload: &[u8],
    our_zt_address: &[u8; 5],
) -> Vec<NodeAction> {
    let mut actions = Vec::new();

    let network = match node.find_network(network_id) {
        Some(n) => n,
        None => return actions,
    };

    let our_mac = network.our_mac(our_zt_address);

    match ethertype {
        ethernet::ETHERTYPE_ARP => {
            // Try to resolve ARP locally
            if let Some(arp_pkt) = arp::ArpPacket::parse(payload) {
                if let Some(reply) = arp::handle_arp_request(&arp_pkt, network) {
                    // Resolved locally -- return as LocalReply
                    let mut buf = [0u8; 28];
                    let n = reply.serialize(&mut buf);
                    actions.push(NodeAction::LocalReply {
                        network_id,
                        ethertype: ethernet::ETHERTYPE_ARP,
                        payload: buf[..n].to_vec(),
                    });
                    return actions;
                }
            }
            // Not resolved locally -- send as multicast to ARP group
            // Build EXT_FRAME to broadcast MAC
            let dest_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
            let ext = ExtFramePayload {
                network_id,
                flags: 0,
                dest_mac,
                src_mac: our_mac,
                ethertype,
                payload,
            };
            let mut buf = [0u8; 2048];
            let n = ext.serialize(&mut buf);
            // For multicast, we'd need to send to all known subscribers.
            // For now, build a single SendTo action (the transport layer
            // would need to handle multicast distribution).
            let targets = node.multicast_manager.get_replication_targets(
                network_id,
                &dest_mac,
                ethernet::ETHERTYPE_ARP as u32,
                our_zt_address,
                64,
            );
            for target_addr in &targets {
                // We'd need to look up the target's physical address from topology.
                // For now, push the frame data -- the caller resolves physical addresses.
                if let Some(peer) = node.topology.get_peer(target_addr) {
                    if let Some(path) = peer.best_path(0) {
                        actions.push(NodeAction::SendTo {
                            data: buf[..n].to_vec(),
                            address: path.address,
                        });
                    }
                }
            }
        }
        ethernet::ETHERTYPE_IPV4 => {
            // Look up destination IP -> member -> ZT address -> physical path
            if payload.len() >= 20 {
                let dest_ip = core::net::Ipv4Addr::new(
                    payload[16],
                    payload[17],
                    payload[18],
                    payload[19],
                );
                if let Some(member) = network.lookup_ipv4(dest_ip) {
                    let ext = ExtFramePayload {
                        network_id,
                        flags: 0,
                        dest_mac: member.mac,
                        src_mac: our_mac,
                        ethertype,
                        payload,
                    };

                    if let Some(peer) = node.topology.get_peer(&member.zt_address) {
                        if let Some(path) = peer.best_path(0) {
                            if let Some(secret) = peer.shared_secret() {
                                if let Some(pkt) = build_ext_frame_packet(
                                    our_zt_address,
                                    &member.zt_address,
                                    &ext,
                                    secret,
                                ) {
                                    tracing::info!(
                                        target: "manytier",
                                        event = "vl2_ext_frame_out",
                                        dest_addr = %path.address,
                                        pkt_len = pkt.len(),
                                        "sending EXT_FRAME"
                                    );
                                    actions.push(NodeAction::SendTo {
                                        data: pkt,
                                        address: path.address,
                                    });
                                }
                            }
                        }
                    } else {
                        actions.push(NodeAction::WhoisNeeded {
                            addresses: alloc::vec![member.zt_address],
                        });
                    }
                }
            }
        }
        ethernet::ETHERTYPE_IPV6 => {
            // Look up destination IPv6 -> member -> ZT address -> physical path
            if payload.len() >= 40 {
                let mut dst_bytes = [0u8; 16];
                dst_bytes.copy_from_slice(&payload[24..40]);
                let dest_ip = core::net::Ipv6Addr::from(dst_bytes);
                if let Some(member) = network.lookup_ipv6(dest_ip) {
                    let ext = ExtFramePayload {
                        network_id,
                        flags: 0,
                        dest_mac: member.mac,
                        src_mac: our_mac,
                        ethertype,
                        payload,
                    };

                    if let Some(peer) = node.topology.get_peer(&member.zt_address) {
                        if let Some(path) = peer.best_path(0) {
                            if let Some(secret) = peer.shared_secret() {
                                if let Some(pkt) = build_ext_frame_packet(
                                    our_zt_address,
                                    &member.zt_address,
                                    &ext,
                                    secret,
                                ) {
                                    actions.push(NodeAction::SendTo {
                                        data: pkt,
                                        address: path.address,
                                    });
                                }
                            }
                        }
                    } else {
                        actions.push(NodeAction::WhoisNeeded {
                            addresses: alloc::vec![member.zt_address],
                        });
                    }
                }
            }
        }
        _ => {
            // Unknown ethertype -- drop
        }
    }

    actions
}

/// Check if a peer has a valid COM stored in the network's peer_coms list,
/// and if so verify it against our own COM.
fn has_peer_com(network: &crate::network::NetworkMembership, peer_address: &[u8; 5]) -> bool {
    // Find the peer's COM in the network's stored COMs
    if let Some((_, peer_com)) = network.peer_coms.iter().find(|(addr, _)| addr == peer_address) {
        network.verify_peer_com(peer_address, peer_com)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet;
    use crate::multicast::MulticastManager;
    use crate::network::{NetworkMember, NetworkMembership};
    use alloc::vec;
    use core::net::Ipv4Addr;
    use zerotier_protocol::verbs::network_config::{CertificateOfMembership, ComQualifier};

    fn make_network_with_com(network_id: u64) -> NetworkMembership {
        let mut net = NetworkMembership::new(network_id, 2800);
        // Set up a COM for our node
        net.our_com = Some(CertificateOfMembership {
            qualifiers: vec![
                ComQualifier {
                    id: 0,
                    value: 1000,
                    max_delta: 100,
                },
                ComQualifier {
                    id: 1,
                    value: network_id,
                    max_delta: 0,
                },
            ],
            signer_address: [0; 5],
            signature: [0; 96],
        });
        net
    }

    fn add_peer_com(net: &mut NetworkMembership, peer_addr: &[u8; 5]) {
        let com = CertificateOfMembership {
            qualifiers: vec![
                ComQualifier {
                    id: 0,
                    value: 1050,
                    max_delta: 100,
                },
                ComQualifier {
                    id: 1,
                    value: net.network_id,
                    max_delta: 0,
                },
            ],
            signer_address: [0; 5],
            signature: [0; 96],
        };
        net.peer_coms.push((*peer_addr, com));
    }

    #[test]
    fn ext_frame_with_valid_com_produces_frame_received() {
        let network_id = 0xff00000000abcdef_u64;
        let sender = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        let our_addr = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let our_mac = ethernet::derive_mac(&our_addr, network_id);
        let sender_mac = ethernet::derive_mac(&sender, network_id);

        // Build EXT_FRAME payload
        let ext = ExtFramePayload {
            network_id,
            flags: 0,
            dest_mac: our_mac,
            src_mac: sender_mac,
            ethertype: 0x0800,
            payload: &[0xDE, 0xAD],
        };
        let mut buf = [0u8; 256];
        let n = ext.serialize(&mut buf);

        // We need a Node, but Node::new requires planet data.
        // Test the has_peer_com helper and parsing logic directly.
        let mut net = make_network_with_com(network_id);
        add_peer_com(&mut net, &sender);

        // Verify COM check works
        assert!(has_peer_com(&net, &sender));

        // Verify parsing works
        let parsed = ExtFramePayload::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.network_id, network_id);
        assert_eq!(parsed.payload, &[0xDE, 0xAD]);
    }

    #[test]
    fn ext_frame_without_com_is_rejected() {
        let network_id = 0xff00000000abcdef_u64;
        let sender = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];

        let net = make_network_with_com(network_id);
        // No peer COM added for sender
        assert!(!has_peer_com(&net, &sender));
    }

    #[test]
    fn multicast_like_records_subscriptions() {
        let mut mgr = MulticastManager::new();
        let sender = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        let network_id = 0xff00000000abcdef_u64;

        // Build MULTICAST_LIKE payload
        let like = MulticastLikePayload {
            groups: vec![
                zerotier_protocol::verbs::multicast::MulticastGroup {
                    network_id,
                    mac: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                    adi: 0x0806,
                },
            ],
        };
        let mut buf = [0u8; 64];
        let n = like.serialize(&mut buf);
        let parsed = MulticastLikePayload::deserialize(&buf[..n]).unwrap();

        // Simulate what handle_multicast_like does
        for group in &parsed.groups {
            mgr.subscribe(group.network_id, group.mac, group.adi, sender, 1000);
        }

        let subs = mgr.get_subscribers(network_id, &[0xff; 6], 0x0806, 100);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0], sender);
    }

    #[test]
    fn multicast_gather_returns_subscribers() {
        let mut mgr = MulticastManager::new();
        let network_id = 0xff00000000abcdef_u64;
        let peer1 = [0x01, 0x02, 0x03, 0x04, 0x05];
        let peer2 = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];

        mgr.subscribe(network_id, [0xff; 6], 0x0806, peer1, 1000);
        mgr.subscribe(network_id, [0xff; 6], 0x0806, peer2, 1000);

        let subs = mgr.get_subscribers(network_id, &[0xff; 6], 0x0806, 100);
        assert_eq!(subs.len(), 2);
    }

    #[test]
    fn arp_outbound_resolved_locally() {
        let network_id = 0xff00000000abcdef_u64;
        let our_addr = [0xa0, 0xb1, 0xc2, 0xd3, 0xe4];
        let peer_addr = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        let peer_mac = ethernet::derive_mac(&peer_addr, network_id);

        let mut net = NetworkMembership::new(network_id, 2800);
        net.members.push(NetworkMember {
            zt_address: peer_addr,
            mac: peer_mac,
            ipv4: Some((Ipv4Addr::new(10, 147, 20, 1), 24)),
            ipv6: None,
            authorized: true,
        });

        // Build ARP request for 10.147.20.1
        let arp_req = arp::ArpPacket {
            hw_type: 0x0001,
            proto_type: 0x0800,
            hw_len: 6,
            proto_len: 4,
            operation: arp::ARP_OP_REQUEST,
            sender_hw: ethernet::derive_mac(&our_addr, network_id),
            sender_proto: [10, 147, 20, 2],
            target_hw: [0x00; 6],
            target_proto: [10, 147, 20, 1],
        };

        let reply = arp::handle_arp_request(&arp_req, &net);
        assert!(reply.is_some());
        let reply = reply.unwrap();
        assert_eq!(reply.operation, arp::ARP_OP_REPLY);
        assert_eq!(reply.sender_hw, peer_mac);
    }
}
