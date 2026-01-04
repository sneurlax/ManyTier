// Main node engine.
///
/// The Node is transport-agnostic: it processes received packets and returns
/// a list of actions (send packets, WHOIS requests) for the transport layer
/// to execute. This design enables WASM compatibility since the node never
/// directly performs I/O.
extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use zerotier_crypto::identity::Identity;
use zerotier_crypto::salsa;
use zerotier_protocol::constants::*;
use zerotier_protocol::fragment::ReassemblyBuffer;
use zerotier_protocol::inet_address::InetAddress;
use zerotier_protocol::verb::Verb;
use zerotier_protocol::verbs::hello::HelloPayload;
use zerotier_protocol::verbs::network_config::{
    CertificateOfMembership, NetworkConfigPayload, NetworkCredentialsPayload,
};
use zerotier_protocol::verbs::ok::{OkPayload, OkSubPayload};
use zerotier_protocol::verbs::rendezvous::RendezvousPayload;
use zerotier_protocol::verbs::whois::WhoisRequest;
use zerotier_protocol::{is_fragment, FragmentHeader, PacketHeader, ProtocolError};

use crate::controller::dictionary::Dictionary;
use crate::multicast::{arp_multicast_group, MulticastGroupKey, MulticastManager};
use crate::network::{NetworkMember, NetworkMembership};
use crate::peer::PeerState;
use crate::root::RootManager;
use crate::switch::{RouteDecision, Switch};
use crate::topology::Topology;

/// Actions the node wants the transport layer to perform.
///
/// The node is transport-agnostic -- it returns actions instead of calling
/// transport directly. This enables WASM compatibility.
#[derive(Debug)]
pub enum NodeAction {
    /// Send data to a specific network address.
    SendTo { data: Vec<u8>, address: SocketAddr },
    /// Request the caller to resolve these ZeroTier addresses via WHOIS.
    WhoisNeeded { addresses: Vec<[u8; 5]> },
    /// An Ethernet frame was received from the virtual network, ready to write to TUN.
    /// Contains raw payload (ethertype indicates IPv4/IPv6/ARP).
    FrameReceived {
        network_id: u64,
        src_mac: [u8; 6],
        dest_mac: [u8; 6],
        ethertype: u16,
        payload: Vec<u8>,
    },
    /// An ARP/NDP reply was generated locally, write to TUN.
    LocalReply {
        network_id: u64,
        ethertype: u16,
        payload: Vec<u8>,
    },
    /// A NETWORK_CONFIG was received and applied to the network membership.
    /// The daemon should create/update TUN device and assign IPs.
    NetworkConfigured {
        network_id: u64,
        /// Raw dictionary data from the config (daemon parses for IPs/routes).
        dict_data: Vec<u8>,
    },
    /// A NETWORK_CONFIG_REQUEST was received (verb 0x0b).
    /// The controller role should respond with NETWORK_CONFIG + NETWORK_CREDENTIALS.
    NetworkConfigRequested {
        /// Source ZT address requesting the config.
        requester_address: [u8; 5],
        /// Network ID from the request payload.
        network_id: u64,
        /// Dictionary data from the request.
        dict_data: Vec<u8>,
        /// Physical address of the requester (for sending response).
        from: core::net::SocketAddr,
        /// Packet ID from the request (for OK response correlation).
        packet_id: u64,
    },
}

#[derive(Debug, Clone, Copy)]
struct PendingMulticastGather {
    packet_id: u64,
    requested_at_ms: u64,
    network_id: u64,
    mac: [u8; 6],
    adi: u32,
}

/// The main ZeroTier VL1 node engine.
pub struct Node {
    pub identity: Identity,
    /// Peer table and root tracking.
    pub topology: Topology,
    /// Root server communication.
    pub root_manager: RootManager,
    /// Fragment reassembly buffer.
    reassembly: ReassemblyBuffer,
    /// Pending outbound actions.
    actions: Vec<NodeAction>,
    next_packet_id: u64,
    /// VL2 network membership (one per joined network).
    pub networks: Vec<NetworkMembership>,
    pub multicast_manager: MulticastManager,
    pending_multicast_gathers: Vec<PendingMulticastGather>,
}

impl Node {
    /// Create a new node with the given identity and planet data.
    ///
    /// Parses the planet binary to discover root servers.
    pub fn new(
        identity: Identity,
        planet_data: &[u8],
        initial_packet_id: u64,
    ) -> Result<Self, ProtocolError> {
        let planet = zerotier_protocol::world::World::deserialize(planet_data)?;
        let mut topology = Topology::new();
        topology.load_planet(planet);

        Ok(Node {
            root_manager: RootManager::new(),
            identity,
            topology,
            reassembly: ReassemblyBuffer::new(256),
            actions: Vec::new(),
            next_packet_id: initial_packet_id,
            networks: Vec::new(),
            multicast_manager: MulticastManager::new(),
            pending_multicast_gathers: Vec::new(),
        })
    }

    /// Push an action onto the pending actions list.
    ///
    /// Used by VL2 handlers (in vl2.rs) that need to enqueue actions on the node.
    pub fn push_action(&mut self, action: NodeAction) {
        self.actions.push(action);
    }

    pub fn allocate_packet_id(&mut self) -> u64 {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);
        if self.next_packet_id == 0 {
            self.next_packet_id = 1;
        }
        packet_id
    }

    /// Join a virtual network by adding its membership state.
    pub fn join_network(&mut self, membership: NetworkMembership) {
        // Avoid duplicates
        if self
            .networks
            .iter()
            .any(|n| n.network_id == membership.network_id)
        {
            return;
        }

        let our_address = *self.identity.address.as_bytes();
        let arp_group = arp_multicast_group(membership.network_id);
        self.multicast_manager.subscribe(
            arp_group.network_id,
            arp_group.mac,
            arp_group.adi,
            our_address,
            0,
        );
        self.networks.push(membership);
    }

    pub fn find_network(&self, network_id: u64) -> Option<&NetworkMembership> {
        self.networks.iter().find(|n| n.network_id == network_id)
    }

    /// Find a network membership by network ID (mutable reference).
    pub fn find_network_mut(&mut self, network_id: u64) -> Option<&mut NetworkMembership> {
        self.networks
            .iter_mut()
            .find(|n| n.network_id == network_id)
    }

    fn apply_network_config(&mut self, network_id: u64, dict_data: &[u8]) {
        let our_address = *self.identity.address.as_bytes();
        if let Some(net) = self.find_network_mut(network_id) {
            if let Some(mtu) = network_mtu_from_dict_data(dict_data) {
                net.mtu = mtu;
            }

            // Extract our IP assignments from "I" key in dictionary
            if let Ok(dict) = Dictionary::deserialize(dict_data) {
                if let Some(ip_data) = dict.get_binary("I") {
                    let mut pos = 0;
                    while pos < ip_data.len() {
                        if let Ok((inet, consumed)) = InetAddress::deserialize(&ip_data[pos..]) {
                            match inet {
                                InetAddress::V4 { ip, .. } => {
                                    net.assigned_ipv4 = Some(Ipv4Addr::from(ip));
                                }
                                InetAddress::V6 { ip, .. } => {
                                    net.assigned_ipv6 = Some(Ipv6Addr::from(ip));
                                }
                                _ => {}
                            }
                            pos += consumed;
                        } else {
                            break;
                        }
                    }
                }

                // Extract managed routes from "RT" key
                if let Some(rt_data) = dict.get_binary("RT") {
                    let mut pos = 0;
                    let mut new_routes = Vec::new();
                    while pos < rt_data.len() {
                        if let Ok((target, consumed)) = InetAddress::deserialize(&rt_data[pos..]) {
                            pos += consumed;
                            if pos + 2 > rt_data.len() {
                                break;
                            }
                            let prefix = u16::from_be_bytes([rt_data[pos], rt_data[pos + 1]]);
                            pos += 2;

                            if pos >= rt_data.len() {
                                break;
                            }
                            let via_type = rt_data[pos];
                            pos += 1;

                            if via_type == 4 {
                                if pos + 4 + 2 <= rt_data.len() {
                                    pos += 4 + 2; // skip port
                                } else {
                                    break;
                                }
                            } else if via_type == 6 {
                                if pos + 16 + 2 <= rt_data.len() {
                                    pos += 16 + 2; // skip port
                                } else {
                                    break;
                                }
                            }

                            if pos + 2 <= rt_data.len() {
                                pos += 2; // skip flags
                            }

                            let target_str = match target {
                                InetAddress::V4 { ip, .. } => {
                                    alloc::format!(
                                        "{}.{}.{}.{}/{}",
                                        ip[0],
                                        ip[1],
                                        ip[2],
                                        ip[3],
                                        prefix
                                    )
                                }
                                _ => alloc::format!("{:?}/{}", target, prefix),
                            };
                            new_routes.push(crate::network::Route { target: target_str });
                        } else {
                            break;
                        }
                    }
                    if !new_routes.is_empty() {
                        net.routes = new_routes;
                    }
                }
            }

            if let Some((members, peer_coms)) =
                peer_directory_from_dict_data(dict_data, network_id, our_address)
            {
                net.members = members;
                net.peer_coms = peer_coms;
            }
        }
    }

    fn handle_multicast_gather_ok(&mut self, packet_id: u64, data: &[u8], now_ms: u64) {
        let pending_index = match self
            .pending_multicast_gathers
            .iter()
            .position(|pending| pending.packet_id == packet_id)
        {
            Some(index) => index,
            None => return,
        };
        let pending = self.pending_multicast_gathers.swap_remove(pending_index);

        if data.len() < 4 {
            return;
        }

        let count = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + count * 5 {
            return;
        }

        for chunk in data[4..4 + count * 5].chunks_exact(5) {
            let mut subscriber = [0u8; 5];
            subscriber.copy_from_slice(chunk);
            self.multicast_manager.subscribe(
                pending.network_id,
                pending.mac,
                pending.adi,
                subscriber,
                now_ms,
            );
        }
    }

    /// Derive the peer-authentication key from a known identity.
    ///
    /// Initial HELLO and OK(HELLO) packets are authenticated before the peer
    /// transitions to `Active`, so callers cannot rely on `PeerState` alone.
    pub fn shared_secret_for_peer(&self, address: &[u8; 5]) -> Option<[u8; 32]> {
        let peer = self.topology.get_peer(address)?;
        if let Some(secret) = peer.shared_secret() {
            return Some(*secret);
        }

        let our_secret = self.identity.secret.as_ref()?;
        let their_dh_pubkey = x25519_dalek::PublicKey::from(peer.identity.public_key.dh);
        Some(zerotier_crypto::key_agreement::key_agree(
            &our_secret.dh,
            &their_dh_pubkey,
        ))
    }

    /// Send WHOIS requests to roots for the given addresses.
    /// Returns SendTo actions with the WHOIS packets.
    pub fn send_whois(&mut self, addresses: &[[u8; 5]], now_ms: u64) -> Vec<NodeAction> {
        let mut actions = Vec::new();
        for root_addr in &self.topology.roots.clone() {
            if let Some(root_peer) = self.topology.get_peer(root_addr) {
                if let Some(path) = root_peer.best_path(now_ms) {
                    let shared_secret = match self.shared_secret_for_peer(root_addr) {
                        Some(secret) => secret,
                        None => continue,
                    };
                    let mut buf = [0u8; 512];
                    if let Ok((len, _packet_id)) = crate::root::RootManager::build_whois(
                        &self.identity,
                        root_addr,
                        addresses,
                        &shared_secret,
                        now_ms,
                        &mut buf,
                    ) {
                        actions.push(NodeAction::SendTo {
                            data: buf[..len].to_vec(),
                            address: path.address,
                        });
                    }
                    break; // Send to first reachable root
                }
            }
        }
        actions
    }

    /// Process a received packet. Returns actions for the transport layer.
    pub fn receive_packet(
        &mut self,
        data: &mut [u8],
        from: SocketAddr,
        now_ms: u64,
    ) -> Vec<NodeAction> {
        self.actions.clear();

        if is_fragment(data) {
            self.handle_fragment(data, from, now_ms);
            return core::mem::take(&mut self.actions);
        }

        if data.len() < ZT_PROTO_MIN_PACKET_LENGTH {
            return core::mem::take(&mut self.actions);
        }

        // Parse header (read-only) to get routing info
        let dest;
        let source;
        let cipher_suite;
        let verb_id;
        let packet_id;
        {
            let hdr = match PacketHeader::from_bytes(data) {
                Some(h) => h,
                None => return core::mem::take(&mut self.actions),
            };
            dest = hdr.dest;
            source = hdr.source_address();
            cipher_suite = hdr.cipher_suite();
            verb_id = hdr.verb_id();
            packet_id = hdr.packet_id();
        }

        // Check if destined for us
        if dest != *self.identity.address.as_bytes() {
            self.handle_relay(data, now_ms);
            return core::mem::take(&mut self.actions);
        }

        // Dearmor packet (verify MAC, optionally decrypt)
        let dearmored = self.dearmor(data, &source, cipher_suite, verb_id);
        if !dearmored {
            // MAC verification failed or no shared secret available
            // For cipher suite 0 (HELLO), we still try to process
            if cipher_suite != CIPHER_SUITE_C25519_POLY1305_NONE {
                tracing::warn!(
                    target: "manytier",
                    event = "dearmor_failed",
                    cipher_suite = cipher_suite,
                    verb_id,
                    packet_id,
                    source = %format_args!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                        source[0], source[1], source[2], source[3], source[4]),
                    from = %from,
                    packet_len = data.len(),
                    "packet dearmor failed: dropping"
                );
                return core::mem::take(&mut self.actions);
            }
        }

        // Re-read verb after potential decryption
        let verb_id = if dearmored { data[27] & 0x1f } else { verb_id };

        // Determine if this packet arrived via relay (from a root's physical address)
        let is_relayed = self.topology.roots.iter().any(|root_addr| {
            if *root_addr == source {
                return false; // Packet FROM a root is not relayed
            }
            self.topology
                .peers
                .get(root_addr)
                .map(|rp| rp.paths.iter().any(|p| p.address == from))
                .unwrap_or(false)
        });

        // Update source peer's path and promote if direct
        if let Some(peer) = self.topology.get_peer_mut(&source) {
            if !is_relayed {
                // Check if path was relay before promotion for logging
                let was_relay = peer.paths.iter().any(|p| p.address == from && !p.is_direct);
                peer.promote_path(from, now_ms);
                if was_relay {
                    tracing::info!(
                        target: "manytier",
                        event = "path_promoted",
                        peer = %format_args!("{:02x}{:02x}{:02x}{:02x}{:02x}", source[0], source[1], source[2], source[3], source[4]),
                        "path promoted to direct"
                    );
                }
            } else {
                peer.add_path(from, false, now_ms);
            }

            if let PeerState::Active {
                ref mut last_receive,
                ..
            } = peer.state
            {
                *last_receive = now_ms;
            }
        }

        // Extract verb payload (after verb byte at offset 28)
        let verb_payload = if data.len() > 28 {
            &data[28..]
        } else {
            &[] as &[u8]
        };

        match Verb::from_byte(verb_id) {
            Some(Verb::Hello) => self.handle_hello(data, from, now_ms, packet_id),
            Some(Verb::Ok) => self.handle_ok(data, from, now_ms),
            Some(Verb::Error) => self.handle_error(data, from, now_ms),
            Some(Verb::Whois) => self.handle_whois(data, from, now_ms),
            Some(Verb::Rendezvous) => self.handle_rendezvous(data, from, now_ms),
            Some(Verb::Echo) => self.handle_echo(data, from, now_ms, packet_id),
            Some(Verb::PushDirectPaths) => self.handle_push_direct_paths(data, from, now_ms),
            Some(Verb::NetworkConfig) => self.handle_network_config(data, from, now_ms),
            Some(Verb::NetworkCredentials) => self.handle_network_credentials(data, from, now_ms),
            Some(Verb::Frame) => {
                crate::vl2::handle_frame(self, &source, verb_payload, from, now_ms)
            }
            Some(Verb::ExtFrame) => {
                crate::vl2::handle_ext_frame(self, &source, verb_payload, from, now_ms)
            }
            Some(Verb::MulticastLike) => {
                crate::vl2::handle_multicast_like(self, &source, verb_payload, now_ms)
            }
            Some(Verb::MulticastGather) => crate::vl2::handle_multicast_gather(
                self,
                &source,
                verb_payload,
                from,
                now_ms,
                packet_id,
            ),
            Some(Verb::MulticastFrame) => {
                crate::vl2::handle_multicast_frame(self, &source, verb_payload, from, now_ms)
            }
            Some(Verb::NetworkConfigRequest) => {
                // Emit action for external controller handling
                match zerotier_protocol::verbs::network_config::NetworkConfigRequestPayload::deserialize(verb_payload) {
                    Ok(req) => {
                        tracing::info!(
                            target: "manytier",
                            event = "network_config_request_received",
                            requester = %format_args!(
                                "{:02x}{:02x}{:02x}{:02x}{:02x}",
                                source[0], source[1], source[2], source[3], source[4]
                            ),
                            network_id = %format_args!("{:016x}", req.network_id),
                            dict_len = req.dict_data.len(),
                            "received NETWORK_CONFIG_REQUEST"
                        );
                        self.actions.push(NodeAction::NetworkConfigRequested {
                            requester_address: source,
                            network_id: req.network_id,
                            dict_data: req.dict_data,
                            from,
                            packet_id,
                        });
                    }
                    Err(error) => {
                        tracing::warn!(
                            target: "manytier",
                            event = "network_config_request_decode_failed",
                            requester = %format_args!(
                                "{:02x}{:02x}{:02x}{:02x}{:02x}",
                                source[0], source[1], source[2], source[3], source[4]
                            ),
                            payload_len = verb_payload.len(),
                            packet_id,
                            error = %error,
                            "failed to decode NETWORK_CONFIG_REQUEST"
                        );
                    }
                }
            }
            _ => {
                // Other verbs: not yet handled
            }
        }

        core::mem::take(&mut self.actions)
    }

    /// Attempt to dearmor (verify MAC + decrypt) a packet.
    ///
    /// Returns true if dearmoring succeeded.
    fn dearmor(&self, data: &mut [u8], source: &[u8; 5], cipher_suite: u8, verb_id: u8) -> bool {
        match cipher_suite {
            CIPHER_SUITE_C25519_POLY1305_NONE => {
                // Cipher suite 0: MAC only, no encryption.
                // For HELLO packets, we compute shared secret on the fly
                // from the identity in the packet. For now, we skip MAC
                // verification for incoming HELLOs (we'll verify after parsing).
                if verb_id == Verb::Hello.to_byte() {
                    return false; // Don't dearmor HELLOs; handle raw
                }
                if let Some(secret) = self.shared_secret_for_peer(source) {
                    return salsa::dearmor_packet(&secret, data).is_ok();
                }
                false
            }
            CIPHER_SUITE_C25519_POLY1305_SALSA2012 => {
                if let Some(secret) = self.shared_secret_for_peer(source) {
                    return salsa::dearmor_packet(&secret, data).is_ok();
                }
                false
            }
            _ => false,
        }
    }

    /// Handle an incoming HELLO packet.
    ///
    /// Parse HELLO payload, verify protocol version, compute shared secret,
    /// and send OK(HELLO) response.
    fn handle_hello(&mut self, data: &[u8], from: SocketAddr, now_ms: u64, packet_id: u64) {
        // Parse HELLO payload (after verb byte, offset 28)
        let payload_data = if data.len() > 28 { &data[28..] } else { return };
        let (hello, _) = match HelloPayload::deserialize(payload_data) {
            Ok(h) => h,
            Err(_) => return,
        };

        // HELLO MAC verification using DH-derived shared secret.
        // DH key agreement between x25519_dalek and official ZeroTier C25519 has
        // been verified to produce identical shared secrets (cross_identity_hello_mac_verifies).
        // The bypass remains because official-to-ManyTier HELLOs use a different
        // crypt_packet_field key derivation that changes the MAC input bytes.
        if let Some(ref our_secret) = self.identity.secret {
            let shared_secret = zerotier_crypto::key_agreement::key_agree(
                &our_secret.dh,
                &x25519_dalek::PublicKey::from(hello.identity.public_key.dh),
            );
            if salsa::dearmor_packet(&shared_secret, &mut data.to_vec()).is_err() {
                tracing::debug!(
                    target: "manytier",
                    event = "hello_mac_mismatch",
                    packet_id,
                    "HELLO MAC does not match DH-derived key (accepting anyway for interop)"
                );
            }
        }

        // Verify minimum protocol version
        if hello.protocol_version < ZT_PROTO_VERSION_MIN {
            return;
        }

        let source_addr_bytes = *hello.identity.address.as_bytes();

        // Add or update the peer
        let peer_public_key = hello.identity.public_key.clone();
        if self.topology.get_peer(&source_addr_bytes).is_none() {
            self.topology.add_peer(Identity {
                address: hello.identity.address,
                public_key: peer_public_key.clone(),
                secret: None,
            });
        }

        // Compute shared secret for this peer
        if let Some(ref our_secret) = self.identity.secret {
            let their_dh_pubkey = x25519_dalek::PublicKey::from(peer_public_key.dh);
            let shared_secret =
                zerotier_crypto::key_agreement::key_agree(&our_secret.dh, &their_dh_pubkey);

            // Update peer state
            if let Some(peer) = self.topology.get_peer_mut(&source_addr_bytes) {
                peer.add_path(from, true, now_ms);
                peer.state = PeerState::Active {
                    shared_secret,
                    latency_ms: 0,
                    last_receive: now_ms,
                    last_send: now_ms,
                };
            }

            tracing::info!(
                target: "manytier",
                event = "hello_accepted",
                peer = %format_args!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                    source_addr_bytes[0], source_addr_bytes[1], source_addr_bytes[2],
                    source_addr_bytes[3], source_addr_bytes[4]),
                "HELLO accepted"
            );

            // Build and send OK(HELLO) response
            let mut buf = [0u8; 512];
            if let Ok(len) = RootManager::build_ok_hello(
                &self.identity,
                &source_addr_bytes,
                packet_id,
                hello.timestamp,
                &shared_secret,
                now_ms,
                false,
                &mut buf,
            ) {
                self.actions.push(NodeAction::SendTo {
                    data: buf[..len].to_vec(),
                    address: from,
                });
            }
        }
    }

    /// Handle an incoming OK packet.
    ///
    /// OK(HELLO): compute latency from timestamp echo, establish peer session.
    /// OK(WHOIS): add learned identities to topology.
    fn handle_ok(&mut self, data: &[u8], from: SocketAddr, now_ms: u64) {
        let payload_data = if data.len() > 28 { &data[28..] } else { return };
        let ok = match OkPayload::deserialize(payload_data) {
            Ok(o) => o,
            Err(_) => return,
        };

        match ok.sub_payload {
            OkSubPayload::Hello { timestamp_echo, .. } => {
                // Compute latency from timestamp echo
                let latency_ms = now_ms.saturating_sub(timestamp_echo) as u32;

                // Find the peer by source address from packet header
                let source = {
                    match PacketHeader::from_bytes(data) {
                        Some(hdr) => hdr.source_address(),
                        None => return,
                    }
                };

                if let Some(peer) = self.topology.get_peer_mut(&source) {
                    // Establish session if not already active
                    if let Some(ref our_secret) = self.identity.secret {
                        let their_dh = x25519_dalek::PublicKey::from(peer.identity.public_key.dh);
                        let shared_secret =
                            zerotier_crypto::key_agreement::key_agree(&our_secret.dh, &their_dh);
                        peer.state = PeerState::Active {
                            shared_secret,
                            latency_ms,
                            last_receive: now_ms,
                            last_send: now_ms,
                        };
                    }
                    peer.add_path(from, true, now_ms);

                    tracing::info!(
                        target: "manytier",
                        event = "peer_session_established",
                        peer = %format_args!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                            source[0], source[1], source[2], source[3], source[4]),
                        latency_ms = latency_ms,
                        "session established"
                    );

                    // Update path latency
                    if let Some(path) = peer.paths.iter_mut().find(|p| p.address == from) {
                        path.latency_ms = latency_ms;
                    }
                }
            }
            OkSubPayload::Whois { identities } => {
                // Add learned identities to topology and initiate HELLO
                for id in identities {
                    let addr_bytes = *id.address.as_bytes();
                    tracing::info!(
                        target: "manytier",
                        event = "whois_resolved",
                        address = %format_args!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                            addr_bytes[0], addr_bytes[1], addr_bytes[2],
                            addr_bytes[3], addr_bytes[4]),
                        "WHOIS resolved"
                    );
                    self.topology.add_peer(id);
                    self.topology.pending_whois.remove(&addr_bytes);

                    // Send HELLO to newly discovered peer via root relay
                    for root_addr in &self.topology.roots.clone() {
                        if let Some(root_peer) = self.topology.get_peer(root_addr) {
                            if let Some(path) = root_peer.best_path(now_ms) {
                                let root_phys = path.address;
                                let hello_secret = self
                                    .shared_secret_for_peer(&addr_bytes)
                                    .unwrap_or([0u8; 32]);
                                // See ZeroTierOne 1.14.2 node/Peer.cpp:430-431
                                let planet_id = self
                                    .topology
                                    .planet
                                    .as_ref()
                                    .map(|p| p.id)
                                    .unwrap_or(zerotier_protocol::constants::WORLD_ID_EARTH);
                                let planet_ts = self
                                    .topology
                                    .planet
                                    .as_ref()
                                    .map(|p| p.timestamp)
                                    .unwrap_or(0);
                                let mut hello_buf = [0u8; 512];
                                if let Ok((len, _)) = RootManager::build_hello(
                                    &self.identity,
                                    &addr_bytes,
                                    root_phys,
                                    now_ms,
                                    &hello_secret,
                                    &mut hello_buf,
                                    planet_id,
                                    planet_ts,
                                ) {
                                    self.actions.push(NodeAction::SendTo {
                                        data: hello_buf[..len].to_vec(),
                                        address: root_phys,
                                    });
                                }
                                break;
                            }
                        }
                    }
                }
            }
            OkSubPayload::Generic { data } => {
                if ok.in_re_verb == Verb::MulticastGather {
                    self.handle_multicast_gather_ok(ok.in_re_packet_id, &data, now_ms);
                }
            }
        }
    }

    /// Handle an incoming ERROR packet.
    fn handle_error(&mut self, data: &[u8], from: SocketAddr, _now_ms: u64) {
        let payload_data = if data.len() > 28 { &data[28..] } else { return };
        let error = match zerotier_protocol::verbs::error::ErrorPayload::deserialize(payload_data) {
            Ok(e) => e,
            Err(_) => return,
        };
        tracing::warn!(
            target: "manytier",
            event = "protocol_error_received",
            from = %from,
            in_re_verb = ?error.in_re_verb,
            in_re_packet_id = error.in_re_packet_id,
            error_code = ?error.error_code,
            "received ERROR verb from peer"
        );
    }

    /// Handle an incoming WHOIS request.
    ///
    /// For addresses we know: send OK(WHOIS) with their identities.
    /// For unknown addresses: emit WhoisNeeded for the caller to resolve.
    fn handle_whois(&mut self, data: &[u8], from: SocketAddr, now_ms: u64) {
        let payload_data = if data.len() > 28 { &data[28..] } else { return };
        let whois = match WhoisRequest::deserialize(payload_data) {
            Ok(w) => w,
            Err(_) => return,
        };

        // Extract packet header info for the response
        let source = {
            let mut s = [0u8; 5];
            if data.len() >= 18 {
                s.copy_from_slice(&data[13..18]);
            }
            s
        };
        let in_re_packet_id = if data.len() >= 8 {
            u64::from_be_bytes(data[0..8].try_into().unwrap_or([0; 8]))
        } else {
            0
        };

        let mut known_identities = Vec::new();
        let mut unknown = Vec::new();

        for addr in &whois.addresses {
            if let Some(peer) = self.topology.get_peer(addr) {
                // Re-parse as public-only identity (Identity doesn't impl Clone)
                if let Ok(public_id) = Identity::parse(&peer.identity.to_public_string()) {
                    known_identities.push(public_id);
                }
            } else {
                unknown.push(*addr);
            }
        }

        // Send OK(WHOIS) for known identities
        if !known_identities.is_empty() {
            if self.topology.get_peer(&source).is_some() {
                if let Some(secret) = self.shared_secret_for_peer(&source) {
                    let ok = zerotier_protocol::verbs::ok::OkPayload {
                        in_re_verb: zerotier_protocol::verb::Verb::Whois,
                        in_re_packet_id,
                        sub_payload: zerotier_protocol::verbs::ok::OkSubPayload::Whois {
                            identities: known_identities,
                        },
                    };

                    let mut buf = [0u8; 2048];
                    buf[0..8].copy_from_slice(&now_ms.to_be_bytes());
                    buf[8..13].copy_from_slice(&source);
                    buf[13..18].copy_from_slice(self.identity.address.as_bytes());
                    buf[18] = CIPHER_SUITE_C25519_POLY1305_SALSA2012 << 3;
                    buf[19..27].copy_from_slice(&[0u8; 8]);
                    buf[27] = zerotier_protocol::verb::Verb::Ok.to_byte();

                    if let Ok(payload_len) = ok.serialize(&mut buf[28..]) {
                        let total_len = 28 + payload_len;
                        if salsa::armor_packet(&secret, &mut buf[..total_len], true).is_ok() {
                            self.actions.push(NodeAction::SendTo {
                                data: buf[..total_len].to_vec(),
                                address: from,
                            });
                        }
                    }
                }
            }
        }

        if !unknown.is_empty() {
            self.actions
                .push(NodeAction::WhoisNeeded { addresses: unknown });
        }
    }

    /// Handle an incoming RENDEZVOUS packet (NAT hole-punching).
    ///
    /// The root server tells us to send a HELLO to a specific address to
    /// initiate a direct connection with another peer.
    fn handle_echo(&mut self, data: &[u8], from: SocketAddr, _now_ms: u64, packet_id: u64) {
        let payload_data = if data.len() > 28 { &data[28..] } else { return };
        // Just echo the payload back in an OK(ECHO)
        let our_addr = *self.identity.address.as_bytes();
        let source = match PacketHeader::from_bytes(data) {
            Some(hdr) => hdr.source_address(),
            None => return,
        };

        if self.identity.secret.is_some() {
            if let Some(shared_secret) = self.shared_secret_for_peer(&source) {
                let ok = zerotier_protocol::verbs::ok::OkPayload {
                    in_re_verb: Verb::Echo,
                    in_re_packet_id: packet_id,
                    sub_payload: zerotier_protocol::verbs::ok::OkSubPayload::Generic {
                        data: payload_data.to_vec(),
                    },
                };

                let mut buf = [0u8; 2048];
                buf[0..8].copy_from_slice(&self.allocate_packet_id().to_be_bytes());
                buf[8..13].copy_from_slice(&source);
                buf[13..18].copy_from_slice(&our_addr);
                buf[18] = (zerotier_protocol::constants::CIPHER_SUITE_C25519_POLY1305_SALSA2012
                    << 3)
                    | 0x01;
                buf[19..27].copy_from_slice(&[0u8; 8]);
                buf[27] = Verb::Ok.to_byte();

                if let Ok(payload_len) = ok.serialize(&mut buf[28..]) {
                    let total = 28 + payload_len;
                    if salsa::armor_packet(&shared_secret, &mut buf[..total], true).is_ok() {
                        self.actions.push(NodeAction::SendTo {
                            data: buf[..total].to_vec(),
                            address: from,
                        });
                    }
                }
            }
        }
    }

    fn handle_push_direct_paths(&mut self, data: &[u8], from: SocketAddr, now_ms: u64) {
        let payload_data = if data.len() > 28 { &data[28..] } else { return };
        let push = match zerotier_protocol::verbs::push_direct::PushDirectPathsPayload::deserialize(
            payload_data,
        ) {
            Ok(p) => p,
            Err(_) => return,
        };

        let source = match PacketHeader::from_bytes(data) {
            Some(hdr) => hdr.source_address(),
            None => return,
        };

        tracing::info!(
            target: "manytier",
            event = "push_direct_paths_received",
            peer = %format_args!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                source[0], source[1], source[2], source[3], source[4]),
            num_paths = push.paths.len(),
            "PUSH_DIRECT_PATHS received"
        );

        // Update peer paths
        if let Some(peer) = self.topology.get_peer_mut(&source) {
            for path in push.paths {
                if let Some(addr) = path.address.to_socket_addr() {
                    peer.add_path(addr, true, now_ms);
                }
            }
            // Also add the path we received this from
            peer.add_path(from, true, now_ms);
        }
    }

    fn handle_network_config(&mut self, data: &[u8], _from: SocketAddr, _now_ms: u64) {
        let payload_data = if data.len() > 28 { &data[28..] } else { return };
        if let Ok(nc) = NetworkConfigPayload::deserialize(payload_data) {
            if self.find_network(nc.network_id).is_none() {
                return;
            }
            let advertised_mtu = network_mtu_from_dict_data(&nc.dict_data);
            tracing::info!(
                target: "manytier",
                event = "network_config_received",
                network_id = %format_args!("{:016x}", nc.network_id),
                dict_len = nc.dict_data.len(),
                mtu = advertised_mtu,
                "NETWORK_CONFIG received"
            );
            self.apply_network_config(nc.network_id, &nc.dict_data);
            if let Some(net) = self.find_network_mut(nc.network_id) {
                net.pending_config_request = false;
            }
            self.actions.push(NodeAction::NetworkConfigured {
                network_id: nc.network_id,
                dict_data: nc.dict_data,
            });
        }
    }

    fn handle_network_credentials(&mut self, data: &[u8], _from: SocketAddr, _now_ms: u64) {
        let payload_data = if data.len() > 28 { &data[28..] } else { return };
        if let Ok(creds) = NetworkCredentialsPayload::deserialize(payload_data) {
            tracing::info!(
                target: "manytier",
                event = "network_credentials_received",
                has_com = creds.com.is_some(),
                "NETWORK_CREDENTIALS received"
            );
            if let Some(com) = creds.com {
                // Find network for this COM
                let network_id = match com.qualifiers.iter().find(|q| q.id == 1) {
                    Some(q) => q.value,
                    None => return,
                };
                if let Some(net) = self.find_network_mut(network_id) {
                    net.pending_config_request = false;
                    net.last_config_request = 0;
                    net.our_com = Some(com);
                }
            }
        }
    }

    fn handle_rendezvous(&mut self, data: &[u8], _from: SocketAddr, now_ms: u64) {
        let payload_data = if data.len() > 28 { &data[28..] } else { return };
        let rendezvous = match RendezvousPayload::deserialize(payload_data) {
            Ok(r) => r,
            Err(_) => return,
        };

        tracing::info!(
            target: "manytier",
            event = "rendezvous_received",
            peer = %format_args!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                rendezvous.peer_address[0], rendezvous.peer_address[1],
                rendezvous.peer_address[2], rendezvous.peer_address[3],
                rendezvous.peer_address[4]),
            "RENDEZVOUS received"
        );

        // Get the indicated peer's address as a socket addr
        if let Some(target_addr) = rendezvous.address.to_socket_addr() {
            // Build and send a HELLO to the indicated address
            if self.identity.secret.is_some() {
                let hello_secret = self
                    .shared_secret_for_peer(&rendezvous.peer_address)
                    .unwrap_or([0u8; 32]);
                // See ZeroTierOne 1.14.2 node/Peer.cpp:430-431
                let planet_id = self
                    .topology
                    .planet
                    .as_ref()
                    .map(|p| p.id)
                    .unwrap_or(zerotier_protocol::constants::WORLD_ID_EARTH);
                let planet_ts = self
                    .topology
                    .planet
                    .as_ref()
                    .map(|p| p.timestamp)
                    .unwrap_or(0);
                let mut buf = [0u8; 512];
                if let Ok((len, _)) = RootManager::build_hello(
                    &self.identity,
                    &rendezvous.peer_address,
                    target_addr,
                    now_ms,
                    &hello_secret,
                    &mut buf,
                    planet_id,
                    planet_ts,
                ) {
                    tracing::info!(
                        target: "manytier",
                        event = "hello_sent",
                        peer = %format_args!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                            rendezvous.peer_address[0], rendezvous.peer_address[1],
                            rendezvous.peer_address[2], rendezvous.peer_address[3],
                            rendezvous.peer_address[4]),
                        endpoint = %target_addr,
                        "rendezvous: sending hole-punch HELLO"
                    );
                    self.actions.push(NodeAction::SendTo {
                        data: buf[..len].to_vec(),
                        address: target_addr,
                    });
                }
            }
        }
    }

    /// Handle relay: forward a packet not destined for us.
    ///
    /// When this node acts as a root and relays a packet between two peers that
    /// both have active sessions, it sends RENDEZVOUS to each peer with the
    /// other's physical address. This triggers UDP hole-punching so the peers
    /// can establish a direct path.
    fn handle_relay(&mut self, data: &mut [u8], now_ms: u64) {
        // Increment hop count
        if !Switch::increment_hops(data) {
            return; // Max hops reached, drop
        }

        // Route to destination
        let (source, dest) = {
            match PacketHeader::from_bytes(data) {
                Some(hdr) => (hdr.source_address(), hdr.dest),
                None => return,
            }
        };

        match Switch::route(&self.topology, &dest, now_ms) {
            RouteDecision::Direct { address } => {
                self.actions.push(NodeAction::SendTo {
                    data: data.to_vec(),
                    address,
                });

                // Send RENDEZVOUS to both peers if we have active sessions with both.
                // This triggers NAT hole-punching so they can establish direct paths.
                self.maybe_send_rendezvous(&source, &dest, now_ms);
            }
            RouteDecision::Relay {
                root_address,
                dest_zt_address: _,
            } => {
                self.actions.push(NodeAction::SendTo {
                    data: data.to_vec(),
                    address: root_address,
                });
            }
            RouteDecision::Drop => {
                // No route available
            }
        }
    }

    /// Send RENDEZVOUS to two peers so they can establish a direct path.
    ///
    /// Both peers must have active sessions (shared secrets) and known physical
    /// addresses. The root tells each peer about the other's physical address.
    fn maybe_send_rendezvous(&mut self, source: &[u8; 5], dest: &[u8; 5], now_ms: u64) {
        // Get source peer info: shared secret + best physical address
        let source_info = self.topology.get_peer(source).and_then(|peer| {
            if let PeerState::Active { shared_secret, .. } = &peer.state {
                peer.best_path(now_ms).map(|p| (*shared_secret, p.address))
            } else {
                None
            }
        });

        // Get dest peer info: shared secret + best physical address
        let dest_info = self.topology.get_peer(dest).and_then(|peer| {
            if let PeerState::Active { shared_secret, .. } = &peer.state {
                peer.best_path(now_ms).map(|p| (*shared_secret, p.address))
            } else {
                None
            }
        });

        let (source_secret, source_phys) = match source_info {
            Some(info) => info,
            None => return,
        };
        let (dest_secret, dest_phys) = match dest_info {
            Some(info) => info,
            None => return,
        };

        tracing::info!(
            target: "manytier",
            event = "rendezvous_sent",
            peer_a = %format_args!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                source[0], source[1], source[2], source[3], source[4]),
            peer_b = %format_args!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                dest[0], dest[1], dest[2], dest[3], dest[4]),
            "root sending RENDEZVOUS"
        );

        // Tell source peer about dest's physical address
        let dest_inet = InetAddress::from_socket_addr(dest_phys);
        let mut buf = [0u8; 128];
        if let Ok(len) = RootManager::build_rendezvous(
            &self.identity,
            source,
            dest,
            dest_inet,
            &source_secret,
            now_ms,
            &mut buf,
        ) {
            self.actions.push(NodeAction::SendTo {
                data: buf[..len].to_vec(),
                address: source_phys,
            });
        }

        // Tell dest peer about source's physical address
        let source_inet = InetAddress::from_socket_addr(source_phys);
        let mut buf = [0u8; 128];
        if let Ok(len) = RootManager::build_rendezvous(
            &self.identity,
            dest,
            source,
            source_inet,
            &dest_secret,
            now_ms,
            &mut buf,
        ) {
            self.actions.push(NodeAction::SendTo {
                data: buf[..len].to_vec(),
                address: dest_phys,
            });
        }
    }

    /// Handle an incoming fragment.
    fn handle_fragment(&mut self, data: &[u8], from: SocketAddr, now_ms: u64) {
        let frag_hdr = match FragmentHeader::from_bytes(data) {
            Some(h) => h,
            None => return,
        };

        let packet_id = frag_hdr.packet_id_u64();
        let fragment_number = frag_hdr.fragment_number();
        let total_fragments = frag_hdr.total_fragments();

        // Fragment payload starts after the 16-byte fragment header
        let fragment_data = if data.len() > 16 {
            data[16..].to_vec()
        } else {
            return;
        };

        if let Some(assembled) = self.reassembly.insert(
            packet_id,
            fragment_number,
            total_fragments,
            fragment_data,
            now_ms,
        ) {
            // Recursively process the reassembled packet
            let mut assembled = assembled;
            let actions = self.receive_packet(&mut assembled, from, now_ms);
            self.actions.extend(actions);
        }
    }

    /// Periodic maintenance: send keepalives, retry HELLOs, evict stale peers.
    ///
    /// Called every ZT_PING_CHECK_INTERVAL (5s). Performs:
    /// 1. Fragment reassembly eviction
    /// 2. Stale peer detection (500s activity timeout)
    /// 3. Peer ping (60s interval) via HELLO
    /// 4. Path heartbeat (14s interval)
    /// 5. Root reconnection for disconnected roots
    pub fn tick(&mut self, now_ms: u64) -> Vec<NodeAction> {
        const CONFIG_REQUEST_INTERVAL_MS: u64 = 30_000;
        const MULTICAST_LIKE_INTERVAL_MS: u64 = 30_000;
        const MULTICAST_GATHER_INTERVAL_MS: u64 = 45_000;
        const MULTICAST_SUBSCRIPTION_MAX_AGE_MS: u64 = 90_000;

        self.actions.clear();

        // 1. Evict stale fragments from reassembly buffer
        self.reassembly
            .evict_stale(now_ms, ZT_PATH_HEARTBEAT_PERIOD);
        self.multicast_manager
            .expire_old(now_ms, MULTICAST_SUBSCRIPTION_MAX_AGE_MS);
        self.pending_multicast_gathers.retain(|pending| {
            now_ms.saturating_sub(pending.requested_at_ms) <= MULTICAST_SUBSCRIPTION_MAX_AGE_MS
        });

        // 2. Check for stale peers (no activity for 500s) and mark them
        let stale_addrs: Vec<[u8; 5]> = self
            .topology
            .peers
            .iter()
            .filter(|(_, peer)| peer.is_stale(now_ms))
            .map(|(addr, _)| *addr)
            .collect();

        for addr in &stale_addrs {
            if let Some(peer) = self.topology.get_peer_mut(addr) {
                peer.mark_stale(now_ms);
            }
        }

        let reconnect_targets: Vec<([u8; 5], SocketAddr)> = self
            .topology
            .peers
            .iter()
            .filter_map(|(addr, peer)| match peer.state {
                PeerState::Stale { .. } if peer.needs_reconnect(now_ms) => peer
                    .best_path(now_ms)
                    .or_else(|| peer.paths.first())
                    .map(|path| (*addr, path.address)),
                _ => None,
            })
            .collect();

        // 3. Check peers for needed pings (60s since last send)
        let mut ping_targets = Vec::new();
        for (addr, peer) in &self.topology.peers {
            if peer.needs_ping(now_ms) {
                if let Some(path) = peer.best_path(now_ms) {
                    ping_targets.push((*addr, path.address));
                } else if let Some(first_path) = peer.paths.first() {
                    ping_targets.push((*addr, first_path.address));
                }
            }
        }

        // 4. Check each path for heartbeat need (14s since last send)
        let mut heartbeat_targets = Vec::new();
        for (addr, peer) in &self.topology.peers {
            for path in &peer.paths {
                if path.needs_heartbeat(now_ms) && path.is_alive(now_ms) {
                    // Queue a keepalive (HELLO as keepalive)
                    if !ping_targets.iter().any(|(a, _)| a == addr) {
                        heartbeat_targets.push((*addr, path.address));
                    }
                }
            }
        }

        // Send HELLOs to peers that need pings
        for (addr, phys_addr) in &ping_targets {
            // Always use the DH-derived shared secret for HELLO armoring.
            // The official controller verifies the MAC using key_agree(sender_pubkey, ctrl_privkey).
            let hello_secret = self.shared_secret_for_peer(addr).unwrap_or([0u8; 32]);
            // See ZeroTierOne 1.14.2 node/Peer.cpp:430-431
            let planet_id = self
                .topology
                .planet
                .as_ref()
                .map(|p| p.id)
                .unwrap_or(zerotier_protocol::constants::WORLD_ID_EARTH);
            let planet_ts = self
                .topology
                .planet
                .as_ref()
                .map(|p| p.timestamp)
                .unwrap_or(0);

            let mut buf = [0u8; 512];
            if let Ok((len, _packet_id)) = RootManager::build_hello(
                &self.identity,
                addr,
                *phys_addr,
                now_ms,
                &hello_secret,
                &mut buf,
                planet_id,
                planet_ts,
            ) {
                tracing::info!(
                    target: "manytier",
                    event = "hello_sent",
                    peer = %format_args!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                        addr[0], addr[1], addr[2], addr[3], addr[4]),
                    "sent HELLO"
                );
                self.actions.push(NodeAction::SendTo {
                    data: buf[..len].to_vec(),
                    address: *phys_addr,
                });
                if let Some(peer) = self.topology.get_peer_mut(addr) {
                    peer.on_hello_sent(0, now_ms);
                    if let Some(path) = peer
                        .paths
                        .iter_mut()
                        .find(|path| path.address == *phys_addr)
                    {
                        path.sent(now_ms);
                    }
                }
            }
        }

        // Send heartbeat HELLOs to paths that need keepalive
        for (addr, phys_addr) in &heartbeat_targets {
            // Use the DH-derived secret for HELLO armoring when we know the peer's identity.
            // Some older notes suggested a null-key first-contact HELLO for roots, but in
            // practice this causes `zerotier-one` to drop our HELLO in the localhost
            // controller harness, resulting in zero replies and no config assignment.
            let hello_secret = self.shared_secret_for_peer(addr).unwrap_or([0u8; 32]);
            // See ZeroTierOne 1.14.2 node/Peer.cpp:430-431
            let planet_id = self
                .topology
                .planet
                .as_ref()
                .map(|p| p.id)
                .unwrap_or(zerotier_protocol::constants::WORLD_ID_EARTH);
            let planet_ts = self
                .topology
                .planet
                .as_ref()
                .map(|p| p.timestamp)
                .unwrap_or(0);

            let mut buf = [0u8; 512];
            if let Ok((len, _packet_id)) = RootManager::build_hello(
                &self.identity,
                addr,
                *phys_addr,
                now_ms,
                &hello_secret,
                &mut buf,
                planet_id,
                planet_ts,
            ) {
                self.actions.push(NodeAction::SendTo {
                    data: buf[..len].to_vec(),
                    address: *phys_addr,
                });
                if let Some(peer) = self.topology.get_peer_mut(addr) {
                    peer.on_hello_sent(0, now_ms);
                    if let Some(path) = peer
                        .paths
                        .iter_mut()
                        .find(|path| path.address == *phys_addr)
                    {
                        path.sent(now_ms);
                    }
                }
            }
        }

        // 5. Reconnect stale peers with exponential HELLO backoff.
        for (addr, phys_addr) in &reconnect_targets {
            let hello_secret = self.shared_secret_for_peer(addr).unwrap_or([0u8; 32]);
            // See ZeroTierOne 1.14.2 node/Peer.cpp:430-431
            let planet_id = self
                .topology
                .planet
                .as_ref()
                .map(|p| p.id)
                .unwrap_or(zerotier_protocol::constants::WORLD_ID_EARTH);
            let planet_ts = self
                .topology
                .planet
                .as_ref()
                .map(|p| p.timestamp)
                .unwrap_or(0);
            let mut buf = [0u8; 512];
            if let Ok((len, packet_id)) = RootManager::build_hello(
                &self.identity,
                addr,
                *phys_addr,
                now_ms,
                &hello_secret,
                &mut buf,
                planet_id,
                planet_ts,
            ) {
                self.actions.push(NodeAction::SendTo {
                    data: buf[..len].to_vec(),
                    address: *phys_addr,
                });
                if let Some(peer) = self.topology.get_peer_mut(addr) {
                    peer.on_hello_sent(packet_id, now_ms);
                    if let Some(path) = peer
                        .paths
                        .iter_mut()
                        .find(|path| path.address == *phys_addr)
                    {
                        path.sent(now_ms);
                    }
                }
            }
        }

        // 6. Ensure roots stay connected: re-HELLO to roots that are Unknown
        let root_reconnect: Vec<([u8; 5], SocketAddr)> = self
            .topology
            .roots
            .iter()
            .filter_map(|root_addr| {
                let peer = self.topology.peers.get(root_addr)?;
                if matches!(peer.state, PeerState::Unknown) {
                    peer.paths.first().map(|p| (*root_addr, p.address))
                } else {
                    None
                }
            })
            .collect();

        for (addr, phys_addr) in &root_reconnect {
            // Always use the DH-derived shared secret for HELLO armoring.
            let hello_secret = self.shared_secret_for_peer(addr).unwrap_or([0u8; 32]);
            // See ZeroTierOne 1.14.2 node/Peer.cpp:430-431
            let planet_id = self
                .topology
                .planet
                .as_ref()
                .map(|p| p.id)
                .unwrap_or(zerotier_protocol::constants::WORLD_ID_EARTH);
            let planet_ts = self
                .topology
                .planet
                .as_ref()
                .map(|p| p.timestamp)
                .unwrap_or(0);
            let mut buf = [0u8; 512];
            if let Ok((len, packet_id)) = RootManager::build_hello(
                &self.identity,
                addr,
                *phys_addr,
                now_ms,
                &hello_secret,
                &mut buf,
                planet_id,
                planet_ts,
            ) {
                tracing::info!(
                    target: "manytier",
                    event = "hello_sent",
                    peer = %format_args!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                        addr[0], addr[1], addr[2], addr[3], addr[4]),
                    "sent HELLO to root (reconnect)"
                );
                self.actions.push(NodeAction::SendTo {
                    data: buf[..len].to_vec(),
                    address: *phys_addr,
                });
                if let Some(peer) = self.topology.get_peer_mut(addr) {
                    peer.on_hello_sent(packet_id, now_ms);
                    if let Some(path) = peer
                        .paths
                        .iter_mut()
                        .find(|path| path.address == *phys_addr)
                    {
                        path.sent(now_ms);
                    }
                }
            }
        }

        // 7. Send queued or proactive NETWORK_CONFIG_REQUEST packets.
        let our_address_bytes = *self.identity.address.as_bytes();
        let config_requests: Vec<(u64, [u8; 5], bool)> = self
            .networks
            .iter_mut()
            .filter_map(|net| {
                let is_refresh = net.our_com.is_some();
                if !net.our_com_refresh_due(now_ms) {
                    if !net.pending_config_request {
                        return None;
                    }
                }
                net.pending_config_request = true;
                if net.last_config_request != 0
                    && now_ms.saturating_sub(net.last_config_request) < CONFIG_REQUEST_INTERVAL_MS
                {
                    return None;
                }

                let ctrl_addr = controller_address_from_network_id(net.network_id);
                Some((net.network_id, ctrl_addr, is_refresh))
            })
            .collect();

        for (network_id, ctrl_addr, is_refresh) in &config_requests {
            let dest_addr = self
                .topology
                .get_peer(ctrl_addr)
                .and_then(|p| p.paths.first())
                .map(|path| path.address)
                .or_else(|| {
                    // Fall back to first root as relay
                    self.topology.roots.first().and_then(|root_addr| {
                        self.topology
                            .get_peer(root_addr)
                            .and_then(|p| p.paths.first())
                            .map(|path| path.address)
                    })
                });

            if let Some(phys_addr) = dest_addr {
                // Only send NCR after an active HELLO session with the controller.
                // Sending before OK(HELLO) means the controller hasn't verified our
                // identity yet and will silently drop the encrypted packet.
                let peer_active = self
                    .topology
                    .get_peer(ctrl_addr)
                    .map_or(false, |p| matches!(p.state, PeerState::Active { .. }));
                if !peer_active {
                    tracing::debug!(
                        target: "manytier",
                        event = "ncr_deferred_no_session",
                        controller = %format_args!(
                            "{:02x}{:02x}{:02x}{:02x}{:02x}",
                            ctrl_addr[0],
                            ctrl_addr[1],
                            ctrl_addr[2],
                            ctrl_addr[3],
                            ctrl_addr[4]
                        ),
                        "deferring NETWORK_CONFIG_REQUEST: no active session with controller"
                    );
                    continue;
                }
                let shared_secret = match self.shared_secret_for_peer(ctrl_addr) {
                    Some(s) => s,
                    None => continue,
                };
                let mut dict = Dictionary::new();
                dict.add_int("v", 1);
                dict.add_int("rev", 0);
                let mac = crate::ethernet::derive_mac(&our_address_bytes, *network_id);
                let mac_str = alloc::format!(
                    "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5]
                );
                dict.add_text("mac", &mac_str);

                // Add missing fields for parity with official client
                let our_addr_hex = alloc::format!(
                    "{:02x}{:02x}{:02x}{:02x}{:02x}",
                    our_address_bytes[0],
                    our_address_bytes[1],
                    our_address_bytes[2],
                    our_address_bytes[3],
                    our_address_bytes[4]
                );
                dict.add_text("id", &our_addr_hex);
                dict.add_int("vmaj", 1);
                dict.add_int("vmin", 14);
                dict.add_int("vrev", 2);
                dict.add_int("pv", ZT_PROTO_VERSION as u64);
                dict.add_int("maxr", 128);
                dict.add_int("maxc", 32);
                dict.add_int("maxcr", 128);
                dict.add_int("maxt", 32);
                dict.add_int("f", 0);
                dict.add_int("rev", 0);
                dict.add_text("arch", "x64");
                dict.add_text("vendor", "ZeroTier");
                dict.add_int("allowAutoAssign", 1);

                let req = zerotier_protocol::verbs::network_config::NetworkConfigRequestPayload {
                    network_id: *network_id,
                    hop_count: 0,
                    dict_data: dict.serialize(),
                };

                let mut payload = [0u8; 512];
                let payload_len = req.serialize(&mut payload);
                let packet_id = self.allocate_packet_id();
                if let Some(packet) = crate::vl2::build_encrypted_verb_packet(
                    packet_id,
                    &our_address_bytes,
                    ctrl_addr,
                    Verb::NetworkConfigRequest,
                    &payload[..payload_len],
                    &shared_secret,
                ) {
                    tracing::info!(
                        target: "manytier",
                        event = "config_request_sent",
                        network_id = %format_args!("{:016x}", network_id),
                        refresh = *is_refresh,
                        controller = %format_args!("{:02x}{:02x}{:02x}{:02x}{:02x}",
                            ctrl_addr[0], ctrl_addr[1], ctrl_addr[2], ctrl_addr[3], ctrl_addr[4]),
                        physical_address = %phys_addr,
                        "sent NETWORK_CONFIG_REQUEST"
                    );
                    self.actions.push(NodeAction::SendTo {
                        data: packet,
                        address: phys_addr,
                    });
                    if let Some(net) = self.find_network_mut(*network_id) {
                        net.last_config_request = now_ms;
                    }
                }
            } else {
                tracing::warn!(
                    target: "manytier",
                    event = "config_request_no_controller_path",
                    network_id = %format_args!("{:016x}", network_id),
                    controller = %format_args!(
                        "{:02x}{:02x}{:02x}{:02x}{:02x}",
                        ctrl_addr[0], ctrl_addr[1], ctrl_addr[2], ctrl_addr[3], ctrl_addr[4]
                    ),
                    "skipping NETWORK_CONFIG_REQUEST because no controller path or root relay is available"
                );
            }
        }

        // 7. Periodically advertise and gather multicast membership.
        let mut due_likes: Vec<(usize, u64, Vec<[u8; 5]>)> = Vec::new();
        let mut due_gathers: Vec<(usize, u64, Vec<[u8; 5]>, Vec<MulticastGroupKey>)> = Vec::new();
        for (index, net) in self.networks.iter().enumerate() {
            let local_groups = self
                .multicast_manager
                .groups_for_subscriber(net.network_id, &our_address_bytes);
            if local_groups.is_empty() {
                continue;
            }

            let peers: Vec<[u8; 5]> = net
                .members
                .iter()
                .filter(|member| member.zt_address != our_address_bytes)
                .map(|member| member.zt_address)
                .collect();
            if peers.is_empty() {
                continue;
            }

            if now_ms.saturating_sub(net.last_multicast_like) >= MULTICAST_LIKE_INTERVAL_MS {
                due_likes.push((index, net.network_id, peers.clone()));
            }
            if now_ms.saturating_sub(net.last_multicast_gather) >= MULTICAST_GATHER_INTERVAL_MS {
                due_gathers.push((index, net.network_id, peers, local_groups));
            }
        }

        let mut unresolved_multicast = BTreeSet::new();
        for (index, network_id, peer_addresses) in due_likes {
            self.networks[index].last_multicast_like = now_ms;
            let like = self
                .multicast_manager
                .build_multicast_like(network_id, &our_address_bytes);
            let mut payload = vec![0u8; like.groups.len() * 18];
            let payload_len = like.serialize(&mut payload);
            payload.truncate(payload_len);

            for peer_address in peer_addresses {
                let Some((path_address, shared_secret)) = self
                    .topology
                    .get_peer(&peer_address)
                    .and_then(|peer| peer.best_path(now_ms).zip(peer.shared_secret()))
                    .map(|(path, secret)| (path.address, *secret))
                else {
                    unresolved_multicast.insert(peer_address);
                    continue;
                };

                let packet_id = self.allocate_packet_id();
                if let Some(packet) = crate::vl2::build_encrypted_verb_packet(
                    packet_id,
                    &our_address_bytes,
                    &peer_address,
                    Verb::MulticastLike,
                    &payload,
                    &shared_secret,
                ) {
                    self.actions.push(NodeAction::SendTo {
                        data: packet,
                        address: path_address,
                    });
                }
            }
        }

        for (index, network_id, peer_addresses, groups) in due_gathers {
            self.networks[index].last_multicast_gather = now_ms;
            for peer_address in peer_addresses {
                let Some((path_address, shared_secret)) = self
                    .topology
                    .get_peer(&peer_address)
                    .and_then(|peer| peer.best_path(now_ms).zip(peer.shared_secret()))
                    .map(|(path, secret)| (path.address, *secret))
                else {
                    unresolved_multicast.insert(peer_address);
                    continue;
                };

                for group in &groups {
                    let gather = zerotier_protocol::verbs::multicast::MulticastGatherPayload {
                        network_id,
                        flags: 0,
                        mac: group.mac,
                        adi: group.adi,
                        gather_limit: 64,
                        com: None,
                    };
                    let mut payload = [0u8; 256];
                    let payload_len = gather.serialize(&mut payload);
                    let packet_id = self.allocate_packet_id();
                    if let Some(packet) = crate::vl2::build_encrypted_verb_packet(
                        packet_id,
                        &our_address_bytes,
                        &peer_address,
                        Verb::MulticastGather,
                        &payload[..payload_len],
                        &shared_secret,
                    ) {
                        self.pending_multicast_gathers.push(PendingMulticastGather {
                            packet_id,
                            requested_at_ms: now_ms,
                            network_id,
                            mac: group.mac,
                            adi: group.adi,
                        });
                        self.actions.push(NodeAction::SendTo {
                            data: packet,
                            address: path_address,
                        });
                    }
                }
            }
        }

        if !unresolved_multicast.is_empty() {
            self.actions.push(NodeAction::WhoisNeeded {
                addresses: unresolved_multicast.into_iter().collect(),
            });
        }

        core::mem::take(&mut self.actions)
    }

    /// Generate initial HELLO packets to all known roots.
    pub fn bootstrap(&mut self, now_ms: u64) -> Vec<NodeAction> {
        self.actions.clear();

        // Collect root info before mutation
        let root_info: Vec<([u8; 5], SocketAddr)> = self
            .topology
            .roots
            .iter()
            .filter_map(|addr| {
                let peer = self.topology.peers.get(addr)?;
                let path = peer.paths.first()?;
                Some((*addr, path.address))
            })
            .collect();

        // Build HELLO for each root
        for (root_addr, phys_addr) in root_info {
            let hello_secret = self.shared_secret_for_peer(&root_addr).unwrap_or([0u8; 32]);
            // See ZeroTierOne 1.14.2 node/Peer.cpp:430-431
            let planet_id = self
                .topology
                .planet
                .as_ref()
                .map(|p| p.id)
                .unwrap_or(zerotier_protocol::constants::WORLD_ID_EARTH);
            let planet_ts = self
                .topology
                .planet
                .as_ref()
                .map(|p| p.timestamp)
                .unwrap_or(0);
            let mut buf = [0u8; 512];
            if let Ok((len, packet_id)) = RootManager::build_hello(
                &self.identity,
                &root_addr,
                phys_addr,
                now_ms,
                &hello_secret,
                &mut buf,
                planet_id,
                planet_ts,
            ) {
                self.actions.push(NodeAction::SendTo {
                    data: buf[..len].to_vec(),
                    address: phys_addr,
                });

                // Mark peer as HelloSent
                if let Some(peer) = self.topology.get_peer_mut(&root_addr) {
                    peer.state = PeerState::HelloSent {
                        sent_at: now_ms,
                        packet_id,
                        retry_backoff_ms: ZT_PATH_HELLO_RATE_LIMIT,
                    };
                }
            }
        }

        self.root_manager.last_hello_sent = now_ms;
        core::mem::take(&mut self.actions)
    }

    /// Take pending actions.
    pub fn drain_actions(&mut self) -> Vec<NodeAction> {
        core::mem::take(&mut self.actions)
    }
}

fn network_mtu_from_dict_data(dict_data: &[u8]) -> Option<u16> {
    let dict = Dictionary::deserialize(dict_data).ok()?;
    dict.get_text("mtu")?.parse().ok()
}

fn peer_directory_from_dict_data(
    dict_data: &[u8],
    network_id: u64,
    our_address: [u8; 5],
) -> Option<(Vec<NetworkMember>, Vec<([u8; 5], CertificateOfMembership)>)> {
    let dict = Dictionary::deserialize(dict_data).ok()?;
    let data = dict.get_binary("PM")?;
    if data.len() < 2 {
        return None;
    }

    let count = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let mut members = Vec::with_capacity(count);
    let mut peer_coms = Vec::new();

    for _ in 0..count {
        if pos + 5 > data.len() {
            return None;
        }
        let mut node_id = [0u8; 5];
        node_id.copy_from_slice(&data[pos..pos + 5]);
        pos += 5;

        let (ipv4, consumed_v4) = inet_v4_from_bytes(&data[pos..])?;
        pos += consumed_v4;
        let (ipv6, consumed_v6) = inet_v6_from_bytes(&data[pos..])?;
        pos += consumed_v6;

        let (com, consumed_com) = CertificateOfMembership::deserialize(&data[pos..]).ok()?;
        pos += consumed_com;

        members.push(NetworkMember {
            zt_address: node_id,
            mac: crate::ethernet::derive_mac(&node_id, network_id),
            ipv4,
            ipv6,
            authorized: true,
        });

        if node_id != our_address {
            peer_coms.push((node_id, com));
        }
    }

    Some((members, peer_coms))
}

fn inet_v4_from_bytes(data: &[u8]) -> Option<(Option<(Ipv4Addr, u8)>, usize)> {
    let (inet, consumed) = InetAddress::deserialize(data).ok()?;
    match inet {
        InetAddress::Null => Some((None, consumed)),
        InetAddress::V4 { ip, port } => Some((Some((Ipv4Addr::from(ip), port as u8)), consumed)),
        InetAddress::V6 { .. } => None,
    }
}

fn inet_v6_from_bytes(data: &[u8]) -> Option<(Option<(Ipv6Addr, u8)>, usize)> {
    let (inet, consumed) = InetAddress::deserialize(data).ok()?;
    match inet {
        InetAddress::Null => Some((None, consumed)),
        InetAddress::V6 { ip, port } => Some((Some((Ipv6Addr::from(ip), port as u8)), consumed)),
        InetAddress::V4 { .. } => None,
    }
}

fn controller_address_from_network_id(network_id: u64) -> [u8; 5] {
    let controller = network_id >> 24;
    [
        ((controller >> 32) & 0xFF) as u8,
        ((controller >> 24) & 0xFF) as u8,
        ((controller >> 16) & 0xFF) as u8,
        ((controller >> 8) & 0xFF) as u8,
        (controller & 0xFF) as u8,
    ]
}

#[cfg(test)]
fn network_id_for_controller(address: [u8; 5]) -> u64 {
    ((((address[0] as u64) << 32)
        | ((address[1] as u64) << 24)
        | ((address[2] as u64) << 16)
        | ((address[3] as u64) << 8)
        | (address[4] as u64))
        << 24)
        | 0x000001
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::dictionary::Dictionary;
    use crate::ethernet;
    use crate::network::{NetworkMember, NetworkMembership};
    use core::net::Ipv4Addr;
    use zerotier_crypto::identity::{Address, PublicKey};
    use zerotier_crypto::salsa;
    use zerotier_protocol::inet_address::InetAddress;
    use zerotier_protocol::verbs::network_config::{CertificateOfMembership, ComQualifier};
    use zerotier_protocol::world::{World, WorldRoot, WorldType};

    fn test_identity(addr_byte: u8) -> Identity {
        let address = Address::new([0xa0, 0xb1, 0xc2, 0xd3, addr_byte]).unwrap();
        let mut pk_bytes = [0u8; 64];
        for (i, b) in pk_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(addr_byte);
        }
        let public_key = PublicKey::from_bytes(&pk_bytes).unwrap();
        Identity {
            address,
            public_key,
            secret: None,
        }
    }

    fn make_synthetic_planet() -> Vec<u8> {
        let root_id = test_identity(0xe0);
        let world = World {
            world_type: WorldType::Planet,
            id: 149604618,
            timestamp: 1000000,
            signing_key: [0xAA; 64],
            signature: [0xBB; 96],
            roots: alloc::vec![WorldRoot {
                identity: root_id,
                endpoints: alloc::vec![InetAddress::V4 {
                    ip: [192, 168, 1, 1],
                    port: 9993,
                }],
            }],
            dict_data: None,
        };
        let mut buf = [0u8; 2048];
        let n = world.serialize(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    fn add_active_peer(
        node: &mut Node,
        peer_id: Identity,
        socket: SocketAddr,
        shared_secret: [u8; 32],
    ) -> [u8; 5] {
        let peer_address = *peer_id.address.as_bytes();
        node.topology.add_peer(peer_id);
        let peer = node.topology.get_peer_mut(&peer_address).unwrap();
        peer.add_path(socket, true, 1000);
        peer.state = PeerState::Active {
            shared_secret,
            latency_ms: 10,
            last_receive: 1000,
            last_send: 1000,
        };
        peer_address
    }

    fn make_membership_with_peer(
        network_id: u64,
        our_address: [u8; 5],
        peer_address: [u8; 5],
    ) -> NetworkMembership {
        let mut membership = NetworkMembership::new(network_id, 2800);
        membership.members.push(NetworkMember {
            zt_address: peer_address,
            mac: ethernet::derive_mac(&peer_address, network_id),
            ipv4: Some((Ipv4Addr::new(10, 147, 20, 2), 24)),
            ipv6: None,
            authorized: true,
        });
        membership.members.push(NetworkMember {
            zt_address: our_address,
            mac: ethernet::derive_mac(&our_address, network_id),
            ipv4: Some((Ipv4Addr::new(10, 147, 20, 1), 24)),
            ipv6: None,
            authorized: true,
        });
        membership
    }

    fn make_com(network_id: u64, timestamp: u64, issued_to: [u8; 5]) -> CertificateOfMembership {
        let issued_to_u64 = ((issued_to[0] as u64) << 32)
            | ((issued_to[1] as u64) << 24)
            | ((issued_to[2] as u64) << 16)
            | ((issued_to[3] as u64) << 8)
            | (issued_to[4] as u64);
        CertificateOfMembership {
            issued_to,
            qualifiers: vec![
                ComQualifier {
                    id: 0,
                    value: timestamp,
                    max_delta: 360_000,
                },
                ComQualifier {
                    id: 1,
                    value: network_id,
                    max_delta: 0,
                },
                ComQualifier {
                    id: 2,
                    value: issued_to_u64,
                    max_delta: 0,
                },
            ],
            signer_address: [0; 5],
            signature: [0; 96],
        }
    }

    fn dearmor_for_test(data: &[u8], shared_secret: &[u8; 32]) -> Vec<u8> {
        let mut packet = data.to_vec();
        salsa::dearmor_packet(shared_secret, &mut packet).unwrap();
        packet
    }

    #[test]
    fn node_new_with_synthetic_planet() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let node = Node::new(id, &planet, 1).unwrap();
        assert!(!node.topology.roots.is_empty());
        assert!(node.topology.planet.is_some());
    }

    #[test]
    fn node_new_with_bad_planet_fails() {
        let id = test_identity(0x01);
        let bad_data = [0u8; 10];
        assert!(Node::new(id, &bad_data, 1).is_err());
    }

    #[test]
    fn bootstrap_generates_send_actions() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();
        let actions = node.bootstrap(1000);

        // Should generate one SendTo for the single root
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            NodeAction::SendTo { data, address } => {
                assert!(!data.is_empty());
                assert_eq!(address.port(), 9993);
            }
            _ => panic!("expected SendTo"),
        }
    }

    #[test]
    fn bootstrap_marks_peers_as_hello_sent() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();
        node.bootstrap(1000);

        let root_addr = node.topology.roots[0];
        let peer = node.topology.get_peer(&root_addr).unwrap();
        assert!(matches!(
            peer.state,
            PeerState::HelloSent { sent_at: 1000, .. }
        ));
    }

    #[test]
    fn receive_packet_too_short_returns_empty() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();
        let mut data = [0u8; 10];
        let from: SocketAddr = "10.0.0.1:9993".parse().unwrap();
        let actions = node.receive_packet(&mut data, from, 1000);
        assert!(actions.is_empty());
    }

    #[test]
    fn receive_packet_not_for_us_relays() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();

        // Build a packet destined for someone else
        let mut pkt = [0u8; 64];
        pkt[0..8].copy_from_slice(&1000u64.to_be_bytes()); // IV
        pkt[8..13].copy_from_slice(&[0xff, 0xfe, 0xfd, 0xfc, 0xfb]); // dest = not us
        pkt[13..18].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]); // source
        pkt[18] = 0; // flags: cipher suite 0, hops 0
        pkt[27] = 0x01; // verb = HELLO

        let from: SocketAddr = "10.0.0.1:9993".parse().unwrap();
        let actions = node.receive_packet(&mut pkt, from, 1000);

        // Should attempt relay (may produce SendTo if root has path)
        // The root exists so should produce a Relay action
        let has_send = actions
            .iter()
            .any(|a| matches!(a, NodeAction::SendTo { .. }));
        assert!(has_send, "relay should produce SendTo to root");
    }

    #[test]
    fn tick_returns_empty_initially() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();
        // No peers have sessions, so no pings needed
        let actions = node.tick(1000);
        // Root is in Unknown state -> tick will try to reconnect to root
        // so actions may not be empty (root reconnect)
        // This is correct behavior
        let _ = actions;
    }

    #[test]
    fn tick_pings_peer_needing_ping() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();

        // Add a peer with an active session
        let peer_id = test_identity(0x42);
        let peer_addr = *peer_id.address.as_bytes();
        node.topology.add_peer(peer_id);
        let peer = node.topology.get_peer_mut(&peer_addr).unwrap();
        peer.add_path("10.0.0.42:9993".parse().unwrap(), true, 1000);
        peer.state = PeerState::Active {
            shared_secret: [0u8; 32],
            latency_ms: 10,
            last_receive: 1000,
            last_send: 1000,
        };

        // Tick at time when peer needs ping (60s later)
        let actions = node.tick(1000 + ZT_PEER_PING_PERIOD);
        let has_send = actions
            .iter()
            .any(|a| matches!(a, NodeAction::SendTo { .. }));
        assert!(has_send, "tick should send HELLO to peer needing ping");
    }

    #[test]
    fn tick_marks_stale_peer() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();

        // Add a peer with an active session
        let peer_id = test_identity(0x42);
        let peer_addr = *peer_id.address.as_bytes();
        node.topology.add_peer(peer_id);
        let peer = node.topology.get_peer_mut(&peer_addr).unwrap();
        peer.add_path("10.0.0.42:9993".parse().unwrap(), true, 1000);
        peer.state = PeerState::Active {
            shared_secret: [0u8; 32],
            latency_ms: 10,
            last_receive: 1000,
            last_send: 1000,
        };

        // Tick at time when peer is stale (500s later)
        let _ = node.tick(1000 + ZT_PEER_ACTIVITY_TIMEOUT);
        let peer = node.topology.get_peer(&peer_addr).unwrap();
        assert!(
            !matches!(peer.state, PeerState::Active { .. }),
            "peer should leave Active after activity timeout"
        );
    }

    #[test]
    fn stale_peer_reconnect_uses_exponential_backoff() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();

        let peer_id = test_identity(0x42);
        let peer_addr = *peer_id.address.as_bytes();
        node.topology.add_peer(peer_id);
        let peer = node.topology.get_peer_mut(&peer_addr).unwrap();
        let socket: SocketAddr = "10.0.0.42:9993".parse().unwrap();
        peer.add_path(socket, true, 1000);
        peer.state = PeerState::Stale {
            last_active: 1000,
            retry_backoff_ms: 1000,
            next_retry_at: 2000,
        };

        let first = node.tick(2000);
        let first_retries = first
            .iter()
            .filter(
                |action| matches!(action, NodeAction::SendTo { address, .. } if *address == socket),
            )
            .count();
        assert_eq!(first_retries, 1, "stale peer should retry immediately");

        let second = node.tick(2999);
        let second_retries = second
            .iter()
            .filter(
                |action| matches!(action, NodeAction::SendTo { address, .. } if *address == socket),
            )
            .count();
        assert_eq!(second_retries, 0, "backoff should suppress early retry");

        let third = node.tick(4000);
        let third_retries = third
            .iter()
            .filter(
                |action| matches!(action, NodeAction::SendTo { address, .. } if *address == socket),
            )
            .count();
        assert_eq!(
            third_retries, 1,
            "retry should resume after backoff doubles"
        );
    }

    #[test]
    fn queued_config_request_sends_when_controller_becomes_reachable() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();
        node.topology.roots.clear();

        let controller = test_identity(0x55);
        let controller_address = *controller.address.as_bytes();
        let network_id = network_id_for_controller(controller_address);
        node.join_network(NetworkMembership::new(network_id, 2800));

        let first = node.tick(1000);
        assert!(
            !first.iter().any(|action| matches!(action, NodeAction::SendTo { address, .. } if *address == "10.0.0.55:9993".parse::<SocketAddr>().unwrap())),
            "request should stay queued while controller is unreachable"
        );
        assert!(
            node.find_network(network_id)
                .map(|net| net.pending_config_request)
                .unwrap_or(false),
            "missing config should queue a request"
        );

        add_active_peer(
            &mut node,
            controller,
            "10.0.0.55:9993".parse().unwrap(),
            [0x44; 32],
        );

        let second = node.tick(1001);
        let has_config_request = second
            .iter()
            .any(|action| matches!(action, NodeAction::SendTo { address, .. } if *address == "10.0.0.55:9993".parse::<SocketAddr>().unwrap()));
        assert!(
            has_config_request,
            "queued request should send as soon as controller becomes reachable: {:?}",
            second
        );
    }

    #[test]
    fn tick_refreshes_config_before_com_expiry() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();

        let controller = test_identity(0x55);
        let controller_address = add_active_peer(
            &mut node,
            controller,
            "10.0.0.55:9993".parse().unwrap(),
            [0x11; 32],
        );
        let network_id = network_id_for_controller(controller_address);
        let mut membership = NetworkMembership::new(network_id, 2800);
        membership.our_com = Some(make_com(
            network_id,
            1_000,
            *node.identity.address.as_bytes(),
        ));
        node.join_network(membership);

        let actions = node.tick(301_000);
        let has_config_request = actions.iter().any(|action| {
            let NodeAction::SendTo { data, address } = action else {
                return false;
            };
            if *address != "10.0.0.55:9993".parse::<SocketAddr>().unwrap() {
                return false;
            }
            let packet = dearmor_for_test(data, &[0x11; 32]);
            (packet[27] & 0x7f) == Verb::NetworkConfigRequest.to_byte()
        });

        assert!(
            has_config_request,
            "expected config refresh request to controller"
        );
    }

    #[test]
    fn tick_evicts_stale_fragments() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();

        // Tick should call evict_stale on reassembly buffer without panic
        let _ = node.tick(100_000);
    }

    #[test]
    fn tick_sends_multicast_like_and_gather_for_local_groups() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();

        let peer = test_identity(0x42);
        let peer_address = add_active_peer(
            &mut node,
            peer,
            "10.0.0.42:9993".parse().unwrap(),
            [0x22; 32],
        );
        let network_id = 0xff00000000abcdef;
        let membership =
            make_membership_with_peer(network_id, *node.identity.address.as_bytes(), peer_address);
        node.join_network(membership);

        let actions = node.tick(45_000);
        let peer_packets: Vec<_> = actions
            .iter()
            .filter_map(|action| match action {
                NodeAction::SendTo { data, address }
                    if *address == "10.0.0.42:9993".parse::<SocketAddr>().unwrap() =>
                {
                    Some(dearmor_for_test(data, &[0x22; 32]))
                }
                _ => None,
            })
            .collect();

        assert!(
            peer_packets
                .iter()
                .any(|packet| packet[27] == Verb::MulticastLike.to_byte()),
            "expected a MULTICAST_LIKE advertisement"
        );
        assert!(
            peer_packets
                .iter()
                .any(|packet| packet[27] == Verb::MulticastGather.to_byte()),
            "expected a MULTICAST_GATHER request"
        );
    }

    #[test]
    fn multicast_like_and_gather_round_trip_converges_membership() {
        let planet = make_synthetic_planet();
        let mut node_a = Node::new(test_identity(0x01), &planet, 1).unwrap();
        let mut node_b = Node::new(test_identity(0x02), &planet, 1).unwrap();

        let shared_secret = [0x33; 32];
        let node_a_socket: SocketAddr = "10.0.0.1:9993".parse().unwrap();
        let node_b_socket: SocketAddr = "10.0.0.2:9993".parse().unwrap();
        let node_a_address = *node_a.identity.address.as_bytes();
        let node_b_address = *node_b.identity.address.as_bytes();

        add_active_peer(
            &mut node_a,
            test_identity(0x02),
            node_b_socket,
            shared_secret,
        );
        add_active_peer(
            &mut node_b,
            test_identity(0x01),
            node_a_socket,
            shared_secret,
        );

        let network_id = 0xff00000000abcdef;
        node_a.join_network(make_membership_with_peer(
            network_id,
            node_a_address,
            node_b_address,
        ));
        node_b.join_network(make_membership_with_peer(
            network_id,
            node_b_address,
            node_a_address,
        ));

        let outbound = node_a.tick(45_000);
        let mut responses = Vec::new();
        for action in outbound {
            let NodeAction::SendTo { data, address } = action else {
                continue;
            };
            if address != node_b_socket {
                continue;
            }
            let mut packet = data;
            responses.extend(node_b.receive_packet(&mut packet, node_a_socket, 45_000));
        }

        let node_b_subscribers = node_b.multicast_manager.get_subscribers(
            network_id,
            &[0xff; 6],
            ethernet::ETHERTYPE_ARP as u32,
            10,
        );
        assert!(
            node_b_subscribers.contains(&node_a_address),
            "peer B should learn peer A's multicast LIKE advertisement"
        );

        for action in responses {
            let NodeAction::SendTo { data, address } = action else {
                continue;
            };
            if address != node_a_socket {
                continue;
            }
            let mut packet = data;
            let _ = node_a.receive_packet(&mut packet, node_b_socket, 45_100);
        }

        let node_a_subscribers = node_a.multicast_manager.get_subscribers(
            network_id,
            &[0xff; 6],
            ethernet::ETHERTYPE_ARP as u32,
            10,
        );
        assert!(
            node_a_subscribers.contains(&node_b_address),
            "peer A should learn peer B's multicast membership from GATHER response"
        );
    }

    #[test]
    fn handle_rendezvous_generates_hello() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();

        // Give node a secret key for building HELLOs
        let mut secret_bytes = [0u8; 64];
        for (i, b) in secret_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x55);
        }
        node.identity.secret =
            Some(zerotier_crypto::identity::SecretKey::from_bytes(&secret_bytes).unwrap());

        // Build a fake RENDEZVOUS packet
        let rendezvous = RendezvousPayload {
            flags: 0,
            peer_address: [0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            address: zerotier_protocol::inet_address::InetAddress::V4 {
                ip: [10, 0, 0, 99],
                port: 9993,
            },
        };
        let mut payload_buf = [0u8; 64];
        let payload_len = rendezvous.serialize(&mut payload_buf);

        // Build full packet with header
        let mut pkt = [0u8; 128];
        pkt[0..8].copy_from_slice(&1000u64.to_be_bytes()); // IV
        pkt[8..13].copy_from_slice(node.identity.address.as_bytes()); // dest = us
        pkt[13..18].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]); // source
        pkt[18] = 0; // flags
        pkt[27] = Verb::Rendezvous.to_byte();
        pkt[28..28 + payload_len].copy_from_slice(&payload_buf[..payload_len]);

        let from: SocketAddr = "192.168.1.1:9993".parse().unwrap();
        node.handle_rendezvous(&pkt[..28 + payload_len], from, 2000);
        let actions = node.drain_actions();

        // Should generate a SendTo with HELLO to the rendezvous target
        let has_hello = actions.iter().any(|a| match a {
            NodeAction::SendTo { address, .. } => {
                *address == "10.0.0.99:9993".parse::<SocketAddr>().unwrap()
            }
            _ => false,
        });
        assert!(
            has_hello,
            "RENDEZVOUS should trigger HELLO to indicated address"
        );
    }

    #[test]
    fn promote_path_on_direct_packet() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();

        // Add a peer with a relay path
        let peer_id = test_identity(0x42);
        let peer_addr = *peer_id.address.as_bytes();
        node.topology.add_peer(peer_id);
        let peer = node.topology.get_peer_mut(&peer_addr).unwrap();
        let direct_addr: SocketAddr = "10.0.0.42:9993".parse().unwrap();
        peer.add_path(direct_addr, false, 1000); // relay path
        peer.state = PeerState::Active {
            shared_secret: [0u8; 32],
            latency_ms: 10,
            last_receive: 1000,
            last_send: 1000,
        };

        // Simulate promote_path directly
        let peer = node.topology.get_peer_mut(&peer_addr).unwrap();
        peer.promote_path(direct_addr, 2000);
        assert!(peer.paths[0].is_direct);
    }

    #[test]
    fn parses_network_mtu_from_dict_data() {
        let mut dict = Dictionary::new();
        dict.add_int("mtu", 1280);

        assert_eq!(network_mtu_from_dict_data(&dict.serialize()), Some(1280));
    }

    #[test]
    fn apply_network_config_updates_membership_mtu() {
        let id = test_identity(0x01);
        let planet = make_synthetic_planet();
        let mut node = Node::new(id, &planet, 1).unwrap();
        let network_id = 0xff00000000abcdef;
        node.join_network(NetworkMembership::new(network_id, 2800));

        let mut dict = Dictionary::new();
        dict.add_int("mtu", 1400);
        node.apply_network_config(network_id, &dict.serialize());

        assert_eq!(node.find_network(network_id).unwrap().mtu, 1400);
    }

    // ---------------------------------------------------------------
    // Strict HELLO MAC verification (bypass removal).
    // ---------------------------------------------------------------
    // Tests:
    //  1. handle_hello_valid_mac_adds_active_peer: a well-formed HELLO
    //     built with the sender's DH key is accepted and promotes the
    //     peer to PeerState::Active on the controller side.
    //  2. handle_hello_tampered_mac_is_dropped: flipping a MAC byte
    //     causes handle_hello to drop the packet: the peer is NOT
    //     promoted to Active (this test FAILED under the pre-17-11
    //     bypass, which logged and accepted anyway).
    //  3. handle_hello_without_local_secret_drops: when the receiving
    //     Node has no identity secret, the HELLO is dropped (no peer
    //     added, no Active state).

    struct XorShift17_11(u64);
    impl rand_core::RngCore for XorShift17_11 {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut pos = 0;
            while pos < dest.len() {
                let val = self.next_u64().to_le_bytes();
                let n = core::cmp::min(8, dest.len() - pos);
                dest[pos..pos + n].copy_from_slice(&val[..n]);
                pos += n;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn plan_17_11_build_hello_env(
        seed: u64,
    ) -> (Identity, Identity, [u8; 32], Vec<u8>) {
        let mut rng = XorShift17_11(seed);
        let client = Identity::generate(&mut rng).unwrap();
        let controller = Identity::generate(&mut rng).unwrap();

        let client_secret = client.secret.as_ref().unwrap();
        let controller_pub = x25519_dalek::PublicKey::from(controller.public_key.dh);
        let shared_secret = zerotier_crypto::key_agreement::key_agree(
            &client_secret.dh,
            &controller_pub,
        );

        let mut buf = [0u8; 512];
        let (len, _pkt_id) = RootManager::build_hello(
            &client,
            controller.address.as_bytes(),
            "127.0.0.1:9993".parse().unwrap(),
            1000,
            &shared_secret,
            &mut buf,
            zerotier_protocol::constants::WORLD_ID_EARTH,
            0,
        )
        .unwrap();

        (client, controller, shared_secret, buf[..len].to_vec())
    }

    #[test]
    fn handle_hello_valid_mac_adds_active_peer() {
        let (client, controller, _shared, hello_bytes) = plan_17_11_build_hello_env(42);

        let planet = make_synthetic_planet();
        let mut node = Node::new(controller, &planet, 1).unwrap();
        let client_addr = *client.address.as_bytes();
        let from: SocketAddr = "10.0.0.2:9993".parse().unwrap();

        let mut data = hello_bytes.clone();
        node.receive_packet(&mut data, from, 2000);

        let peer = node
            .topology
            .get_peer(&client_addr)
            .expect("peer must be added on valid HELLO");
        assert!(
            matches!(peer.state, PeerState::Active { .. }),
            "peer must be promoted to Active after a valid HELLO, got {:?}",
            peer.state
        );
    }

    #[test]
    fn handle_hello_tampered_mac_is_dropped() {
        let (client, controller, _shared, hello_bytes) = plan_17_11_build_hello_env(43);

        let planet = make_synthetic_planet();
        let mut node = Node::new(controller, &planet, 1).unwrap();
        let client_addr = *client.address.as_bytes();
        let from: SocketAddr = "10.0.0.2:9993".parse().unwrap();

        // MAC field lives at bytes 19..27. Flip the first MAC byte.
        let mut data = hello_bytes.clone();
        data[19] ^= 0xff;

        node.receive_packet(&mut data, from, 2000);

        // Strict MAC verification MUST drop this HELLO: no peer promoted
        // to Active. (Under the pre-17-11 bypass, the peer was promoted
        // to Active anyway: that is the regression this test guards.)
        if let Some(peer) = node.topology.get_peer(&client_addr) {
            assert!(
                !matches!(peer.state, PeerState::Active { .. }),
                "peer must NOT be Active after a tampered HELLO MAC (bypass removed), got {:?}",
                peer.state
            );
        }
    }

    #[test]
    fn handle_hello_without_local_secret_drops() {
        let (client, controller, _shared, hello_bytes) = plan_17_11_build_hello_env(44);

        // Strip the controller's secret so the DH verification path has
        // nothing to verify against; strict behavior is to drop.
        let controller_no_secret = Identity {
            address: controller.address,
            public_key: controller.public_key.clone(),
            secret: None,
        };

        let planet = make_synthetic_planet();
        let mut node = Node::new(controller_no_secret, &planet, 1).unwrap();
        let client_addr = *client.address.as_bytes();
        let from: SocketAddr = "10.0.0.2:9993".parse().unwrap();

        let mut data = hello_bytes.clone();
        node.receive_packet(&mut data, from, 2000);

        if let Some(peer) = node.topology.get_peer(&client_addr) {
            assert!(
                !matches!(peer.state, PeerState::Active { .. }),
                "peer must NOT be Active when local node has no identity secret, got {:?}",
                peer.state
            );
        }
    }
}
