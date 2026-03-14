//! Service daemon main loop: integrates Node + Controller + API server.
//!
//! This is the main entry point for `manytier service`. It starts the Node
//! engine, optionally a controller, and the REST API server.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;

use zerotier_crypto::identity::Identity;
use zerotier_node::controller::dictionary::Dictionary;
use zerotier_node::node::{Node, NodeAction};
use zerotier_node::traits::{Clock, CryptoProvider, Storage, Transport, TunDevice};
use zerotier_protocol::constants::ZT_PING_CHECK_INTERVAL;
use zerotier_protocol::header::PacketHeader;
use zerotier_protocol::inet_address::InetAddress;
use zerotier_protocol::verb::Verb;
use zerotier_protocol::verbs::network_config::NetworkConfigPayload;
use zerotier_protocol::verbs::ok::{OkPayload, OkSubPayload};
use zerotier_protocol::world::DEFAULT_PLANET;

/// Write a single UDP datagram to `dump_dir` iff it is a HELLO verb, using the
/// shared `{dir}-hello-*.bin` filename scheme. This helper is shared between
/// the rx path (`dir = "rx"`, peer is the remote source address) and the tx
/// path (`dir = "tx"`, peer is the remote destination address).
///
/// Gated by `MANYTIER_DUMP_UDP=1`: the caller passes `Some(dump_dir)` only
/// when the env var is set, so this is zero-cost in normal runs.
fn dump_hello_if_match(
    dump_dir: &Path,
    direction: &str,
    header: &PacketHeader,
    peer: &std::net::SocketAddr,
    now_ms: u64,
    bytes: &[u8],
) {
    if header.verb_id() != Verb::Hello.to_byte() {
        return;
    }
    let src = header.source_address();
    let dst = header.dest_address();
    let peer_label = if direction == "rx" { "from" } else { "to" };
    let filename = format!(
        "{}-hello-{}-{}-{}-{}-src-{:02x}{:02x}{:02x}{:02x}{:02x}-dst-{:02x}{:02x}{:02x}{:02x}{:02x}-pid-{}.bin",
        direction,
        now_ms,
        peer_label,
        peer.ip(),
        peer.port(),
        src[0], src[1], src[2], src[3], src[4],
        dst[0], dst[1], dst[2], dst[3], dst[4],
        header.packet_id()
    );
    let _ = std::fs::write(dump_dir.join(filename), bytes);
}

use crate::api;
use crate::platform::clock::NativeClock;
use crate::platform::crypto::NativeCryptoProvider;
use crate::platform::storage::NativeStorage;
use crate::platform::transport::NativeTransport;
use crate::platform::tun::NativeTun;
use crate::storage::SqliteStorage;

/// Configuration for the service daemon.
pub struct ServiceConfig {
    pub identity_path: String,
    /// Data directory for planet, authtoken, controller DB, etc.
    pub data_dir: String,
    pub api_port: u16,
    pub udp_port: u16,
    pub controller_mode: bool,
}

/// Run the ManyTier service daemon.
///
/// This starts the Node engine, UDP transport, and optionally the controller.
/// The REST API server runs on api_port (default 9993) on localhost.
pub async fn run_service(config: ServiceConfig) -> anyhow::Result<()> {
    let clock = NativeClock::new();
    let crypto = NativeCryptoProvider;
    let data_storage = NativeStorage::new(&config.data_dir)?;
    let udp_dump_enabled = std::env::var("MANYTIER_DUMP_UDP")
        .ok()
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false);
    let udp_dump_dir = if udp_dump_enabled {
        let dir = PathBuf::from(&config.data_dir).join("udp-dumps");
        std::fs::create_dir_all(&dir).ok();
        Some(dir)
    } else {
        None
    };
    let (identity_root, identity_key) = storage_scope_and_key(&config.identity_path)?;
    let identity_storage = NativeStorage::new(&identity_root)?;

    // 1. Load or generate identity
    let identity = load_or_generate_identity(&identity_storage, &crypto, &identity_key).await?;
    let addr = identity.address.as_bytes();
    let local_zt_address = *addr;
    tracing::info!(
        address = %format!("{:02x}{:02x}{:02x}{:02x}{:02x}", addr[0], addr[1], addr[2], addr[3], addr[4]),
        "starting ManyTier service"
    );

    // 2. Load planet file
    let planet_data = load_planet(&data_storage).await?;

    // 3. Create Node (identity is moved into node)
    let initial_packet_id = clock.now_wall_ms() & 0x0000_FFFF_FFFF_FFFF;
    let node = Node::new(identity, &planet_data, initial_packet_id)
        .map_err(|e| anyhow::anyhow!("failed to create node: {e}"))?;
    let node = Arc::new(Mutex::new(node));

    // 4. Generate or load authtoken.secret
    let auth_token = load_or_generate_auth_token(&data_storage, "authtoken.secret").await?;

    // 5. Optionally create Controller
    let controller = if config.controller_mode {
        let db_path = format!("{}/controller.db", config.data_dir);
        let storage = SqliteStorage::new(&db_path)?;
        // Use the SAME identity as the node for the controller
        let node_guard = node.lock().await;
        let identity_for_ctrl = node_guard.identity.clone();
        drop(node_guard);

        let secret = identity_for_ctrl
            .secret
            .clone()
            .expect("controller needs secret identity");
        Some(Arc::new(Mutex::new(
            zerotier_node::controller::engine::Controller::new(
                *identity_for_ctrl.address.as_bytes(),
                secret.signing.clone(),
                storage,
            ),
        )))
    } else {
        None
    };

    // 6. Bind UDP transport
    let bind_addr: std::net::SocketAddr = format!("0.0.0.0:{}", config.udp_port).parse()?;
    let transport = NativeTransport::bind(bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind UDP on port {}: {}", config.udp_port, e))?;
    tracing::info!(udp_bind = %bind_addr, "UDP transport bound");

    // 7. Start API server in background task
    let state = Arc::new(api::AppState {
        node: node.clone(),
        auth_token,
        controller: controller.clone(),
    });
    let router = api::build_router(state);
    let api_bind_addr = format!("127.0.0.1:{}", config.api_port);
    let listener = tokio::net::TcpListener::bind(&api_bind_addr).await?;
    tracing::info!(api_port = config.api_port, "API server starting");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            tracing::error!(error = %e, "API server error");
        }
    });

    // 8. Bootstrap: send initial HELLO to roots
    {
        let mut n = node.lock().await;
        let now = clock.now_wall_ms();
        let actions = n.bootstrap(now);
        let whois_actions = drain_whois_actions(&mut n, &actions, now);
        drop(n);
        execute_actions(&transport, &actions, udp_dump_dir.as_deref(), now).await;
        execute_actions(&transport, &whois_actions, udp_dump_dir.as_deref(), now).await;
    }

    // 9. Main event loop
    let mut buf = [0u8; 4096];
    let mut tick_interval =
        tokio::time::interval(std::time::Duration::from_millis(ZT_PING_CHECK_INTERVAL));
    // TUN devices per network, created lazily on NetworkConfigured.
    // Arc-wrapped so read tasks can share the device with the main loop.
    let mut tun_devices: HashMap<u64, Arc<NativeTun>> = HashMap::new();

    // Channel for TUN reads: avoids borrow checker issues with select!
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<(u64, Vec<u8>)>(64);

    // Graceful shutdown signal
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            // UDP packet received
            result = transport.recv_from(&mut buf) => {
                match result {
                    Ok((n, from)) => {
                        let now = clock.now_wall_ms();
                        tracing::info!(event = "udp_raw_received", from = %from, len = n, "UDP packet received");
                        if let Some(header) = PacketHeader::from_bytes(&buf[..n]) {
                            let source = header.source_address();
                            let dest = header.dest_address();
                            tracing::info!(
                                event = "udp_packet_received",
                                from = %from,
                                packet_id = header.packet_id(),
                                source = %format_args!(
                                    "{:02x}{:02x}{:02x}{:02x}{:02x}",
                                    source[0], source[1], source[2], source[3], source[4]
                                ),
                                dest = %format_args!(
                                    "{:02x}{:02x}{:02x}{:02x}{:02x}",
                                    dest[0], dest[1], dest[2], dest[3], dest[4]
                                ),
                                cipher_suite = header.cipher_suite(),
                                verb_id = header.verb_id(),
                                verb = ?Verb::from_byte(header.verb_id()),
                                len = n,
                                "UDP packet received"
                            );

                            // Opt-in raw HELLO packet dump, used to debug official interop.
                            // We keep this very narrow to avoid ballooning artifacts in normal runs.
                            if let Some(ref dump_dir) = udp_dump_dir {
                                dump_hello_if_match(dump_dir, "rx", header, &from, now, &buf[..n]);
                            }
                        } else {
                            tracing::info!(
                                event = "udp_raw_packet_received",
                                from = %from,
                                len = n,
                                "raw UDP packet received (not a valid ZT header)"
                            );
                        }
                        let mut node_guard = node.lock().await;
                        let actions = node_guard.receive_packet(&mut buf[..n], from, now);

                        // Handle controller actions inline
                        if let Some(ref ctrl) = controller {
                            handle_controller_actions(&actions, ctrl, &mut node_guard, now).await;
                        }

                        // Drain any actions queued by controller handling
                        let pending = node_guard.drain_actions();
                        let whois_actions = drain_whois_actions_from_sets(
                            &mut node_guard,
                            [&actions, &pending],
                            now,
                        );
                        drop(node_guard);

                        execute_actions(&transport, &actions, udp_dump_dir.as_deref(), now).await;
                        execute_actions(&transport, &pending, udp_dump_dir.as_deref(), now).await;
                        execute_actions(&transport, &whois_actions, udp_dump_dir.as_deref(), now)
                            .await;
                        handle_tun_actions(&actions, &mut tun_devices, &tun_tx, local_zt_address)
                            .await;
                        handle_tun_actions(&pending, &mut tun_devices, &tun_tx, local_zt_address)
                            .await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "UDP recv error");
                    }
                }
            }

            // Tick timer
            _ = tick_interval.tick() => {
                let now = clock.now_wall_ms();
                let mut node_guard = node.lock().await;
                let actions = node_guard.tick(now);
                let whois_actions = drain_whois_actions(&mut node_guard, &actions, now);
                drop(node_guard);
                execute_actions(&transport, &actions, udp_dump_dir.as_deref(), now).await;
                execute_actions(&transport, &whois_actions, udp_dump_dir.as_deref(), now).await;
                handle_tun_actions(&actions, &mut tun_devices, &tun_tx, local_zt_address).await;
            }

            // TUN device read (outbound VL2 traffic)
            Some((network_id, frame)) = tun_rx.recv() => {
                if frame.is_empty() {
                    continue;
                }
                // Detect ethertype from IP version nibble
                let ethertype = match frame[0] >> 4 {
                    4 => 0x0800u16,  // IPv4
                    6 => 0x86DDu16,  // IPv6
                    _ => continue,    // Unknown, skip
                };
                tracing::info!(
                    network_id = %format!("{network_id:016x}"),
                    ethertype = %format!("0x{ethertype:04x}"),
                    payload_len = frame.len(),
                    event = "tun_packet_read",
                    "read outbound packet from TUN"
                );
                let mut node_guard = node.lock().await;
                let our_addr = *node_guard.identity.address.as_bytes();
                let now = clock.now_wall_ms();
                let actions = zerotier_node::vl2::process_outbound_frame(
                    &mut node_guard, network_id, ethertype, &frame, &our_addr, now,
                );
                let whois_actions = drain_whois_actions(&mut node_guard, &actions, now);
                drop(node_guard);
                let send_count = actions
                    .iter()
                    .filter(|action| matches!(action, NodeAction::SendTo { .. }))
                    .count();
                let local_reply_count = actions
                    .iter()
                    .filter(|action| matches!(action, NodeAction::LocalReply { .. }))
                    .count();
                let frame_received_count = actions
                    .iter()
                    .filter(|action| matches!(action, NodeAction::FrameReceived { .. }))
                    .count();
                tracing::info!(
                    network_id = %format!("{network_id:016x}"),
                    payload_len = frame.len(),
                    send_count,
                    whois_count = whois_actions.len(),
                    local_reply_count,
                    frame_received_count,
                    event = "tun_packet_actions",
                    "processed outbound TUN packet into VL2 actions"
                );
                execute_actions(&transport, &actions, udp_dump_dir.as_deref(), now).await;
                execute_actions(&transport, &whois_actions, udp_dump_dir.as_deref(), now).await;
            }

            // Graceful shutdown
            _ = &mut shutdown => {
                tracing::info!("shutting down");
                break;
            }
        }
    }

    Ok(())
}

fn storage_scope_and_key(path: &str) -> anyhow::Result<(PathBuf, String)> {
    let path = Path::new(path);
    let key = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid storage path: {path:?}"))?;
    let root = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    Ok((root, key.to_string()))
}

fn public_identity_key(identity_key: &str) -> String {
    identity_key
        .strip_suffix(".secret")
        .map(|stem| format!("{stem}.public"))
        .unwrap_or_else(|| format!("{identity_key}.public"))
}

/// Execute SendTo actions via the transport.
///
/// If `udp_dump_dir` is `Some`, outgoing HELLO datagrams are additionally
/// dumped as `tx-hello-*.bin` under that directory (symmetric to the rx
/// dumper). This is gated by the caller on `MANYTIER_DUMP_UDP=1` and is a
/// no-op when `None`.
async fn execute_actions(
    transport: &NativeTransport,
    actions: &[NodeAction],
    udp_dump_dir: Option<&Path>,
    now_ms: u64,
) {
    for action in actions {
        if let NodeAction::SendTo { data, address } = action {
            if let Some(header) = PacketHeader::from_bytes(data) {
                let source = header.source_address();
                let dest = header.dest_address();
                tracing::info!(
                    event = "udp_packet_sent",
                    to = %address,
                    packet_id = header.packet_id(),
                    source = %format_args!(
                        "{:02x}{:02x}{:02x}{:02x}{:02x}",
                        source[0], source[1], source[2], source[3], source[4]
                    ),
                    dest = %format_args!(
                        "{:02x}{:02x}{:02x}{:02x}{:02x}",
                        dest[0], dest[1], dest[2], dest[3], dest[4]
                    ),
                    cipher_suite = header.cipher_suite(),
                    verb_id = header.verb_id(),
                    verb = ?Verb::from_byte(header.verb_id()),
                    len = data.len(),
                    "UDP packet sent"
                );

                // Opt-in tx HELLO dump, mirrors the rx dump under
                // `MANYTIER_DUMP_UDP=1`.
                if let Some(dump_dir) = udp_dump_dir {
                    dump_hello_if_match(dump_dir, "tx", header, address, now_ms, data);
                }
            } else {
                tracing::info!(
                    event = "udp_raw_packet_sent",
                    to = %address,
                    len = data.len(),
                    "raw UDP packet sent (not a valid ZT header)"
                );
            }
            if let Err(e) = transport.send_to(data, *address).await {
                tracing::warn!(error = %e, "failed to send UDP packet");
            }
        }
    }
}

fn drain_whois_actions(
    node: &mut zerotier_node::node::Node,
    actions: &[NodeAction],
    now_ms: u64,
) -> Vec<NodeAction> {
    drain_whois_actions_from_sets(node, [actions], now_ms)
}

fn drain_whois_actions_from_sets<const N: usize>(
    node: &mut zerotier_node::node::Node,
    action_sets: [&[NodeAction]; N],
    now_ms: u64,
) -> Vec<NodeAction> {
    let mut targets = BTreeSet::new();
    for actions in action_sets {
        for action in actions {
            if let NodeAction::WhoisNeeded { addresses } = action {
                targets.extend(addresses.iter().copied());
            }
        }
    }

    if targets.is_empty() {
        Vec::new()
    } else {
        let addresses: Vec<_> = targets.into_iter().collect();
        node.send_whois(&addresses, now_ms)
    }
}

const NETWORK_CONFIG_CHUNK_BYTES: usize = 1024;

fn build_encrypted_verb_packet(
    packet_id: u64,
    source_address: &[u8; 5],
    dest_address: &[u8; 5],
    verb: Verb,
    payload: &[u8],
    shared_secret: &[u8; 48],
    compress: bool,
) -> Option<Vec<u8>> {
    use zerotier_protocol::constants::{
        CIPHER_SUITE_C25519_POLY1305_SALSA2012, VERB_FLAG_COMPRESSED, ZT_PACKET_IDX_PAYLOAD,
    };

    let payload = if compress {
        lz4_flex::block::compress(payload)
    } else {
        payload.to_vec()
    };

    let mut packet = vec![0u8; ZT_PACKET_IDX_PAYLOAD + payload.len()];
    packet[0..8].copy_from_slice(&packet_id.to_be_bytes());
    packet[8..13].copy_from_slice(dest_address);
    packet[13..18].copy_from_slice(source_address);
    packet[18] = CIPHER_SUITE_C25519_POLY1305_SALSA2012 << 3;
    packet[19..27].copy_from_slice(&[0u8; 8]);
    packet[27] = verb.to_byte() | if compress { VERB_FLAG_COMPRESSED } else { 0 };
    packet[ZT_PACKET_IDX_PAYLOAD..].copy_from_slice(&payload);

    zerotier_crypto::salsa::armor_packet(shared_secret, &mut packet, true).ok()?;
    Some(packet)
}

fn build_network_config_response_packets(
    node: &mut Node,
    requester_address: &[u8; 5],
    request_packet_id: u64,
    network_id: u64,
    dict_data: &[u8],
    shared_secret: &[u8; 48],
) -> Option<Vec<Vec<u8>>> {
    let our_address = *node.identity.address.as_bytes();
    let total_length = u32::try_from(dict_data.len()).ok()?;
    let config_update_id = node.allocate_packet_id();
    let mut packets = Vec::new();

    for (chunk_index, chunk) in dict_data.chunks(NETWORK_CONFIG_CHUNK_BYTES).enumerate() {
        let chunk_offset = u32::try_from(chunk_index * NETWORK_CONFIG_CHUNK_BYTES).ok()?;
        let mut signed_data = Vec::with_capacity(10 + chunk.len() + 17);
        signed_data.extend_from_slice(&network_id.to_be_bytes());
        signed_data.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        signed_data.extend_from_slice(chunk);
        signed_data.push(0);
        signed_data.extend_from_slice(&config_update_id.to_be_bytes());
        signed_data.extend_from_slice(&total_length.to_be_bytes());
        signed_data.extend_from_slice(&chunk_offset.to_be_bytes());
        let mut config = NetworkConfigPayload {
            network_id,
            dict_data: chunk.to_vec(),
            flags: Some(0),
            config_update_id: Some(config_update_id),
            total_length: Some(total_length),
            chunk_index: Some(chunk_offset),
            signature_type: None,
            signature: None,
        };

        let signature = {
            let identity_secret = node.identity.secret.as_ref()?;
            zerotier_crypto::signing::sign(&identity_secret.signing, &signed_data).to_vec()
        };
        config.signature_type = Some(1);
        config.signature = Some(signature);

        let mut config_buf = vec![0u8; signed_data.len() + 99];
        let config_len = config.serialize(&mut config_buf);
        config_buf.truncate(config_len);

        let ok = OkPayload {
            in_re_verb: Verb::NetworkConfigRequest,
            in_re_packet_id: request_packet_id,
            sub_payload: OkSubPayload::Generic { data: config_buf },
        };
        let mut ok_buf = vec![0u8; 9 + config_len];
        let ok_len = ok.serialize(&mut ok_buf).ok()?;
        ok_buf.truncate(ok_len);

        let packet = build_encrypted_verb_packet(
            node.allocate_packet_id(),
            &our_address,
            requester_address,
            Verb::Ok,
            &ok_buf,
            shared_secret,
            true,
        )?;
        packets.push(packet);
    }

    Some(packets)
}

/// Handle controller-related actions (NetworkConfigRequested).
/// Follows shadow-node pattern: inline in main loop, build response packets.
async fn handle_controller_actions(
    actions: &[NodeAction],
    controller: &Arc<Mutex<zerotier_node::controller::engine::Controller<SqliteStorage>>>,
    node: &mut zerotier_node::node::Node,
    now_ms: u64,
) {
    for action in actions {
        if let NodeAction::NetworkConfigRequested {
            requester_address,
            network_id,
            from,
            packet_id,
            ..
        } = action
        {
            let shared_secret_ready = node.shared_secret_for_peer(requester_address).is_some();
            tracing::info!(
                event = "controller_network_config_request_received",
                requester = %format_args!(
                    "{:02x}{:02x}{:02x}{:02x}{:02x}",
                    requester_address[0],
                    requester_address[1],
                    requester_address[2],
                    requester_address[3],
                    requester_address[4]
                ),
                network_id = %format_args!("{:016x}", network_id),
                from = %from,
                shared_secret_ready,
                "controller handling NETWORK_CONFIG_REQUEST"
            );
            let ctrl = controller.lock().await;
            let response = ctrl
                .handle_config_request(*network_id, requester_address, now_ms)
                .await;
            drop(ctrl);

            let response = match response {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "controller error");
                    continue;
                }
            };

            // Record the issued COM in the node's own membership state so it can verify
            // incoming data-plane frames from this peer.
            if let Some(ref com) = response.credentials.com {
                if let Some(net) = node.find_network_mut(*network_id) {
                    net.peer_coms.retain(|(addr, _)| addr != requester_address);
                    net.peer_coms.push((*requester_address, com.clone()));
                    tracing::debug!(
                        target: "manytier",
                        event = "controller_recorded_peer_com",
                        peer = %format_args!(
                            "{:02x}{:02x}{:02x}{:02x}{:02x}",
                            requester_address[0], requester_address[1], requester_address[2], requester_address[3], requester_address[4]
                        ),
                        "recorded issued COM in node membership state"
                    );
                }
            }

            let Some(shared_secret) = node.shared_secret_for_peer(requester_address) else {
                tracing::warn!(
                    event = "controller_network_config_missing_shared_secret",
                    requester = %format_args!(
                        "{:02x}{:02x}{:02x}{:02x}{:02x}",
                        requester_address[0],
                        requester_address[1],
                        requester_address[2],
                        requester_address[3],
                        requester_address[4]
                    ),
                    "controller had no shared secret for NETWORK_CONFIG_REQUEST sender"
                );
                continue;
            };

            tracing::info!(
                event = "controller_network_config_response_ready",
                requester = %format_args!(
                    "{:02x}{:02x}{:02x}{:02x}{:02x}",
                    requester_address[0],
                    requester_address[1],
                    requester_address[2],
                    requester_address[3],
                    requester_address[4]
                ),
                network_id = %format_args!("{:016x}", network_id),
                dict_len = response.config.dict_data.len(),
                credentials_has_com = response.credentials.com.is_some(),
                "controller built NETWORK_CONFIG response"
            );

            let config_packets = match build_network_config_response_packets(
                node,
                requester_address,
                *packet_id,
                *network_id,
                &response.config.dict_data,
                &shared_secret,
            ) {
                Some(packets) if !packets.is_empty() => packets,
                _ => {
                    tracing::error!(
                        event = "controller_config_build_failed",
                        network_id = %format_args!("{:016x}", network_id),
                        "failed to build NETWORK_CONFIG response packets"
                    );
                    continue;
                }
            };

            for packet in config_packets {
                node.push_action(NodeAction::SendTo {
                    data: packet,
                    address: *from,
                });
            }
            tracing::info!(
                target: "manytier",
                event = "controller_config_sent",
                response_verb = "ok(network_config_request)",
                "sent NETWORK_CONFIG response"
            );

            let our_addr = *node.identity.address.as_bytes();
            let mut creds_payload = vec![0u8; 512];
            let creds_len = response.credentials.serialize(&mut creds_payload);
            creds_payload.truncate(creds_len);
            if let Some(packet) = build_encrypted_verb_packet(
                node.allocate_packet_id(),
                &our_addr,
                requester_address,
                Verb::NetworkCredentials,
                &creds_payload,
                &shared_secret,
                false,
            ) {
                node.push_action(NodeAction::SendTo {
                    data: packet,
                    address: *from,
                });
                tracing::info!(
                    target: "manytier",
                    event = "network_credentials_sent",
                    "sent NETWORK_CREDENTIALS"
                );
            } else {
                tracing::error!(
                    event = "network_credentials_build_failed",
                    network_id = %format_args!("{:016x}", network_id),
                    "failed to build NETWORK_CREDENTIALS response packet"
                );
            }
        }
    }
}

/// Handle TUN-related actions: write frames, create devices on config.
///
/// When a new TUN device is created, spawns a read task that sends frames
/// over the provided channel for the main loop to process.
async fn handle_tun_actions(
    actions: &[NodeAction],
    tun_devices: &mut HashMap<u64, Arc<NativeTun>>,
    tun_tx: &tokio::sync::mpsc::Sender<(u64, Vec<u8>)>,
    local_zt_address: [u8; 5],
) {
    for action in actions {
        match action {
            NodeAction::FrameReceived {
                network_id,
                ethertype,
                payload,
                ..
            } => {
                if let Some(tun) = tun_devices.get(network_id) {
                    tracing::info!(
                        network_id = %format!("{network_id:016x}"),
                        ethertype = %format!("0x{ethertype:04x}"),
                        payload_len = payload.len(),
                        event = "tun_packet_inject",
                        "injecting received VL2 payload into TUN"
                    );
                    if let Err(e) = tun.write(payload).await {
                        tracing::warn!(error = %e, "TUN write failed");
                    }
                }
            }
            NodeAction::LocalReply {
                network_id,
                ethertype,
                payload,
                ..
            } => {
                if let Some(tun) = tun_devices.get(network_id) {
                    tracing::info!(
                        network_id = %format!("{network_id:016x}"),
                        ethertype = %format!("0x{ethertype:04x}"),
                        payload_len = payload.len(),
                        event = "tun_local_reply_inject",
                        "injecting local reply into TUN"
                    );
                    if let Err(e) = tun.write(payload).await {
                        tracing::warn!(error = %e, "TUN write (local reply) failed");
                    }
                }
            }
            NodeAction::NetworkConfigured {
                network_id,
                dict_data,
            } => {
                // Create TUN device if not already exists for this network
                if !tun_devices.contains_key(network_id) {
                    let tun_name = tun_name_for_network(*network_id, local_zt_address);
                    let mtu = network_mtu_from_dict_data(dict_data).unwrap_or(2800);
                    match NativeTun::create(&tun_name, mtu).await {
                        Ok(tun) => {
                            tracing::info!(
                                network_id = %format!("{:016x}", network_id),
                                tun_name = %tun.name(),
                                mtu = mtu,
                                "TUN device created"
                            );
                            configure_tun_from_dict_data(&tun, *network_id, dict_data).await;
                            let tun = Arc::new(tun);
                            tun_devices.insert(*network_id, Arc::clone(&tun));

                            // Spawn a read task for this TUN device
                            let nwid = *network_id;
                            let tx = tun_tx.clone();
                            tokio::spawn(async move {
                                let mut buf = [0u8; 4096];
                                loop {
                                    match tun.read(&mut buf).await {
                                        Ok(n) if n > 0 => {
                                            if tx.send((nwid, buf[..n].to_vec())).await.is_err() {
                                                // Main loop dropped: exit
                                                break;
                                            }
                                        }
                                        Ok(_) => {} // empty read, continue
                                        Err(e) => {
                                            tracing::warn!(error = %e, "TUN read error");
                                            break;
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                network_id = %format!("{:016x}", network_id),
                                "failed to create TUN device (may need root/CAP_NET_ADMIN)"
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn network_mtu_from_dict_data(dict_data: &[u8]) -> Option<usize> {
    let dict = Dictionary::deserialize(dict_data).ok()?;
    dict.get_hex_u64("mtu")?.try_into().ok()
}

async fn configure_tun_from_dict_data(tun: &NativeTun, network_id: u64, dict_data: &[u8]) {
    for (addr, prefix) in managed_ips_from_dict_data(dict_data) {
        if let Err(error) = tun.set_ip(addr, prefix).await {
            tracing::warn!(
                error = %error,
                network_id = %format!("{network_id:016x}"),
                address = %format!("{addr}/{prefix}"),
                "failed to configure managed address on TUN device"
            );
        } else {
            tracing::info!(
                network_id = %format!("{network_id:016x}"),
                address = %format!("{addr}/{prefix}"),
                "configured managed address on TUN device"
            );
        }
    }

    for (target, gateway) in managed_routes_from_dict_data(dict_data) {
        if let Err(error) = tun.add_route(&target, gateway).await {
            tracing::warn!(
                error = %error,
                network_id = %format!("{network_id:016x}"),
                target = %target,
                gateway = gateway.map(|ip| ip.to_string()).unwrap_or_else(|| "direct".to_string()),
                "failed to configure managed route on TUN device"
            );
        } else {
            tracing::info!(
                network_id = %format!("{network_id:016x}"),
                target = %target,
                gateway = gateway.map(|ip| ip.to_string()).unwrap_or_else(|| "direct".to_string()),
                "configured managed route on TUN device"
            );
        }
    }
}

fn managed_ips_from_dict_data(dict_data: &[u8]) -> Vec<(std::net::IpAddr, u8)> {
    let Some(data) = Dictionary::deserialize(dict_data)
        .ok()
        .and_then(|dict| dict.get_binary("I").map(|data| data.to_vec()))
    else {
        return Vec::new();
    };

    let mut ips = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let Ok((address, consumed)) = InetAddress::deserialize(&data[pos..]) else {
            break;
        };
        pos += consumed;
        match address {
            InetAddress::Null => {}
            InetAddress::V4 { ip, port } => ips.push((std::net::IpAddr::V4(ip.into()), port as u8)),
            InetAddress::V6 { ip, port } => ips.push((std::net::IpAddr::V6(ip.into()), port as u8)),
        }
    }

    ips
}

fn managed_routes_from_dict_data(dict_data: &[u8]) -> Vec<(String, Option<std::net::IpAddr>)> {
    let Some(data) = Dictionary::deserialize(dict_data)
        .ok()
        .and_then(|dict| dict.get_binary("RT").map(|data| data.to_vec()))
    else {
        return Vec::new();
    };

    let mut routes = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let Ok((target, target_consumed)) = InetAddress::deserialize(&data[pos..]) else {
            break;
        };
        pos += target_consumed;

        let Ok((via, via_consumed)) = InetAddress::deserialize(&data[pos..]) else {
            break;
        };
        pos += via_consumed;

        if pos + 2 > data.len() {
            break;
        }
        pos += 2;

        let Some(target_cidr) = inet_address_to_cidr(&target) else {
            continue;
        };
        let gateway = inet_address_to_ip(&via);
        routes.push((target_cidr, gateway));
    }

    routes
}

fn inet_address_to_cidr(address: &InetAddress) -> Option<String> {
    match address {
        InetAddress::Null => None,
        InetAddress::V4 { ip, port } => Some(format!("{}/{}", std::net::Ipv4Addr::from(*ip), port)),
        InetAddress::V6 { ip, port } => Some(format!("{}/{}", std::net::Ipv6Addr::from(*ip), port)),
    }
}

fn inet_address_to_ip(address: &InetAddress) -> Option<std::net::IpAddr> {
    match address {
        InetAddress::Null => None,
        InetAddress::V4 { ip, .. } => Some(std::net::IpAddr::V4((*ip).into())),
        InetAddress::V6 { ip, .. } => Some(std::net::IpAddr::V6((*ip).into())),
    }
}

fn tun_name_for_network(network_id: u64, local_zt_address: [u8; 5]) -> String {
    let network_suffix = network_id & 0x00FF_FFFF;
    let node_suffix = u32::from_be_bytes([
        0,
        local_zt_address[2],
        local_zt_address[3],
        local_zt_address[4],
    ]);
    format!("zt{network_suffix:06x}{node_suffix:06x}")
}

/// Load an identity from native storage, or generate a new one and save it.
async fn load_or_generate_identity(
    storage: &NativeStorage,
    crypto: &NativeCryptoProvider,
    key: &str,
) -> anyhow::Result<Identity> {
    if let Some(secret_bytes) = storage.load(key).await? {
        let secret_str = String::from_utf8(secret_bytes)
            .map_err(|_| anyhow::anyhow!("stored identity is not valid UTF-8"))?;
        let identity = Identity::parse(secret_str.trim())
            .map_err(|e| anyhow::anyhow!("failed to parse identity: {:?}", e))?;
        tracing::info!(identity_key = key, "loaded identity from native storage");
        Ok(identity)
    } else {
        let mut rng = GetrandomRng;
        let identity_bytes = crypto
            .generate_identity(&mut rng)
            .map_err(|e| anyhow::anyhow!("failed to generate identity: {:?}", e))?;
        let secret_str = String::from_utf8(identity_bytes)
            .map_err(|_| anyhow::anyhow!("generated identity is not valid UTF-8"))?;
        let identity = Identity::parse(secret_str.trim())
            .map_err(|e| anyhow::anyhow!("failed to parse generated identity: {:?}", e))?;

        storage.store(key, secret_str.as_bytes()).await?;
        storage
            .store(
                &public_identity_key(key),
                identity.to_public_string().as_bytes(),
            )
            .await?;

        tracing::info!(
            identity_key = key,
            "generated new identity in native storage"
        );
        Ok(identity)
    }
}

/// Load planet file from native storage, or use the embedded default.
async fn load_planet(storage: &NativeStorage) -> anyhow::Result<Vec<u8>> {
    for key in ["planet.bin", "planet"] {
        if let Some(data) = storage.load(key).await? {
            tracing::info!(planet_key = key, "loaded planet from native storage");
            return Ok(data);
        }
    }

    tracing::info!("using embedded default planet");
    Ok(DEFAULT_PLANET.to_vec())
}

/// Load or generate an authentication token for the REST API.
async fn load_or_generate_auth_token(storage: &NativeStorage, key: &str) -> anyhow::Result<String> {
    if let Some(token) = storage.load(key).await? {
        let token = String::from_utf8(token)
            .map_err(|_| anyhow::anyhow!("stored auth token is not valid UTF-8"))?;
        Ok(token.trim().to_string())
    } else {
        let mut random_bytes = [0u8; 24];
        getrandom::getrandom(&mut random_bytes)
            .map_err(|e| anyhow::anyhow!("failed to get random bytes: {:?}", e))?;
        let token: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        storage.store(key, token.as_bytes()).await?;
        tracing::info!(
            auth_token_key = key,
            "generated auth token in native storage"
        );
        Ok(token)
    }
}

/// Wrapper to bridge getrandom 0.4 -> rand_core 0.6 CryptoRng for Identity::generate.
struct GetrandomRng;

impl rand_core::RngCore for GetrandomRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("getrandom failed");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::getrandom(dest).map_err(|_| {
            rand_core::Error::from(
                core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
            )
        })
    }
}

impl rand_core::CryptoRng for GetrandomRng {}

#[cfg(test)]
mod tests {
    use super::{managed_ips_from_dict_data, managed_routes_from_dict_data, tun_name_for_network};
    use zerotier_node::controller::dictionary::Dictionary;
    use zerotier_protocol::inet_address::InetAddress;

    fn inet_bytes(address: InetAddress) -> Vec<u8> {
        let mut buf = [0u8; 32];
        let written = address.serialize(&mut buf);
        buf[..written].to_vec()
    }

    #[test]
    fn tun_name_for_network_is_stable_and_node_specific() {
        let network_id = 0xd73835e5b10894e0;
        let left = tun_name_for_network(network_id, [0x51, 0x8d, 0x35, 0xae, 0x76]);
        let right = tun_name_for_network(network_id, [0x34, 0x4c, 0x97, 0x49, 0x46]);

        assert_eq!(left, "zt0894e035ae76");
        assert_eq!(right, "zt0894e0974946");
        assert_ne!(left, right);
        assert!(left.len() <= 15);
        assert!(right.len() <= 15);
    }

    #[test]
    fn parses_managed_ips_and_routes_from_dict_data() {
        let mut ip_bytes = Vec::new();
        ip_bytes.extend_from_slice(&inet_bytes(InetAddress::V4 {
            ip: [10, 147, 20, 7],
            port: 24,
        }));
        ip_bytes.extend_from_slice(&inet_bytes(InetAddress::V6 {
            ip: [0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
            port: 64,
        }));

        let mut route_bytes = Vec::new();
        route_bytes.extend_from_slice(&inet_bytes(InetAddress::V4 {
            ip: [10, 147, 20, 0],
            port: 24,
        }));
        route_bytes.extend_from_slice(&inet_bytes(InetAddress::Null));
        route_bytes.extend_from_slice(&0u16.to_be_bytes());

        let mut dict = Dictionary::new();
        dict.add_binary("I", ip_bytes);
        dict.add_binary("RT", route_bytes);

        let dict_data = dict.serialize();
        let ips = managed_ips_from_dict_data(&dict_data);
        let routes = managed_routes_from_dict_data(&dict_data);

        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].0.to_string(), "10.147.20.7");
        assert_eq!(ips[0].1, 24);
        assert_eq!(ips[1].0.to_string(), "fd00::7");
        assert_eq!(ips[1].1, 64);

        assert_eq!(routes, vec![("10.147.20.0/24".to_string(), None)]);
    }
}
