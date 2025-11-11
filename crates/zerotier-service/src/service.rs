//! Service daemon main loop: integrates Node + Controller + API server.
//!
//! This is the main entry point for `manytier service`. It starts the Node
//! engine, optionally a controller, and the REST API server.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::Mutex;

use zerotier_crypto::identity::Identity;
use zerotier_node::node::{Node, NodeAction};
use zerotier_node::traits::Transport;
use zerotier_node::traits::TunDevice;
use zerotier_protocol::constants::ZT_PING_CHECK_INTERVAL;
use zerotier_protocol::world::DEFAULT_PLANET;

use crate::api;
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
    // 1. Ensure data directory exists
    fs::create_dir_all(&config.data_dir)?;

    // 2. Load or generate identity
    let identity = load_or_generate_identity(&config.identity_path)?;
    let addr = identity.address.as_bytes();
    tracing::info!(
        address = %format!("{:02x}{:02x}{:02x}{:02x}{:02x}", addr[0], addr[1], addr[2], addr[3], addr[4]),
        "starting ManyTier service"
    );

    // 3. Load planet file
    let planet_data = load_planet(&config.data_dir)?;

    // 4. Create Node (identity is moved into node)
    let node = Node::new(identity, &planet_data)
        .map_err(|e| anyhow::anyhow!("failed to create node: {e}"))?;
    let node = Arc::new(Mutex::new(node));

    // 5. Generate or load authtoken.secret
    let auth_token = load_or_generate_auth_token(&config.data_dir)?;

    // 6. Optionally create Controller
    let controller = if config.controller_mode {
        let db_path = format!("{}/controller.db", config.data_dir);
        let storage = SqliteStorage::new(&db_path)?;
        let identity_for_ctrl = load_or_generate_identity(&config.identity_path)?;
        let secret = identity_for_ctrl
            .secret
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

    // 7. Bind UDP transport
    let bind_addr: std::net::SocketAddr = format!("0.0.0.0:{}", config.udp_port).parse()?;
    let transport = NativeTransport::bind(bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind UDP on port {}: {}", config.udp_port, e))?;
    tracing::info!(udp_port = config.udp_port, "UDP transport bound");

    // 8. Start API server in background task
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

    // 9. Bootstrap: send initial HELLO to roots
    {
        let mut n = node.lock().await;
        let now = now_ms();
        let actions = n.bootstrap(now);
        drop(n);
        execute_actions(&transport, &actions).await;
    }

    // 10. Main event loop
    let mut buf = [0u8; 4096];
    let mut tick_interval = tokio::time::interval(
        std::time::Duration::from_millis(ZT_PING_CHECK_INTERVAL),
    );
    // TUN devices per network, created lazily on NetworkConfigured.
    // Arc-wrapped so read tasks can share the device with the main loop.
    let mut tun_devices: HashMap<u64, Arc<NativeTun>> = HashMap::new();

    // Channel for TUN reads: avoids borrow checker issues with select!
    let (tun_tx, mut tun_rx) =
        tokio::sync::mpsc::channel::<(u64, Vec<u8>)>(64);

    // Graceful shutdown signal
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            // UDP packet received
            result = transport.recv_from(&mut buf) => {
                match result {
                    Ok((n, from)) => {
                        let now = now_ms();
                        let mut node_guard = node.lock().await;
                        let actions = node_guard.receive_packet(&mut buf[..n], from, now);

                        // Handle controller actions inline
                        if let Some(ref ctrl) = controller {
                            handle_controller_actions(&actions, ctrl, &mut node_guard, now).await;
                        }

                        // Drain any actions queued by controller handling
                        let pending = node_guard.drain_actions();
                        drop(node_guard);

                        execute_actions(&transport, &actions).await;
                        execute_actions(&transport, &pending).await;
                        handle_tun_actions(&actions, &mut tun_devices, &tun_tx).await;
                        handle_tun_actions(&pending, &mut tun_devices, &tun_tx).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "UDP recv error");
                    }
                }
            }

            // Tick timer
            _ = tick_interval.tick() => {
                let now = now_ms();
                let mut node_guard = node.lock().await;
                let actions = node_guard.tick(now);
                drop(node_guard);
                execute_actions(&transport, &actions).await;
                handle_tun_actions(&actions, &mut tun_devices, &tun_tx).await;
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
                let mut node_guard = node.lock().await;
                let our_addr = *node_guard.identity.address.as_bytes();
                let actions = zerotier_node::vl2::process_outbound_frame(
                    &mut node_guard, network_id, ethertype, &frame, &our_addr,
                );
                drop(node_guard);
                execute_actions(&transport, &actions).await;
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

/// Get current time in milliseconds.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Execute SendTo actions via the transport.
async fn execute_actions(transport: &NativeTransport, actions: &[NodeAction]) {
    for action in actions {
        if let NodeAction::SendTo { data, address } = action {
            if let Err(e) = transport.send_to(data, *address).await {
                tracing::warn!(error = %e, "failed to send UDP packet");
            }
        }
    }
}

/// Handle controller-related actions (NetworkConfigRequested).
/// Follows shadow-node pattern: inline in main loop, build response packets.
async fn handle_controller_actions(
    actions: &[NodeAction],
    controller: &Arc<Mutex<zerotier_node::controller::engine::Controller<SqliteStorage>>>,
    node: &mut zerotier_node::node::Node,
    now_ms: u64,
) {
    use zerotier_protocol::constants::CIPHER_SUITE_C25519_POLY1305_SALSA2012;
    use zerotier_protocol::verb::Verb;

    for action in actions {
        if let NodeAction::NetworkConfigRequested {
            requester_address,
            network_id,
            from,
            ..
        } = action
        {
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

            // Get shared secret for this peer
            let shared_secret = node
                .topology
                .get_peer(requester_address)
                .and_then(|p| p.shared_secret().map(|s| *s))
                .unwrap_or([0u8; 32]);

            let our_addr = *node.identity.address.as_bytes();

            // Build NETWORK_CONFIG packet
            let mut pkt_buf = [0u8; 2048];
            pkt_buf[0..8].copy_from_slice(&now_ms.to_be_bytes());
            pkt_buf[8..13].copy_from_slice(requester_address);
            pkt_buf[13..18].copy_from_slice(&our_addr);
            pkt_buf[18] = CIPHER_SUITE_C25519_POLY1305_SALSA2012 << 3;
            pkt_buf[19..27].copy_from_slice(&[0u8; 8]);
            pkt_buf[27] = Verb::NetworkConfig.to_byte();
            let payload_len = response.config.serialize(&mut pkt_buf[28..]);
            let total = 28 + payload_len;
            if zerotier_crypto::salsa::armor_packet(&shared_secret, &mut pkt_buf[..total], true)
                .is_ok()
            {
                node.push_action(NodeAction::SendTo {
                    data: pkt_buf[..total].to_vec(),
                    address: *from,
                });
                tracing::info!(
                    target: "manytier",
                    event = "controller_config_sent",
                    "sent NETWORK_CONFIG response"
                );
            }

            // Build NETWORK_CREDENTIALS packet
            let mut creds_buf = [0u8; 2048];
            let creds_now = now_ms + 1;
            creds_buf[0..8].copy_from_slice(&creds_now.to_be_bytes());
            creds_buf[8..13].copy_from_slice(requester_address);
            creds_buf[13..18].copy_from_slice(&our_addr);
            creds_buf[18] = CIPHER_SUITE_C25519_POLY1305_SALSA2012 << 3;
            creds_buf[19..27].copy_from_slice(&[0u8; 8]);
            creds_buf[27] = Verb::NetworkCredentials.to_byte();
            let creds_payload_len = response.credentials.serialize(&mut creds_buf[28..]);
            let creds_total = 28 + creds_payload_len;
            if zerotier_crypto::salsa::armor_packet(
                &shared_secret,
                &mut creds_buf[..creds_total],
                true,
            )
            .is_ok()
            {
                node.push_action(NodeAction::SendTo {
                    data: creds_buf[..creds_total].to_vec(),
                    address: *from,
                });
                tracing::info!(
                    target: "manytier",
                    event = "network_credentials_sent",
                    "sent NETWORK_CREDENTIALS response"
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
) {
    for action in actions {
        match action {
            NodeAction::FrameReceived {
                network_id,
                payload,
                ..
            } => {
                if let Some(tun) = tun_devices.get(network_id) {
                    if let Err(e) = tun.write(payload).await {
                        tracing::warn!(error = %e, "TUN write failed");
                    }
                }
            }
            NodeAction::LocalReply {
                network_id,
                payload,
                ..
            } => {
                if let Some(tun) = tun_devices.get(network_id) {
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
                    let tun_name = format!("zt{:x}", network_id & 0xFFFFFF);
                    match NativeTun::create(&tun_name, 2800).await {
                        Ok(tun) => {
                            tracing::info!(
                                network_id = %format!("{:016x}", network_id),
                                tun_name = %tun.name(),
                                "TUN device created"
                            );
                            // TODO: Parse dict_data for managed IPs and routes,
                            // call tun.set_ip() and tun.add_route().
                            // For now, TUN is created but IP assignment requires
                            // dictionary parsing which is complex. IP assignment
                            // will work via the NetworkMembership.members list
                            // populated by the controller config.
                            let _ = dict_data; // suppress unused warning
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

/// Load an identity from file, or generate a new one and save it.
fn load_or_generate_identity(path: &str) -> anyhow::Result<Identity> {
    if Path::new(path).exists() {
        let secret_str = fs::read_to_string(path)?;
        let identity = Identity::parse(secret_str.trim())
            .map_err(|e| anyhow::anyhow!("failed to parse identity: {:?}", e))?;
        tracing::info!("loaded identity from {}", path);
        Ok(identity)
    } else {
        // Generate new identity
        let mut rng = GetrandomRng;
        let identity = Identity::generate(&mut rng)
            .map_err(|e| anyhow::anyhow!("failed to generate identity: {:?}", e))?;

        // Save secret identity
        let secret_str = identity
            .to_secret_string()
            .expect("generated identity must have secret");
        let parent = Path::new(path).parent();
        if let Some(dir) = parent {
            fs::create_dir_all(dir)?;
        }
        fs::write(path, &secret_str)?;

        // Save public identity alongside
        let public_path = path.replace(".secret", ".public");
        if public_path != path {
            fs::write(&public_path, identity.to_public_string())?;
        }

        tracing::info!("generated new identity, saved to {}", path);
        Ok(identity)
    }
}

/// Load planet file from data directory, or use the embedded default.
fn load_planet(data_dir: &str) -> anyhow::Result<Vec<u8>> {
    let planet_path = format!("{}/planet", data_dir);
    if Path::new(&planet_path).exists() {
        let data = fs::read(&planet_path)?;
        tracing::info!("loaded planet from {}", planet_path);
        Ok(data)
    } else {
        tracing::info!("using embedded default planet");
        Ok(DEFAULT_PLANET.to_vec())
    }
}

/// Load or generate an authentication token for the REST API.
///
/// Uses atomic file creation (create_new) to avoid race conditions
fn load_or_generate_auth_token(data_dir: &str) -> anyhow::Result<String> {
    let token_path = format!("{}/authtoken.secret", data_dir);
    if Path::new(&token_path).exists() {
        let token = fs::read_to_string(&token_path)?;
        Ok(token.trim().to_string())
    } else {
        // Generate 24 random bytes, encode as 48-char hex
        let mut random_bytes = [0u8; 24];
        getrandom::getrandom(&mut random_bytes)
            .map_err(|e| anyhow::anyhow!("failed to get random bytes: {:?}", e))?;
        let token: String = random_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        // Atomic creation to prevent race conditions
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&token_path)?;
        file.write_all(token.as_bytes())?;

        tracing::info!("generated authtoken.secret at {}", token_path);
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
