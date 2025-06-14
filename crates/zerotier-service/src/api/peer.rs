//! GET /peer handler.

use axum::{extract::State, Json};
use std::sync::Arc;

use super::{
    types::{PathResponse, PeerResponse},
    AppState,
};

/// Returns the list of known peers as JSON.
pub async fn list_peers(State(state): State<Arc<AppState>>) -> Json<Vec<PeerResponse>> {
    let node = state.node.lock().await;

    let peers: Vec<PeerResponse> = node
        .topology
        .peers
        .values()
        .map(|peer| {
            let addr = peer.identity.address.as_bytes();
            let address = format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}",
                addr[0], addr[1], addr[2], addr[3], addr[4]
            );

            let paths: Vec<PathResponse> = peer
                .paths
                .iter()
                .map(|p| PathResponse {
                    address: p.address.to_string(),
                    active: p.is_alive(0), // Approximate -- no clock available here
                    last_receive: p.last_receive,
                })
                .collect();

            let latency = match &peer.state {
                zerotier_node::peer::PeerState::Active { latency_ms, .. } => {
                    *latency_ms as i64
                }
                _ => -1,
            };

            PeerResponse {
                address,
                paths,
                latency,
                role: if peer.is_root {
                    "ROOT".to_string()
                } else {
                    "LEAF".to_string()
                },
            }
        })
        .collect();

    Json(peers)
}
