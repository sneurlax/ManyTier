//! GET /status handler.

use axum::{extract::State, Json};
use std::sync::Arc;

use super::{types::StatusResponse, AppState};

/// Format a 5-byte ZeroTier address as a 10-character hex string.
fn format_address(addr: &[u8; 5]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}",
        addr[0], addr[1], addr[2], addr[3], addr[4]
    )
}

/// Format raw bytes as a hex string (no separators).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Returns the node's status as JSON.
pub async fn get_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let node = state.node.lock().await;
    let addr = node.identity.address.as_bytes();
    let addr_hex = format_address(addr);

    // Combine DH + signing public key bytes for the public identity string
    let mut pubkey_bytes = Vec::with_capacity(64);
    pubkey_bytes.extend_from_slice(&node.identity.public_key.dh);
    pubkey_bytes.extend_from_slice(&node.identity.public_key.signing);

    Json(StatusResponse {
        address: addr_hex.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        online: true, // If the API is responding, we're online
        public_identity: format!("{}:0:{}", addr_hex, hex_encode(&pubkey_bytes)),
    })
}
