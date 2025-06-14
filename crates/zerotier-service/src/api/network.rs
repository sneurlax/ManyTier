//! GET/POST/DELETE /network handlers.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;

use super::{types::NetworkResponse, AppState};

/// Format a MAC address as "aa:bb:cc:dd:ee:ff".
fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Build a NetworkResponse from a NetworkMembership and our address.
fn membership_to_response(
    net: &zerotier_node::network::NetworkMembership,
    our_addr: &[u8; 5],
) -> NetworkResponse {
    // Collect assigned addresses from members matching our address
    let mut assigned = Vec::new();
    if let Some(member) = net.members.iter().find(|m| m.zt_address == *our_addr) {
        if let Some((ip, prefix)) = &member.ipv4 {
            assigned.push(format!("{}/{}", ip, prefix));
        }
        if let Some((ip, prefix)) = &member.ipv6 {
            assigned.push(format!("{}/{}", ip, prefix));
        }
    }

    let mac = zerotier_node::ethernet::derive_mac(our_addr, net.network_id);
    let status = if net.our_com.is_some() {
        "OK"
    } else {
        "REQUESTING_CONFIGURATION"
    };

    NetworkResponse {
        id: format!("{:016x}", net.network_id),
        name: String::new(), // Network name not stored in membership yet
        status: status.to_string(),
        assigned_addresses: assigned,
        mac: format_mac(&mac),
        mtu: net.mtu,
    }
}

/// List all joined networks.
pub async fn list_networks(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<NetworkResponse>> {
    let node = state.node.lock().await;
    let our_addr = node.identity.address.as_bytes();

    let networks: Vec<NetworkResponse> = node
        .networks
        .iter()
        .map(|net| membership_to_response(net, our_addr))
        .collect();

    Json(networks)
}

/// Join a network by ID (16-char hex).
pub async fn join_network(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<NetworkResponse>, StatusCode> {
    let network_id = u64::from_str_radix(&id, 16).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut node = state.node.lock().await;

    // Create empty membership -- config will come from controller
    let membership = zerotier_node::network::NetworkMembership::new(network_id, 2800);
    node.join_network(membership);

    let our_addr = node.identity.address.as_bytes();
    let mac = zerotier_node::ethernet::derive_mac(our_addr, network_id);

    Ok(Json(NetworkResponse {
        id: format!("{:016x}", network_id),
        name: String::new(),
        status: "REQUESTING_CONFIGURATION".to_string(),
        assigned_addresses: vec![],
        mac: format_mac(&mac),
        mtu: 2800,
    }))
}

/// Leave a network by ID (16-char hex).
pub async fn leave_network(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let network_id = u64::from_str_radix(&id, 16).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut node = state.node.lock().await;
    node.networks.retain(|n| n.network_id != network_id);
    Ok(StatusCode::OK)
}
