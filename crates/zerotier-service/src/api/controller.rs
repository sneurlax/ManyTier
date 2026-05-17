//! Controller REST API handlers for network and member CRUD.
//!
//! Implements the official ZeroTier controller API endpoints:
//! - GET    /controller/network                         -> list network IDs
//! - POST   /controller/network/:nwid                  -> create or update network
//! - GET    /controller/network/:nwid                  -> get network config
//! - DELETE /controller/network/:nwid                  -> delete network
//! - GET    /controller/network/:nwid/member           -> list member IDs
//! - GET    /controller/network/:nwid/member/:nodeId   -> get member
//! - POST   /controller/network/:nwid/member/:nodeId   -> update member
//! - DELETE /controller/network/:nwid/member/:nodeId   -> delete member

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Json, Router};

use zerotier_node::controller::storage::ControllerStorage;
use zerotier_node::controller::types::{IpPool, ManagedRoute};

use super::types::{
    CapabilityResponse, ControllerMemberResponse, ControllerNetworkResponse, IpPoolResponse,
    RouteResponse, RuleResponse, TagResponse, UpdateMemberRequest, UpdateNetworkRequest,
};
use super::AppState;

/// Build the controller sub-router with all network/member endpoints.
pub fn controller_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/network", axum::routing::get(list_networks))
        .route(
            "/network/:nwid",
            axum::routing::get(get_network)
                .post(update_network)
                .delete(delete_network),
        )
        .route("/network/:nwid/member", axum::routing::get(list_members))
        .route(
            "/network/:nwid/member/:node_id",
            axum::routing::get(get_member)
                .post(update_member)
                .delete(delete_member),
        )
}

type ApiError = (StatusCode, Json<serde_json::Value>);

fn error_response(status: StatusCode, message: &str) -> ApiError {
    (status, Json(serde_json::json!({ "message": message })))
}

fn parse_network_id(hex: &str) -> Result<u64, ApiError> {
    u64::from_str_radix(hex, 16)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "invalid network ID hex"))
}

fn parse_node_id_bytes(hex: &str) -> Result<[u8; 5], ApiError> {
    let val = u64::from_str_radix(hex, 16)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "invalid node ID hex"))?;
    Ok([
        (val >> 32) as u8,
        (val >> 24) as u8,
        (val >> 16) as u8,
        (val >> 8) as u8,
        val as u8,
    ])
}

fn format_network_id(id: u64) -> String {
    format!("{:016x}", id)
}

fn format_node_id(addr: &[u8; 5]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}",
        addr[0], addr[1], addr[2], addr[3], addr[4]
    )
}

fn v4_assign_mode_to_json(mode: &str) -> serde_json::Value {
    serde_json::json!({ "zt": mode == "zt" })
}

fn v6_assign_mode_to_json(mode: &str) -> serde_json::Value {
    serde_json::json!({
        "zt": mode == "zt",
        "6plane": mode == "6plane",
        "rfc4193": mode == "rfc4193",
    })
}

fn ip_pool_to_response(pool: &IpPool) -> IpPoolResponse {
    IpPoolResponse {
        ip_range_start: format!(
            "{}.{}.{}.{}",
            pool.range_start[0], pool.range_start[1], pool.range_start[2], pool.range_start[3]
        ),
        ip_range_end: format!(
            "{}.{}.{}.{}",
            pool.range_end[0], pool.range_end[1], pool.range_end[2], pool.range_end[3]
        ),
    }
}

fn parse_ip_pool(resp: &IpPoolResponse) -> Option<IpPool> {
    let start = parse_dotted_ipv4(&resp.ip_range_start)?;
    let end = parse_dotted_ipv4(&resp.ip_range_end)?;
    Some(IpPool {
        range_start: start,
        range_end: end,
    })
}

fn parse_dotted_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    Some([
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
        parts[3].parse().ok()?,
    ])
}

fn route_to_response(route: &ManagedRoute) -> RouteResponse {
    RouteResponse {
        target: route.target.clone(),
        via: route.via.clone(),
    }
}

fn parse_managed_route(resp: &RouteResponse) -> ManagedRoute {
    ManagedRoute {
        target: resp.target.clone(),
        via: resp.via.clone(),
    }
}

/// GET /controller/network -- list all network IDs.
async fn list_networks(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, ApiError> {
    let controller = state
        .controller
        .as_ref()
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "controller not enabled"))?;
    let ctrl = controller.lock().await;
    let ids = ctrl
        .storage
        .list_networks()
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;
    let hex_ids: Vec<String> = ids.iter().map(|id| format_network_id(*id)).collect();
    Ok(Json(hex_ids))
}

/// GET /controller/network/{nwid} -- get network configuration.
async fn get_network(
    State(state): State<Arc<AppState>>,
    Path(nwid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let controller = state
        .controller
        .as_ref()
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "controller not enabled"))?;
    let network_id = parse_network_id(&nwid)?;
    let ctrl = controller.lock().await;
    let network = ctrl
        .storage
        .get_network(network_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "network not found"))?;

    let pools = ctrl
        .storage
        .get_ip_pools(network_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;

    let routes = ctrl
        .storage
        .get_routes(network_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;

    let response = network_to_response(network, &pools, &routes);

    Ok(Json(response))
}

/// POST /controller/network/{nwid} -- create new network or update existing.
///
/// If nwid ends with "______" (6 underscores), it is a create request.
/// The prefix before the underscores is the controller address.
/// Otherwise, it is an update to an existing network.
async fn update_network(
    State(state): State<Arc<AppState>>,
    Path(nwid): Path<String>,
    Json(body): Json<UpdateNetworkRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let controller = state
        .controller
        .as_ref()
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "controller not enabled"))?;

    if nwid.ends_with("______") {
        // Create new network
        let ctrl = controller.lock().await;
        let mut random_bytes = [0u8; 4];
        getrandom::getrandom(&mut random_bytes)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;
        let random_24 = u32::from_be_bytes(random_bytes) & 0x00FFFFFF;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let network_id = ctrl
            .create_network(random_24, now_ms)
            .await
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;

        // Apply any fields from the request body
        if body.name.is_some()
            || body.private.is_some()
            || body.multicast_limit.is_some()
            || body.mtu.is_some()
            || body.enable_broadcast.is_some()
            || body.v4_assign_mode.is_some()
            || body.rules.is_some()
            || body.capabilities.is_some()
        {
            if let Some(mut network) =
                ctrl.storage.get_network(network_id).await.map_err(|e| {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e))
                })?
            {
                apply_network_updates(&mut network, &body);
                ctrl.storage.update_network(&network).await.map_err(|e| {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e))
                })?;
            }
        }

        // Apply IP pools if provided
        if let Some(ref pools) = body.ip_assignment_pools {
            let parsed: Vec<IpPool> = pools.iter().filter_map(parse_ip_pool).collect();
            ctrl.storage
                .set_ip_pools(network_id, &parsed)
                .await
                .map_err(|e| {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e))
                })?;
        }

        // Apply routes if provided
        if let Some(ref routes) = body.routes {
            let parsed: Vec<ManagedRoute> = routes.iter().map(parse_managed_route).collect();
            ctrl.storage
                .set_routes(network_id, &parsed)
                .await
                .map_err(|e| {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e))
                })?;
        }

        // Return the created network
        let network = ctrl
            .storage
            .get_network(network_id)
            .await
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?
            .ok_or_else(|| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "created network not found",
                )
            })?;
        let ip_pools =
            ctrl.storage.get_ip_pools(network_id).await.map_err(|e| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e))
            })?;
        let routes =
            ctrl.storage.get_routes(network_id).await.map_err(|e| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e))
            })?;

        return Ok(Json(network_to_response(network, &ip_pools, &routes)));
    }

    // Update existing network
    let network_id = parse_network_id(&nwid)?;
    let ctrl = controller.lock().await;
    let mut network = ctrl
        .storage
        .get_network(network_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "network not found"))?;

    apply_network_updates(&mut network, &body);
    network.revision += 1;

    ctrl.storage
        .update_network(&network)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;

    // Update IP pools if provided
    if let Some(ref pools) = body.ip_assignment_pools {
        let parsed: Vec<IpPool> = pools.iter().filter_map(parse_ip_pool).collect();
        ctrl.storage
            .set_ip_pools(network_id, &parsed)
            .await
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;
    }

    // Update routes if provided
    if let Some(ref routes) = body.routes {
        let parsed: Vec<ManagedRoute> = routes.iter().map(parse_managed_route).collect();
        ctrl.storage
            .set_routes(network_id, &parsed)
            .await
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;
    }

    let ip_pools = ctrl
        .storage
        .get_ip_pools(network_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;

    let routes = ctrl
        .storage
        .get_routes(network_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;

    Ok(Json(network_to_response(network, &ip_pools, &routes)))
}

/// Apply partial updates from an UpdateNetworkRequest to a NetworkRecord.
fn apply_network_updates(
    network: &mut zerotier_node::controller::types::NetworkRecord,
    body: &UpdateNetworkRequest,
) {
    if let Some(ref name) = body.name {
        network.name = name.clone();
    }
    if let Some(private) = body.private {
        network.private = private;
    }
    if let Some(limit) = body.multicast_limit {
        network.multicast_limit = limit;
    }
    if let Some(mtu) = body.mtu {
        network.mtu = mtu;
    }
    if let Some(broadcast) = body.enable_broadcast {
        network.enable_broadcast = broadcast;
    }
    if let Some(ref v4) = body.v4_assign_mode {
        if let Some(zt) = v4.get("zt").and_then(|v| v.as_bool()) {
            network.v4_assign_mode = if zt {
                String::from("zt")
            } else {
                String::from("none")
            };
        }
    }
    if let Some(ref rules) = body.rules {
        network.rules = rules.iter().map(rule_from_response).collect();
    }
    if let Some(ref caps) = body.capabilities {
        network.capabilities = caps.iter().map(capability_from_response).collect();
    }
}

fn rule_to_response(rule: &zerotier_node::controller::rules::Rule) -> RuleResponse {
    RuleResponse {
        rule_type: rule.rule_type,
        not: rule.not_flag,
        or_flag: rule.or_flag,
        value: rule.value.clone(),
    }
}

fn rule_from_response(rule: &RuleResponse) -> zerotier_node::controller::rules::Rule {
    zerotier_node::controller::rules::Rule {
        rule_type: rule.rule_type,
        not_flag: rule.not,
        or_flag: rule.or_flag,
        value: rule.value.clone(),
    }
}

fn capability_to_response(
    cap: &zerotier_node::controller::rules::Capability,
) -> CapabilityResponse {
    CapabilityResponse {
        id: cap.id,
        rules: cap.rules.iter().map(rule_to_response).collect(),
    }
}

fn capability_from_response(
    cap: &CapabilityResponse,
) -> zerotier_node::controller::rules::Capability {
    zerotier_node::controller::rules::Capability {
        id: cap.id,
        rules: cap.rules.iter().map(rule_from_response).collect(),
    }
}

fn tag_to_response(tag: &zerotier_node::controller::rules::Tag) -> TagResponse {
    TagResponse {
        id: tag.id,
        value: tag.value,
    }
}

fn tag_from_response(tag: &TagResponse) -> zerotier_node::controller::rules::Tag {
    zerotier_node::controller::rules::Tag {
        id: tag.id,
        value: tag.value,
    }
}

/// Convert a NetworkRecord + IP pools to a ControllerNetworkResponse.
fn network_to_response(
    network: zerotier_node::controller::types::NetworkRecord,
    pools: &[IpPool],
    routes: &[ManagedRoute],
) -> ControllerNetworkResponse {
    ControllerNetworkResponse {
        id: format_network_id(network.id),
        name: network.name,
        private: network.private,
        creation_time: network.creation_time,
        revision: network.revision,
        multicast_limit: network.multicast_limit,
        mtu: network.mtu,
        v4_assign_mode: v4_assign_mode_to_json(&network.v4_assign_mode),
        v6_assign_mode: v6_assign_mode_to_json(&network.v6_assign_mode),
        ip_assignment_pools: pools.iter().map(ip_pool_to_response).collect(),
        enable_broadcast: network.enable_broadcast,
        routes: routes.iter().map(route_to_response).collect(),
        rules: network.rules.iter().map(rule_to_response).collect(),
        capabilities: network
            .capabilities
            .iter()
            .map(capability_to_response)
            .collect(),
    }
}

/// DELETE /controller/network/{nwid} -- delete a network.
async fn delete_network(
    State(state): State<Arc<AppState>>,
    Path(nwid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let controller = state
        .controller
        .as_ref()
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "controller not enabled"))?;
    let network_id = parse_network_id(&nwid)?;
    let ctrl = controller.lock().await;

    // Get the network before deleting so we can return it
    let network = ctrl
        .storage
        .get_network(network_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "network not found"))?;

    let pools = ctrl
        .storage
        .get_ip_pools(network_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;

    let routes = ctrl
        .storage
        .get_routes(network_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;

    ctrl.storage
        .delete_network(network_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;

    Ok(Json(network_to_response(network, &pools, &routes)))
}

/// GET /controller/network/{nwid}/member -- list member node IDs.
///
/// Returns JSON object with node IDs as keys and 1 as values,
/// matching the official ZeroTier API format.
async fn list_members(
    State(state): State<Arc<AppState>>,
    Path(nwid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let controller = state
        .controller
        .as_ref()
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "controller not enabled"))?;
    let network_id = parse_network_id(&nwid)?;
    let ctrl = controller.lock().await;
    let member_ids = ctrl
        .storage
        .list_members(network_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;

    let map: HashMap<String, u8> = member_ids
        .iter()
        .map(|id| (format_node_id(id), 1))
        .collect();

    Ok(Json(map))
}

/// GET /controller/network/{nwid}/member/{nodeId} -- get member details.
async fn get_member(
    State(state): State<Arc<AppState>>,
    Path((nwid, node_id_hex)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let controller = state
        .controller
        .as_ref()
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "controller not enabled"))?;
    let network_id = parse_network_id(&nwid)?;
    let node_id = parse_node_id_bytes(&node_id_hex)?;
    let ctrl = controller.lock().await;
    let member = ctrl
        .storage
        .get_member(network_id, &node_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "member not found"))?;

    Ok(Json(member_to_response(&member)))
}

/// POST /controller/network/{nwid}/member/{nodeId} -- update member.
///
/// Supports authorize/deauthorize, IP assignment changes, and name updates.
async fn update_member(
    State(state): State<Arc<AppState>>,
    Path((nwid, node_id_hex)): Path<(String, String)>,
    Json(body): Json<UpdateMemberRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let controller = state
        .controller
        .as_ref()
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "controller not enabled"))?;
    let network_id = parse_network_id(&nwid)?;
    let node_id = parse_node_id_bytes(&node_id_hex)?;
    let ctrl = controller.lock().await;

    // Load or create member
    let is_new = ctrl
        .storage
        .get_member(network_id, &node_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?
        .is_none();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut member = if is_new {
        zerotier_node::controller::types::MemberRecord {
            network_id,
            node_id,
            authorized: false,
            ip_assignments: Vec::new(),
            creation_time: now_ms,
            last_seen: now_ms,
            name: String::new(),
            revision: 0,
            last_authorized_time: 0,
            last_deauthorized_time: 0,
            active_bridge: false,
            no_auto_assign_ips: false,
            capabilities: Vec::new(),
            tags: Vec::new(),
        }
    } else {
        ctrl.storage
            .get_member(network_id, &node_id)
            .await
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?
            .unwrap()
    };

    // Apply updates
    if let Some(ref name) = body.name {
        member.name = name.clone();
    }
    if let Some(ref ips) = body.ip_assignments {
        member.ip_assignments = ips.clone();
    }
    if let Some(authorized) = body.authorized {
        if authorized != member.authorized {
            if authorized {
                member.last_authorized_time = now_ms;
            } else {
                member.last_deauthorized_time = now_ms;
            }
        }
        member.authorized = authorized;
    }
    if let Some(active_bridge) = body.active_bridge {
        member.active_bridge = active_bridge;
    }
    if let Some(no_auto_assign_ips) = body.no_auto_assign_ips {
        member.no_auto_assign_ips = no_auto_assign_ips;
    }
    if let Some(ref capabilities) = body.capabilities {
        member.capabilities = capabilities.clone();
    }
    if let Some(ref tags) = body.tags {
        member.tags = tags.iter().map(tag_from_response).collect();
    }
    member.revision += 1;

    // Save the member first (so engine methods can find it)
    ctrl.storage
        .upsert_member(&member)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;

    Ok(Json(member_to_response(&member)))
}

/// DELETE /controller/network/{nwid}/member/{nodeId} -- delete member.
async fn delete_member(
    State(state): State<Arc<AppState>>,
    Path((nwid, node_id_hex)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let controller = state
        .controller
        .as_ref()
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "controller not enabled"))?;
    let network_id = parse_network_id(&nwid)?;
    let node_id = parse_node_id_bytes(&node_id_hex)?;
    let ctrl = controller.lock().await;

    ctrl.storage
        .delete_member(network_id, &node_id)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", e)))?;

    Ok(StatusCode::OK)
}

/// Convert a MemberRecord to a ControllerMemberResponse.
fn member_to_response(
    member: &zerotier_node::controller::types::MemberRecord,
) -> ControllerMemberResponse {
    ControllerMemberResponse {
        id: format_node_id(&member.node_id),
        network_id: format_network_id(member.network_id),
        authorized: member.authorized,
        ip_assignments: member.ip_assignments.clone(),
        creation_time: member.creation_time,
        last_seen: member.last_seen,
        name: member.name.clone(),
        revision: member.revision,
        active_bridge: member.active_bridge,
        no_auto_assign_ips: member.no_auto_assign_ips,
        last_authorized_time: member.last_authorized_time,
        last_deauthorized_time: member.last_deauthorized_time,
        // ManyTier does not track peer protocol/version per member yet; -1 matches
        // official ZeroTier's "unknown" sentinel for these fields.
        v_major: -1,
        v_minor: -1,
        v_rev: -1,
        v_proto: -1,
        capabilities: member.capabilities.clone(),
        tags: member.tags.iter().map(tag_to_response).collect(),
    }
}
