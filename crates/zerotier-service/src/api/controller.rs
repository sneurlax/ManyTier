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
    RouteResponse, RuleResponse, TagDefinitionResponse, TagResponse, UpdateMemberRequest,
    UpdateNetworkRequest,
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
            || body.tags.is_some()
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
    if let Some(ref tags) = body.tags {
        network.tags = tags.iter().map(tag_definition_from_response).collect();
    }
}

fn rule_to_response(rule: &zerotier_node::controller::rules::Rule) -> RuleResponse {
    RuleResponse {
        rule_type: rule.rule_type,
        type_name: zerotier_node::controller::rules::rule_type_name(rule.rule_type).to_string(),
        not: rule.not_flag,
        or_flag: rule.or_flag,
        value: rule.value.clone(),
        fields: zerotier_node::controller::rules::decode_rule_fields(rule.rule_type, &rule.value)
            .map(rule_fields_to_json),
    }
}

fn rule_from_response(rule: &RuleResponse) -> zerotier_node::controller::rules::Rule {
    let value = if rule.value.is_empty() {
        rule.fields
            .as_ref()
            .and_then(|f| rule_fields_from_json(rule.rule_type, f))
            .map(|f| zerotier_node::controller::rules::encode_rule_fields(&f))
            .unwrap_or_default()
    } else {
        rule.value.clone()
    };
    zerotier_node::controller::rules::Rule {
        rule_type: rule.rule_type,
        not_flag: rule.not,
        or_flag: rule.or_flag,
        value,
    }
}

/// Render decoded rule fields into official's per-rule-type JSON key names
/// (e.g. `"ipProtocol"`, `"vlanId"`), matching `EmbeddedNetworkController.cpp`
/// `_renderRule`'s field shapes.
fn rule_fields_to_json(fields: zerotier_node::controller::rules::RuleFields) -> serde_json::Value {
    use zerotier_node::controller::rules::RuleFields;
    match fields {
        RuleFields::Forward {
            address,
            flags,
            length,
        } => serde_json::json!({
            "address": format_node_id(&addr_u64_to_bytes(address)),
            "flags": flags,
            "length": length,
        }),
        RuleFields::ZtAddress(addr) => serde_json::json!({
            "zt": format_node_id(&addr_u64_to_bytes(addr)),
        }),
        RuleFields::VlanId(v) => serde_json::json!({ "vlanId": v }),
        RuleFields::VlanPcp(v) => serde_json::json!({ "vlanPcp": v }),
        RuleFields::VlanDei(v) => serde_json::json!({ "vlanDei": v }),
        RuleFields::Mac(mac) => serde_json::json!({
            "mac": format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ),
        }),
        RuleFields::Ipv4 { ip, mask } => serde_json::json!({
            "ip": format!("{}.{}.{}.{}/{}", ip[0], ip[1], ip[2], ip[3], mask),
        }),
        RuleFields::Ipv6 { ip, mask } => {
            let addr = std::net::Ipv6Addr::from(ip);
            serde_json::json!({ "ip": format!("{}/{}", addr, mask) })
        }
        RuleFields::IpTos { mask, start, end } => serde_json::json!({
            "mask": mask,
            "start": start,
            "end": end,
        }),
        RuleFields::IpProtocol(v) => serde_json::json!({ "ipProtocol": v }),
        RuleFields::EtherType(v) => serde_json::json!({ "etherType": v }),
        RuleFields::Icmp {
            icmp_type,
            icmp_code,
        } => serde_json::json!({
            "icmpType": icmp_type,
            "icmpCode": icmp_code,
        }),
        RuleFields::PortRange { start, end } => serde_json::json!({
            "start": start,
            "end": end,
        }),
        RuleFields::Characteristics(v) => serde_json::json!({
            "mask": format!("{:016x}", v),
        }),
        RuleFields::FrameSizeRange { start, end } => serde_json::json!({
            "start": start,
            "end": end,
        }),
        RuleFields::RandomProbability(v) => serde_json::json!({ "probability": v }),
        RuleFields::Tag { id, value } => serde_json::json!({
            "id": id,
            "value": value,
        }),
        RuleFields::IntegerRange {
            start,
            end,
            idx,
            little,
            bits,
        } => serde_json::json!({
            "start": format!("{:016x}", start),
            "end": format!("{:016x}", end),
            "idx": idx,
            "little": little,
            "bits": bits,
        }),
    }
}

/// Parse official's per-rule-type JSON fields back into [`RuleFields`] for a
/// given rule type, the inverse of [`rule_fields_to_json`]. Returns `None` if
/// the JSON is missing required keys or the rule type has no field shape.
fn rule_fields_from_json(
    rule_type: u8,
    json: &serde_json::Value,
) -> Option<zerotier_node::controller::rules::RuleFields> {
    use zerotier_node::controller::rules::{
        RuleFields, ACTION_REDIRECT, ACTION_TEE, ACTION_WATCH, MATCH_CHARACTERISTICS,
        MATCH_DEST_ZEROTIER_ADDRESS, MATCH_ETHERTYPE, MATCH_FRAME_SIZE_RANGE, MATCH_ICMP,
        MATCH_INTEGER_RANGE, MATCH_IPV4_DEST, MATCH_IPV4_SOURCE, MATCH_IPV6_DEST,
        MATCH_IPV6_SOURCE, MATCH_IP_DEST_PORT_RANGE, MATCH_IP_PROTOCOL, MATCH_IP_SOURCE_PORT_RANGE,
        MATCH_IP_TOS, MATCH_MAC_DEST, MATCH_MAC_SOURCE, MATCH_RANDOM,
        MATCH_SOURCE_ZEROTIER_ADDRESS, MATCH_TAGS_BITWISE_AND, MATCH_TAGS_BITWISE_OR,
        MATCH_TAGS_BITWISE_XOR, MATCH_TAGS_DIFFERENCE, MATCH_TAGS_EQUAL, MATCH_TAG_RECEIVER,
        MATCH_TAG_SENDER, MATCH_VLAN_DEI, MATCH_VLAN_ID, MATCH_VLAN_PCP,
    };

    fn u(json: &serde_json::Value, key: &str) -> Option<u64> {
        json.get(key).and_then(|v| v.as_u64())
    }
    fn hex_addr(json: &serde_json::Value, key: &str) -> Option<u64> {
        json.get(key)
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s, 16).ok())
    }
    fn hex_u64(json: &serde_json::Value, key: &str) -> Option<u64> {
        json.get(key)
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s, 16).ok())
    }

    match rule_type & 0x3F {
        ACTION_TEE | ACTION_WATCH | ACTION_REDIRECT => Some(RuleFields::Forward {
            address: hex_addr(json, "address")?,
            flags: u(json, "flags").unwrap_or(0) as u32,
            length: u(json, "length").unwrap_or(0) as u16,
        }),
        MATCH_SOURCE_ZEROTIER_ADDRESS | MATCH_DEST_ZEROTIER_ADDRESS => {
            Some(RuleFields::ZtAddress(hex_addr(json, "zt")?))
        }
        MATCH_VLAN_ID => Some(RuleFields::VlanId(u(json, "vlanId")? as u16)),
        MATCH_VLAN_PCP => Some(RuleFields::VlanPcp(u(json, "vlanPcp")? as u8)),
        MATCH_VLAN_DEI => Some(RuleFields::VlanDei(u(json, "vlanDei")? as u8)),
        MATCH_MAC_SOURCE | MATCH_MAC_DEST => {
            let s = json.get("mac")?.as_str()?;
            let bytes: Vec<u8> = s
                .split(':')
                .map(|h| u8::from_str_radix(h, 16))
                .collect::<Result<_, _>>()
                .ok()?;
            let mut mac = [0u8; 6];
            if bytes.len() != 6 {
                return None;
            }
            mac.copy_from_slice(&bytes);
            Some(RuleFields::Mac(mac))
        }
        MATCH_IPV4_SOURCE | MATCH_IPV4_DEST => {
            let s = json.get("ip")?.as_str()?;
            let (addr, mask) = s.split_once('/')?;
            let ip: std::net::Ipv4Addr = addr.parse().ok()?;
            Some(RuleFields::Ipv4 {
                ip: ip.octets(),
                mask: mask.parse().ok()?,
            })
        }
        MATCH_IPV6_SOURCE | MATCH_IPV6_DEST => {
            let s = json.get("ip")?.as_str()?;
            let (addr, mask) = s.split_once('/')?;
            let ip: std::net::Ipv6Addr = addr.parse().ok()?;
            Some(RuleFields::Ipv6 {
                ip: ip.octets(),
                mask: mask.parse().ok()?,
            })
        }
        MATCH_IP_TOS => Some(RuleFields::IpTos {
            mask: u(json, "mask")? as u8,
            start: u(json, "start")? as u8,
            end: u(json, "end")? as u8,
        }),
        MATCH_IP_PROTOCOL => Some(RuleFields::IpProtocol(u(json, "ipProtocol")? as u8)),
        MATCH_ETHERTYPE => Some(RuleFields::EtherType(u(json, "etherType")? as u16)),
        MATCH_ICMP => Some(RuleFields::Icmp {
            icmp_type: u(json, "icmpType")? as u8,
            icmp_code: json
                .get("icmpCode")
                .and_then(|v| v.as_u64())
                .map(|v| v as u8),
        }),
        MATCH_IP_SOURCE_PORT_RANGE | MATCH_IP_DEST_PORT_RANGE => Some(RuleFields::PortRange {
            start: u(json, "start")? as u16,
            end: u(json, "end")? as u16,
        }),
        MATCH_CHARACTERISTICS => Some(RuleFields::Characteristics(hex_u64(json, "mask")?)),
        MATCH_FRAME_SIZE_RANGE => Some(RuleFields::FrameSizeRange {
            start: u(json, "start")? as u16,
            end: u(json, "end")? as u16,
        }),
        MATCH_RANDOM => Some(RuleFields::RandomProbability(u(json, "probability")? as u32)),
        MATCH_TAGS_DIFFERENCE
        | MATCH_TAGS_BITWISE_AND
        | MATCH_TAGS_BITWISE_OR
        | MATCH_TAGS_BITWISE_XOR
        | MATCH_TAGS_EQUAL
        | MATCH_TAG_SENDER
        | MATCH_TAG_RECEIVER => Some(RuleFields::Tag {
            id: u(json, "id")? as u32,
            value: u(json, "value")? as u32,
        }),
        MATCH_INTEGER_RANGE => Some(RuleFields::IntegerRange {
            start: hex_u64(json, "start")?,
            end: hex_u64(json, "end")?,
            idx: u(json, "idx")? as u16,
            little: json
                .get("little")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            bits: u(json, "bits")? as u8,
        }),
        _ => None,
    }
}

fn addr_u64_to_bytes(addr: u64) -> [u8; 5] {
    [
        (addr >> 32) as u8,
        (addr >> 24) as u8,
        (addr >> 16) as u8,
        (addr >> 8) as u8,
        addr as u8,
    ]
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

fn tag_definition_to_response(
    def: &zerotier_node::controller::rules::TagDefinition,
) -> TagDefinitionResponse {
    TagDefinitionResponse {
        id: def.id,
        name: def.name.clone(),
        default: def.default,
        enums: def.enums.iter().cloned().collect(),
    }
}

fn tag_definition_from_response(
    def: &TagDefinitionResponse,
) -> zerotier_node::controller::rules::TagDefinition {
    zerotier_node::controller::rules::TagDefinition {
        id: def.id,
        name: def.name.clone(),
        default: def.default,
        enums: def.enums.iter().map(|(k, v)| (k.clone(), *v)).collect(),
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
        tags: network
            .tags
            .iter()
            .map(tag_definition_to_response)
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

#[cfg(test)]
mod tests {
    use super::*;
    use zerotier_node::controller::rules::{
        Rule, MATCH_ETHERTYPE, MATCH_IP_PROTOCOL, MATCH_TAGS_EQUAL,
    };

    #[test]
    fn rule_to_response_decodes_named_fields_and_keeps_raw_value() {
        let rule = Rule {
            rule_type: MATCH_IP_PROTOCOL,
            not_flag: false,
            or_flag: false,
            value: vec![6],
        };
        let resp = rule_to_response(&rule);
        assert_eq!(resp.value, vec![6]);
        assert_eq!(resp.type_name, "MATCH_IP_PROTOCOL");
        assert_eq!(resp.fields, Some(serde_json::json!({ "ipProtocol": 6 })));
    }

    #[test]
    fn rule_to_response_has_no_fields_for_valueless_action() {
        let rule = Rule {
            rule_type: zerotier_node::controller::rules::ACTION_ACCEPT,
            not_flag: false,
            or_flag: false,
            value: vec![],
        };
        let resp = rule_to_response(&rule);
        assert_eq!(resp.fields, None);
    }

    #[test]
    fn rule_from_response_prefers_explicit_value_over_fields() {
        let resp = RuleResponse {
            rule_type: MATCH_ETHERTYPE,
            type_name: "MATCH_ETHERTYPE".to_string(),
            not: false,
            or_flag: false,
            value: vec![0x08, 0x00],
            fields: Some(serde_json::json!({ "etherType": 0x86dd })),
        };
        let rule = rule_from_response(&resp);
        // value is non-empty, so it wins over the (mismatched) fields.
        assert_eq!(rule.value, vec![0x08, 0x00]);
    }

    #[test]
    fn rule_from_response_encodes_fields_when_value_is_empty() {
        let resp = RuleResponse {
            rule_type: MATCH_TAGS_EQUAL,
            type_name: "MATCH_TAGS_EQUAL".to_string(),
            not: false,
            or_flag: false,
            value: vec![],
            fields: Some(serde_json::json!({ "id": 9, "value": 12345 })),
        };
        let rule = rule_from_response(&resp);
        assert_eq!(rule.value, vec![0, 0, 0, 9, 0, 0, 48, 57]);
    }

    #[test]
    fn rule_fields_round_trip_through_json_for_every_named_type() {
        use zerotier_node::controller::rules::*;
        let cases = [
            (
                ACTION_TEE,
                Rule {
                    rule_type: ACTION_TEE,
                    not_flag: false,
                    or_flag: false,
                    value: encode_rule_fields(&RuleFields::Forward {
                        address: 0x0102030405,
                        flags: 7,
                        length: 200,
                    }),
                },
            ),
            (
                MATCH_VLAN_ID,
                Rule {
                    rule_type: MATCH_VLAN_ID,
                    not_flag: false,
                    or_flag: false,
                    value: encode_rule_fields(&RuleFields::VlanId(42)),
                },
            ),
            (
                MATCH_MAC_SOURCE,
                Rule {
                    rule_type: MATCH_MAC_SOURCE,
                    not_flag: false,
                    or_flag: false,
                    value: encode_rule_fields(&RuleFields::Mac([0, 0x11, 0x22, 0x33, 0x44, 0x55])),
                },
            ),
            (
                MATCH_IPV4_SOURCE,
                Rule {
                    rule_type: MATCH_IPV4_SOURCE,
                    not_flag: true,
                    or_flag: false,
                    value: encode_rule_fields(&RuleFields::Ipv4 {
                        ip: [10, 0, 0, 1],
                        mask: 24,
                    }),
                },
            ),
            (
                MATCH_IPV6_DEST,
                Rule {
                    rule_type: MATCH_IPV6_DEST,
                    not_flag: false,
                    or_flag: true,
                    value: encode_rule_fields(&RuleFields::Ipv6 {
                        ip: [0xfd; 16],
                        mask: 64,
                    }),
                },
            ),
            (
                MATCH_INTEGER_RANGE,
                Rule {
                    rule_type: MATCH_INTEGER_RANGE,
                    not_flag: false,
                    or_flag: false,
                    value: encode_rule_fields(&RuleFields::IntegerRange {
                        start: 100,
                        end: 200,
                        idx: 4,
                        little: true,
                        bits: 32,
                    }),
                },
            ),
        ];
        for (rule_type, rule) in cases {
            let resp = rule_to_response(&rule);
            assert!(
                resp.fields.is_some(),
                "expected decoded fields for rule_type {rule_type:#x}"
            );
            // Simulate a client round-trip: re-encode value from fields alone.
            let resp_via_fields = RuleResponse {
                rule_type: resp.rule_type,
                type_name: resp.type_name.clone(),
                not: resp.not,
                or_flag: resp.or_flag,
                value: vec![],
                fields: resp.fields.clone(),
            };
            let round_tripped = rule_from_response(&resp_via_fields);
            assert_eq!(
                round_tripped.value, rule.value,
                "mismatch for rule_type {rule_type:#x}"
            );
        }
    }
}
