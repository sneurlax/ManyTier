//! JSON response types for the service REST API.
//!
//! These types are serialized directly to JSON for API responses.
//! Field names use camelCase via serde rename where needed to match
//! the official ZeroTier API format.

use serde::{Deserialize, Serialize};

/// Response for GET /status.
#[derive(Serialize)]
pub struct StatusResponse {
    pub address: String,
    pub version: String,
    pub online: bool,
    /// Full public identity string (address:0:pubkey_hex).
    #[serde(rename = "publicIdentity")]
    pub public_identity: String,
}

/// Response for GET /peer (each element in the array).
#[derive(Serialize)]
pub struct PeerResponse {
    pub address: String,
    pub paths: Vec<PathResponse>,
    pub latency: i64,
    /// "LEAF" or "ROOT".
    pub role: String,
}

/// A network path to a peer.
#[derive(Serialize)]
pub struct PathResponse {
    pub address: String,
    pub active: bool,
    /// Timestamp of last received packet on this path.
    #[serde(rename = "lastReceive")]
    pub last_receive: u64,
}

/// Response for GET /network and POST /network/{id}.
#[derive(Serialize)]
pub struct NetworkResponse {
    pub id: String,
    pub name: String,
    /// "OK" or "REQUESTING_CONFIGURATION".
    pub status: String,
    /// Assigned IP addresses with prefix length.
    #[serde(rename = "assignedAddresses")]
    pub assigned_addresses: Vec<String>,
    pub mac: String,
    pub mtu: u16,
}

// --- Controller API types (Plan 05) ---

/// Response for GET /controller/network/{nwid}.
#[derive(Serialize)]
pub struct ControllerNetworkResponse {
    pub id: String,
    pub name: String,
    /// Whether members must be explicitly authorized.
    pub private: bool,
    /// Creation time in milliseconds since epoch.
    #[serde(rename = "creationTime")]
    pub creation_time: u64,
    pub revision: u64,
    /// Maximum number of multicast recipients.
    #[serde(rename = "multicastLimit")]
    pub multicast_limit: u32,
    pub mtu: u16,
    /// IPv4 assignment mode, e.g., {"zt": true}.
    #[serde(rename = "v4AssignMode")]
    pub v4_assign_mode: serde_json::Value,
    /// IPv6 assignment mode, e.g., {"zt": false, "6plane": false, "rfc4193": false}.
    #[serde(rename = "v6AssignMode")]
    pub v6_assign_mode: serde_json::Value,
    /// IP auto-assignment pools.
    #[serde(rename = "ipAssignmentPools")]
    pub ip_assignment_pools: Vec<IpPoolResponse>,
    /// Whether broadcast is enabled.
    #[serde(rename = "enableBroadcast")]
    pub enable_broadcast: bool,
    pub routes: Vec<RouteResponse>,
}

/// An IP assignment pool range.
#[derive(Serialize, Deserialize)]
pub struct IpPoolResponse {
    /// Start of IP range as dotted-decimal string.
    #[serde(rename = "ipRangeStart")]
    pub ip_range_start: String,
    /// End of IP range as dotted-decimal string.
    #[serde(rename = "ipRangeEnd")]
    pub ip_range_end: String,
}

/// A managed route entry.
#[derive(Serialize, Deserialize)]
pub struct RouteResponse {
    pub target: String,
    /// Gateway address, or null for local routes.
    pub via: Option<String>,
}

/// Response for GET /controller/network/{nwid}/member/{nodeId}.
#[derive(Serialize)]
pub struct ControllerMemberResponse {
    pub id: String,
    /// 16-character hex network ID.
    #[serde(rename = "networkId")]
    pub network_id: String,
    pub authorized: bool,
    /// Assigned IP addresses with prefix length.
    #[serde(rename = "ipAssignments")]
    pub ip_assignments: Vec<String>,
    /// Creation time in milliseconds since epoch.
    #[serde(rename = "creationTime")]
    pub creation_time: u64,
    /// Last seen timestamp in milliseconds since epoch.
    #[serde(rename = "lastSeen")]
    pub last_seen: u64,
    pub name: String,
}

/// Request body for POST /controller/network/{nwid} (partial update).
#[derive(Deserialize)]
pub struct UpdateNetworkRequest {
    pub name: Option<String>,
    /// New privacy setting.
    pub private: Option<bool>,
    /// New multicast limit.
    #[serde(rename = "multicastLimit")]
    pub multicast_limit: Option<u32>,
    pub mtu: Option<u16>,
    /// New v4 assignment mode.
    #[serde(rename = "v4AssignMode")]
    pub v4_assign_mode: Option<serde_json::Value>,
    /// New IP assignment pools.
    #[serde(rename = "ipAssignmentPools")]
    pub ip_assignment_pools: Option<Vec<IpPoolResponse>>,
    pub routes: Option<Vec<RouteResponse>>,
    /// New broadcast setting.
    #[serde(rename = "enableBroadcast")]
    pub enable_broadcast: Option<bool>,
}

/// Request body for POST /controller/network/{nwid}/member/{nodeId} (partial update).
#[derive(Deserialize)]
pub struct UpdateMemberRequest {
    /// New authorization status.
    pub authorized: Option<bool>,
    /// New IP assignments.
    #[serde(rename = "ipAssignments")]
    pub ip_assignments: Option<Vec<String>>,
    pub name: Option<String>,
}
