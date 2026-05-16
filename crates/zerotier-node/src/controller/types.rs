//! Controller data types for network and member records.
//!
//! These types are no_std compatible (using alloc) and represent the
//! controller's view of networks, members, and IP pools.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// A network record as stored by the controller.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkRecord {
    pub id: u64,
    pub name: String,
    /// If true, members must be explicitly authorized
    pub private: bool,
    /// Milliseconds since epoch
    pub creation_time: u64,
    pub revision: u64,
    /// Maximum number of multicast recipients
    pub multicast_limit: u32,
    pub mtu: u16,
    pub v4_assign_mode: String,
    /// IPv6 assignment mode: "none", "zt", "6plane", "rfc4193"
    pub v6_assign_mode: String,
    /// Raw rules binary
    pub rules_source: Vec<u8>,
    /// Whether broadcast is enabled
    pub enable_broadcast: bool,
}

/// A member record as stored by the controller.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemberRecord {
    pub network_id: u64,
    /// ZeroTier 5-byte address
    pub node_id: [u8; 5],
    pub authorized: bool,
    pub ip_assignments: Vec<String>,
    /// Milliseconds since epoch
    pub creation_time: u64,
    pub last_seen: u64,
    pub name: String,
    /// Incremented on every update; used for optimistic-concurrency-style clients.
    pub revision: u64,
    /// Milliseconds since epoch of the most recent authorization, or 0 if never authorized.
    pub last_authorized_time: u64,
    /// Milliseconds since epoch of the most recent deauthorization, or 0 if never deauthorized.
    pub last_deauthorized_time: u64,
    /// Whether this member acts as an active bridge for the network.
    pub active_bridge: bool,
    /// If true, this member does not receive IPs from the network's auto-assign pools.
    pub no_auto_assign_ips: bool,
}

/// An IPv4 address pool for auto-assignment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IpPool {
    pub range_start: [u8; 4],
    pub range_end: [u8; 4],
}

/// A managed route entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManagedRoute {
    pub target: String,
    pub via: Option<String>,
}
