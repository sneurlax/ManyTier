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
