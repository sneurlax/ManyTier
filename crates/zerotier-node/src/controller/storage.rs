//! Controller storage trait for network/member/IP pool persistence.
//!
//! This trait is no_std compatible (using alloc) and defines the CRUD
//! operations that any controller storage backend must implement.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::types::{IpPool, MemberRecord, NetworkRecord};

/// Trait for controller storage backends.
///
/// Implementations include SQLite (production), in-memory (testing),
/// and filesystem (fallback). All methods are async to support both
/// native (tokio) and WASM backends.
pub trait ControllerStorage: Send + Sync {
    /// Error type for storage operations.
    type Error: core::fmt::Debug + core::fmt::Display;

    /// Get a network by ID.
    async fn get_network(&self, id: u64) -> Result<Option<NetworkRecord>, Self::Error>;

    /// Create a new network record.
    async fn create_network(&self, network: &NetworkRecord) -> Result<(), Self::Error>;

    /// Update an existing network record.
    async fn update_network(&self, network: &NetworkRecord) -> Result<(), Self::Error>;

    /// Delete a network by ID.
    async fn delete_network(&self, id: u64) -> Result<(), Self::Error>;

    /// List all network IDs.
    async fn list_networks(&self) -> Result<Vec<u64>, Self::Error>;

    /// Get a member by network ID and node ID.
    async fn get_member(
        &self,
        network_id: u64,
        node_id: &[u8; 5],
    ) -> Result<Option<MemberRecord>, Self::Error>;

    /// Insert or update a member record.
    async fn upsert_member(&self, member: &MemberRecord) -> Result<(), Self::Error>;

    /// Delete a member from a network.
    async fn delete_member(
        &self,
        network_id: u64,
        node_id: &[u8; 5],
    ) -> Result<(), Self::Error>;

    /// List all member node IDs in a network.
    async fn list_members(&self, network_id: u64) -> Result<Vec<[u8; 5]>, Self::Error>;

    /// Get all IP pools for a network.
    async fn get_ip_pools(&self, network_id: u64) -> Result<Vec<IpPool>, Self::Error>;

    /// Set (replace) all IP pools for a network.
    async fn set_ip_pools(&self, network_id: u64, pools: &[IpPool]) -> Result<(), Self::Error>;

    /// Get all assigned IPs across all members in a network.
    async fn get_assigned_ips(&self, network_id: u64) -> Result<Vec<String>, Self::Error>;
}
