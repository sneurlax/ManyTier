//! In-memory controller storage for testing and lightweight use.

use std::sync::Mutex;

use zerotier_node::controller::storage::ControllerStorage;
use zerotier_node::controller::types::{IpPool, ManagedRoute, MemberRecord, NetworkRecord};

/// In-memory storage error.
#[derive(Debug, thiserror::Error)]
pub enum MemoryStorageError {
    #[error("not found")]
    NotFound,
}

struct InMemoryState {
    networks: Vec<NetworkRecord>,
    members: Vec<MemberRecord>,
    ip_pools: Vec<(u64, IpPool)>,
    routes: Vec<(u64, ManagedRoute)>,
}

/// In-memory controller storage backend.
///
/// All operations are linear scans, adequate for tests and lightweight use.
pub struct InMemoryStorage {
    state: Mutex<InMemoryState>,
}

impl InMemoryStorage {
    /// Create a new empty in-memory storage.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(InMemoryState {
                networks: Vec::new(),
                members: Vec::new(),
                ip_pools: Vec::new(),
                routes: Vec::new(),
            }),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl ControllerStorage for InMemoryStorage {
    type Error = MemoryStorageError;

    async fn get_network(&self, id: u64) -> Result<Option<NetworkRecord>, Self::Error> {
        let state = self.state.lock().unwrap();
        Ok(state.networks.iter().find(|n| n.id == id).cloned())
    }

    async fn create_network(&self, network: &NetworkRecord) -> Result<(), Self::Error> {
        let mut state = self.state.lock().unwrap();
        state.networks.push(network.clone());
        Ok(())
    }

    async fn update_network(&self, network: &NetworkRecord) -> Result<(), Self::Error> {
        let mut state = self.state.lock().unwrap();
        if let Some(existing) = state.networks.iter_mut().find(|n| n.id == network.id) {
            *existing = network.clone();
            Ok(())
        } else {
            Err(MemoryStorageError::NotFound)
        }
    }

    async fn delete_network(&self, id: u64) -> Result<(), Self::Error> {
        let mut state = self.state.lock().unwrap();
        state.networks.retain(|n| n.id != id);
        state.members.retain(|m| m.network_id != id);
        state.ip_pools.retain(|(nid, _)| *nid != id);
        state.routes.retain(|(nid, _)| *nid != id);
        Ok(())
    }

    async fn list_networks(&self) -> Result<Vec<u64>, Self::Error> {
        let state = self.state.lock().unwrap();
        Ok(state.networks.iter().map(|n| n.id).collect())
    }

    async fn get_member(
        &self,
        network_id: u64,
        node_id: &[u8; 5],
    ) -> Result<Option<MemberRecord>, Self::Error> {
        let state = self.state.lock().unwrap();
        Ok(state
            .members
            .iter()
            .find(|m| m.network_id == network_id && m.node_id == *node_id)
            .cloned())
    }

    async fn upsert_member(&self, member: &MemberRecord) -> Result<(), Self::Error> {
        let mut state = self.state.lock().unwrap();
        if let Some(existing) = state
            .members
            .iter_mut()
            .find(|m| m.network_id == member.network_id && m.node_id == member.node_id)
        {
            *existing = member.clone();
        } else {
            state.members.push(member.clone());
        }
        Ok(())
    }

    async fn delete_member(&self, network_id: u64, node_id: &[u8; 5]) -> Result<(), Self::Error> {
        let mut state = self.state.lock().unwrap();
        state
            .members
            .retain(|m| !(m.network_id == network_id && m.node_id == *node_id));
        Ok(())
    }

    async fn list_members(&self, network_id: u64) -> Result<Vec<[u8; 5]>, Self::Error> {
        let state = self.state.lock().unwrap();
        Ok(state
            .members
            .iter()
            .filter(|m| m.network_id == network_id)
            .map(|m| m.node_id)
            .collect())
    }

    async fn get_ip_pools(&self, network_id: u64) -> Result<Vec<IpPool>, Self::Error> {
        let state = self.state.lock().unwrap();
        Ok(state
            .ip_pools
            .iter()
            .filter(|(nid, _)| *nid == network_id)
            .map(|(_, pool)| pool.clone())
            .collect())
    }

    async fn set_ip_pools(&self, network_id: u64, pools: &[IpPool]) -> Result<(), Self::Error> {
        let mut state = self.state.lock().unwrap();
        state.ip_pools.retain(|(nid, _)| *nid != network_id);
        for pool in pools {
            state.ip_pools.push((network_id, pool.clone()));
        }
        Ok(())
    }

    async fn get_assigned_ips(&self, network_id: u64) -> Result<Vec<String>, Self::Error> {
        let state = self.state.lock().unwrap();
        let mut all_ips = Vec::new();
        for member in state.members.iter().filter(|m| m.network_id == network_id) {
            all_ips.extend(member.ip_assignments.clone());
        }
        Ok(all_ips)
    }

    async fn get_routes(&self, network_id: u64) -> Result<Vec<ManagedRoute>, Self::Error> {
        let state = self.state.lock().unwrap();
        Ok(state
            .routes
            .iter()
            .filter(|(nid, _)| *nid == network_id)
            .map(|(_, route)| route.clone())
            .collect())
    }

    async fn set_routes(
        &self,
        network_id: u64,
        routes: &[ManagedRoute],
    ) -> Result<(), Self::Error> {
        let mut state = self.state.lock().unwrap();
        state.routes.retain(|(nid, _)| *nid != network_id);
        for route in routes {
            state.routes.push((network_id, route.clone()));
        }
        Ok(())
    }
}
