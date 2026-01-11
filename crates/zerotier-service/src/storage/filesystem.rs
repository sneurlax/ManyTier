//! Filesystem-backed controller storage using JSON files.
//!
//! Directory layout:
//! - `{base}/networks/{network_id_hex}.json`
//! - `{base}/members/{network_id_hex}/{node_id_hex}.json`
//! - `{base}/pools/{network_id_hex}.json`

use std::path::PathBuf;

use zerotier_node::controller::storage::ControllerStorage;
use zerotier_node::controller::types::{IpPool, ManagedRoute, MemberRecord, NetworkRecord};

/// Filesystem storage error.
#[derive(Debug, thiserror::Error)]
pub enum FsStorageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Filesystem-backed controller storage.
///
/// Each record is stored as a JSON file on disk, suitable as a
/// fallback backend when SQLite is not desired.
pub struct FilesystemStorage {
    base_dir: PathBuf,
}

impl FilesystemStorage {
    /// Create a new filesystem storage rooted at the given directory.
    ///
    /// Creates the base directory and subdirectories if they do not exist.
    pub async fn new(base_dir: &str) -> Result<Self, FsStorageError> {
        let base = PathBuf::from(base_dir);
        tokio::fs::create_dir_all(base.join("networks")).await?;
        tokio::fs::create_dir_all(base.join("members")).await?;
        tokio::fs::create_dir_all(base.join("pools")).await?;
        tokio::fs::create_dir_all(base.join("routes")).await?;
        Ok(Self { base_dir: base })
    }

    fn network_path(&self, id: u64) -> PathBuf {
        self.base_dir
            .join("networks")
            .join(format!("{:016x}.json", id))
    }

    fn member_dir(&self, network_id: u64) -> PathBuf {
        self.base_dir
            .join("members")
            .join(format!("{:016x}", network_id))
    }

    fn member_path(&self, network_id: u64, node_id: &[u8; 5]) -> PathBuf {
        self.member_dir(network_id)
            .join(format!("{}.json", hex_encode_5(node_id)))
    }

    fn pools_path(&self, network_id: u64) -> PathBuf {
        self.base_dir
            .join("pools")
            .join(format!("{:016x}.json", network_id))
    }

    fn routes_path(&self, network_id: u64) -> PathBuf {
        self.base_dir
            .join("routes")
            .join(format!("{:016x}.json", network_id))
    }
}

fn hex_encode_5(bytes: &[u8; 5]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4]
    )
}

fn hex_decode_5(s: &str) -> Option<[u8; 5]> {
    if s.len() != 10 {
        return None;
    }
    let mut out = [0u8; 5];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl ControllerStorage for FilesystemStorage {
    type Error = FsStorageError;

    async fn get_network(&self, id: u64) -> Result<Option<NetworkRecord>, Self::Error> {
        let path = self.network_path(id);
        match tokio::fs::read_to_string(&path).await {
            Ok(data) => Ok(Some(serde_json::from_str(&data)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn create_network(&self, network: &NetworkRecord) -> Result<(), Self::Error> {
        let path = self.network_path(network.id);
        let data = serde_json::to_string_pretty(network)?;
        tokio::fs::write(&path, data).await?;
        Ok(())
    }

    async fn update_network(&self, network: &NetworkRecord) -> Result<(), Self::Error> {
        self.create_network(network).await
    }

    async fn delete_network(&self, id: u64) -> Result<(), Self::Error> {
        let path = self.network_path(id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        // Also clean up members, pools, and routes for this network
        let member_dir = self.member_dir(id);
        let _ = tokio::fs::remove_dir_all(&member_dir).await;
        let pools_path = self.pools_path(id);
        let _ = tokio::fs::remove_file(&pools_path).await;
        let routes_path = self.routes_path(id);
        let _ = tokio::fs::remove_file(&routes_path).await;
        Ok(())
    }

    async fn list_networks(&self) -> Result<Vec<u64>, Self::Error> {
        let dir = self.base_dir.join("networks");
        let mut ids = Vec::new();
        let mut entries = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(hex) = name.strip_suffix(".json") {
                if let Ok(id) = u64::from_str_radix(hex, 16) {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    async fn get_member(
        &self,
        network_id: u64,
        node_id: &[u8; 5],
    ) -> Result<Option<MemberRecord>, Self::Error> {
        let path = self.member_path(network_id, node_id);
        match tokio::fs::read_to_string(&path).await {
            Ok(data) => Ok(Some(serde_json::from_str(&data)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn upsert_member(&self, member: &MemberRecord) -> Result<(), Self::Error> {
        let dir = self.member_dir(member.network_id);
        tokio::fs::create_dir_all(&dir).await?;
        let path = self.member_path(member.network_id, &member.node_id);
        let data = serde_json::to_string_pretty(member)?;
        tokio::fs::write(&path, data).await?;
        Ok(())
    }

    async fn delete_member(&self, network_id: u64, node_id: &[u8; 5]) -> Result<(), Self::Error> {
        let path = self.member_path(network_id, node_id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn list_members(&self, network_id: u64) -> Result<Vec<[u8; 5]>, Self::Error> {
        let dir = self.member_dir(network_id);
        let mut ids = Vec::new();
        match tokio::fs::read_dir(&dir).await {
            Ok(mut entries) => {
                while let Some(entry) = entries.next_entry().await? {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if let Some(hex) = name.strip_suffix(".json") {
                        if let Some(nid) = hex_decode_5(hex) {
                            ids.push(nid);
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(ids)
    }

    async fn get_ip_pools(&self, network_id: u64) -> Result<Vec<IpPool>, Self::Error> {
        let path = self.pools_path(network_id);
        match tokio::fs::read_to_string(&path).await {
            Ok(data) => Ok(serde_json::from_str(&data)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    async fn set_ip_pools(&self, network_id: u64, pools: &[IpPool]) -> Result<(), Self::Error> {
        let path = self.pools_path(network_id);
        let data = serde_json::to_string_pretty(pools)?;
        tokio::fs::write(&path, data).await?;
        Ok(())
    }

    async fn get_assigned_ips(&self, network_id: u64) -> Result<Vec<String>, Self::Error> {
        let members = self.list_members(network_id).await?;
        let mut all_ips = Vec::new();
        for nid in &members {
            if let Some(member) = self.get_member(network_id, nid).await? {
                all_ips.extend(member.ip_assignments);
            }
        }
        Ok(all_ips)
    }

    async fn get_routes(&self, network_id: u64) -> Result<Vec<ManagedRoute>, Self::Error> {
        let path = self.routes_path(network_id);
        match tokio::fs::read_to_string(&path).await {
            Ok(data) => Ok(serde_json::from_str(&data)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    async fn set_routes(
        &self,
        network_id: u64,
        routes: &[ManagedRoute],
    ) -> Result<(), Self::Error> {
        let path = self.routes_path(network_id);
        let data = serde_json::to_string_pretty(routes)?;
        tokio::fs::write(&path, data).await?;
        Ok(())
    }
}
