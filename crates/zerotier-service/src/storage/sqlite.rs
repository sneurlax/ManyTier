//! SQLite-backed controller storage.
//!
//! Uses `rusqlite` with `bundled` feature for zero system dependencies.
//! All database operations run inside `tokio::task::spawn_blocking` to
//! avoid blocking the async runtime.

use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};
use zerotier_node::controller::storage::ControllerStorage;
use zerotier_node::controller::types::{IpPool, MemberRecord, NetworkRecord};

/// SQLite-backed controller storage error.
#[derive(Debug, thiserror::Error)]
pub enum SqliteStorageError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
}

/// SQLite-backed controller storage.
pub struct SqliteStorage {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStorage {
    /// Open or create a SQLite database at the given path.
    ///
    /// Creates the schema tables if they do not already exist.
    pub fn new(path: &str) -> Result<Self, SqliteStorageError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                private INTEGER NOT NULL,
                creation_time INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                multicast_limit INTEGER NOT NULL,
                mtu INTEGER NOT NULL,
                v4_assign_mode TEXT NOT NULL,
                v6_assign_mode TEXT NOT NULL,
                rules_source BLOB NOT NULL,
                enable_broadcast INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS members (
                network_id INTEGER NOT NULL,
                node_id BLOB NOT NULL,
                authorized INTEGER NOT NULL,
                ip_assignments TEXT NOT NULL,
                creation_time INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                name TEXT NOT NULL,
                PRIMARY KEY (network_id, node_id)
            );
            CREATE TABLE IF NOT EXISTS ip_pools (
                network_id INTEGER NOT NULL,
                range_start BLOB NOT NULL,
                range_end BLOB NOT NULL,
                PRIMARY KEY (network_id, range_start, range_end)
            );",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

impl ControllerStorage for SqliteStorage {
    type Error = SqliteStorageError;

    async fn get_network(&self, id: u64) -> Result<Option<NetworkRecord>, Self::Error> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, name, private, creation_time, revision, multicast_limit, \
                 mtu, v4_assign_mode, v6_assign_mode, rules_source, enable_broadcast \
                 FROM networks WHERE id = ?1",
            )?;
            let result = stmt.query_row(params![id as i64], |row| {
                Ok(NetworkRecord {
                    id: row.get::<_, i64>(0)? as u64,
                    name: row.get(1)?,
                    private: row.get::<_, i32>(2)? != 0,
                    creation_time: row.get::<_, i64>(3)? as u64,
                    revision: row.get::<_, i64>(4)? as u64,
                    multicast_limit: row.get::<_, i32>(5)? as u32,
                    mtu: row.get::<_, i32>(6)? as u16,
                    v4_assign_mode: row.get(7)?,
                    v6_assign_mode: row.get(8)?,
                    rules_source: row.get(9)?,
                    enable_broadcast: row.get::<_, i32>(10)? != 0,
                })
            });
            match result {
                Ok(record) => Ok(Some(record)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(SqliteStorageError::Sqlite(e)),
            }
        })
        .await?
    }

    async fn create_network(&self, network: &NetworkRecord) -> Result<(), Self::Error> {
        let network = network.clone();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO networks (id, name, private, creation_time, revision, \
                 multicast_limit, mtu, v4_assign_mode, v6_assign_mode, rules_source, \
                 enable_broadcast) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    network.id as i64,
                    network.name,
                    network.private as i32,
                    network.creation_time as i64,
                    network.revision as i64,
                    network.multicast_limit as i32,
                    network.mtu as i32,
                    network.v4_assign_mode,
                    network.v6_assign_mode,
                    network.rules_source,
                    network.enable_broadcast as i32,
                ],
            )?;
            Ok(())
        })
        .await?
    }

    async fn update_network(&self, network: &NetworkRecord) -> Result<(), Self::Error> {
        let network = network.clone();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE networks SET name = ?2, private = ?3, creation_time = ?4, \
                 revision = ?5, multicast_limit = ?6, mtu = ?7, v4_assign_mode = ?8, \
                 v6_assign_mode = ?9, rules_source = ?10, enable_broadcast = ?11 \
                 WHERE id = ?1",
                params![
                    network.id as i64,
                    network.name,
                    network.private as i32,
                    network.creation_time as i64,
                    network.revision as i64,
                    network.multicast_limit as i32,
                    network.mtu as i32,
                    network.v4_assign_mode,
                    network.v6_assign_mode,
                    network.rules_source,
                    network.enable_broadcast as i32,
                ],
            )?;
            Ok(())
        })
        .await?
    }

    async fn delete_network(&self, id: u64) -> Result<(), Self::Error> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute("DELETE FROM networks WHERE id = ?1", params![id as i64])?;
            Ok(())
        })
        .await?
    }

    async fn list_networks(&self) -> Result<Vec<u64>, Self::Error> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT id FROM networks")?;
            let ids = stmt
                .query_map([], |row| row.get::<_, i64>(0).map(|id| id as u64))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ids)
        })
        .await?
    }

    async fn get_member(
        &self,
        network_id: u64,
        node_id: &[u8; 5],
    ) -> Result<Option<MemberRecord>, Self::Error> {
        let conn = self.conn.clone();
        let node_id = *node_id;
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT network_id, node_id, authorized, ip_assignments, creation_time, \
                 last_seen, name FROM members WHERE network_id = ?1 AND node_id = ?2",
            )?;
            let result = stmt.query_row(
                params![network_id as i64, node_id.as_slice()],
                |row| {
                    let node_blob: Vec<u8> = row.get(1)?;
                    let mut nid = [0u8; 5];
                    nid.copy_from_slice(&node_blob[..5]);
                    let ip_json: String = row.get(3)?;
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        nid,
                        row.get::<_, i32>(2)? != 0,
                        ip_json,
                        row.get::<_, i64>(4)? as u64,
                        row.get::<_, i64>(5)? as u64,
                        row.get::<_, String>(6)?,
                    ))
                },
            );
            match result {
                Ok((nw_id, nid, authorized, ip_json, creation_time, last_seen, name)) => {
                    let ip_assignments: Vec<String> = serde_json::from_str(&ip_json)?;
                    Ok(Some(MemberRecord {
                        network_id: nw_id,
                        node_id: nid,
                        authorized,
                        ip_assignments,
                        creation_time,
                        last_seen,
                        name,
                    }))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(SqliteStorageError::Sqlite(e)),
            }
        })
        .await?
    }

    async fn upsert_member(&self, member: &MemberRecord) -> Result<(), Self::Error> {
        let member = member.clone();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let ip_json = serde_json::to_string(&member.ip_assignments)?;
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO members \
                 (network_id, node_id, authorized, ip_assignments, creation_time, last_seen, name) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    member.network_id as i64,
                    member.node_id.as_slice(),
                    member.authorized as i32,
                    ip_json,
                    member.creation_time as i64,
                    member.last_seen as i64,
                    member.name,
                ],
            )?;
            Ok(())
        })
        .await?
    }

    async fn delete_member(
        &self,
        network_id: u64,
        node_id: &[u8; 5],
    ) -> Result<(), Self::Error> {
        let conn = self.conn.clone();
        let node_id = *node_id;
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "DELETE FROM members WHERE network_id = ?1 AND node_id = ?2",
                params![network_id as i64, node_id.as_slice()],
            )?;
            Ok(())
        })
        .await?
    }

    async fn list_members(&self, network_id: u64) -> Result<Vec<[u8; 5]>, Self::Error> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt =
                conn.prepare("SELECT node_id FROM members WHERE network_id = ?1")?;
            let ids = stmt
                .query_map(params![network_id as i64], |row| {
                    let blob: Vec<u8> = row.get(0)?;
                    let mut nid = [0u8; 5];
                    nid.copy_from_slice(&blob[..5]);
                    Ok(nid)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ids)
        })
        .await?
    }

    async fn get_ip_pools(&self, network_id: u64) -> Result<Vec<IpPool>, Self::Error> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT range_start, range_end FROM ip_pools WHERE network_id = ?1",
            )?;
            let pools = stmt
                .query_map(params![network_id as i64], |row| {
                    let start: Vec<u8> = row.get(0)?;
                    let end: Vec<u8> = row.get(1)?;
                    let mut rs = [0u8; 4];
                    let mut re = [0u8; 4];
                    rs.copy_from_slice(&start[..4]);
                    re.copy_from_slice(&end[..4]);
                    Ok(IpPool {
                        range_start: rs,
                        range_end: re,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(pools)
        })
        .await?
    }

    async fn set_ip_pools(
        &self,
        network_id: u64,
        pools: &[IpPool],
    ) -> Result<(), Self::Error> {
        let pools: Vec<IpPool> = pools.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "DELETE FROM ip_pools WHERE network_id = ?1",
                params![network_id as i64],
            )?;
            for pool in &pools {
                conn.execute(
                    "INSERT INTO ip_pools (network_id, range_start, range_end) \
                     VALUES (?1, ?2, ?3)",
                    params![
                        network_id as i64,
                        pool.range_start.as_slice(),
                        pool.range_end.as_slice(),
                    ],
                )?;
            }
            Ok(())
        })
        .await?
    }

    async fn get_assigned_ips(&self, network_id: u64) -> Result<Vec<String>, Self::Error> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT ip_assignments FROM members WHERE network_id = ?1",
            )?;
            let mut all_ips = Vec::new();
            let rows = stmt.query_map(params![network_id as i64], |row| {
                row.get::<_, String>(0)
            })?;
            for row in rows {
                let ip_json = row?;
                let ips: Vec<String> = serde_json::from_str(&ip_json)
                    .unwrap_or_default();
                all_ips.extend(ips);
            }
            Ok(all_ips)
        })
        .await?
    }
}
