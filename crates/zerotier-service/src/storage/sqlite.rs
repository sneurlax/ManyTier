//! SQLite-backed controller storage.
//!
//! Uses `rusqlite` with `bundled` feature for zero system dependencies.
//! All database operations run inside `tokio::task::spawn_blocking` to
//! avoid blocking the async runtime.

use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};
use zerotier_node::controller::storage::ControllerStorage;
use zerotier_node::controller::types::{IpPool, ManagedRoute, MemberRecord, NetworkRecord};

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
                revision INTEGER NOT NULL DEFAULT 0,
                last_authorized_time INTEGER NOT NULL DEFAULT 0,
                last_deauthorized_time INTEGER NOT NULL DEFAULT 0,
                active_bridge INTEGER NOT NULL DEFAULT 0,
                no_auto_assign_ips INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (network_id, node_id)
            );
            CREATE TABLE IF NOT EXISTS ip_pools (
                network_id INTEGER NOT NULL,
                range_start BLOB NOT NULL,
                range_end BLOB NOT NULL,
                PRIMARY KEY (network_id, range_start, range_end)
            );
            CREATE TABLE IF NOT EXISTS routes (
                network_id INTEGER NOT NULL,
                target TEXT NOT NULL,
                via TEXT,
                PRIMARY KEY (network_id, target)
            );",
        )?;
        Self::migrate_members_table(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Add columns introduced after the initial `members` table shape.
    ///
    /// `CREATE TABLE IF NOT EXISTS` only creates the table on first run, so a
    /// pre-existing database (e.g. a live deployment's `members` table) needs
    /// an explicit `ALTER TABLE` to pick up new columns.
    fn migrate_members_table(conn: &Connection) -> Result<(), SqliteStorageError> {
        let mut existing = std::collections::HashSet::new();
        {
            let mut stmt = conn.prepare("PRAGMA table_info(members)")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                existing.insert(name);
            }
        }
        let new_columns: &[(&str, &str)] = &[
            ("revision", "INTEGER NOT NULL DEFAULT 0"),
            ("last_authorized_time", "INTEGER NOT NULL DEFAULT 0"),
            ("last_deauthorized_time", "INTEGER NOT NULL DEFAULT 0"),
            ("active_bridge", "INTEGER NOT NULL DEFAULT 0"),
            ("no_auto_assign_ips", "INTEGER NOT NULL DEFAULT 0"),
        ];
        for (name, decl) in new_columns {
            if !existing.contains(*name) {
                conn.execute(&format!("ALTER TABLE members ADD COLUMN {name} {decl}"), [])?;
            }
        }
        Ok(())
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
                 last_seen, name, revision, last_authorized_time, last_deauthorized_time, \
                 active_bridge, no_auto_assign_ips \
                 FROM members WHERE network_id = ?1 AND node_id = ?2",
            )?;
            let result = stmt.query_row(params![network_id as i64, node_id.as_slice()], |row| {
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
                    row.get::<_, i64>(7)? as u64,
                    row.get::<_, i64>(8)? as u64,
                    row.get::<_, i64>(9)? as u64,
                    row.get::<_, i32>(10)? != 0,
                    row.get::<_, i32>(11)? != 0,
                ))
            });
            match result {
                Ok((
                    nw_id,
                    nid,
                    authorized,
                    ip_json,
                    creation_time,
                    last_seen,
                    name,
                    revision,
                    last_authorized_time,
                    last_deauthorized_time,
                    active_bridge,
                    no_auto_assign_ips,
                )) => {
                    let ip_assignments: Vec<String> = serde_json::from_str(&ip_json)?;
                    Ok(Some(MemberRecord {
                        network_id: nw_id,
                        node_id: nid,
                        authorized,
                        ip_assignments,
                        creation_time,
                        last_seen,
                        name,
                        revision,
                        last_authorized_time,
                        last_deauthorized_time,
                        active_bridge,
                        no_auto_assign_ips,
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
                 (network_id, node_id, authorized, ip_assignments, creation_time, last_seen, name, \
                  revision, last_authorized_time, last_deauthorized_time, active_bridge, \
                  no_auto_assign_ips) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    member.network_id as i64,
                    member.node_id.as_slice(),
                    member.authorized as i32,
                    ip_json,
                    member.creation_time as i64,
                    member.last_seen as i64,
                    member.name,
                    member.revision as i64,
                    member.last_authorized_time as i64,
                    member.last_deauthorized_time as i64,
                    member.active_bridge as i32,
                    member.no_auto_assign_ips as i32,
                ],
            )?;
            Ok(())
        })
        .await?
    }

    async fn delete_member(&self, network_id: u64, node_id: &[u8; 5]) -> Result<(), Self::Error> {
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
            let mut stmt = conn.prepare("SELECT node_id FROM members WHERE network_id = ?1")?;
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
            let mut stmt =
                conn.prepare("SELECT range_start, range_end FROM ip_pools WHERE network_id = ?1")?;
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

    async fn set_ip_pools(&self, network_id: u64, pools: &[IpPool]) -> Result<(), Self::Error> {
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
            let mut stmt =
                conn.prepare("SELECT ip_assignments FROM members WHERE network_id = ?1")?;
            let mut all_ips = Vec::new();
            let rows = stmt.query_map(params![network_id as i64], |row| row.get::<_, String>(0))?;
            for row in rows {
                let ip_json = row?;
                let ips: Vec<String> = serde_json::from_str(&ip_json).unwrap_or_default();
                all_ips.extend(ips);
            }
            Ok(all_ips)
        })
        .await?
    }

    async fn get_routes(&self, network_id: u64) -> Result<Vec<ManagedRoute>, Self::Error> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT target, via FROM routes WHERE network_id = ?1")?;
            let routes = stmt
                .query_map(params![network_id as i64], |row| {
                    Ok(ManagedRoute {
                        target: row.get(0)?,
                        via: row.get(1)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(routes)
        })
        .await?
    }

    async fn set_routes(
        &self,
        network_id: u64,
        routes: &[ManagedRoute],
    ) -> Result<(), Self::Error> {
        let routes: Vec<ManagedRoute> = routes.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = conn.lock().unwrap();
            let tx = conn.transaction()?;
            tx.execute(
                "DELETE FROM routes WHERE network_id = ?1",
                params![network_id as i64],
            )?;
            for route in &routes {
                tx.execute(
                    "INSERT INTO routes (network_id, target, via) VALUES (?1, ?2, ?3)",
                    params![network_id as i64, route.target, route.via],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_member(network_id: u64) -> MemberRecord {
        MemberRecord {
            network_id,
            node_id: [0xa0, 0xb1, 0xc2, 0xd3, 0xe4],
            authorized: true,
            ip_assignments: vec![String::from("192.168.192.1/24")],
            creation_time: 1000,
            last_seen: 2000,
            name: String::from("member"),
            revision: 3,
            last_authorized_time: 1500,
            last_deauthorized_time: 0,
            active_bridge: true,
            no_auto_assign_ips: true,
        }
    }

    #[tokio::test]
    async fn member_round_trips_new_fields() {
        let storage = SqliteStorage::new(":memory:").unwrap();
        let member = test_member(1);
        storage.upsert_member(&member).await.unwrap();

        let loaded = storage
            .get_member(1, &member.node_id)
            .await
            .unwrap()
            .expect("member should exist");

        assert_eq!(loaded.revision, 3);
        assert_eq!(loaded.last_authorized_time, 1500);
        assert_eq!(loaded.last_deauthorized_time, 0);
        assert!(loaded.active_bridge);
        assert!(loaded.no_auto_assign_ips);
    }

    #[test]
    fn migrate_members_table_adds_missing_columns_to_legacy_schema() {
        let conn = Connection::open_in_memory().unwrap();
        // Recreate the pre-migration members table shape (no new columns).
        conn.execute_batch(
            "CREATE TABLE members (
                network_id INTEGER NOT NULL,
                node_id BLOB NOT NULL,
                authorized INTEGER NOT NULL,
                ip_assignments TEXT NOT NULL,
                creation_time INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                name TEXT NOT NULL,
                PRIMARY KEY (network_id, node_id)
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO members (network_id, node_id, authorized, ip_assignments, \
             creation_time, last_seen, name) VALUES (1, X'aabbccddee', 1, '[]', 10, 20, 'n')",
            [],
        )
        .unwrap();

        SqliteStorage::migrate_members_table(&conn).unwrap();

        let (revision, active_bridge): (i64, i32) = conn
            .query_row(
                "SELECT revision, active_bridge FROM members WHERE network_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(revision, 0);
        assert_eq!(active_bridge, 0);

        // Running the migration again on an already-migrated table must not error.
        SqliteStorage::migrate_members_table(&conn).unwrap();
    }
}
