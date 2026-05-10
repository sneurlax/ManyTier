//! GET/POST/DELETE /moon handlers.
//!
//! Orbiting is file-based: `POST /moon/{id}` loads
//! `{data-dir}/moons.d/{id:016x}.moon` into the live topology, so the moon
//! file must be placed there first (matching official ZeroTier's moons.d
//! distribution model). `DELETE /moon/{id}` removes the moon's roots from the
//! topology but leaves the file in place for later re-orbit.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use std::sync::Arc;
use zerotier_protocol::world::{World, WorldType};

use super::AppState;

#[derive(Serialize)]
pub struct MoonResponse {
    pub id: String,
    pub timestamp: u64,
    pub roots: Vec<MoonRootResponse>,
}

#[derive(Serialize)]
pub struct MoonRootResponse {
    pub address: String,
    pub endpoints: Vec<String>,
}

fn world_to_response(world: &World) -> MoonResponse {
    MoonResponse {
        id: format!("{:016x}", world.id),
        timestamp: world.timestamp,
        roots: world
            .roots
            .iter()
            .map(|root| {
                let a = root.identity.address.as_bytes();
                MoonRootResponse {
                    address: format!(
                        "{:02x}{:02x}{:02x}{:02x}{:02x}",
                        a[0], a[1], a[2], a[3], a[4]
                    ),
                    endpoints: root
                        .endpoints
                        .iter()
                        .filter_map(|e| e.to_socket_addr())
                        .map(|s| s.to_string())
                        .collect(),
                }
            })
            .collect(),
    }
}

/// List currently loaded moons.
pub async fn list_moons(State(state): State<Arc<AppState>>) -> Json<Vec<MoonResponse>> {
    let node = state.node.lock().await;
    Json(node.topology.moons.iter().map(world_to_response).collect())
}

/// Orbit a moon: load `{data-dir}/moons.d/{id:016x}.moon` into the topology.
pub async fn orbit_moon(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<MoonResponse>, StatusCode> {
    let moon_id = u64::from_str_radix(&id, 16).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut node = state.node.lock().await;
    if let Some(existing) = node.topology.moons.iter().find(|m| m.id == moon_id) {
        // Idempotent: already orbiting.
        return Ok(Json(world_to_response(existing)));
    }

    let path = std::path::PathBuf::from(&state.data_dir)
        .join("moons.d")
        .join(format!("{:016x}.moon", moon_id));
    let bytes = std::fs::read(&path).map_err(|_| StatusCode::NOT_FOUND)?;
    let world = World::deserialize(&bytes).map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
    if world.world_type != WorldType::Moon || world.id != moon_id {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }

    let response = world_to_response(&world);
    node.topology
        .load_moon(world)
        .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
    tracing::info!(
        moon = %format!("{:016x}", moon_id),
        roots = response.roots.len(),
        "orbiting moon"
    );
    Ok(Json(response))
}

/// Deorbit a moon: remove its roots from the live topology.
pub async fn deorbit_moon(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let moon_id = u64::from_str_radix(&id, 16).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut node = state.node.lock().await;
    if node.topology.unload_moon(moon_id) {
        tracing::info!(moon = %format!("{:016x}", moon_id), "deorbited moon");
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
