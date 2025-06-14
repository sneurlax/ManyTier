//! Authentication middleware for the service REST API.
//!
//! Checks the X-ZT1-Auth header (or ?auth= query parameter) against
//! the configured auth token. Returns 401 Unauthorized on mismatch.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use super::AppState;

/// Middleware that validates the X-ZT1-Auth header or ?auth= query parameter.
///
/// All endpoints require authentication. The token is checked
/// against AppState.auth_token. Missing or invalid tokens return 401.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check X-ZT1-Auth header first
    let header_token = req
        .headers()
        .get("X-ZT1-Auth")
        .and_then(|v| v.to_str().ok());

    // Also check ?auth= query parameter as fallback
    let query_token = req
        .uri()
        .query()
        .and_then(|q| q.split('&').find(|p| p.starts_with("auth=")))
        .map(|p| &p[5..]);

    let provided = header_token.or(query_token);

    match provided {
        Some(t) if t == state.auth_token => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
