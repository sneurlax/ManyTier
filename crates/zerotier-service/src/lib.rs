//! Native ManyTier service.
//!
//! Runs the [`zerotier_node`] engine on real infrastructure: tokio UDP
//! transport, TUN/TAP devices, SQLite-backed controller storage, and the
//! ZeroTier-compatible local REST API. Native targets only.

pub mod api;
pub mod platform;
pub mod service;
pub mod storage;

pub use platform::transport::NativeTransport;
