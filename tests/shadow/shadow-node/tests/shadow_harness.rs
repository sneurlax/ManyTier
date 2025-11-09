//! Shadow test harness integration test.
//!
//! Run with: cargo test -p shadow-node --test shadow_harness -- --ignored
//!
//! Prerequisites:
//! - Shadow installed (e.g., ~/.local/bin/shadow or on PATH)
//! - cargo build --release -p shadow-node

// Include the shared harness module
#[path = "../../harness.rs"]
mod harness;
