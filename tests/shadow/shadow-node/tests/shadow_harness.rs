//! Shadow test harness integration test.
//!
//! Run with: cargo test -p shadow-node --test shadow_harness -- --ignored
//! Full strict live validation is opt-in via
//! `MANYTIER_PRIVILEGED_LIVE=1 tests/shadow/run-privileged-live.sh`.
//!
//! Prerequisites:
//! - Shadow installed (e.g., ~/.local/bin/shadow or on PATH)
//! - cargo build --release -p shadow-node

// Include the shared harness module
#[path = "../../harness.rs"]
mod harness;
