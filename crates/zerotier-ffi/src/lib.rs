//! C ABI bindings for the ManyTier node engine.
//!
//! Builds as a `cdylib` for embedding the node in non-Rust hosts. This is
//! the only crate in the workspace permitted to use `unsafe` (required for
//! the C ABI surface).
