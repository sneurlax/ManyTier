/// WASM stub implementations of platform traits.
///
/// These compile when neither `native` nor `wasm` feature is active
/// (bare no_std mode, including `cargo check --target wasm32-unknown-unknown --no-default-features`).
/// They serve as compile-time API contract validation: every trait method must have
/// a matching stub, so the trait signatures are proven correct before protocol code depends on them.
#[cfg(not(any(feature = "native", feature = "wasm")))]
pub mod wasm_stubs;
