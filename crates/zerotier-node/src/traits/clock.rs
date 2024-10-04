/// Time source abstraction for the ZeroTier protocol engine.
///
/// Clock is NOT async -- time queries are synchronous on all platforms.
/// Native uses `std::time::Instant`/`SystemTime`, WASM uses `performance.now()`/`Date.now()`.
pub trait Clock: Send + Sync {
    /// Monotonic time in milliseconds (for measuring intervals, not wall clock).
    /// Must be non-decreasing. Zero point is arbitrary.
    fn now_monotonic_ms(&self) -> u64;

    /// Wall clock time in milliseconds since Unix epoch (for protocol timestamps).
    /// May jump backward (e.g., NTP correction). Used only for protocol fields
    /// that require real wall time.
    fn now_wall_ms(&self) -> u64;
}
