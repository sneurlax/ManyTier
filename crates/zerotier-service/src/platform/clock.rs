use zerotier_node::traits::Clock;

/// Native clock using std::time.
pub struct NativeClock;

impl Clock for NativeClock {
    fn now_monotonic_ms(&self) -> u64 {
        todo!("native clock")
    }

    fn now_wall_ms(&self) -> u64 {
        todo!("native clock")
    }
}
