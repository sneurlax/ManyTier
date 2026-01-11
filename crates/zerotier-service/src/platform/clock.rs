use zerotier_node::traits::Clock;

/// Native clock using std::time.
pub struct NativeClock {
    start: std::time::Instant,
}

impl NativeClock {
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }
}

impl Default for NativeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for NativeClock {
    fn now_monotonic_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn now_wall_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::NativeClock;
    use zerotier_node::traits::Clock;

    #[test]
    fn monotonic_time_is_non_decreasing() {
        let clock = NativeClock::new();
        let first = clock.now_monotonic_ms();
        let second = clock.now_monotonic_ms();

        assert!(second >= first);
    }

    #[test]
    fn wall_time_is_after_2024() {
        let clock = NativeClock::new();
        assert!(clock.now_wall_ms() > 1_700_000_000_000);
    }
}
