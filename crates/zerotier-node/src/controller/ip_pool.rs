//! IP pool allocation logic for IPv4 auto-assignment.
//!
//! Iterates pool ranges, checking against assigned addresses.
//! Simple linear scan suitable for typical /24 pools.
//!
//! This module is no_std compatible (using alloc).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::types::IpPool;

/// Allocate the next available IPv4 address from a pool.
///
/// Takes a list of pools and a list of already-assigned IPs (as "a.b.c.d/prefix" strings).
/// Returns the first unassigned IP in any pool as `[u8; 4]`, or `None` if all full.
pub fn allocate_ipv4(pools: &[IpPool], assigned: &[String]) -> Option<[u8; 4]> {
    // Parse assigned IPs into a set of [u8; 4] for fast lookup
    let assigned_ips: Vec<[u8; 4]> = assigned
        .iter()
        .filter_map(|s| parse_ipv4_from_assignment(s))
        .collect();

    for pool in pools {
        let start = u32::from_be_bytes(pool.range_start);
        let end = u32::from_be_bytes(pool.range_end);
        for addr in start..=end {
            let ip_bytes = addr.to_be_bytes();
            if !assigned_ips.contains(&ip_bytes) {
                return Some(ip_bytes);
            }
        }
    }
    None
}

/// Parse "192.168.192.1/24" or "192.168.192.1" into `[u8; 4]`.
pub fn parse_ipv4_from_assignment(s: &str) -> Option<[u8; 4]> {
    let ip_part = s.split('/').next()?;
    let parts: Vec<&str> = ip_part.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    Some([
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
        parts[3].parse().ok()?,
    ])
}

/// Format `[u8; 4]` as "a.b.c.d" string.
pub fn format_ipv4(ip: [u8; 4]) -> String {
    alloc::format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;

    fn pool(start: [u8; 4], end: [u8; 4]) -> IpPool {
        IpPool {
            range_start: start,
            range_end: end,
        }
    }

    #[test]
    fn ip_pool_allocates_first_ip_when_none_assigned() {
        let pools = vec![pool([192, 168, 192, 1], [192, 168, 192, 254])];
        let assigned: Vec<String> = vec![];
        let result = allocate_ipv4(&pools, &assigned);
        assert_eq!(result, Some([192, 168, 192, 1]));
    }

    #[test]
    fn ip_pool_skips_assigned_ips() {
        let pools = vec![pool([10, 0, 0, 1], [10, 0, 0, 5])];
        let assigned = vec![
            String::from("10.0.0.1/24"),
            String::from("10.0.0.2/24"),
        ];
        let result = allocate_ipv4(&pools, &assigned);
        assert_eq!(result, Some([10, 0, 0, 3]));
    }

    #[test]
    fn ip_pool_returns_none_when_exhausted() {
        let pools = vec![pool([10, 0, 0, 1], [10, 0, 0, 2])];
        let assigned = vec![
            String::from("10.0.0.1/24"),
            String::from("10.0.0.2/24"),
        ];
        let result = allocate_ipv4(&pools, &assigned);
        assert_eq!(result, None);
    }

    #[test]
    fn ip_pool_falls_through_to_second_pool() {
        let pools = vec![
            pool([10, 0, 0, 1], [10, 0, 0, 1]), // single IP, will be full
            pool([172, 16, 0, 1], [172, 16, 0, 5]),
        ];
        let assigned = vec![String::from("10.0.0.1/24")];
        let result = allocate_ipv4(&pools, &assigned);
        assert_eq!(result, Some([172, 16, 0, 1]));
    }

    #[test]
    fn ip_pool_parse_with_prefix() {
        assert_eq!(
            parse_ipv4_from_assignment("192.168.1.100/24"),
            Some([192, 168, 1, 100])
        );
    }

    #[test]
    fn ip_pool_parse_without_prefix() {
        assert_eq!(
            parse_ipv4_from_assignment("10.0.0.1"),
            Some([10, 0, 0, 1])
        );
    }

    #[test]
    fn ip_pool_parse_invalid() {
        assert_eq!(parse_ipv4_from_assignment("not-an-ip"), None);
        assert_eq!(parse_ipv4_from_assignment("1.2.3"), None);
    }

    #[test]
    fn ip_pool_format_ipv4() {
        assert_eq!(format_ipv4([192, 168, 1, 1]), "192.168.1.1");
        assert_eq!(format_ipv4([10, 0, 0, 255]), "10.0.0.255");
    }
}
