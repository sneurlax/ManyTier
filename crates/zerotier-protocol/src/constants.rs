// ZeroTier V1 protocol constants. Values match official implementation.

// --- Protocol version ---

/// Current protocol version (V1).
pub const ZT_PROTO_VERSION: u8 = 13;

/// Minimum supported protocol version.
pub const ZT_PROTO_VERSION_MIN: u8 = 4;

// --- Packet sizes ---

/// Minimum valid packet length (28 bytes: 8 IV + 5 dest + 5 source + 1 flags + 8 MAC + 1 verb).
pub const ZT_PROTO_MIN_PACKET_LENGTH: usize = 28;

/// Minimum valid fragment length (16 bytes: 8 packet_id + 5 dest + 1 indicator + 1 fragment_info + 1 hops).
pub const ZT_PROTO_MIN_FRAGMENT_LENGTH: usize = 16;

/// Maximum number of fragments per packet.
pub const ZT_MAX_PACKET_FRAGMENTS: usize = 7;

/// Maximum relay hops.
pub const ZT_RELAY_MAX_HOPS: u8 = 3;

/// Default MTU for ZeroTier virtual networks.
pub const ZT_DEFAULT_MTU: usize = 2800;

/// Number of Salsa20 rounds used for packet encryption.
pub const ZT_PROTO_SALSA20_ROUNDS: u32 = 12;

// --- Cipher suites ---

/// Cipher suite: C25519/Poly1305 with no payload encryption (MAC only).
pub const CIPHER_SUITE_C25519_POLY1305_NONE: u8 = 0;

/// Cipher suite: C25519/Poly1305 with Salsa20/12 payload encryption.
pub const CIPHER_SUITE_C25519_POLY1305_SALSA2012: u8 = 1;

pub const CIPHER_SUITE_NO_CRYPTO_TRUSTED_PATH: u8 = 2;

pub const CIPHER_SUITE_AES_GMAC_SIV: u8 = 3;

// --- Packet flags ---

pub const FLAG_FRAGMENTED: u8 = 0x40;

pub const FLAG_EXTENDED_ARMOR: u8 = 0x80;

pub const VERB_FLAG_COMPRESSED: u8 = 0x80;

pub const FRAGMENT_INDICATOR: u8 = 0xff;

// --- Timing constants (milliseconds) ---

/// How often to send keepalive/heartbeat on active paths.
pub const ZT_PATH_HEARTBEAT_PERIOD: u64 = 14_000;

/// How often to ping peers.
pub const ZT_PEER_PING_PERIOD: u64 = 60_000;

/// When a path expires if no traffic received.
pub const ZT_PEER_PATH_EXPIRATION: u64 = 243_000;

/// When a peer is considered inactive.
pub const ZT_PEER_ACTIVITY_TIMEOUT: u64 = 500_000;

pub const ZT_PATH_HELLO_RATE_LIMIT: u64 = 1_000;

/// Minimum interval between UNITE (rendezvous) messages for a peer pair.
pub const ZT_MIN_UNITE_INTERVAL: u64 = 30_000;

/// How often to check for peers needing pings.
pub const ZT_PING_CHECK_INTERVAL: u64 = 5_000;

/// Interval for pushing direct paths when no direct path exists.
pub const ZT_DIRECT_PATH_PUSH_INTERVAL: u64 = 30_000;

/// Interval for pushing direct paths when a direct path already exists.
pub const ZT_DIRECT_PATH_PUSH_INTERVAL_HAVEPATH: u64 = 120_000;

// --- World (planet/moon) constants ---

pub const WORLD_TYPE_PLANET: u8 = 1;

pub const WORLD_TYPE_MOON: u8 = 127;

/// Maximum number of roots in a world definition.
pub const WORLD_MAX_ROOTS: usize = 4;

/// Maximum number of endpoints per root.
pub const WORLD_MAX_ENDPOINTS_PER_ROOT: usize = 32;

pub const WORLD_ID_EARTH: u64 = 149604618;

// --- Address constants ---

/// Length of a ZeroTier address in bytes (40 bits).
pub const ZT_ADDRESS_LENGTH: usize = 5;

pub const ZT_ADDRESS_RESERVED_PREFIX: u8 = 0xff;

// --- Error codes (used in ERROR verb responses) ---

/// No error.
pub const ERROR_NONE: u8 = 0x00;

/// Invalid request.
pub const ERROR_INVALID_REQUEST: u8 = 0x01;

pub const ERROR_BAD_PROTOCOL_VERSION: u8 = 0x02;

/// Object not found.
pub const ERROR_OBJ_NOT_FOUND: u8 = 0x03;

/// Identity collision.
pub const ERROR_IDENTITY_COLLISION: u8 = 0x04;

/// Unsupported operation.
pub const ERROR_UNSUPPORTED_OPERATION: u8 = 0x05;

pub const ERROR_NEED_MEMBERSHIP_CERTIFICATE: u8 = 0x06;

pub const ERROR_NETWORK_ACCESS_DENIED: u8 = 0x07;

/// Unwanted multicast.
pub const ERROR_UNWANTED_MULTICAST: u8 = 0x08;

pub const ERROR_NETWORK_AUTHENTICATION_REQUIRED: u8 = 0x09;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_values() {
        assert_eq!(ZT_PROTO_VERSION, 13);
        assert_eq!(ZT_PROTO_VERSION_MIN, 4);
    }

    #[test]
    fn packet_size_values() {
        assert_eq!(ZT_PROTO_MIN_PACKET_LENGTH, 28);
        assert_eq!(ZT_PROTO_MIN_FRAGMENT_LENGTH, 16);
        assert_eq!(ZT_MAX_PACKET_FRAGMENTS, 7);
    }

    #[test]
    fn cipher_suite_values() {
        assert_eq!(CIPHER_SUITE_C25519_POLY1305_NONE, 0);
        assert_eq!(CIPHER_SUITE_C25519_POLY1305_SALSA2012, 1);
        assert_eq!(CIPHER_SUITE_NO_CRYPTO_TRUSTED_PATH, 2);
        assert_eq!(CIPHER_SUITE_AES_GMAC_SIV, 3);
    }

    #[test]
    fn timing_values() {
        assert_eq!(ZT_PATH_HEARTBEAT_PERIOD, 14_000);
        assert_eq!(ZT_PEER_PING_PERIOD, 60_000);
        assert_eq!(ZT_PEER_PATH_EXPIRATION, 243_000);
        assert_eq!(ZT_PEER_ACTIVITY_TIMEOUT, 500_000);
        assert_eq!(ZT_PATH_HELLO_RATE_LIMIT, 1_000);
        assert_eq!(ZT_MIN_UNITE_INTERVAL, 30_000);
        assert_eq!(ZT_PING_CHECK_INTERVAL, 5_000);
        assert_eq!(ZT_DIRECT_PATH_PUSH_INTERVAL, 30_000);
        assert_eq!(ZT_DIRECT_PATH_PUSH_INTERVAL_HAVEPATH, 120_000);
    }

    #[test]
    fn flag_values() {
        assert_eq!(FLAG_FRAGMENTED, 0x40);
        assert_eq!(FLAG_EXTENDED_ARMOR, 0x80);
        assert_eq!(VERB_FLAG_COMPRESSED, 0x80);
        assert_eq!(FRAGMENT_INDICATOR, 0xff);
    }

    #[test]
    fn world_values() {
        assert_eq!(WORLD_TYPE_PLANET, 1);
        assert_eq!(WORLD_TYPE_MOON, 127);
        assert_eq!(WORLD_MAX_ROOTS, 4);
        assert_eq!(WORLD_MAX_ENDPOINTS_PER_ROOT, 32);
        assert_eq!(WORLD_ID_EARTH, 149604618);
    }

    #[test]
    fn address_values() {
        assert_eq!(ZT_ADDRESS_LENGTH, 5);
        assert_eq!(ZT_ADDRESS_RESERVED_PREFIX, 0xff);
    }

    #[test]
    fn error_code_values() {
        assert_eq!(ERROR_NONE, 0x00);
        assert_eq!(ERROR_INVALID_REQUEST, 0x01);
        assert_eq!(ERROR_BAD_PROTOCOL_VERSION, 0x02);
        assert_eq!(ERROR_OBJ_NOT_FOUND, 0x03);
        assert_eq!(ERROR_IDENTITY_COLLISION, 0x04);
        assert_eq!(ERROR_UNSUPPORTED_OPERATION, 0x05);
        assert_eq!(ERROR_NEED_MEMBERSHIP_CERTIFICATE, 0x06);
        assert_eq!(ERROR_NETWORK_ACCESS_DENIED, 0x07);
        assert_eq!(ERROR_UNWANTED_MULTICAST, 0x08);
        assert_eq!(ERROR_NETWORK_AUTHENTICATION_REQUIRED, 0x09);
    }
}
