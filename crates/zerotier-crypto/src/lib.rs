//! Cryptographic primitives for the ZeroTier V1 protocol.
//!
//! Pure-Rust, `no_std` implementations of everything the wire format needs:
//! C25519/Ed25519 identities with proof-of-work generation and validation,
//! X25519 key agreement, Salsa20/12 packet armoring with Poly1305 MACs,
//! AES-GMAC-SIV, and the KBKDF/memory-hard helpers used by identity PoW.
//! All constructions match official ZeroTier byte for byte.

#![no_std]

extern crate alloc;

pub mod aes_gmac_siv;
pub mod error;
pub mod hex_util;
pub mod identity;
pub mod kbkdf;
pub mod key_agreement;
pub mod memory_hard;
pub mod poly;
pub mod salsa;
pub mod signing;
#[cfg(feature = "v2")]
pub mod v2;
