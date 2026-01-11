//! WASM stub implementations of all platform traits.
//!
//! Every method panics with `unimplemented!`. These stubs exist to prove
//! the trait API compiles on WASM before real implementations are written.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};

use crate::traits::{Clock, CryptoProvider, Storage, Transport, TunDevice};

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

pub struct StubTransport;

impl Transport for StubTransport {
    type Error = String;

    async fn bind(_addr: SocketAddr) -> Result<Self, Self::Error> {
        unimplemented!("WASM stub ")
    }

    async fn send_to(&self, _data: &[u8], _addr: SocketAddr) -> Result<usize, Self::Error> {
        unimplemented!("WASM stub ")
    }

    async fn recv_from(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr), Self::Error> {
        unimplemented!("WASM stub ")
    }

    fn local_addr(&self) -> Result<SocketAddr, Self::Error> {
        unimplemented!("WASM stub ")
    }
}

// ---------------------------------------------------------------------------
// TunDevice
// ---------------------------------------------------------------------------

pub struct StubTunDevice;

impl TunDevice for StubTunDevice {
    type Error = String;

    async fn create(_name: &str, _mtu: usize) -> Result<Self, Self::Error> {
        unimplemented!("WASM stub -- TUN is not available in browsers")
    }

    async fn read(&self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        unimplemented!("WASM stub -- TUN is not available in browsers")
    }

    async fn write(&self, _data: &[u8]) -> Result<usize, Self::Error> {
        unimplemented!("WASM stub -- TUN is not available in browsers")
    }

    fn mtu(&self) -> usize {
        unimplemented!("WASM stub -- TUN is not available in browsers")
    }

    fn name(&self) -> &str {
        unimplemented!("WASM stub -- TUN is not available in browsers")
    }

    async fn set_ip(&self, _addr: IpAddr, _prefix_len: u8) -> Result<(), Self::Error> {
        unimplemented!("WASM stub -- TUN is not available in browsers")
    }

    async fn add_route(&self, _target: &str, _gateway: Option<IpAddr>) -> Result<(), Self::Error> {
        unimplemented!("WASM stub -- TUN is not available in browsers")
    }
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

pub struct StubStorage;

impl Storage for StubStorage {
    type Error = String;

    async fn load(&self, _key: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        unimplemented!("WASM stub ")
    }

    async fn store(&self, _key: &str, _value: &[u8]) -> Result<(), Self::Error> {
        unimplemented!("WASM stub ")
    }

    async fn delete(&self, _key: &str) -> Result<(), Self::Error> {
        unimplemented!("WASM stub ")
    }

    async fn list_keys(&self, _prefix: &str) -> Result<Vec<String>, Self::Error> {
        unimplemented!("WASM stub ")
    }
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

pub struct StubClock;

impl Clock for StubClock {
    fn now_monotonic_ms(&self) -> u64 {
        unimplemented!("WASM stub ")
    }

    fn now_wall_ms(&self) -> u64 {
        unimplemented!("WASM stub ")
    }
}

// ---------------------------------------------------------------------------
// CryptoProvider
// ---------------------------------------------------------------------------

pub struct StubCryptoProvider;

impl CryptoProvider for StubCryptoProvider {
    type Error = String;

    fn generate_identity(
        &self,
        _rng: &mut dyn rand_core::CryptoRng,
    ) -> Result<Vec<u8>, Self::Error> {
        unimplemented!("WASM stub ")
    }

    fn validate_identity(&self, _identity_bytes: &[u8]) -> Result<bool, Self::Error> {
        unimplemented!("WASM stub ")
    }

    fn key_agreement(
        &self,
        _our_secret: &[u8],
        _their_public: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        unimplemented!("WASM stub ")
    }

    fn encrypt_packet(
        &self,
        _shared_secret: &[u8],
        _packet: &mut [u8],
        _encrypt_payload: bool,
    ) -> Result<(), Self::Error> {
        unimplemented!("WASM stub ")
    }

    fn decrypt_packet(
        &self,
        _shared_secret: &[u8],
        _packet: &mut [u8],
    ) -> Result<bool, Self::Error> {
        unimplemented!("WASM stub ")
    }

    fn sign(&self, _secret_key: &[u8], _message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unimplemented!("WASM stub ")
    }

    fn verify(
        &self,
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<bool, Self::Error> {
        unimplemented!("WASM stub ")
    }
}
