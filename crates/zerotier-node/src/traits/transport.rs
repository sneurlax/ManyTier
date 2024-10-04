use core::net::SocketAddr;

/// Network transport abstraction for sending and receiving UDP packets.
///
/// Implementations exist for native (tokio UdpSocket) and WASM (WebSocket relay).
/// Uses `core::net::SocketAddr` (not `std::net`) for no_std/WASM compatibility.
pub trait Transport: Send + Sync {
    type Error: core::fmt::Debug + core::fmt::Display;

    /// Bind to the given socket address and create a transport instance.
    async fn bind(addr: SocketAddr) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Send data to the specified address. Returns bytes sent.
    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize, Self::Error>;

    /// Receive data into the buffer. Returns (bytes_read, source_address).
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Self::Error>;

    /// Return the local address this transport is bound to.
    fn local_addr(&self) -> Result<SocketAddr, Self::Error>;
}
