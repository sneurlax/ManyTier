use std::net::SocketAddr;

use tokio::net::UdpSocket;
use zerotier_node::traits::Transport;

/// Native transport using tokio's UdpSocket.
///
/// This is the production transport for native (non-WASM) platforms.
/// Shadow intercepts real syscalls, so this works transparently in
/// Shadow network simulations.
pub struct NativeTransport {
    socket: UdpSocket,
}

impl Transport for NativeTransport {
    type Error = std::io::Error;

    async fn bind(addr: SocketAddr) -> Result<Self, Self::Error> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(NativeTransport { socket })
    }

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize, Self::Error> {
        self.socket.send_to(data, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Self::Error> {
        self.socket.recv_from(buf).await
    }

    fn local_addr(&self) -> Result<SocketAddr, Self::Error> {
        self.socket.local_addr()
    }
}
