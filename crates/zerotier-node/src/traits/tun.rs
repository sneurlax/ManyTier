use core::net::IpAddr;

/// Virtual network interface (TUN/TAP) abstraction.
///
/// Native implementations use OS-level TUN devices (via tun-rs).
/// WASM has a permanent stub since TUN is not available in browsers.
pub trait TunDevice: Send + Sync {
    type Error: core::fmt::Debug + core::fmt::Display;

    /// Create a TUN device with the given name and MTU.
    async fn create(name: &str, mtu: usize) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Read a packet from the TUN device into the buffer. Returns bytes read.
    async fn read(&self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Write a packet to the TUN device. Returns bytes written.
    async fn write(&self, data: &[u8]) -> Result<usize, Self::Error>;

    /// Return the MTU of this TUN device.
    fn mtu(&self) -> usize;

    /// Return the name of this TUN device.
    fn name(&self) -> &str;

    /// Configure an IP address on this TUN device.
    async fn set_ip(&self, addr: IpAddr, prefix_len: u8) -> Result<(), Self::Error>;

    /// Add a route through this TUN device.
    /// target is the destination network in CIDR notation (e.g., "10.147.20.0/24" or "fd00::/64").
    /// gateway is optional; if None, the route goes directly through this device.
    async fn add_route(&self, target: &str, gateway: Option<IpAddr>) -> Result<(), Self::Error>;
}
