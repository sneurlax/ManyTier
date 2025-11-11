use std::net::IpAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tun2::AbstractDevice;
use zerotier_node::traits::TunDevice;

// ---------------------------------------------------------------------------
// Linux: Full NativeTun implementation via tun2
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub struct NativeTun {
    device: Mutex<tun2::AsyncDevice>,
    name: String,
    mtu: usize,
}

#[cfg(target_os = "linux")]
impl TunDevice for NativeTun {
    type Error = std::io::Error;

    async fn create(name: &str, mtu: usize) -> Result<Self, Self::Error> {
        let mut config = tun2::Configuration::default();
        config.tun_name(name).mtu(mtu as u16).up();
        let device = tun2::create_as_async(&config)?;

        // Retrieve the actual interface name (tun2 may adjust it)
        let actual_name = device
            .as_ref()
            .tun_name()
            .unwrap_or_else(|_| name.to_string());

        Ok(NativeTun {
            device: Mutex::new(device),
            name: actual_name,
            mtu,
        })
    }

    async fn read(&self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut device = self.device.lock().await;
        device.read(buf).await
    }

    async fn write(&self, data: &[u8]) -> Result<usize, Self::Error> {
        let mut device = self.device.lock().await;
        device.write(data).await
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn set_ip(&self, addr: IpAddr, prefix_len: u8) -> Result<(), Self::Error> {
        let mut device = self.device.lock().await;
        device.as_mut().set_address(addr)?;

        if let IpAddr::V4(_) = addr {
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len as u32)
            };
            device
                .as_mut()
                .set_netmask(IpAddr::V4(std::net::Ipv4Addr::from(mask)))?;
        }

        Ok(())
    }

    async fn add_route(
        &self,
        target: &str,
        gateway: Option<IpAddr>,
    ) -> Result<(), Self::Error> {
        // Validate CIDR notation
        let parts: Vec<&str> = target.split('/').collect();
        if parts.len() != 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "route target must be in CIDR notation (e.g., 10.0.0.0/24)",
            ));
        }

        // tun2 does not expose a post-creation route addition API on AsyncDevice.
        // Fall back to `ip route add`.
        let target = target.to_string();
        let name = self.name.clone();

        tokio::task::spawn_blocking(move || {
            let mut cmd = std::process::Command::new("ip");
            cmd.args(["route", "add", &target, "dev", &name]);
            if let Some(gw) = gateway {
                cmd.args(["via", &gw.to_string()]);
            }

            let output = cmd.output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // "RTNETLINK answers: File exists" means route already exists -- not an error
                if !stderr.contains("File exists") {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("ip route add failed: {}", stderr.trim()),
                    ));
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
    }
}

// ---------------------------------------------------------------------------
// macOS: stub returning unsupported-platform errors
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub struct NativeTun {
    _private: (),
}

#[cfg(target_os = "macos")]
impl TunDevice for NativeTun {
    type Error = std::io::Error;

    async fn create(_name: &str, _mtu: usize) -> Result<Self, Self::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN device creation is not supported on macOS in this version. macOS utun support deferred.",
        ))
    }

    async fn read(&self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "macOS TUN not supported",
        ))
    }

    async fn write(&self, _data: &[u8]) -> Result<usize, Self::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "macOS TUN not supported",
        ))
    }

    fn mtu(&self) -> usize {
        0
    }

    fn name(&self) -> &str {
        ""
    }

    async fn set_ip(&self, _addr: IpAddr, _prefix_len: u8) -> Result<(), Self::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "macOS TUN not supported",
        ))
    }

    async fn add_route(
        &self,
        _target: &str,
        _gateway: Option<IpAddr>,
    ) -> Result<(), Self::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "macOS TUN not supported",
        ))
    }
}
