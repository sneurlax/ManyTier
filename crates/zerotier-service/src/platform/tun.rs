use std::net::IpAddr;
use std::sync::{Mutex as StdMutex, OnceLock};

use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tun2::AbstractDevice;
use zerotier_node::traits::TunDevice;

// ---------------------------------------------------------------------------
// Linux: Full NativeTun implementation via tun2
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub struct NativeTun {
    control: StdMutex<Option<tun2::AsyncDevice>>,
    reader: OnceLock<tokio::sync::Mutex<ReadHalf<tun2::AsyncDevice>>>,
    writer: OnceLock<tokio::sync::Mutex<WriteHalf<tun2::AsyncDevice>>>,
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
            control: StdMutex::new(Some(device)),
            reader: OnceLock::new(),
            writer: OnceLock::new(),
            name: actual_name,
            mtu,
        })
    }

    async fn read(&self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.ensure_halves()?;
        let reader = self.reader.get().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "TUN reader unavailable")
        })?;
        let mut reader = reader.lock().await;
        reader.read(buf).await
    }

    async fn write(&self, data: &[u8]) -> Result<usize, Self::Error> {
        self.ensure_halves()?;
        let writer = self.writer.get().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "TUN writer unavailable")
        })?;
        let mut writer = writer.lock().await;
        writer.write(data).await
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn set_ip(&self, addr: IpAddr, prefix_len: u8) -> Result<(), Self::Error> {
        let mut control = self.control.lock().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "TUN control lock poisoned")
        })?;
        let device = control.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "cannot configure TUN after I/O has started",
            )
        })?;
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

    async fn add_route(&self, target: &str, gateway: Option<IpAddr>) -> Result<(), Self::Error> {
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

#[cfg(target_os = "linux")]
impl NativeTun {
    fn ensure_halves(&self) -> Result<(), std::io::Error> {
        if self.reader.get().is_some() && self.writer.get().is_some() {
            return Ok(());
        }

        let mut control = self.control.lock().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "TUN control lock poisoned")
        })?;

        if self.reader.get().is_none() || self.writer.get().is_none() {
            let device = control.take().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "TUN runtime already taken")
            })?;
            let (reader, writer) = tokio::io::split(device);
            let _ = self.reader.set(tokio::sync::Mutex::new(reader));
            let _ = self.writer.set(tokio::sync::Mutex::new(writer));
        }

        Ok(())
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

    async fn add_route(&self, _target: &str, _gateway: Option<IpAddr>) -> Result<(), Self::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "macOS TUN not supported",
        ))
    }
}
