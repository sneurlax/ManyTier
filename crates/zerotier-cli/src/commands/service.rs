//! `manytier service` subcommand -- starts the ManyTier service daemon.

use zerotier_service::service::{run_service, ServiceConfig};

/// Run the service daemon with the given configuration.
pub async fn run(
    data_dir: &str,
    api_port: u16,
    udp_port: u16,
    controller_mode: bool,
    identity: Option<String>,
) -> anyhow::Result<()> {
    let identity_path = identity.unwrap_or_else(|| format!("{}/identity.secret", data_dir));

    let config = ServiceConfig {
        identity_path,
        data_dir: data_dir.to_string(),
        api_port,
        udp_port,
        controller_mode,
    };

    run_service(config).await
}
