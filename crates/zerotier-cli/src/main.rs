//! ManyTier CLI -- ZeroTier-compatible command-line interface.
//!
//! This is the `manytier` binary providing all subcommands for interacting
//! with the ManyTier service via its HTTP API on localhost:9993.

use clap::{Parser, Subcommand};
use tracing_subscriber::filter::LevelFilter;

mod client;
mod commands;

#[derive(Parser)]
#[command(name = "manytier", about = "ManyTier ZeroTier-compatible network tool")]
struct Cli {
    /// Auth token (reads from authtoken.secret if not provided)
    #[arg(long, env = "ZT_AUTH_TOKEN")]
    auth_token: Option<String>,

    /// Service API port
    #[arg(short, long, default_value = "9993")]
    port: u16,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show node status
    Status,
    /// List peers
    Peers,
    /// List joined networks
    Listnetworks,
    /// Join a network
    Join {
        /// 16-character hex network ID
        network_id: String,
    },
    /// Leave a network
    Leave {
        /// 16-character hex network ID
        network_id: String,
    },
    /// Identity management
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Moon (custom root) file management
    Moon {
        #[command(subcommand)]
        action: MoonAction,
    },
    /// Add a custom root server (moon)
    Orbit {
        /// Moon ID
        moon_id: String,
    },
    /// Remove a custom root server
    Deorbit {
        /// Moon ID
        moon_id: String,
    },
    /// Start the ManyTier service daemon
    Service {
        /// Data directory for identity, planet, authtoken, and controller DB
        #[arg(long, default_value = "./manytier-data")]
        data_dir: String,

        /// TCP port for the local REST API
        #[arg(long, default_value = "9993")]
        api_port: u16,

        /// UDP port for ZeroTier protocol traffic
        #[arg(long, default_value = "9993")]
        udp_port: u16,

        /// Enable controller mode
        #[arg(long)]
        controller_mode: bool,

        /// Path to identity.secret (default: {data-dir}/identity.secret)
        #[arg(long)]
        identity: Option<String>,
    },
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Generate a new identity
    Generate,
    /// Show current identity
    Show,
}

#[derive(Subcommand)]
enum MoonAction {
    /// Generate a signed .moon world file from a secret identity (offline)
    Generate {
        /// Path to identity.secret of the moon's root node
        #[arg(long)]
        identity: String,

        /// Stable public endpoint of the root, ip:port (repeatable)
        #[arg(long = "endpoint", required = true)]
        endpoints: Vec<String>,

        /// Output file (default: <moon-id>.moon)
        #[arg(long)]
        output: Option<String>,

        /// Override the moon world ID (16-char hex; default: root address)
        #[arg(long)]
        moon_id: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(true)
        .with_max_level(LevelFilter::INFO)
        .try_init();

    let cli = Cli::parse();

    // Resolve auth token: CLI arg > env var > file lookup
    let auth_token = cli.auth_token.unwrap_or_else(|| {
        let paths = ["authtoken.secret", "/var/lib/manytier/authtoken.secret"];
        for path in &paths {
            if let Ok(token) = std::fs::read_to_string(path) {
                return token.trim().to_string();
            }
        }
        String::new()
    });

    match cli.command {
        Commands::Status => commands::status::run(&auth_token, cli.port).await?,
        Commands::Peers => commands::peers::run(&auth_token, cli.port).await?,
        Commands::Listnetworks => commands::networks::run(&auth_token, cli.port).await?,
        Commands::Join { network_id } => {
            commands::join::run(&auth_token, cli.port, &network_id).await?
        }
        Commands::Leave { network_id } => {
            commands::leave::run(&auth_token, cli.port, &network_id).await?
        }
        Commands::Identity { action } => match action {
            IdentityAction::Generate => commands::identity::generate()?,
            IdentityAction::Show => commands::identity::show()?,
        },
        Commands::Moon { action } => match action {
            MoonAction::Generate {
                identity,
                endpoints,
                output,
                moon_id,
            } => commands::moon::generate(
                &identity,
                &endpoints,
                output.as_deref(),
                moon_id.as_deref(),
            )?,
        },
        Commands::Orbit { moon_id } => {
            commands::orbit::run(&auth_token, cli.port, &moon_id, true).await?
        }
        Commands::Deorbit { moon_id } => {
            commands::orbit::run(&auth_token, cli.port, &moon_id, false).await?
        }
        Commands::Service {
            data_dir,
            api_port,
            udp_port,
            controller_mode,
            identity,
        } => {
            commands::service::run(&data_dir, api_port, udp_port, controller_mode, identity).await?
        }
    }

    Ok(())
}
