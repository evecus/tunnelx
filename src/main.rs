mod agent;
mod common;
mod edge;
mod protocol;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "tunnelx", version, about = "Cloudflare Tunnel-like reverse proxy over QUIC")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run as Edge (public server with Web UI and QUIC listener)
    Edge {
        /// Working directory (SQLite DB, certs, config.toml)
        #[arg(short = 'd', long, default_value = ".")]
        data_dir: String,

        /// Override config.toml listen.quic
        #[arg(long)]
        quic_addr: Option<String>,

        /// Override config.toml listen.panel
        #[arg(long)]
        panel_addr: Option<String>,

        /// Override config.toml listen.http
        #[arg(long)]
        http_addr: Option<String>,

        /// Override config.toml panel.user
        #[arg(long)]
        panel_user: Option<String>,

        /// Override config.toml panel.password
        #[arg(long)]
        panel_pass: Option<String>,
    },

    /// Run as Agent (outbound connector to Edge)
    Agent {
        /// Edge server address (host:port)
        #[arg(long)]
        server: String,

        /// Tunnel token
        #[arg(long)]
        token: String,

        /// Optional agent name for identification
        #[arg(long, default_value = "")]
        name: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    common::install_crypto_provider();

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            "tunnelx=info,quinn=warn,sqlx=warn".into()
        }))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Edge {
            data_dir,
            quic_addr,
            panel_addr,
            http_addr,
            panel_user,
            panel_pass,
        } => {
            let config = edge::load_edge_config(
                data_dir.into(),
                edge::CliOverrides {
                    quic_addr,
                    panel_addr,
                    http_addr,
                    panel_user,
                    panel_pass,
                },
            )?;
            edge::run(config).await
        }
        Commands::Agent { server, token, name } => {
            agent::run(agent::AgentConfig {
                server,
                token,
                name: if name.is_empty() {
                    hostname::get()
                        .ok()
                        .and_then(|h| h.into_string().ok())
                        .unwrap_or_else(|| "agent".into())
                } else {
                    name
                },
            })
            .await
        }
    }
}

mod hostname {
    use std::ffi::OsString;
    pub fn get() -> Result<OsString, ()> {
        std::env::var_os("HOSTNAME")
            .or_else(|| std::env::var_os("COMPUTERNAME"))
            .ok_or(())
    }
}
