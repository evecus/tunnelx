mod agent;
mod common;
mod edge;
mod protocol;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "tunnelx", version, about = "Self-hosted Cloudflare Tunnel alternative")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run as Edge (public server with Web UI and QUIC listener)
    Edge {
        /// Working directory (contains SQLite DB, certs, config)
        #[arg(short = 'd', long, default_value = ".")]
        data_dir: String,

        /// QUIC listen address for Agents
        #[arg(long, default_value = "0.0.0.0:7844")]
        quic_addr: String,

        /// HTTP management panel listen address
        #[arg(long, default_value = "0.0.0.0:8080")]
        panel_addr: String,

        /// Public HTTP listen address (for HTTP tunnels)
        #[arg(long, default_value = "0.0.0.0:80")]
        http_addr: String,

        /// Public HTTPS listen address (for HTTP tunnels with TLS)
        #[arg(long, default_value = "0.0.0.0:443")]
        https_addr: String,

        /// Panel basic auth username
        #[arg(long, default_value = "admin")]
        panel_user: String,

        /// Panel basic auth password
        #[arg(long, default_value = "tunnelx")]
        panel_pass: String,
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
            https_addr,
            panel_user,
            panel_pass,
        } => {
            edge::run(edge::EdgeConfig {
                data_dir: data_dir.into(),
                quic_addr: quic_addr.parse()?,
                panel_addr: panel_addr.parse()?,
                http_addr: http_addr.parse()?,
                https_addr: https_addr.parse()?,
                panel_user,
                panel_pass,
            })
            .await
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

// Minimal hostname helper without extra crate
mod hostname {
    use std::ffi::OsString;
    pub fn get() -> Result<OsString, ()> {
        std::env::var_os("HOSTNAME")
            .or_else(|| std::env::var_os("COMPUTERNAME"))
            .ok_or(())
    }
}
