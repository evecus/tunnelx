mod db;
mod panel;
mod quic;
mod routing;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

pub use db::Db;
pub use routing::AgentPool;

#[derive(Clone)]
pub struct EdgeConfig {
    pub data_dir: PathBuf,
    pub quic_addr: SocketAddr,
    pub panel_addr: SocketAddr,
    pub http_addr: SocketAddr,
    pub https_addr: SocketAddr,
    pub panel_user: String,
    pub panel_pass: String,
}

pub struct EdgeState {
    pub config: EdgeConfig,
    pub db: Db,
    pub agents: AgentPool,
    pub config_version: RwLock<u64>,
}

pub async fn run(config: EdgeConfig) -> Result<()> {
    std::fs::create_dir_all(&config.data_dir).context("create data dir")?;
    let certs_dir = config.data_dir.join("certs");
    std::fs::create_dir_all(&certs_dir)?;

    let db_path = config.data_dir.join("tunnelx.db");
    let db = Db::open(&db_path).await?;

    let state = Arc::new(EdgeState {
        config: config.clone(),
        db,
        agents: AgentPool::new(),
        config_version: RwLock::new(1),
    });

    info!("Edge starting");
    info!("  data_dir   = {}", config.data_dir.display());
    info!("  QUIC       = {}", config.quic_addr);
    info!("  panel      = http://{}", config.panel_addr);
    info!("  HTTP       = {}", config.http_addr);
    info!("  HTTPS      = {}", config.https_addr);

    let quic_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = quic::run_quic_server(quic_state).await {
            tracing::error!("QUIC server error: {e:#}");
        }
    });

    let http_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = routing::run_http_listener(http_state, false).await {
            tracing::error!("HTTP listener error: {e:#}");
        }
    });

    let https_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = routing::run_http_listener(https_state, true).await {
            tracing::warn!("HTTPS listener not started: {e:#}");
        }
    });

    {
        let rules = state.db.list_all_tcp_rules().await?;
        for rule in rules {
            if let Some(port) = rule.public_port {
                let st = state.clone();
                let rule_id = match uuid::Uuid::parse_str(&rule.id) {
                    Ok(id) => id,
                    Err(_) => continue,
                };
                let port = port as u16;
                let target = rule.target.clone();
                tokio::spawn(async move {
                    if let Err(e) = routing::run_tcp_listener(st, rule_id, port, target).await {
                        tracing::error!("TCP listener :{port} error: {e:#}");
                    }
                });
            }
        }
    }

    {
        let rules = state.db.list_all_udp_rules().await?;
        for rule in rules {
            if let Some(port) = rule.public_port {
                let st = state.clone();
                let rule_id = match uuid::Uuid::parse_str(&rule.id) {
                    Ok(id) => id,
                    Err(_) => continue,
                };
                let port = port as u16;
                let target = rule.target.clone();
                tokio::spawn(async move {
                    if let Err(e) = routing::run_udp_listener(st, rule_id, port, target).await {
                        tracing::error!("UDP listener :{port} error: {e:#}");
                    }
                });
            }
        }
    }

    panel::run_panel(state).await
}
