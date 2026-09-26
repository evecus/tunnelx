mod config;
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

pub use config::{load_edge_config, CliOverrides};
pub use db::Db;
pub use routing::{AgentPool, ListenerRegistry};

#[derive(Clone)]
pub struct EdgeConfig {
    pub data_dir: PathBuf,
    pub quic_addr: SocketAddr,
    pub panel_addr: SocketAddr,
    pub http_addr: SocketAddr,
    pub panel_user: String,
    pub panel_pass: String,
    pub quic_cert: PathBuf,
    pub quic_key: PathBuf,
    pub quic_auto_self_signed: bool,
    pub https_cert: PathBuf,
    pub https_key: PathBuf,
    pub https_enabled: bool,
}

pub struct EdgeState {
    pub config: EdgeConfig,
    pub db: Db,
    pub agents: AgentPool,
    pub listeners: ListenerRegistry,
    pub panel_auth: panel::PanelAuth,
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
        listeners: ListenerRegistry::new(),
        panel_auth: panel::PanelAuth::new(),
        config_version: RwLock::new(1),
    });

    info!("Edge starting");
    info!("  data_dir   = {}", config.data_dir.display());
    info!("  QUIC       = UDP {}", config.quic_addr);
    info!("  panel      = http://{}", config.panel_addr);
    info!(
        "  public HTTP(S) = {} (https_enabled={})",
        config.http_addr,
        config.https_enabled
    );

    let quic_state = state.clone();
    let quic_addr = config.quic_addr;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Err(e) = quic::run_quic_server(quic_state, Some(ready_tx)).await {
            tracing::error!("QUIC server error: {e:#}");
        }
    });
    match ready_rx.await {
        Ok(Ok(())) => {
            info!("QUIC ready on UDP {quic_addr}");
        }
        Ok(Err(e)) => {
            anyhow::bail!("QUIC failed to start on UDP {quic_addr}: {e:#}");
        }
        Err(_) => {
            anyhow::bail!("QUIC task exited before signaling ready on UDP {quic_addr}");
        }
    }

    // Single public front port (`listen.http`):
    // - https_enabled + port 443 → TLS on 443 + redirect-only on :80
    // - https_enabled + other port → TLS only on that port
    // - https disabled → plain HTTP on that port
    if state.config.https_enabled {
        let port = state.config.http_addr.port();
        let https_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = routing::run_http_listener(https_state, true).await {
                tracing::warn!("HTTPS listener not started: {e:#}");
            }
        });

        if port == 443 {
            let redir_addr = std::net::SocketAddr::new(state.config.http_addr.ip(), 80);
            let http_state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = routing::run_http_redirect_listener(http_state, redir_addr).await {
                    tracing::warn!("HTTP→HTTPS redirect on {redir_addr} failed: {e:#}");
                }
            });
            info!("HTTPS on :443 → also binding {redir_addr} for HTTP→HTTPS redirect");
        } else {
            info!(
                "HTTPS on non-443 port {} → only occupying that port (no :80 redirect)",
                port
            );
        }
    } else {
        info!("HTTPS disabled; plain HTTP on {}", state.config.http_addr);
        let http_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = routing::run_http_listener(http_state, false).await {
                tracing::error!("HTTP listener error: {e:#}");
            }
        });
    }

    {
        let rules = state.db.list_all_tcp_rules().await?;
        for rule in rules {
            if let Some(port) = rule.public_port {
                let rule_id = match uuid::Uuid::parse_str(&rule.id) {
                    Ok(id) => id,
                    Err(_) => continue,
                };
                state.listeners.start_tcp(
                    state.clone(),
                    rule_id,
                    port as u16,
                    rule.target.clone(),
                );
            }
        }
    }

    {
        let rules = state.db.list_all_udp_rules().await?;
        for rule in rules {
            if let Some(port) = rule.public_port {
                let rule_id = match uuid::Uuid::parse_str(&rule.id) {
                    Ok(id) => id,
                    Err(_) => continue,
                };
                state.listeners.start_udp(
                    state.clone(),
                    rule_id,
                    port as u16,
                    rule.target.clone(),
                );
            }
        }
    }

    panel::run_panel(state).await
}
