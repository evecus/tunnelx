use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use uuid::Uuid;

use super::EdgeState;
use crate::protocol::{DataStreamHeader, DataStreamType};

/// Holds active Agent connections for a tunnel.
pub struct AgentPool {
    /// tunnel_id -> list of sender channels that can open new data streams
    inner: DashMap<Uuid, Vec<AgentHandle>>,
}

#[derive(Clone)]
pub struct AgentHandle {
    pub agent_id: Uuid,
    pub agent_name: String,
    /// Send a request to open a new data stream. The receiver side will open the QUIC stream.
    pub open_stream: mpsc::UnboundedSender<OpenStreamReq>,
}

pub struct OpenStreamReq {
    pub header: DataStreamHeader,
    /// The public side TCP stream (or a oneshot for HTTP response later)
    pub public_tcp: Option<TcpStream>,
    /// For HTTP we pass the request and a oneshot for the response body
    pub http_tx: Option<tokio::sync::oneshot::Sender<Response<Full<Bytes>>>>,
    pub http_req: Option<Request<Incoming>>,
}

impl AgentPool {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    pub fn register(&self, tunnel_id: Uuid, handle: AgentHandle) {
        self.inner.entry(tunnel_id).or_default().push(handle);
        info!("Agent registered for tunnel {tunnel_id}");
    }

    pub fn unregister(&self, tunnel_id: Uuid, agent_id: Uuid) {
        if let Some(mut list) = self.inner.get_mut(&tunnel_id) {
            list.retain(|h| h.agent_id != agent_id);
        }
        info!("Agent {agent_id} unregistered from tunnel {tunnel_id}");
    }

    pub fn pick(&self, tunnel_id: &Uuid) -> Option<AgentHandle> {
        self.inner.get(tunnel_id).and_then(|list| {
            if list.is_empty() {
                None
            } else {
                // Simple round-robin by random for MVP
                let idx = rand::random::<usize>() % list.len();
                list.get(idx).cloned()
            }
        })
    }

    pub fn count(&self, tunnel_id: &Uuid) -> usize {
        self.inner.get(tunnel_id).map(|l| l.len()).unwrap_or(0)
    }
}

/// Public HTTP/HTTPS listener. For MVP HTTPS just tries to load certs from data_dir/certs.
pub async fn run_http_listener(state: Arc<EdgeState>, tls: bool) -> Result<()> {
    let addr = if tls {
        state.config.https_addr
    } else {
        state.config.http_addr
    };

    let listener = TcpListener::bind(addr).await.context("bind http")?;
    info!("{} listening on {}", if tls { "HTTPS" } else { "HTTP" }, addr);

    // For MVP we only implement plain HTTP. TLS termination can be added later
    // by loading certs from data_dir/certs/fullchain.pem + privkey.pem.
    if tls {
        let cert_path = state.config.data_dir.join("certs/fullchain.pem");
        let key_path = state.config.data_dir.join("certs/privkey.pem");
        if !cert_path.exists() || !key_path.exists() {
            return Err(anyhow!(
                "HTTPS certs not found at {} / {} – skipping HTTPS listener",
                cert_path.display(),
                key_path.display()
            ));
        }
        // TODO: real TLS with rustls. For now skip.
        return Err(anyhow!("HTTPS not yet implemented – put certs and use a reverse proxy for now"));
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { handle_http_request(state, req).await }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                debug!("HTTP connection from {peer} error: {e}");
            }
        });
    }
}

async fn handle_http_request(
    state: Arc<EdgeState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();

    if host.is_empty() {
        return Ok(simple_response(StatusCode::BAD_REQUEST, "missing Host header"));
    }

    let rule = match state.db.find_http_rule(&host).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Ok(simple_response(StatusCode::NOT_FOUND, format!("no tunnel for host {host}")));
        }
        Err(e) => {
            error!("db error: {e:#}");
            return Ok(simple_response(StatusCode::INTERNAL_SERVER_ERROR, "db error"));
        }
    };

    let tunnel_id = match Uuid::parse_str(&rule.tunnel_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(simple_response(StatusCode::INTERNAL_SERVER_ERROR, "bad tunnel id"));
        }
    };

    let agent = match state.agents.pick(&tunnel_id) {
        Some(a) => a,
        None => {
            return Ok(simple_response(
                StatusCode::BAD_GATEWAY,
                "no agent online for this tunnel",
            ));
        }
    };

    let rule_id = match Uuid::parse_str(&rule.id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(simple_response(StatusCode::INTERNAL_SERVER_ERROR, "bad rule id"));
        }
    };

    let (tx, rx) = tokio::sync::oneshot::channel();
    let open = OpenStreamReq {
        header: DataStreamHeader {
            rule_id,
            stream_type: DataStreamType::Http,
        },
        public_tcp: None,
        http_tx: Some(tx),
        http_req: Some(req),
    };

    if agent.open_stream.send(open).is_err() {
        return Ok(simple_response(StatusCode::BAD_GATEWAY, "agent disconnected"));
    }

    match rx.await {
        Ok(resp) => Ok(resp),
        Err(_) => Ok(simple_response(StatusCode::BAD_GATEWAY, "agent failed to respond")),
    }
}

fn simple_response(status: StatusCode, body: impl Into<String>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body.into())))
        .unwrap()
}

/// Bind a public TCP port and forward connections through an Agent.
pub async fn run_tcp_listener(
    state: Arc<EdgeState>,
    rule_id: Uuid,
    public_port: u16,
    _target: String, // target is known by Agent via config
) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], public_port));
    let listener = TcpListener::bind(addr).await.context("bind tcp")?;
    info!("TCP listener on :{public_port} for rule {rule_id}");

    // We need the tunnel_id; look it up once
    // For simplicity we store rule_id and look up tunnel on each connection via DB.
    loop {
        let (public_stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_connection(state, rule_id, public_stream, peer).await {
                debug!("TCP proxy error from {peer}: {e:#}");
            }
        });
    }
}

async fn handle_tcp_connection(
    state: Arc<EdgeState>,
    rule_id: Uuid,
    public_stream: TcpStream,
    _peer: SocketAddr,
) -> Result<()> {
    // Find which tunnel this rule belongs to
    let rules = state.db.list_all_tcp_rules().await?;
    let rule = rules
        .into_iter()
        .find(|r| r.id == rule_id.to_string())
        .ok_or_else(|| anyhow!("rule gone"))?;
    let tunnel_id = Uuid::parse_str(&rule.tunnel_id)?;

    let agent = state
        .agents
        .pick(&tunnel_id)
        .ok_or_else(|| anyhow!("no agent online"))?;

    let open = OpenStreamReq {
        header: DataStreamHeader {
            rule_id,
            stream_type: DataStreamType::Tcp,
        },
        public_tcp: Some(public_stream),
        http_tx: None,
        http_req: None,
    };

    agent
        .open_stream
        .send(open)
        .map_err(|_| anyhow!("agent disconnected"))?;
    // The Agent side (inside the QUIC handler) will take the TcpStream and bidirectional copy.
    Ok(())
}
