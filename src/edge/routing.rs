use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::EdgeState;
use crate::protocol::{DataStreamHeader, DataStreamType};

#[derive(Clone)]
pub struct AgentHandle {
    pub agent_id: Uuid,
    #[allow(dead_code)]
    pub agent_name: String,
    pub open_stream: mpsc::UnboundedSender<OpenStreamReq>,
    pub config_tx: mpsc::UnboundedSender<crate::protocol::ConfigUpdate>,
}

pub struct OpenStreamReq {
    pub header: DataStreamHeader,
    pub public_tcp: Option<TcpStream>,
    pub http_tx: Option<tokio::sync::oneshot::Sender<Response<Full<Bytes>>>>,
    pub http_req: Option<Request<Incoming>>,
    pub udp_to_agent: Option<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    pub udp_from_agent: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
}

pub struct AgentPool {
    inner: DashMap<Uuid, Vec<AgentHandle>>,
}

impl AgentPool {
    pub fn new() -> Self {
        Self { inner: DashMap::new() }
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
                let idx = rand::random::<usize>() % list.len();
                list.get(idx).cloned()
            }
        })
    }

    pub fn count(&self, tunnel_id: &Uuid) -> usize {
        self.inner.get(tunnel_id).map(|l| l.len()).unwrap_or(0)
    }

    pub fn broadcast_config(&self, tunnel_id: &Uuid, cfg: crate::protocol::ConfigUpdate) {
        if let Some(list) = self.inner.get(tunnel_id) {
            for h in list.iter() {
                if h.config_tx.send(cfg.clone()).is_err() {
                    tracing::warn!("failed to push config to agent {}", h.agent_id);
                }
            }
            tracing::info!(
                "pushed config v{} ({} rules) to {} agent(s) for tunnel {tunnel_id}",
                cfg.version,
                cfg.rules.len(),
                list.len()
            );
        }
    }
}

/// Tracks TCP/UDP public listeners so we can stop them and free ports.
pub struct ListenerRegistry {
    tcp: DashMap<Uuid, tokio::task::JoinHandle<()>>,
    udp: DashMap<Uuid, tokio::task::JoinHandle<()>>,
}

impl ListenerRegistry {
    pub fn new() -> Self {
        Self {
            tcp: DashMap::new(),
            udp: DashMap::new(),
        }
    }

    /// Abort any existing TCP/UDP listener for this rule (releases the public port).
    pub fn stop(&self, rule_id: Uuid) {
        if let Some((_, h)) = self.tcp.remove(&rule_id) {
            h.abort();
            tracing::info!("stopped TCP listener for rule {rule_id}");
        }
        if let Some((_, h)) = self.udp.remove(&rule_id) {
            h.abort();
            tracing::info!("stopped UDP listener for rule {rule_id}");
        }
    }

    pub fn start_tcp(&self, state: Arc<EdgeState>, rule_id: Uuid, port: u16, target: String) {
        self.stop(rule_id);
        let handle = tokio::spawn(async move {
            if let Err(e) = run_tcp_listener(state, rule_id, port, target).await {
                tracing::error!("TCP listener :{port} rule {rule_id}: {e:#}");
            }
        });
        self.tcp.insert(rule_id, handle);
    }

    pub fn start_udp(&self, state: Arc<EdgeState>, rule_id: Uuid, port: u16, target: String) {
        self.stop(rule_id);
        let handle = tokio::spawn(async move {
            if let Err(e) = run_udp_listener(state, rule_id, port, target).await {
                tracing::error!("UDP listener :{port} rule {rule_id}: {e:#}");
            }
        });
        self.udp.insert(rule_id, handle);
    }
}

pub async fn run_http_listener(state: Arc<EdgeState>, tls: bool) -> Result<()> {
    let addr = if tls { state.config.https_addr } else { state.config.http_addr };

    let tls_acceptor = if tls {
        let cert_path = state.config.https_cert.clone();
        let key_path = state.config.https_key.clone();
        if !cert_path.exists() || !key_path.exists() {
            return Err(anyhow!(
                "HTTPS certs not found at {} / {}",
                cert_path.display(), key_path.display()
            ));
        }
        let server_config = crate::common::load_https_server_config(&cert_path, &key_path)?;
        Some(tokio_rustls::TlsAcceptor::from(server_config))
    } else {
        None
    };

    let listener = TcpListener::bind(addr).await.context("bind http")?;
    info!("{} listening on {}", if tls { "HTTPS" } else { "HTTP" }, addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let result = async {
                if let Some(acceptor) = tls_acceptor {
                    let tls_stream = acceptor.accept(stream).await.context("tls accept")?;
                    serve_http(state, TokioIo::new(tls_stream)).await
                } else {
                    serve_http(state, TokioIo::new(stream)).await
                }
            };
            if let Err(e) = result.await {
                debug!("http conn from {peer}: {e:#}");
            }
        });
    }
}

async fn serve_http<S>(state: Arc<EdgeState>, io: TokioIo<S>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |req| {
        let state = state.clone();
        async move { handle_http_request(state, req).await }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .await
        .context("http1 serve")?;
    Ok(())
}

async fn handle_http_request(
    state: Arc<EdgeState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
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

    let rule = match state.db.find_http_rule(&host).await? {
        Some(r) => r,
        None => {
            return Ok(simple_response(
                StatusCode::NOT_FOUND,
                format!("no HTTP rule for host '{host}'"),
            ));
        }
    };

    let tunnel_id = match Uuid::parse_str(&rule.tunnel_id) {
        Ok(id) => id,
        Err(_) => return Ok(simple_response(StatusCode::INTERNAL_SERVER_ERROR, "bad tunnel id")),
    };

    let agent = match state.agents.pick(&tunnel_id) {
        Some(a) => a,
        None => return Ok(simple_response(StatusCode::BAD_GATEWAY, "no agent online for this tunnel")),
    };

    let rule_id = match Uuid::parse_str(&rule.id) {
        Ok(id) => id,
        Err(_) => return Ok(simple_response(StatusCode::INTERNAL_SERVER_ERROR, "bad rule id")),
    };

    let (tx, rx) = tokio::sync::oneshot::channel();
    let open = OpenStreamReq {
        header: DataStreamHeader {
            rule_id,
            stream_type: DataStreamType::Http,
            target: rule.target.clone(),
        },
        public_tcp: None,
        http_tx: Some(tx),
        http_req: Some(req),
        udp_to_agent: None,
        udp_from_agent: None,
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

pub async fn run_tcp_listener(
    state: Arc<EdgeState>,
    rule_id: Uuid,
    public_port: u16,
    _target: String,
) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], public_port));
    let listener = TcpListener::bind(addr).await.context("bind tcp")?;
    info!("TCP listener on :{public_port} for rule {rule_id}");

    loop {
        let (public_stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_connection(state, rule_id, public_stream, peer).await {
                warn!("TCP proxy error from {peer}: {e:#}");
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
    let rules = state.db.list_all_tcp_rules().await?;
    let rule = rules
        .into_iter()
        .find(|r| r.id == rule_id.to_string())
        .ok_or_else(|| anyhow!("rule gone"))?;
    let tunnel_id = Uuid::parse_str(&rule.tunnel_id)?;
    let agent = state
        .agents
        .pick(&tunnel_id)
        .ok_or_else(|| anyhow!("no agent online for tunnel {tunnel_id}"))?;
    info!(
        "TCP peer -> agent {} rule {rule_id} target {}",
        agent.agent_id,
        rule.target
    );

    let open = OpenStreamReq {
        header: DataStreamHeader {
            rule_id,
            stream_type: DataStreamType::Tcp,
            target: rule.target.clone(),
        },
        public_tcp: Some(public_stream),
        http_tx: None,
        http_req: None,
        udp_to_agent: None,
        udp_from_agent: None,
    };

    agent
        .open_stream
        .send(open)
        .map_err(|_| anyhow!("agent disconnected"))?;
    Ok(())
}

pub async fn run_udp_listener(
    state: Arc<EdgeState>,
    rule_id: Uuid,
    public_port: u16,
    _target: String,
) -> Result<()> {
    use std::collections::HashMap;
    use tokio::time::{timeout, Duration};

    let addr = SocketAddr::from(([0, 0, 0, 0], public_port));
    let sock = Arc::new(tokio::net::UdpSocket::bind(addr).await.context("bind udp")?);
    info!("UDP listener on :{public_port} for rule {rule_id}");

    let rules = state.db.list_all_udp_rules().await?;
    let rule = rules
        .into_iter()
        .find(|r| r.id == rule_id.to_string())
        .ok_or_else(|| anyhow!("rule gone"))?;
    let tunnel_id = Uuid::parse_str(&rule.tunnel_id)?;
    let target = rule.target.clone();

    let mut sessions: HashMap<SocketAddr, tokio::sync::mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buf = vec![0u8; 65535];

    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let pkt = buf[..n].to_vec();

        if let Some(tx) = sessions.get(&peer) {
            if tx.send(pkt).await.is_err() {
                sessions.remove(&peer);
            }
            continue;
        }

        let agent = match state.agents.pick(&tunnel_id) {
            Some(a) => a,
            None => {
                warn!("UDP no agent for tunnel {tunnel_id}");
                continue;
            }
        };

        let (to_agent_tx, to_agent_rx) = mpsc::channel::<Vec<u8>>(64);
        let (from_agent_tx, mut from_agent_rx) = mpsc::channel::<Vec<u8>>(64);
        let _ = to_agent_tx.send(pkt).await;

        let open = OpenStreamReq {
            header: DataStreamHeader {
                rule_id,
                stream_type: DataStreamType::Udp,
                target: target.clone(),
            },
            public_tcp: None,
            http_tx: None,
            http_req: None,
            udp_to_agent: Some(to_agent_rx),
            udp_from_agent: Some(from_agent_tx),
        };
        if agent.open_stream.send(open).is_err() {
            warn!("UDP agent disconnected");
            continue;
        }
        sessions.insert(peer, to_agent_tx);

        let sock2 = sock.clone();
        tokio::spawn(async move {
            while let Ok(Some(pkt)) = timeout(Duration::from_secs(60), from_agent_rx.recv()).await {
                let _ = sock2.send_to(&pkt, peer).await;
            }
        });
    }
}
