use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http_body_util::BodyExt;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::common::make_quic_client_config;
use crate::protocol::{
    encode_message, try_decode_message, ConfigUpdate, ControlMessage, DataStreamHeader,
    DataStreamType, IngressRule, RegisterRequest,
};

pub struct AgentConfig {
    pub server: String,
    pub token: String,
    pub name: String,
}

struct AgentState {
    config: AgentConfig,
    rules: RwLock<Vec<IngressRule>>,
    agent_id: Uuid,
}

pub async fn run(config: AgentConfig) -> Result<()> {
    info!("Agent starting, connecting to {}", config.server);
    let agent_id = Uuid::new_v4();
    let state = Arc::new(AgentState {
        config, rules: RwLock::new(Vec::new()), agent_id,
    });
    loop {
        match connect_and_run(state.clone()).await {
            Ok(()) => info!("connection closed cleanly, reconnecting in 3s"),
            Err(e) => warn!("connection error: {e:#}; reconnecting in 3s"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

async fn connect_and_run(state: Arc<AgentState>) -> Result<()> {
    let addr = state.config.server.to_socket_addrs()?.next()
        .ok_or_else(|| anyhow!("cannot resolve {}", state.config.server))?;
    let client_config = make_quic_client_config()?;
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    let conn = endpoint.connect(addr, "tunnelx")?.await.context("QUIC connect")?;
    info!("connected to Edge via QUIC");
    let (mut send, mut recv) = conn.open_bi().await?;
    let reg = ControlMessage::Register(RegisterRequest {
        token: state.config.token.clone(), agent_id: state.agent_id,
        agent_name: state.config.name.clone(), version: env!("CARGO_PKG_VERSION").to_string(),
    });
    send.write_all(&encode_message(&reg)?).await?;
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.context("read register response len")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload).await.context("read register response body")?;
    let msg: ControlMessage = bincode::deserialize(&payload).context("decode register response")?;
    match msg {
        ControlMessage::RegisterResponse(resp) if resp.ok => {
            info!("registered, tunnel_id={:?}", resp.tunnel_id);
            if let Some(cfg) = resp.config { apply_config(&state, cfg).await; }
        }
        ControlMessage::RegisterResponse(resp) => return Err(anyhow!("register rejected: {}", resp.message)),
        _ => return Err(anyhow!("unexpected response")),
    }

    let _conn_keep = conn.clone();
    let conn2 = conn.clone();
    let state2 = state.clone();
    let data_task = tokio::spawn(async move {
        while let Ok((send, recv)) = conn2.accept_bi().await {
            let state = state2.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_data_stream(state, send, recv).await {
                    error!("data stream error: {e:#}");
                }
            });
        }
    });

    let mut ping_interval = tokio::time::interval(std::time::Duration::from_secs(15));
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping_interval.tick().await;

    info!("session up, holding control channel");
    let mut ctrl_buf = Vec::new();
    loop {
        tokio::select! {
            _ = ping_interval.tick() => {
                if let Err(e) = send.write_all(&encode_message(&ControlMessage::Ping)?).await {
                    warn!("control ping failed: {e}");
                    break;
                }
            }
            chunk = recv.read_chunk(8192, true) => {
                match chunk {
                    Ok(Some(chunk)) => {
                        ctrl_buf.extend_from_slice(&chunk.bytes);
                        while let Ok(Some((msg, consumed))) = try_decode_message(&ctrl_buf) {
                            ctrl_buf.drain(..consumed);
                            match msg {
                                ControlMessage::ConfigUpdate(cfg) => apply_config(&state, cfg).await,
                                ControlMessage::Ping => {
                                    send.write_all(&encode_message(&ControlMessage::Pong)?).await?;
                                }
                                ControlMessage::Pong => {}
                                _ => {}
                            }
                        }
                    }
                    Ok(None) => {
                        info!("control stream finished by Edge");
                        break;
                    }
                    Err(e) => {
                        warn!("control error: {e}");
                        break;
                    }
                }
            }
        }
    }
    data_task.abort();
    drop(_conn_keep);
    drop(endpoint);
    Ok(())
}

async fn apply_config(state: &AgentState, cfg: ConfigUpdate) {
    info!("received config v{} with {} rules", cfg.version, cfg.rules.len());
    for r in &cfg.rules { info!("  rule {} {:?} -> {}", r.id, r.service_type, r.target); }
    *state.rules.write().await = cfg.rules;
}

async fn handle_data_stream(state: Arc<AgentState>, mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Result<()> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut hdr_buf = vec![0u8; len];
    recv.read_exact(&mut hdr_buf).await?;
    let header: DataStreamHeader = bincode::deserialize(&hdr_buf)?;
    let rules = state.rules.read().await;
    let rule = rules.iter().find(|r| r.id == header.rule_id).cloned();
    drop(rules);
    let target_str = if !header.target.is_empty() {
        header.target.clone()
    } else if let Some(ref r) = rule {
        r.target.clone()
    } else {
        anyhow::bail!("unknown rule {} and no target in header", header.rule_id);
    };
    match header.stream_type {
        DataStreamType::Tcp => {
            let target = parse_target(&target_str)?;
            let local = tokio::net::TcpStream::connect(&target).await
                .with_context(|| format!("connect to {target}"))?;
            info!("TCP proxy {} <-> {}", header.rule_id, target);
            let (mut local_r, mut local_w) = local.into_split();
            let t1 = tokio::spawn(async move {
                let mut buf = [0u8; 16384];
                loop {
                    match recv.read(&mut buf).await {
                        Ok(Some(n)) if n > 0 => { if local_w.write_all(&buf[..n]).await.is_err() { break; } }
                        _ => break,
                    }
                }
            });
            let t2 = tokio::spawn(async move {
                let mut buf = [0u8; 16384];
                loop {
                    match local_r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => { if send.write_all(&buf[..n]).await.is_err() { break; } }
                    }
                }
                let _ = send.finish();
            });
            let _ = tokio::join!(t1, t2);
        }
        DataStreamType::Udp => {
            let target = parse_target(&target_str)?;
            let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.context("bind local udp")?;
            sock.connect(&target).await.with_context(|| format!("connect udp to {target}"))?;
            info!("UDP proxy {} <-> {}", header.rule_id, target);
            let sock = Arc::new(sock);
            let sock2 = sock.clone();
            let t1 = tokio::spawn(async move {
                loop {
                    let mut len_buf = [0u8; 4];
                    if recv.read_exact(&mut len_buf).await.is_err() { break; }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    if len == 0 || len > 65535 { break; }
                    let mut pkt = vec![0u8; len];
                    if recv.read_exact(&mut pkt).await.is_err() { break; }
                    if sock.send(&pkt).await.is_err() { break; }
                }
            });
            let t2 = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    match sock2.recv(&mut buf).await {
                        Ok(n) if n > 0 => {
                            let mut frame = Vec::with_capacity(4 + n);
                            frame.extend_from_slice(&(n as u32).to_be_bytes());
                            frame.extend_from_slice(&buf[..n]);
                            if send.write_all(&frame).await.is_err() { break; }
                        }
                        _ => break,
                    }
                }
                let _ = send.finish();
            });
            let _ = tokio::join!(t1, t2);
        }
        DataStreamType::Http => {
            let mut len_buf = [0u8; 4];
            recv.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut req_buf = vec![0u8; len];
            recv.read_exact(&mut req_buf).await?;
            #[derive(serde::Deserialize)]
            struct HttpReqWire { method: String, uri: String, headers: Vec<(String, String)>, body: Vec<u8> }
            let req_wire: HttpReqWire = bincode::deserialize(&req_buf)?;
            let base = target_str.trim_end_matches('/');
            let path = if req_wire.uri.starts_with("http") {
                url::Url::parse(&req_wire.uri).map(|u| {
                    let mut p = u.path().to_string();
                    if let Some(q) = u.query() { p.push('?'); p.push_str(q); }
                    p
                }).unwrap_or_else(|_| req_wire.uri.clone())
            } else { req_wire.uri.clone() };
            let local_url = format!("{base}{path}");
            info!("HTTP {} {}", req_wire.method, local_url);
            let result = local_http(&req_wire.method, &local_url, &req_wire.headers, req_wire.body).await;
            #[derive(serde::Serialize)]
            struct HttpRespWire { status: u16, headers: Vec<(String, String)>, body: Vec<u8> }
            let resp_wire = match result {
                Ok((status, headers, body)) => HttpRespWire { status, headers, body },
                Err(e) => {
                    error!("local request failed: {e:#}");
                    HttpRespWire { status: 502, headers: vec![("content-type".into(), "text/plain".into())],
                        body: format!("Bad Gateway: {e:#}").into_bytes() }
                }
            };
            let payload = bincode::serialize(&resp_wire)?;
            send.write_all(&(payload.len() as u32).to_be_bytes()).await?;
            send.write_all(&payload).await?;
            send.finish()?;
        }
    }
    Ok(())
}

fn parse_target(target: &str) -> Result<String> {
    let t = target.strip_prefix("tcp://").or_else(|| target.strip_prefix("udp://"))
        .or_else(|| target.strip_prefix("http://"))
        .or_else(|| target.strip_prefix("https://")).unwrap_or(target);
    Ok(t.to_string())
}

async fn local_http(method: &str, url: &str, headers: &[(String, String)], body: Vec<u8>)
    -> Result<(u16, Vec<(String, String)>, Vec<u8>)>
{
    use http_body_util::Full;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    let uri: hyper::Uri = url.parse().context("parse url")?;
    let mut builder = hyper::Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        let lk = k.to_ascii_lowercase();
        if lk == "host" || lk == "connection" || lk == "transfer-encoding" || lk == "content-length" { continue; }
        builder = builder.header(k.as_str(), v.as_str());
    }
    let req = builder.body(Full::new(Bytes::from(body)))?;
    let client = Client::builder(TokioExecutor::new()).build_http();
    let resp = client.request(req).await.context("local http request")?;
    let status = resp.status().as_u16();
    let mut out_headers = Vec::new();
    for (k, v) in resp.headers() {
        if let Ok(v) = v.to_str() { out_headers.push((k.as_str().to_string(), v.to_string())); }
    }
    let body = resp.collect().await?.to_bytes().to_vec();
    Ok((status, out_headers, body))
}
