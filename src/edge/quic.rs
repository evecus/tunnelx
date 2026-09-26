use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Response;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::routing::{AgentHandle, OpenStreamReq};
use super::EdgeState;
use crate::common::{load_or_generate_quic_cert, make_quic_server_config};
use crate::protocol::{
    encode_message, try_decode_message, ConfigUpdate, ControlMessage,
    DataStreamType, RegisterResponse,
};

pub async fn run_quic_server(
    state: Arc<EdgeState>,
    ready: Option<tokio::sync::oneshot::Sender<Result<()>>>,
) -> Result<()> {
    let notify = |r: Result<()>| {
        if let Some(tx) = ready {
            let _ = tx.send(r);
        }
    };

    let cert_path = &state.config.quic_cert;
    let key_path = &state.config.quic_key;
    let (certs, key) = match load_or_generate_quic_cert(
        cert_path,
        key_path,
        state.config.quic_auto_self_signed,
    ) {
        Ok(v) => v,
        Err(e) => {
            notify(Err(anyhow!("{e:#}")));
            return Err(e);
        }
    };
    let server_config = match make_quic_server_config(certs, key, state.config.congestion) {
        Ok(c) => c,
        Err(e) => {
            notify(Err(anyhow!("{e:#}")));
            return Err(e);
        }
    };
    let endpoint = match quinn::Endpoint::server(server_config, state.config.quic_addr) {
        Ok(ep) => ep,
        Err(e) => {
            let msg = format!("bind QUIC UDP on {}: {e}", state.config.quic_addr);
            notify(Err(anyhow!("{msg}")));
            return Err(anyhow!("{msg}"));
        }
    };
    info!(
        "QUIC server listening on UDP {} (Agents connect here)",
        state.config.quic_addr
    );
    notify(Ok(()));
    while let Some(connecting) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => {
                    if let Err(e) = handle_agent_connection(state, conn).await {
                        warn!("agent connection closed: {e:#}");
                    }
                }
                Err(e) => warn!("QUIC accept error: {e}"),
            }
        });
    }
    Ok(())
}

async fn read_one_message(recv: &mut quinn::RecvStream) -> Result<ControlMessage> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.context("read msg len")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 16 * 1024 * 1024 {
        anyhow::bail!("invalid control message length {len}");
    }
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload).await.context("read msg payload")?;
    bincode::deserialize(&payload).context("decode control message")
}

/// Write a rejection response and give it time to reach the peer.
///
/// Dropping the connection discards unacked stream data, so without this wait
/// the agent would only ever see "closed by peer: 0" and never the reason.
async fn reject(send: &mut quinn::SendStream, tunnel_id: Option<Uuid>, message: String) {
    let resp = ControlMessage::RegisterResponse(RegisterResponse {
        ok: false,
        tunnel_id,
        message,
        config: None,
    });
    match encode_message(&resp) {
        Ok(bytes) => {
            let _ = send.write_all(&bytes).await;
            let _ = send.finish();
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        Err(e) => tracing::warn!("encode rejection response: {e:#}"),
    }
}

async fn handle_agent_connection(state: Arc<EdgeState>, conn: quinn::Connection) -> Result<()> {
    let remote = conn.remote_address();
    info!("new QUIC connection from {remote}");
    let (mut send, mut recv) = conn.accept_bi().await.context("accept control stream")?;

    let msg = match read_one_message(&mut recv).await {
        Ok(m) => m,
        Err(e) => {
            warn!("register read from {remote}: {e:#}");
            reject(&mut send, None, format!("bad register: {e:#}")).await;
            return Err(e);
        }
    };
    let ControlMessage::Register(reg) = msg else {
        warn!("unexpected first message from {remote}");
        reject(&mut send, None, "expected Register".into()).await;
        anyhow::bail!("expected Register from {remote}");
    };

    let tunnel = match state.db.get_tunnel_by_token(&reg.token).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            warn!("invalid token from {remote} agent={}", reg.agent_name);
            reject(&mut send, None, "invalid token".into()).await;
            anyhow::bail!("invalid token from {remote}");
        }
        Err(e) => {
            warn!("db error from {remote}: {e:#}");
            reject(&mut send, None, format!("db error: {e:#}")).await;
            return Err(e);
        }
    };

    let tunnel_id = Uuid::parse_str(&tunnel.id)?;
    let rules = state.db.rules_for_tunnel(&tunnel.id).await?;
    let version = *state.config_version.read().await;
    let (tx, mut rx) = mpsc::unbounded_channel::<OpenStreamReq>();
    let (cfg_tx, mut cfg_rx) = mpsc::unbounded_channel::<ConfigUpdate>();
    let handle = AgentHandle {
        agent_id: reg.agent_id,
        agent_name: reg.agent_name.clone(),
        open_stream: tx,
        config_tx: cfg_tx,
    };
    if !state.agents.try_register(tunnel_id, handle) {
        warn!(
            "rejected agent {} ({}) for tunnel {} — already occupied",
            reg.agent_name, reg.agent_id, tunnel.name
        );
        reject(
            &mut send,
            Some(tunnel_id),
            "tunnel already has an agent online; only one agent per token".into(),
        )
        .await;
        return Ok(());
    }

    let resp = ControlMessage::RegisterResponse(RegisterResponse {
        ok: true, tunnel_id: Some(tunnel_id), message: "ok".into(),
        config: Some(ConfigUpdate { version, rules }),
    });
    send.write_all(&encode_message(&resp)?).await?;
    info!("Agent {} ({}) registered for tunnel {} ({})", reg.agent_name, reg.agent_id, tunnel.name, tunnel_id);
    let conn2 = conn.clone();
    let open_task = tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            let conn = conn2.clone();
            tokio::spawn(async move {
                if let Err(e) = open_data_stream(conn, req).await {
                    error!("open data stream: {e:#}");
                }
            });
        }
    });
    let mut ctrl_buf = Vec::new();
    loop {
        tokio::select! {
            cfg = cfg_rx.recv() => {
                match cfg {
                    Some(cfg) => {
                        info!("pushing config v{} to agent {}", cfg.version, reg.agent_id);
                        if let Err(e) = send.write_all(&encode_message(&ControlMessage::ConfigUpdate(cfg))?).await {
                            warn!("failed to write ConfigUpdate: {e}");
                            break;
                        }
                    }
                    None => break,
                }
            }
            chunk = recv.read_chunk(8192, true) => {
                match chunk {
                    Ok(Some(chunk)) => {
                        ctrl_buf.extend_from_slice(&chunk.bytes);
                        while let Ok(Some((msg, consumed))) = try_decode_message(&ctrl_buf) {
                            ctrl_buf.drain(..consumed);
                            if matches!(msg, ControlMessage::Ping) {
                                send.write_all(&encode_message(&ControlMessage::Pong)?).await?;
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(e) => { warn!("control stream error: {e}"); break; }
                }
            }
        }
    }
    state.agents.unregister(tunnel_id, reg.agent_id);
    open_task.abort();
    info!("Agent {} disconnected", reg.agent_id);
    Ok(())
}

async fn open_data_stream(conn: quinn::Connection, req: OpenStreamReq) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open bi stream")?;
    let header_bytes = bincode::serialize(&req.header)?;
    let mut hdr = Vec::with_capacity(4 + header_bytes.len());
    hdr.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    hdr.extend_from_slice(&header_bytes);
    send.write_all(&hdr).await?;
    match req.header.stream_type {
        DataStreamType::Tcp => {
            let public = req.public_tcp.ok_or_else(|| anyhow!("missing public_tcp"))?;
            let (mut pub_r, mut pub_w) = public.into_split();
            let t1 = tokio::spawn(async move {
                let mut buf = [0u8; 16384];
                loop {
                    match pub_r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => { if send.write_all(&buf[..n]).await.is_err() { break; } }
                    }
                }
                let _ = send.finish();
            });
            let t2 = tokio::spawn(async move {
                let mut buf = [0u8; 16384];
                loop {
                    match recv.read(&mut buf).await {
                        Ok(Some(n)) if n > 0 => { if pub_w.write_all(&buf[..n]).await.is_err() { break; } }
                        _ => break,
                    }
                }
            });
            let _ = tokio::join!(t1, t2);
        }
        DataStreamType::Http => {
            let mut http_req = req.http_req.ok_or_else(|| anyhow!("missing http_req"))?;
            let tx = req.http_tx.ok_or_else(|| anyhow!("missing http_tx"))?;
            let body_bytes = http_req.body_mut().collect().await?.to_bytes();
            let method = http_req.method().as_str().to_string();
            let uri = http_req.uri().to_string();
            let mut headers = Vec::new();
            for (k, v) in http_req.headers() {
                if let Ok(v) = v.to_str() { headers.push((k.as_str().to_string(), v.to_string())); }
            }
            #[derive(serde::Serialize)]
            struct HttpReqWire { method: String, uri: String, headers: Vec<(String, String)>, body: Vec<u8> }
            let wire = HttpReqWire { method, uri, headers, body: body_bytes.to_vec() };
            let payload = bincode::serialize(&wire)?;
            send.write_all(&(payload.len() as u32).to_be_bytes()).await?;
            send.write_all(&payload).await?;
            send.finish()?;
            let mut len_buf = [0u8; 4];
            recv.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut resp_buf = vec![0u8; len];
            recv.read_exact(&mut resp_buf).await?;
            #[derive(serde::Deserialize)]
            struct HttpRespWire { status: u16, headers: Vec<(String, String)>, body: Vec<u8> }
            let resp_wire: HttpRespWire = bincode::deserialize(&resp_buf)?;
            let mut builder = Response::builder().status(resp_wire.status);
            for (k, v) in resp_wire.headers { builder = builder.header(k, v); }
            let response = builder.body(Full::new(Bytes::from(resp_wire.body))).unwrap_or_else(|_| {
                Response::builder().status(502).body(Full::new(Bytes::from("bad response"))).unwrap()
            });
            let _ = tx.send(response);
        }
        DataStreamType::Udp => {
            let mut to_agent = req.udp_to_agent.ok_or_else(|| anyhow!("missing udp_to_agent"))?;
            let from_agent = req.udp_from_agent.ok_or_else(|| anyhow!("missing udp_from_agent"))?;
            let t1 = tokio::spawn(async move {
                while let Some(pkt) = to_agent.recv().await {
                    if pkt.len() > 65535 { continue; }
                    let mut frame = Vec::with_capacity(4 + pkt.len());
                    frame.extend_from_slice(&(pkt.len() as u32).to_be_bytes());
                    frame.extend_from_slice(&pkt);
                    if send.write_all(&frame).await.is_err() { break; }
                }
                let _ = send.finish();
            });
            let t2 = tokio::spawn(async move {
                loop {
                    let mut len_buf = [0u8; 4];
                    if recv.read_exact(&mut len_buf).await.is_err() { break; }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    if len == 0 || len > 65535 { break; }
                    let mut pkt = vec![0u8; len];
                    if recv.read_exact(&mut pkt).await.is_err() { break; }
                    if from_agent.send(pkt).await.is_err() { break; }
                }
            });
            let _ = tokio::join!(t1, t2);
        }
    }
    Ok(())
}
