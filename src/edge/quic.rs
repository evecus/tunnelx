use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::routing::{AgentHandle, OpenStreamReq};
use super::EdgeState;
use crate::protocol::{
    decode_message, encode_message, try_decode_message, ConfigUpdate, ControlMessage,
    DataStreamType, RegisterResponse,
};

pub async fn run_quic_server(
    state: Arc<EdgeState>,
    ready: Option<tokio::sync::oneshot::Sender<Result<()>>>,
) -> Result<()> {
    let addr = state.config.quic_addr;
    let (server_config, _) = crate::common::make_quic_server_config(
        &state.config.quic_cert,
        &state.config.quic_key,
        state.config.quic_auto_self_signed,
    )?;

    let endpoint = match quinn::Endpoint::server(server_config, addr) {
        Ok(ep) => {
            if let Some(tx) = ready {
                let _ = tx.send(Ok(()));
            }
            ep
        }
        Err(e) => {
            let err = anyhow::anyhow!("QUIC bind {addr}: {e:#}");
            if let Some(tx) = ready {
                let _ = tx.send(Err(anyhow::anyhow!("{err:#}")));
            }
            return Err(err);
        }
    };

    info!("QUIC listening on UDP {addr}");

    while let Some(connecting) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => {
                    if let Err(e) = handle_agent_connection(state, conn).await {
                        warn!("agent connection ended: {e:#}");
                    }
                }
                Err(e) => warn!("QUIC handshake failed: {e}"),
            }
        });
    }
    Ok(())
}

async fn handle_agent_connection(state: Arc<EdgeState>, conn: quinn::Connection) -> Result<()> {
    let remote = conn.remote_address();
    info!("new QUIC connection from {remote}");
    let (mut send, mut recv) = conn.accept_bi().await.context("accept control stream")?;

    let msg = match read_one_message(&mut recv).await {
        Ok(m) => m,
        Err(e) => {
            warn!("register read from {remote}: {e:#}");
            let resp = ControlMessage::RegisterResponse(RegisterResponse {
                ok: false,
                tunnel_id: None,
                message: format!("bad register: {e:#}"),
                config: None,
            });
            let _ = send.write_all(&encode_message(&resp)?).await;
            return Err(e);
        }
    };
    let ControlMessage::Register(reg) = msg else {
        let resp = ControlMessage::RegisterResponse(RegisterResponse {
            ok: false,
            tunnel_id: None,
            message: "expected Register".into(),
            config: None,
        });
        let _ = send.write_all(&encode_message(&resp)?).await;
        anyhow::bail!("expected Register from {remote}");
    };

    let tunnel = match state.db.get_tunnel_by_token(&reg.token).await? {
        Some(t) => t,
        None => {
            let resp = ControlMessage::RegisterResponse(RegisterResponse {
                ok: false,
                tunnel_id: None,
                message: "invalid token".into(),
                config: None,
            });
            let _ = send.write_all(&encode_message(&resp)?).await;
            anyhow::bail!("invalid token from {remote}");
        }
    };
    let tunnel_id = match Uuid::parse_str(&tunnel.id) {
        Ok(id) => id,
        Err(e) => {
            let resp = ControlMessage::RegisterResponse(RegisterResponse {
                ok: false,
                tunnel_id: None,
                message: format!("bad tunnel id: {e}"),
                config: None,
            });
            let _ = send.write_all(&encode_message(&resp)?).await;
            return Err(e.into());
        }
    };

    let rules = state.db.rules_for_tunnel(&tunnel.id).await.unwrap_or_default();
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
        let resp = ControlMessage::RegisterResponse(RegisterResponse {
            ok: false,
            tunnel_id: Some(tunnel_id),
            message: "tunnel already has an agent online; only one agent per token".into(),
            config: None,
        });
        let _ = send.write_all(&encode_message(&resp)?).await;
        warn!(
            "rejected agent {} ({}) for tunnel {} — already occupied",
            reg.agent_name, reg.agent_id, tunnel.name
        );
        return Ok(());
    }

    let resp = ControlMessage::RegisterResponse(RegisterResponse {
        ok: true,
        tunnel_id: Some(tunnel_id),
        message: "ok".into(),
        config: Some(ConfigUpdate { version, rules }),
    });
    send.write_all(&encode_message(&resp)?).await?;
    info!(
        "Agent {} ({}) registered for tunnel {} ({})",
        reg.agent_name, reg.agent_id, tunnel.name, tunnel_id
    );

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

async fn read_one_message(recv: &mut quinn::RecvStream) -> Result<ControlMessage> {
    let mut buf = Vec::new();
    loop {
        let Some(chunk) = recv.read_chunk(8192, true).await? else {
            anyhow::bail!("control stream closed before register");
        };
        buf.extend_from_slice(&chunk.bytes);
        if let Ok(Some((msg, _))) = try_decode_message(&buf) {
            return Ok(msg);
        }
        if buf.len() > 1024 * 1024 {
            anyhow::bail!("register message too large");
        }
    }
}

async fn open_data_stream(conn: quinn::Connection, req: OpenStreamReq) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open data bi")?;
    let header = encode_message(&ControlMessage::DataStreamOpen(req.header.clone()))?;
    send.write_all(&header).await?;

    match req.header.stream_type {
        DataStreamType::Tcp => {
            let public = req
                .public_tcp
                .ok_or_else(|| anyhow::anyhow!("tcp open without public stream"))?;
            let (mut pr, mut pw) = public.into_split();
            let (mut sr, mut sw) = (recv, send);
            let a = tokio::spawn(async move {
                let _ = tokio::io::copy(&mut pr, &mut sw).await;
                let _ = sw.finish();
            });
            let b = tokio::spawn(async move {
                let _ = tokio::io::copy(&mut sr, &mut pw).await;
            });
            let _ = tokio::join!(a, b);
        }
        DataStreamType::Http => {
            // HTTP proxying is handled on the agent side after DataStreamOpen;
            // Edge currently expects the agent path via control + data streams.
            // Placeholder: close if incomplete wiring.
            if let Some(tx) = req.http_tx {
                let _ = tx.send(
                    hyper::Response::builder()
                        .status(502)
                        .body(http_body_util::Full::new(bytes::Bytes::from(
                            "HTTP data path not fully wired on Edge open",
                        )))
                        .unwrap(),
                );
            }
            let _ = req.http_req;
            let _ = (send, recv);
        }
        DataStreamType::Udp => {
            let mut to_agent = req
                .udp_to_agent
                .ok_or_else(|| anyhow::anyhow!("udp open without to_agent"))?;
            let from_agent = req
                .udp_from_agent
                .ok_or_else(|| anyhow::anyhow!("udp open without from_agent"))?;
            let mut send = send;
            let mut recv = recv;
            let up = tokio::spawn(async move {
                while let Some(pkt) = to_agent.recv().await {
                    let len = (pkt.len() as u32).to_be_bytes();
                    if send.write_all(&len).await.is_err() {
                        break;
                    }
                    if send.write_all(&pkt).await.is_err() {
                        break;
                    }
                }
            });
            let down = tokio::spawn(async move {
                let mut len_buf = [0u8; 4];
                loop {
                    if tokio::io::AsyncReadExt::read_exact(&mut recv, &mut len_buf)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    let n = u32::from_be_bytes(len_buf) as usize;
                    if n > 65535 {
                        break;
                    }
                    let mut buf = vec![0u8; n];
                    if tokio::io::AsyncReadExt::read_exact(&mut recv, &mut buf)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if from_agent.send(buf).await.is_err() {
                        break;
                    }
                }
            });
            let _ = tokio::join!(up, down);
        }
    }
    Ok(())
}

async fn read_one_message_from_bytes(data: &[u8]) -> Result<(ControlMessage, usize)> {
    match try_decode_message(data) {
        Ok(Some(v)) => Ok(v),
        Ok(None) => anyhow::bail!("incomplete"),
        Err(e) => Err(e),
    }
}

#[allow(dead_code)]
fn _use_decode(data: &[u8]) -> Result<ControlMessage> {
    decode_message(data)
}
