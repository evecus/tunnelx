//! Wire protocol between Edge and Agent over QUIC.
//!
//! - Stream 0 is the control channel (bi-directional).
//! - Subsequent bi-directional streams are data channels (HTTP / TCP / UDP).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum ControlMessage {
    Register(RegisterRequest),
    RegisterResponse(RegisterResponse),
    ConfigUpdate(ConfigUpdate),
    Ping,
    Pong,
    AgentStatus(AgentStatus),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub token: String,
    pub agent_id: Uuid,
    pub agent_name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub ok: bool,
    pub tunnel_id: Option<Uuid>,
    pub message: String,
    pub config: Option<ConfigUpdate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUpdate {
    pub version: u64,
    pub rules: Vec<IngressRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRule {
    pub id: Uuid,
    pub hostname: Option<String>,
    pub path_prefix: Option<String>,
    pub service_type: ServiceType,
    pub target: String,
    /// For TCP/UDP: the public port Edge binds
    pub public_port: Option<u16>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceType {
    Http,
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub agent_id: Uuid,
    pub active_streams: u32,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataStreamHeader {
    pub rule_id: Uuid,
    pub stream_type: DataStreamType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataStreamType {
    Http,
    Tcp,
    /// Framed UDP datagrams: each packet is [u32 BE len][payload]
    Udp,
}

pub fn encode_message(msg: &ControlMessage) -> anyhow::Result<Vec<u8>> {
    let payload = bincode::serialize(msg)?;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

pub fn try_decode_message(buf: &[u8]) -> anyhow::Result<Option<(ControlMessage, usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let msg: ControlMessage = bincode::deserialize(&buf[4..4 + len])?;
    Ok(Some((msg, 4 + len)))
}
