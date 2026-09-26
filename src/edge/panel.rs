use anyhow::Result;
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower_http::trace::TraceLayer;
use tracing::info;
use uuid::Uuid;

use super::EdgeState;
use crate::protocol::ServiceType;

const SESSION_COOKIE: &str = "tunnelx_session";
const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);
const MAX_FAILS: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(15 * 60);
const FAIL_WINDOW: Duration = Duration::from_secs(15 * 60);

/// In-memory auth: sessions + per-IP login failure tracking.
pub struct PanelAuth {
    sessions: dashmap::DashMap<String, SessionEntry>,
    failures: dashmap::DashMap<String, FailEntry>,
}

struct SessionEntry {
    #[allow(dead_code)]
    user: String,
    expires: Instant,
}

struct FailEntry {
    count: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

impl PanelAuth {
    pub fn new() -> Self {
        Self {
            sessions: dashmap::DashMap::new(),
            failures: dashmap::DashMap::new(),
        }
    }

    fn create_session(&self, user: &str) -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        self.sessions.insert(
            token.clone(),
            SessionEntry {
                user: user.to_string(),
                expires: Instant::now() + SESSION_TTL,
            },
        );
        token
    }

    fn validate(&self, token: &str) -> bool {
        let Some(mut e) = self.sessions.get_mut(token) else {
            return false;
        };
        if Instant::now() > e.expires {
            drop(e);
            self.sessions.remove(token);
            return false;
        }
        e.expires = Instant::now() + SESSION_TTL;
        true
    }

    fn destroy(&self, token: &str) {
        self.sessions.remove(token);
    }

    fn is_locked(&self, ip: &str) -> Option<Duration> {
        let e = self.failures.get(ip)?;
        if let Some(until) = e.locked_until {
            if Instant::now() < until {
                return Some(until.saturating_duration_since(Instant::now()));
            }
        }
        None
    }

    fn record_failure(&self, ip: &str) -> (u32, bool) {
        let now = Instant::now();
        let mut e = self.failures.entry(ip.to_string()).or_insert(FailEntry {
            count: 0,
            window_start: now,
            locked_until: None,
        });
        if now.duration_since(e.window_start) > FAIL_WINDOW {
            e.count = 0;
            e.window_start = now;
            e.locked_until = None;
        }
        if let Some(until) = e.locked_until {
            if now < until {
                return (e.count, true);
            }
            e.locked_until = None;
            e.count = 0;
            e.window_start = now;
        }
        e.count = e.count.saturating_add(1);
        let locked = e.count >= MAX_FAILS;
        if locked {
            e.locked_until = Some(now + LOCKOUT);
        }
        (e.count, locked)
    }

    fn clear_failures(&self, ip: &str) {
        self.failures.remove(ip);
    }
}

pub async fn run_panel(state: Arc<EdgeState>) -> Result<()> {
    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/tunnels", get(list_tunnels).post(create_tunnel))
        .route("/tunnels/:id", get(tunnel_detail).post(delete_tunnel))
        .route("/tunnels/:id/rules", post(add_rule))
        .route("/rules/:id/delete", post(delete_rule))
        .route("/rules/:id/toggle", post(toggle_rule))
        .with_state(state.clone())
        .layer(TraceLayer::new_for_http());

    let addr = state.config.panel_addr;
    info!("panel listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn client_ip(headers: &HeaderMap, conn: Option<ConnectInfo<SocketAddr>>) -> String {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let t = first.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    conn.map(|c| c.0.ip().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn session_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn is_authed(state: &EdgeState, headers: &HeaderMap) -> bool {
    session_from_headers(headers)
        .map(|token| state.panel_auth.validate(&token))
        .unwrap_or(false)
}

fn redirect_login() -> Response {
    Redirect::to("/login").into_response()
}

fn set_session_cookie(token: &str) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        SESSION_TTL.as_secs()
    )
}

fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

fn shell_css() -> &'static str {
    r#"
:root {
  --bg: #0f1419;
  --card: #1a2332;
  --border: #2d3a4f;
  --text: #e7ecf3;
  --muted: #8b9bb4;
  --accent: #3b82f6;
  --accent-hover: #2563eb;
  --danger: #ef4444;
  --ok: #22c55e;
  --input: #0d1117;
  --radius: 10px;
  --font: "Segoe UI", system-ui, -apple-system, sans-serif;
}
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh;
  font-family: var(--font);
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap { max-width: 960px; margin: 0 auto; padding: 1.5rem; }
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.25rem 1.5rem;
  margin-bottom: 1.25rem;
}
h1,h2 { margin: 0 0 0.75rem; font-weight: 600; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.1rem; color: var(--muted); font-weight: 500; }
.muted { color: var(--muted); font-size: 0.9rem; }
table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
th, td { text-align: left; padding: 0.65rem 0.5rem; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 500; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
code, pre {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.85em;
  background: var(--input);
  padding: 0.15em 0.4em;
  border-radius: 4px;
  word-break: break-all;
}
pre { padding: 0.75rem 1rem; overflow-x: auto; border: 1px solid var(--border); }
input, button {
  font: inherit;
  border-radius: 8px;
  border: 1px solid var(--border);
  padding: 0.55rem 0.85rem;
}
input {
  background: var(--input);
  color: var(--text);
  width: 100%;
  max-width: 320px;
}
input:focus { outline: 2px solid var(--accent); outline-offset: 1px; border-color: transparent; }
button, .btn {
  background: var(--accent);
  color: #fff;
  border: none;
  cursor: pointer;
  font-weight: 500;
  display: inline-block;
}
button:hover, .btn:hover { background: var(--accent-hover); }
button.secondary { background: transparent; border: 1px solid var(--border); color: var(--text); }
button.danger { background: var(--danger); }
button.danger:hover { filter: brightness(1.1); }
.row { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; margin: 0.5rem 0; }
.topbar {
  display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border);
}
.badge-ok { color: var(--ok); font-weight: 500; }
.badge-off { color: var(--muted); }
.form-grid { display: flex; flex-direction: column; gap: 0.75rem; max-width: 400px; }
.form-grid label { font-size: 0.85rem; color: var(--muted); }
.error {
  background: rgba(239,68,68,0.12);
  border: 1px solid rgba(239,68,68,0.4);
  color: #fca5a5;
  padding: 0.75rem 1rem;
  border-radius: 8px;
  margin-bottom: 1rem;
  font-size: 0.9rem;
}
.login-page {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background:
    radial-gradient(ellipse at 20% 20%, rgba(59,130,246,0.15), transparent 50%),
    radial-gradient(ellipse at 80% 80%, rgba(99,102,241,0.1), transparent 45%),
    var(--bg);
}
.login-box {
  width: 100%; max-width: 400px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 2rem;
  box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5);
}
.login-box .logo { text-align: center; margin-bottom: 1.75rem; }
.login-box .logo h1 { font-size: 1.75rem; letter-spacing: -0.02em; margin: 0; }
.login-box .logo p { margin: 0.35rem 0 0; color: var(--muted); font-size: 0.9rem; }
.login-box .form-grid input { max-width: none; }
.login-box button[type=submit] {
  width: 100%; padding: 0.7rem; margin-top: 0.5rem; font-size: 1rem;
}
.hint { margin-top: 1.25rem; text-align: center; font-size: 0.8rem; color: var(--muted); }
"#
}

fn login_html(error: Option<&str>, locked_secs: Option<u64>) -> String {
    let err_block = if let Some(secs) = locked_secs {
        let m = secs.div_ceil(60);
        format!(
            r#"<div class="error">登录已锁定，请约 {m} 分钟后再试（连续失败过多）。</div>"#
        )
    } else if let Some(e) = error {
        format!(r#"<div class="error">{e}</div>"#)
    } else {
        String::new()
    };
    let disabled = if locked_secs.is_some() { "disabled" } else { "" };
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录 · tunnelx</title>
<style>{css}</style>
</head>
<body>
<div class="login-page">
  <div class="login-box">
    <div class="logo">
      <h1>tunnelx</h1>
      <p>Edge 管理面板</p>
    </div>
    {err_block}
    <form method="post" action="/login" class="form-grid">
      <div>
        <label for="username">用户名</label>
        <input id="username" name="username" autocomplete="username" required autofocus {disabled}>
      </div>
      <div>
        <label for="password">密码</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required {disabled}>
      </div>
      <button type="submit" {disabled}>登录</button>
    </form>
    <p class="hint">连续失败 {max} 次将锁定 {lock} 分钟</p>
  </div>
</div>
</body>
</html>"#,
        css = shell_css(),
        err_block = err_block,
        disabled = disabled,
        max = MAX_FAILS,
        lock = LOCKOUT.as_secs() / 60,
    )
}

async fn login_page(
    State(state): State<Arc<EdgeState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    if is_authed(&state, &headers) {
        return Redirect::to("/tunnels").into_response();
    }
    let ip = client_ip(&headers, Some(ConnectInfo(addr)));
    let locked = state.panel_auth.is_locked(&ip).map(|d| d.as_secs());
    Html(login_html(None, locked)).into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_submit(
    State(state): State<Arc<EdgeState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    let ip = client_ip(&headers, Some(ConnectInfo(addr)));

    if let Some(rem) = state.panel_auth.is_locked(&ip) {
        return Html(login_html(None, Some(rem.as_secs()))).into_response();
    }

    let ok = form.username == state.config.panel_user
        && form.password == state.config.panel_pass;

    if !ok {
        let (count, locked) = state.panel_auth.record_failure(&ip);
        tracing::warn!("panel login failed from {ip} (attempt {count}/{MAX_FAILS})");
        let msg = if locked {
            format!("用户名或密码错误。已连续失败 {count} 次，账户暂时锁定。")
        } else {
            format!(
                "用户名或密码错误（还可尝试 {} 次）",
                MAX_FAILS.saturating_sub(count)
            )
        };
        let locked_secs = if locked {
            Some(LOCKOUT.as_secs())
        } else {
            None
        };
        return Html(login_html(Some(&msg), locked_secs)).into_response();
    }

    state.panel_auth.clear_failures(&ip);
    let token = state.panel_auth.create_session(&form.username);
    tracing::info!("panel login ok from {ip} user={}", form.username);

    let mut res = Redirect::to("/tunnels").into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        set_session_cookie(&token).parse().unwrap(),
    );
    res
}

async fn logout(State(state): State<Arc<EdgeState>>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(token) = session_from_headers(&headers) {
        state.panel_auth.destroy(&token);
    }
    let mut res = Redirect::to("/login").into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        clear_session_cookie().parse().unwrap(),
    );
    res
}

fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · tunnelx</title>
<style>{css}</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <div><strong>tunnelx</strong> <span class="muted">Edge</span></div>
    <form method="post" action="/logout" style="margin:0">
      <button type="submit" class="secondary">退出登录</button>
    </form>
  </div>
  {body}
</div>
</body>
</html>"#,
        title = title,
        css = shell_css(),
        body = body,
    )
}

async fn index(State(state): State<Arc<EdgeState>>, headers: HeaderMap) -> impl IntoResponse {
    if !is_authed(&state, &headers) {
        return redirect_login();
    }
    Redirect::to("/tunnels").into_response()
}

async fn list_tunnels(State(state): State<Arc<EdgeState>>, headers: HeaderMap) -> impl IntoResponse {
    if !is_authed(&state, &headers) {
        return redirect_login();
    }
    let tunnels = state.db.list_tunnels().await.unwrap_or_default();
    let mut rows = String::new();
    for t in &tunnels {
        let agents = state.agents.count(&Uuid::parse_str(&t.id).unwrap_or_default());
        rows.push_str(&format!(
            r#"<tr>
              <td><a href="/tunnels/{id}">{name}</a></td>
              <td><code>{token}</code></td>
              <td>{agents}</td>
              <td>
                <form method="post" action="/tunnels/{id}" style="display:inline"
                  onsubmit="return confirm('删除此 Tunnel？')">
                  <button type="submit" class="danger">删除</button>
                </form>
              </td>
            </tr>"#,
            id = t.id,
            name = html_escape(&t.name),
            token = t.token,
            agents = agents,
        ));
    }
    let body = format!(
        r#"<h1>Tunnels</h1>
<div class="card">
  <form method="post" action="/tunnels" class="row">
    <input name="name" placeholder="新 Tunnel 名称" required>
    <button type="submit">创建</button>
  </form>
</div>
<div class="card">
  <table>
    <tr><th>名称</th><th>Token</th><th>在线 Agent</th><th></th></tr>
    {rows}
  </table>
</div>"#,
        rows = rows,
    );
    Html(page("Tunnels", &body)).into_response()
}

#[derive(Deserialize)]
struct CreateTunnelForm {
    name: String,
}

async fn create_tunnel(
    State(state): State<Arc<EdgeState>>,
    headers: HeaderMap,
    Form(form): Form<CreateTunnelForm>,
) -> impl IntoResponse {
    if !is_authed(&state, &headers) {
        return redirect_login();
    }
    match state.db.create_tunnel(&form.name).await {
        Ok(t) => Redirect::to(&format!("/tunnels/{}", t.id)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
}

async fn tunnel_detail(
    State(state): State<Arc<EdgeState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !is_authed(&state, &headers) {
        return redirect_login();
    }
    let tunnel = match state.db.get_tunnel(&id).await {
        Ok(Some(t)) => t,
        _ => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let rules = state.db.list_rules(&id).await.unwrap_or_default();
    let agents = state.agents.count(&Uuid::parse_str(&id).unwrap_or_default());
    let mut rule_rows = String::new();
    for r in &rules {
        let enabled = r.enabled != 0;
        let status = if enabled {
            r#"<span class="badge-ok">启用</span>"#
        } else {
            r#"<span class="badge-off">停用</span>"#
        };
        let toggle_label = if enabled { "停用" } else { "启用" };
        rule_rows.push_str(&format!(
            r#"<tr>
            <td>{stype}</td>
            <td>{host}</td>
            <td>{port}</td>
            <td><code>{target}</code></td>
            <td>{status}</td>
            <td style="white-space:nowrap">
              <form method="post" action="/rules/{rid}/toggle" style="display:inline">
                <button type="submit" class="secondary">{toggle_label}</button>
              </form>
              <form method="post" action="/rules/{rid}/delete" style="display:inline"
                onsubmit="return confirm('删除规则？')">
                <button type="submit" class="danger">删除</button>
              </form>
            </td>
            </tr>"#,
            stype = r.service_type,
            host = html_escape(r.hostname.as_deref().unwrap_or("-")),
            port = r
                .public_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into()),
            target = html_escape(&r.target),
            rid = r.id,
            status = status,
            toggle_label = toggle_label,
        ));
    }
    let body = format!(
        r#"<p><a href="/tunnels">&larr; 返回</a></p>
<h1>{name}</h1>
<div class="card">
  <p class="muted">Token</p>
  <p><code>{token}</code></p>
  <p>在线 Agent：<b>{agents}</b></p>
  <p class="muted">Agent 启动命令</p>
  <pre>./tunnelx agent --server EDGE_IP:QUIC_PORT --token {token}</pre>
</div>

<div class="card">
  <h2>规则</h2>
  <table>
    <tr><th>类型</th><th>Hostname</th><th>公网端口</th><th>目标</th><th>状态</th><th>操作</th></tr>
    {rule_rows}
  </table>
</div>

<div class="card">
  <h2>添加 HTTP 规则</h2>
  <form method="post" action="/tunnels/{id}/rules" class="form-grid">
    <input type="hidden" name="service_type" value="http">
    <input name="hostname" placeholder="app.example.com" required>
    <input name="target" placeholder="http://127.0.0.1:8080" required>
    <button type="submit">添加 HTTP</button>
  </form>
</div>

<div class="card">
  <h2>添加 TCP 规则</h2>
  <form method="post" action="/tunnels/{id}/rules" class="form-grid">
    <input type="hidden" name="service_type" value="tcp">
    <input name="target" placeholder="tcp://127.0.0.1:22" required>
    <input name="public_port" type="number" placeholder="公网端口 如 2222" required>
    <button type="submit">添加 TCP</button>
  </form>
</div>

<div class="card">
  <h2>添加 UDP 规则</h2>
  <form method="post" action="/tunnels/{id}/rules" class="form-grid">
    <input type="hidden" name="service_type" value="udp">
    <input name="target" placeholder="udp://127.0.0.1:53" required>
    <input name="public_port" type="number" placeholder="公网端口 如 5353" required>
    <button type="submit">添加 UDP</button>
  </form>
</div>"#,
        name = html_escape(&tunnel.name),
        token = tunnel.token,
        agents = agents,
        id = id,
        rule_rows = rule_rows,
    );
    Html(page(&tunnel.name, &body)).into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[derive(Deserialize)]
struct AddRuleForm {
    service_type: String,
    hostname: Option<String>,
    target: String,
    public_port: Option<u16>,
}

async fn add_rule(
    State(state): State<Arc<EdgeState>>,
    Path(tunnel_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<AddRuleForm>,
) -> impl IntoResponse {
    if !is_authed(&state, &headers) {
        return redirect_login();
    }
    let st = match form.service_type.as_str() {
        "tcp" => ServiceType::Tcp,
        "udp" => ServiceType::Udp,
        _ => ServiceType::Http,
    };
    match state
        .db
        .add_rule(
            &tunnel_id,
            form.hostname.as_deref(),
            None,
            st,
            &form.target,
            form.public_port,
        )
        .await
    {
        Ok(rule) => {
            *state.config_version.write().await += 1;
            if st == ServiceType::Tcp {
                if let Some(port) = form.public_port {
                    if let Ok(rid) = Uuid::parse_str(&rule.id) {
                        state
                            .listeners
                            .start_tcp(state.clone(), rid, port, rule.target.clone());
                    }
                }
            }
            if st == ServiceType::Udp {
                if let Some(port) = form.public_port {
                    if let Ok(rid) = Uuid::parse_str(&rule.id) {
                        state
                            .listeners
                            .start_udp(state.clone(), rid, port, rule.target.clone());
                    }
                }
            }
            if let Ok(tid) = Uuid::parse_str(&tunnel_id) {
                let version = *state.config_version.read().await;
                if let Ok(rules) = state.db.rules_for_tunnel(&tunnel_id).await {
                    state.agents.broadcast_config(
                        &tid,
                        crate::protocol::ConfigUpdate { version, rules },
                    );
                }
            }
            Redirect::to(&format!("/tunnels/{tunnel_id}")).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
}

async fn toggle_rule(
    State(state): State<Arc<EdgeState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !is_authed(&state, &headers) {
        return redirect_login();
    }
    let rule = match state.db.get_rule(&id).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "rule not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    };
    let new_enabled = rule.enabled == 0;
    if let Err(e) = state.db.set_rule_enabled(&id, new_enabled).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response();
    }
    *state.config_version.write().await += 1;

    if let Ok(rid) = Uuid::parse_str(&rule.id) {
        if new_enabled {
            if let Some(port) = rule.public_port {
                let port = port as u16;
                match rule.service_type.as_str() {
                    "tcp" => state
                        .listeners
                        .start_tcp(state.clone(), rid, port, rule.target.clone()),
                    "udp" => state
                        .listeners
                        .start_udp(state.clone(), rid, port, rule.target.clone()),
                    _ => {}
                }
            }
        } else {
            state.listeners.stop(rid);
        }
    }

    if let Ok(tid) = Uuid::parse_str(&rule.tunnel_id) {
        let version = *state.config_version.read().await;
        if let Ok(rules) = state.db.rules_for_tunnel(&rule.tunnel_id).await {
            state
                .agents
                .broadcast_config(&tid, crate::protocol::ConfigUpdate { version, rules });
        }
    }
    Redirect::to(&format!("/tunnels/{}", rule.tunnel_id)).into_response()
}

async fn delete_rule(
    State(state): State<Arc<EdgeState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !is_authed(&state, &headers) {
        return redirect_login();
    }
    if let Ok(Some(rule)) = state.db.get_rule(&id).await {
        if let Ok(rid) = Uuid::parse_str(&rule.id) {
            state.listeners.stop(rid);
        }
    }
    let _ = state.db.delete_rule(&id).await;
    *state.config_version.write().await += 1;
    if let Ok(tunnels) = state.db.list_tunnels().await {
        let version = *state.config_version.read().await;
        for t in tunnels {
            if let (Ok(tid), Ok(rules)) =
                (Uuid::parse_str(&t.id), state.db.rules_for_tunnel(&t.id).await)
            {
                state
                    .agents
                    .broadcast_config(&tid, crate::protocol::ConfigUpdate { version, rules });
            }
        }
    }
    Redirect::to("/tunnels").into_response()
}

async fn delete_tunnel(
    State(state): State<Arc<EdgeState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !is_authed(&state, &headers) {
        return redirect_login();
    }
    if let Ok(rules) = state.db.list_rules(&id).await {
        for r in rules {
            if let Ok(rid) = Uuid::parse_str(&r.id) {
                state.listeners.stop(rid);
            }
        }
    }
    let _ = state.db.delete_tunnel(&id).await;
    Redirect::to("/tunnels").into_response()
}
