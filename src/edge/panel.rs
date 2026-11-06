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

/// Normalize the user-supplied target so the prefix (http:// tcp:// udp://) is optional.
/// - http  → ensure `http://` (or keep `https://`) so the Agent can build a base URL
/// - tcp/udp → strip any scheme prefix; the Agent only needs `host:port`
fn normalize_target(service_type: &str, raw: &str) -> String {
    let t = raw.trim();
    let lower = t.to_ascii_lowercase();
    match service_type {
        "http" => {
            if lower.starts_with("http://") || lower.starts_with("https://") {
                t.to_string()
            } else {
                format!("http://{t}")
            }
        }
        _ => {
            for p in ["tcp://", "udp://", "https://", "http://"] {
                if lower.starts_with(p) {
                    return t[p.len()..].to_string();
                }
            }
            t.to_string()
        }
    }
}

fn online_badge(online: bool) -> &'static str {
    if online {
        r#"<span class="badge badge-online"><span class="dot"></span>在线</span>"#
    } else {
        r#"<span class="badge badge-offline"><span class="dot"></span>离线</span>"#
    }
}

fn type_pill(st: &str) -> String {
    let cls = match st {
        "tcp" => "pill-tcp",
        "udp" => "pill-udp",
        _ => "pill-http",
    };
    format!(r#"<span class="pill {cls}">{}</span>"#, st.to_uppercase())
}

fn shell_css() -> &'static str {
    r#"
:root {
  --bg: #f6f8fb;
  --card: #ffffff;
  --border: #e6eaf2;
  --text: #1c2333;
  --muted: #6b7688;
  --accent: #3b82f6;
  --accent-2: #6366f1;
  --accent-hover: #2563eb;
  --danger: #ef4444;
  --ok: #10b981;
  --input: #f4f6fa;
  --radius: 14px;
  --shadow: 0 1px 2px rgba(16,24,40,.04), 0 8px 24px -12px rgba(16,24,40,.12);
  --shadow-lift: 0 4px 8px rgba(16,24,40,.06), 0 16px 32px -12px rgba(16,24,40,.18);
  --font: "Segoe UI", system-ui, -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; min-height: 100vh;
  font-family: var(--font);
  color: var(--text);
  line-height: 1.55;
  background:
    radial-gradient(1100px 520px at 85% -10%, rgba(99,102,241,.10), transparent 60%),
    radial-gradient(900px 480px at -10% 15%, rgba(59,130,246,.09), transparent 55%),
    radial-gradient(700px 420px at 50% 110%, rgba(16,185,129,.06), transparent 60%),
    var(--bg);
  -webkit-font-smoothing: antialiased;
}
a { color: var(--accent); text-decoration: none; transition: color .15s; }
a:hover { color: var(--accent-hover); text-decoration: underline; }
.wrap { max-width: 960px; margin: 0 auto; padding: 0 1.5rem 2.5rem; }
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.35rem 1.5rem;
  margin-bottom: 1.25rem;
  box-shadow: var(--shadow);
  transition: box-shadow .2s ease, transform .2s ease;
}
h1,h2 { margin: 0 0 .75rem; font-weight: 700; letter-spacing: -0.01em; }
h1 { font-size: 1.55rem; }
h2 { font-size: 1.05rem; color: var(--text); font-weight: 600; }
.muted { color: var(--muted); font-size: .9rem; }
.page-head { margin: 1.75rem 0 1.1rem; display: flex; align-items: center; gap: .75rem; flex-wrap: wrap; }
.page-head h1 { margin: 0; }

table { width: 100%; border-collapse: collapse; font-size: .92rem; }
th, td { text-align: left; padding: .7rem .6rem; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: .74rem; text-transform: uppercase; letter-spacing: .06em; }
tbody tr { transition: background .15s; }
tbody tr:hover { background: #f8faff; }
tbody tr:last-child td { border-bottom: none; }

code, pre {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .85em;
  background: var(--input);
  padding: .15em .45em;
  border-radius: 6px;
  word-break: break-all;
}
pre { padding: .85rem 1rem; overflow-x: auto; border: 1px solid var(--border); border-radius: 10px; }

input, select, button {
  font: inherit;
  border-radius: 10px;
  border: 1px solid var(--border);
  transition: border-color .15s, box-shadow .15s, background .15s, transform .12s, filter .15s;
}
input, select {
  background: var(--input);
  color: var(--text);
  width: 100%;
  max-width: 340px;
  padding: .55rem .85rem;
}
input::placeholder { color: #9aa5b6; }
input:focus, select:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(59,130,246,.18); background: #fff; }
button, .btn {
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  color: #fff;
  border: none;
  cursor: pointer;
  font-weight: 600;
  display: inline-block;
  padding: .55rem 1.1rem;
  box-shadow: 0 2px 8px -2px rgba(59,130,246,.5);
}
button:hover, .btn:hover { filter: brightness(1.06); transform: translateY(-1px); box-shadow: 0 6px 16px -4px rgba(59,130,246,.55); }
button:active { transform: translateY(0); }
button.secondary {
  background: #fff; border: 1px solid var(--border); color: var(--text); box-shadow: none;
}
button.secondary:hover { border-color: #c9d3e3; background: #f8fafc; box-shadow: var(--shadow); }
button.danger {
  background: #fff; color: var(--danger); border: 1px solid rgba(239,68,68,.35); box-shadow: none;
}
button.danger:hover { background: rgba(239,68,68,.06); box-shadow: none; filter: none; }
button.small, .small { font-size: .82rem; padding: .35rem .75rem; border-radius: 8px; }

.row { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center; margin: .5rem 0; }
.topbar {
  position: sticky; top: 0; z-index: 20;
  display: flex; justify-content: space-between; align-items: center;
  margin: 0 -1.5rem 1.5rem; padding: .85rem 1.5rem;
  background: rgba(255,255,255,.82);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
}
.brand { display: flex; align-items: center; gap: .55rem; font-weight: 700; font-size: 1.05rem; letter-spacing: -0.01em; }
.brand .logo-dot {
  width: 12px; height: 12px; border-radius: 4px; flex: none;
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  box-shadow: 0 0 0 4px rgba(99,102,241,.14);
}
.brand .muted { font-weight: 500; }

.badge {
  display: inline-flex; align-items: center; gap: .45em;
  padding: .22em .8em; border-radius: 999px;
  font-size: .8rem; font-weight: 600; line-height: 1.5;
  border: 1px solid transparent; white-space: nowrap;
}
.badge .dot { width: 7px; height: 7px; border-radius: 50%; flex: none; }
.badge-online { color: #047857; background: rgba(16,185,129,.1); border-color: rgba(16,185,129,.3); }
.badge-online .dot { background: var(--ok); animation: pulse 1.8s ease-in-out infinite; }
.badge-offline { color: var(--muted); background: #f1f4f8; border-color: var(--border); }
.badge-offline .dot { background: #b3bdcc; }
@keyframes pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(16,185,129,.45); }
  50% { box-shadow: 0 0 0 5px rgba(16,185,129,0); }
}

.pill {
  display: inline-block; padding: .18em .7em; border-radius: 999px;
  font-size: .72rem; font-weight: 700; letter-spacing: .05em;
}
.pill-http { color: #1d4ed8; background: rgba(59,130,246,.1); }
.pill-tcp  { color: #6d28d9; background: rgba(139,92,246,.12); }
.pill-udp  { color: #0f766e; background: rgba(20,184,166,.12); }

.form-grid { display: flex; flex-direction: column; gap: .8rem; max-width: 420px; }
.form-grid label { font-size: .84rem; color: var(--muted); font-weight: 600; }
.form-grid input, .form-grid select { max-width: none; }
.field-hint { font-size: .78rem; color: #9aa5b6; margin-top: .25rem; }

.error {
  background: rgba(239,68,68,.07);
  border: 1px solid rgba(239,68,68,.3);
  color: #b91c1c;
  padding: .75rem 1rem;
  border-radius: 10px;
  margin-bottom: 1rem;
  font-size: .9rem;
}

.login-page {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  padding: 1.25rem;
}
.login-box {
  width: 100%; max-width: 400px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 2.25rem 2rem;
  box-shadow: var(--shadow-lift);
  animation: rise .35s ease;
}
@keyframes rise { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }
.login-box .logo { text-align: center; margin-bottom: 1.75rem; }
.login-box .logo h1 {
  font-size: 1.9rem; margin: 0; letter-spacing: -0.03em;
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  -webkit-background-clip: text; background-clip: text;
  -webkit-text-fill-color: transparent; color: transparent;
}
.login-box .logo p { margin: .35rem 0 0; color: var(--muted); font-size: .9rem; }
.login-box .form-grid input { max-width: none; }
.login-box button[type=submit] { width: 100%; padding: .72rem; margin-top: .4rem; font-size: 1rem; }
.hint { margin-top: 1.25rem; text-align: center; font-size: .8rem; color: #9aa5b6; }

.card-head { display: flex; align-items: center; justify-content: space-between; gap: .75rem; margin-bottom: .9rem; }
.card-head h2 { margin: 0; }
.token-row { display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; }
.token-row code { font-size: .95em; }

@media (max-width: 720px) {
  .wrap { padding: 0 1rem 2rem; }
  .topbar { margin: 0 -1rem 1.25rem; padding: .75rem 1rem; }
  h1 { font-size: 1.3rem; }
  .card { padding: 1.1rem 1rem; }
  input, select { max-width: none; }
  .row .btn-grow { flex: 1 1 100%; }
  button[type=submit].btn-grow { width: 100%; }
  /* tables collapse into stacked cards */
  table, tbody, tr, td { display: block; width: 100%; }
  thead { display: none; }
  tbody tr {
    background: #fff;
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-bottom: .7rem;
    padding: .35rem .9rem;
    box-shadow: var(--shadow);
  }
  tbody tr:hover { background: #fff; }
  td {
    display: flex; justify-content: space-between; align-items: center; gap: 1rem;
    padding: .55rem 0; border-bottom: 1px dashed var(--border);
    word-break: break-all;
  }
  td:last-child { border-bottom: none; }
  td[data-label]::before {
    content: attr(data-label);
    color: var(--muted); font-size: .74rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: .05em; flex: none;
  }
  td.no-label { justify-content: flex-end; }
}
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
    <div class="brand"><span class="logo-dot"></span>tunnelx <span class="muted">Edge</span></div>
    <form method="post" action="/logout" style="margin:0">
      <button type="submit" class="secondary small">退出登录</button>
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
        let online = state.agents.count(&Uuid::parse_str(&t.id).unwrap_or_default()) > 0;
        rows.push_str(&format!(
            r#"<tr>
              <td data-label="名称"><a href="/tunnels/{id}">{name}</a></td>
              <td data-label="Token"><code>{token}</code></td>
              <td data-label="状态">{badge}</td>
              <td class="no-label">
                <form method="post" action="/tunnels/{id}" style="display:inline"
                  onsubmit="return confirm('删除此 Tunnel？')">
                  <button type="submit" class="danger small">删除</button>
                </form>
              </td>
            </tr>"#,
            id = t.id,
            name = html_escape(&t.name),
            token = t.token,
            badge = online_badge(online),
        ));
    }
    let empty_row = if rows.is_empty() {
        r#"<tr><td colspan="4" class="muted" style="text-align:center;padding:1.5rem 0">
             还没有 Tunnel，先在上方创建一个吧
           </td></tr>"#
    } else {
        ""
    };
    let body = format!(
        r#"<div class="page-head"><h1>Tunnels</h1></div>
<div class="card">
  <form method="post" action="/tunnels" class="row" style="margin:0">
    <input name="name" placeholder="新 Tunnel 名称" required style="flex:1;min-width:200px">
    <button type="submit" class="btn-grow">创建 Tunnel</button>
  </form>
</div>
<div class="card">
  <table>
    <thead><tr><th>名称</th><th>Token</th><th>状态</th><th></th></tr></thead>
    <tbody>
    {rows}
    {empty_row}
    </tbody>
  </table>
</div>"#,
        rows = rows,
        empty_row = empty_row,
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
    let online = state.agents.count(&Uuid::parse_str(&id).unwrap_or_default()) > 0;
    let mut rule_rows = String::new();
    for r in &rules {
        let enabled = r.enabled != 0;
        let status = if enabled {
            r#"<span class="badge badge-online"><span class="dot"></span>启用</span>"#
        } else {
            r#"<span class="badge badge-offline"><span class="dot"></span>停用</span>"#
        };
        let toggle_label = if enabled { "停用" } else { "启用" };
        rule_rows.push_str(&format!(
            r#"<tr>
            <td data-label="类型">{pill}</td>
            <td data-label="Hostname">{host}</td>
            <td data-label="公网端口">{port}</td>
            <td data-label="目标"><code>{target}</code></td>
            <td data-label="状态">{status}</td>
            <td class="no-label" style="white-space:nowrap">
              <form method="post" action="/rules/{rid}/toggle" style="display:inline">
                <button type="submit" class="secondary small">{toggle_label}</button>
              </form>
              <form method="post" action="/rules/{rid}/delete" style="display:inline"
                onsubmit="return confirm('删除规则？')">
                <button type="submit" class="danger small">删除</button>
              </form>
            </td>
            </tr>"#,
            pill = type_pill(&r.service_type),
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
    let empty_rules = if rule_rows.is_empty() {
        r#"<tr><td colspan="6" class="muted" style="text-align:center;padding:1.5rem 0">
             暂无规则，在下方添加第一条
           </td></tr>"#
    } else {
        ""
    };
    let body = format!(
        r#"<p style="margin:0"><a href="/tunnels">&larr; 返回列表</a></p>
<div class="page-head">
  <h1>{name}</h1>
  {badge}
</div>

<div class="card">
  <div class="card-head"><h2>Agent 接入</h2></div>
  <p class="muted" style="margin-top:0">Token</p>
  <p class="token-row"><code>{token}</code></p>
  <p class="muted">Agent 启动命令</p>
  <pre>./tunnelx agent --server EDGE_IP:QUIC_PORT --token {token}</pre>
  <p class="field-hint">一个 Tunnel 同一时刻只能由一个 Agent 占用，重复连接会被拒绝。</p>
</div>

<div class="card">
  <div class="card-head"><h2>规则</h2></div>
  <table>
    <thead><tr><th>类型</th><th>Hostname</th><th>公网端口</th><th>目标</th><th>状态</th><th></th></tr></thead>
    <tbody>
    {rule_rows}
    {empty_rules}
    </tbody>
  </table>
</div>

<div class="card">
  <div class="card-head"><h2>添加规则</h2></div>
  <form method="post" action="/tunnels/{id}/rules" class="form-grid">
    <div>
      <label for="stype">类型</label>
      <select id="stype" name="service_type" onchange="updFields()">
        <option value="http">HTTP（按域名转发）</option>
        <option value="tcp">TCP（按端口转发）</option>
        <option value="udp">UDP（按端口转发）</option>
      </select>
    </div>
    <div id="f-host">
      <label for="hostname">Hostname</label>
      <input id="hostname" name="hostname" placeholder="app.example.com" required>
    </div>
    <div id="f-port" style="display:none">
      <label for="public_port">公网端口</label>
      <input id="public_port" name="public_port" type="number" min="1" max="65535" placeholder="如 2222">
    </div>
    <div>
      <label for="target">目标地址</label>
      <input id="target" name="target" placeholder="127.0.0.1:8080" required>
      <p class="field-hint" id="target-hint">直接填 host:port 即可，无需 http:// 前缀</p>
    </div>
    <button type="submit">添加规则</button>
  </form>
</div>
<script>
function updFields() {{
  var t = document.getElementById('stype').value;
  var http = t === 'http';
  var fh = document.getElementById('f-host');
  var fp = document.getElementById('f-port');
  var hi = document.getElementById('hostname');
  var pi = document.getElementById('public_port');
  fh.style.display = http ? '' : 'none';
  fp.style.display = http ? 'none' : '';
  hi.disabled = !http; hi.required = http;
  pi.disabled = http; pi.required = !http;
  document.getElementById('target').placeholder =
    http ? '127.0.0.1:8080' : (t === 'tcp' ? '127.0.0.1:22' : '127.0.0.1:53');
  document.getElementById('target-hint').textContent =
    http ? '直接填 host:port 即可，无需 http:// 前缀'
         : '直接填 host:port 即可，无需 ' + t + ':// 前缀';
}}
updFields();
</script>"#,
        name = html_escape(&tunnel.name),
        badge = online_badge(online),
        token = tunnel.token,
        id = id,
        rule_rows = rule_rows,
        empty_rules = empty_rules,
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
    // 前缀可选：按服务类型归一化 target（http 补 http://，tcp/udp 去掉协议前缀）
    let target = normalize_target(form.service_type.as_str(), &form.target);
    // HTTP 才有 hostname；空串视为未填写
    let hostname = if st == ServiceType::Http {
        form.hostname
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
    } else {
        None
    };
    let public_port = if st == ServiceType::Http {
        None
    } else {
        form.public_port
    };
    match state
        .db
        .add_rule(
            &tunnel_id,
            hostname,
            None,
            st,
            &target,
            public_port,
        )
        .await
    {
        Ok(rule) => {
            *state.config_version.write().await += 1;
            if st == ServiceType::Tcp {
                if let Some(port) = public_port {
                    if let Ok(rid) = Uuid::parse_str(&rule.id) {
                        state
                            .listeners
                            .start_tcp(state.clone(), rid, port, rule.target.clone());
                    }
                }
            }
            if st == ServiceType::Udp {
                if let Some(port) = public_port {
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
