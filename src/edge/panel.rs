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
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// In-memory auth: sessions + per-IP login failure tracking.
#[derive(Clone)]
pub struct PanelAuth {
    sessions: dashmap::DashMap<String, SessionEntry>,
    failures: dashmap::DashMap<String, FailEntry>,
}

#[derive(Clone)]
struct SessionEntry {
    #[allow(dead_code)]
    user: String,
    expires: Instant,
}

#[derive(Clone)]
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

    /// Drop expired sessions and stale failure entries (bounded memory).
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.sessions.retain(|_, e| now < e.expires);
        self.failures.retain(|_, e| match e.locked_until {
            Some(until) => now < until,
            None => now.duration_since(e.window_start) <= FAIL_WINDOW,
        });
    }
}

/// Constant-time byte-string equality (no early return on content mismatch).
fn ct_eq(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let mut diff = (ab.len() ^ bb.len()) as u64;
    let n = ab.len().max(bb.len());
    for i in 0..n {
        let x = ab.get(i).copied().unwrap_or(0u8);
        let y = bb.get(i).copied().unwrap_or(0u8);
        diff |= (x ^ y) as u64;
    }
    diff == 0
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

    // Periodic cleanup of expired sessions / stale failure entries.
    let auth = state.panel_auth.clone();
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            iv.tick().await;
            auth.cleanup();
        }
    });

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Resolve the rate-limit key for a request.
///
/// By default the direct connection IP is used. `x-forwarded-for` is only
/// honored when `trust_proxy` is explicitly enabled in config — otherwise any
/// client could spoof the header on every attempt and bypass login lockout.
fn client_ip(
    state: &EdgeState,
    headers: &HeaderMap,
    conn: Option<ConnectInfo<SocketAddr>>,
) -> String {
    if state.config.trust_proxy {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                let t = first.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
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

fn set_session_cookie(token: &str, secure: bool) -> String {
    let mut c = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        SESSION_TTL.as_secs()
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn clear_session_cookie(secure: bool) -> String {
    let mut c = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if secure {
        c.push_str("; Secure");
    }
    c
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
        r#"<span class="badge badge-online"><span class="dot"></span><span data-i18n="badge.online">Online</span></span>"#
    } else {
        r#"<span class="badge badge-offline"><span class="dot"></span><span data-i18n="badge.offline">Offline</span></span>"#
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

const LANG_SWITCH_HTML: &str = r#"<div class="lang-switch" role="group" aria-label="Language">
  <button type="button" data-lang="zh">中</button>
  <button type="button" data-lang="en">EN</button>
</div>"#;

/// Tab icon: inline SVG + PNG fallbacks (data URIs, no external files).
/// PNG needed because some mobile browsers ignore SVG favicons.
const FAVICON_LINK: &str = "<link rel=\"icon\" type=\"image/svg+xml\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%233b82f6'/%3E%3Cstop offset='1' stop-color='%236366f1'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='64' height='64' rx='14' fill='url(%23g)'/%3E%3Cpath fill='%23fff' fill-rule='evenodd' d='M32 12a20 20 0 1 0 0 40 20 20 0 0 0 0-40zm0 13a7 7 0 1 1 0 14 7 7 0 0 1 0-14z'/%3E%3C/svg%3E\">\
<link rel=\"icon\" type=\"image/png\" sizes=\"32x32\" href=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABmJLR0QA/wD/AP+gvaeTAAADkUlEQVRYhcWWT0xcZRDAf/Ptt0tSyyKQ9iBcDMGEKtjYtLG0CXrSSiU2aS9N1EYrNz0Zr+LZ6IVT10jaEA8mVrDFWG9NlkgsadigUlJRD6UHFeSv2uW9feNhebBsv/d2RV3n8r28N/N+38w3M98IJdI9sLbfYt4QlV5E20V5QLT4TRQEoGzd8ay6pQvhOwBWRPWWgY+8P/d+8MWg5EOmhA897/xxRpUPRakHLTX+p/By+1kNglNX30vPbm1gE/6xKPIfw8N10Urh6OV3G76XYtgTczXwvMReEWV6qX7vIVM889rCKep0Na6svWgEOVlr+LauvGRRbasWXmehp9PS3ZGgvcXQnC7m8MKq8sN8wMSMz3jOx/OrgYOBg/LU279rNfCnuyz9J5I01W8VjlN+W1WGxjbI5vxYeLjaSvCEgdefT/HcYRsLDqUpLbx5to7HHk6QGc2jQTRcilGI9/zvwEvl2aOW/hdSsXBRMJXCvhv49iaSHH/cRsIBTFzC9Z9I7hoeyrm+OpI2ulpMVKn1dNrYhLvzc8Bo1uOzrMf8L0GkXnOD0N1lnXABbFSdd3ckIn96Zdxj6PMNgkJR9+IYnO9L0XvMHbEjnZbsTd9R6rodgfIm095iIj0vhaOgAQxdyXP3V3ck2lqNEy5s5oCrw0WFf3K2sAMe1nlQgJszBadNY4NxwtGyJCxtr+r8lSNapU0mwiYKXuwDEb19ac29hcMdCYzcD7cChw6482ZpJXDCt4/AcbHMzbvPs3W/4XxfioTZCX/1VB0P7XPnzY93AiccBRt1q03M+Dz5qNuj3mNJDj6SYGq2AApPdCQi4QCT037krWpdcIDxnM/Lz6RoSrtPtmWfoSUGGsrisnIj50Vc6ZutuBwuCp4PQ2MbFQGVZHjkHp7nhkN4GZXBQ8VszufahL9r+JfZDb6e8iPholtJeD88XDOjea5NeLuCX/okHwuHKuYBDZQLl/N8N1fgXF8dzQ3xA8nisjI8cq+i57CdhCuiNFSa4b7K+Ux+69PdZTnSaWlrNTRtdrjF5YCf5gMmp31u5LzYMy/LuVU5+db6dYGeama4+AHUXefx9jplBBn+n+AYuGrW9uy5JPBNreGirCQLMmiuD4ifKASnBRZrCFc0eCWTSS8YgJH307etBseBW7XwHA1OX7zQ+Gn4bUvODGjKX11/TeCsKAeAB/8l+Dqqt40wlizIYCaTXgiZfwGjTlP2OwGnfAAAAABJRU5ErkJggg==\">\
<link rel=\"apple-touch-icon\" sizes=\"180x180\" href=\"data:image/png;base64,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\">";

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

.lang-switch {
  display: inline-flex;
  border: 1px solid var(--border);
  border-radius: 999px;
  overflow: hidden;
  background: #fff;
  box-shadow: var(--shadow);
  flex: none;
}
.lang-switch button {
  background: transparent;
  border: none;
  border-radius: 0;
  color: var(--muted);
  padding: .28rem .75rem;
  font-size: .8rem;
  font-weight: 600;
  cursor: pointer;
  box-shadow: none;
  transform: none;
  filter: none;
}
.lang-switch button:hover { filter: none; transform: none; background: #f1f5fb; box-shadow: none; }
.lang-switch button.active {
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  color: #fff;
}

.row { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center; margin: .5rem 0; }
.topbar {
  position: sticky; top: 0; z-index: 20;
  display: flex; justify-content: space-between; align-items: center; gap: .75rem;
  margin: 0 -1.5rem 1.5rem; padding: .85rem 1.5rem;
  background: rgba(255,255,255,.82);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
}
.topbar-actions { display: flex; align-items: center; gap: .6rem; }
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
  position: relative;
  width: 100%; max-width: 400px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 2.25rem 2rem;
  box-shadow: var(--shadow-lift);
  animation: rise .35s ease;
}
.login-box .lang-switch { position: absolute; top: 1rem; right: 1rem; }
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

/// Client-side i18n core: dictionary + applier, cached in localStorage
/// (`tunnelx_lang`, default `en`). Injected into every page.
fn i18n_js() -> &'static str {
    r#"
<script>
var I18N_DICT = {
  en: {
    "title.login": "Sign in \u00b7 tunnelx",
    "login.subtitle": "Edge Admin Panel",
    "login.username": "Username",
    "login.password": "Password",
    "login.submit": "Sign in",
    "login.hint": "Account locks for {lock} min after {max} failed attempts",
    "err.locked": "Login locked. Try again in about {m} min.",
    "err.bad_cred": "Wrong username or password ({n} attempts left)",
    "err.bad_cred_locked": "Wrong username or password. {n} failed attempts \u2014 account temporarily locked.",
    "topbar.logout": "Log out",
    "ph.tunnel_name": "New tunnel name",
    "tunnels.create": "Create tunnel",
    "th.name": "Name",
    "th.token": "Token",
    "th.status": "Status",
    "tunnels.empty": "No tunnels yet \u2014 create one above",
    "badge.online": "Online",
    "badge.offline": "Offline",
    "confirm.del_tunnel": "Delete this tunnel?",
    "btn.delete": "Delete",
    "detail.back": "\u2190 Back to list",
    "detail.agent_h2": "Agent access",
    "detail.cmd_label": "Agent start command",
    "detail.agent_hint": "Only one Agent can occupy a tunnel at a time; duplicate connections are rejected.",
    "detail.rules_h2": "Rules",
    "th.type": "Type",
    "th.hostname": "Hostname",
    "th.port": "Public port",
    "th.target": "Target",
    "rule.on": "Enabled",
    "rule.off": "Disabled",
    "rule.enable": "Enable",
    "rule.disable": "Disable",
    "confirm.del_rule": "Delete this rule?",
    "rules.empty": "No rules yet \u2014 add the first one below",
    "detail.add_h2": "Add rule",
    "label.stype": "Type",
    "opt.http": "HTTP (route by hostname)",
    "opt.tcp": "TCP (route by port)",
    "opt.udp": "UDP (route by port)",
    "label.hostname": "Hostname",
    "label.port": "Public port",
    "ph.port": "e.g. 2222",
    "label.target": "Target address",
    "hint.target_http": "Just host:port \u2014 no http:// prefix needed",
    "hint.target_x": "Just host:port \u2014 no {t}:// prefix needed",
    "btn.add_rule": "Add rule"
  },
  zh: {
    "title.login": "\u767b\u5f55 \u00b7 tunnelx",
    "login.subtitle": "Edge \u7ba1\u7406\u9762\u677f",
    "login.username": "\u7528\u6237\u540d",
    "login.password": "\u5bc6\u7801",
    "login.submit": "\u767b\u5f55",
    "login.hint": "\u8fde\u7eed\u5931\u8d25 {max} \u6b21\u5c06\u9501\u5b9a {lock} \u5206\u949f",
    "err.locked": "\u767b\u5f55\u5df2\u9501\u5b9a\uff0c\u8bf7\u7ea6 {m} \u5206\u949f\u540e\u518d\u8bd5\uff08\u8fde\u7eed\u5931\u8d25\u8fc7\u591a\uff09\u3002",
    "err.bad_cred": "\u7528\u6237\u540d\u6216\u5bc6\u7801\u9519\u8bef\uff08\u8fd8\u53ef\u5c1d\u8bd5 {n} \u6b21\uff09",
    "err.bad_cred_locked": "\u7528\u6237\u540d\u6216\u5bc6\u7801\u9519\u8bef\u3002\u5df2\u8fde\u7eed\u5931\u8d25 {n} \u6b21\uff0c\u8d26\u6237\u6682\u65f6\u9501\u5b9a\u3002",
    "topbar.logout": "\u9000\u51fa\u767b\u5f55",
    "ph.tunnel_name": "\u65b0 Tunnel \u540d\u79f0",
    "tunnels.create": "\u521b\u5efa Tunnel",
    "th.name": "\u540d\u79f0",
    "th.token": "Token",
    "th.status": "\u72b6\u6001",
    "tunnels.empty": "\u8fd8\u6ca1\u6709 Tunnel\uff0c\u5148\u5728\u4e0a\u65b9\u521b\u5efa\u4e00\u4e2a\u5427",
    "badge.online": "\u5728\u7ebf",
    "badge.offline": "\u79bb\u7ebf",
    "confirm.del_tunnel": "\u5220\u9664\u6b64 Tunnel\uff1f",
    "btn.delete": "\u5220\u9664",
    "detail.back": "\u2190 \u8fd4\u56de\u5217\u8868",
    "detail.agent_h2": "Agent \u63a5\u5165",
    "detail.cmd_label": "Agent \u542f\u52a8\u547d\u4ee4",
    "detail.agent_hint": "\u4e00\u4e2a Tunnel \u540c\u4e00\u65f6\u523b\u53ea\u80fd\u7531\u4e00\u4e2a Agent \u5360\u7528\uff0c\u91cd\u590d\u8fde\u63a5\u4f1a\u88ab\u62d2\u7edd\u3002",
    "detail.rules_h2": "\u89c4\u5219",
    "th.type": "\u7c7b\u578b",
    "th.hostname": "Hostname",
    "th.port": "\u516c\u7f51\u7aef\u53e3",
    "th.target": "\u76ee\u6807",
    "rule.on": "\u542f\u7528",
    "rule.off": "\u505c\u7528",
    "rule.enable": "\u542f\u7528",
    "rule.disable": "\u505c\u7528",
    "confirm.del_rule": "\u5220\u9664\u89c4\u5219\uff1f",
    "rules.empty": "\u6682\u65e0\u89c4\u5219\uff0c\u5728\u4e0b\u65b9\u6dfb\u52a0\u7b2c\u4e00\u6761",
    "detail.add_h2": "\u6dfb\u52a0\u89c4\u5219",
    "label.stype": "\u7c7b\u578b",
    "opt.http": "HTTP\uff08\u6309\u57df\u540d\u8f6c\u53d1\uff09",
    "opt.tcp": "TCP\uff08\u6309\u7aef\u53e3\u8f6c\u53d1\uff09",
    "opt.udp": "UDP\uff08\u6309\u7aef\u53e3\u8f6c\u53d1\uff09",
    "label.hostname": "Hostname",
    "label.port": "\u516c\u7f51\u7aef\u53e3",
    "ph.port": "\u5982 2222",
    "label.target": "\u76ee\u6807\u5730\u5740",
    "hint.target_http": "\u76f4\u63a5\u586b host:port \u5373\u53ef\uff0c\u65e0\u9700 http:// \u524d\u7f00",
    "hint.target_x": "\u76f4\u63a5\u586b host:port \u5373\u53ef\uff0c\u65e0\u9700 {t}:// \u524d\u7f00",
    "btn.add_rule": "\u6dfb\u52a0\u89c4\u5219"
  }
};
function i18nLang() {
  try { return localStorage.getItem('tunnelx_lang') || 'en'; } catch (e) { return 'en'; }
}
function i18nFmt(s, args) {
  return String(s).replace(/\{(\w+)\}/g, function (_, k) {
    return args && args[k] !== undefined ? args[k] : '{' + k + '}';
  });
}
function i18nTx(key, args) {
  var lang = window.__tunnelxLang || i18nLang();
  var dict = I18N_DICT[lang] || I18N_DICT.en;
  var val = dict[key] !== undefined ? dict[key] : I18N_DICT.en[key];
  return i18nFmt(val !== undefined ? val : key, args || {});
}
function i18nConfirm(key) {
  return window.confirm(i18nTx(key));
}
function i18nParseArgs(el) {
  try { return JSON.parse(el.getAttribute('data-args') || '{}'); } catch (e) { return {}; }
}
function i18nApply(lang) {
  window.__tunnelxLang = lang;
  try { localStorage.setItem('tunnelx_lang', lang); } catch (e) {}
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  var dict = I18N_DICT[lang] || I18N_DICT.en;
  document.querySelectorAll('[data-i18n]').forEach(function (el) {
    var key = el.getAttribute('data-i18n');
    var val = dict[key] !== undefined ? dict[key] : I18N_DICT.en[key];
    if (val !== undefined) el.textContent = i18nFmt(val, i18nParseArgs(el));
  });
  document.querySelectorAll('[data-i18n-ph]').forEach(function (el) {
    var key = el.getAttribute('data-i18n-ph');
    var val = dict[key] !== undefined ? dict[key] : I18N_DICT.en[key];
    if (val !== undefined) el.setAttribute('placeholder', val);
  });
  document.querySelectorAll('[data-i18n-label]').forEach(function (el) {
    var key = el.getAttribute('data-i18n-label');
    var val = dict[key] !== undefined ? dict[key] : I18N_DICT.en[key];
    if (val !== undefined) el.setAttribute('data-label', val);
  });
  document.querySelectorAll('.lang-switch button').forEach(function (b) {
    b.classList.toggle('active', b.getAttribute('data-lang') === lang);
  });
}
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.lang-switch button').forEach(function (b) {
    b.addEventListener('click', function () { i18nApply(this.getAttribute('data-lang')); });
  });
  i18nApply(i18nLang());
});
</script>
"#
}

fn login_html(error: Option<&LoginError>, locked_secs: Option<u64>) -> String {
    let err_block = if let Some(secs) = locked_secs {
        let m = secs.div_ceil(60);
        let args = format!(r#"{{"m":{m}}}"#);
        let text = format!("Login locked. Try again in about {m} min.");
        format!(
            r#"<div class="error" data-i18n="err.locked" data-args='{args}'>{text}</div>"#,
            args = args,
            text = text,
        )
    } else if let Some(e) = error {
        let text = e.default_text();
        format!(
            r#"<div class="error" data-i18n="{key}" data-args='{args}'>{text}</div>"#,
            key = e.key(),
            args = e.args_json(),
            text = text,
        )
    } else {
        String::new()
    };
    let disabled = if locked_secs.is_some() { "disabled" } else { "" };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title data-i18n="title.login">Sign in · tunnelx</title>
{favicon}
<style>{css}</style>
</head>
<body>
<div class="login-page">
  <div class="login-box">
    {lang_switch}
    <div class="logo">
      <h1>tunnelx</h1>
      <p data-i18n="login.subtitle">Edge Admin Panel</p>
    </div>
    {err_block}
    <form method="post" action="/login" class="form-grid">
      <div>
        <label for="username" data-i18n="login.username">Username</label>
        <input id="username" name="username" autocomplete="username" required autofocus {disabled}>
      </div>
      <div>
        <label for="password" data-i18n="login.password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required {disabled}>
      </div>
      <button type="submit" {disabled} data-i18n="login.submit">Sign in</button>
    </form>
    <p class="hint" data-i18n="login.hint" data-args='{{"max":{max},"lock":{lock}}}'>Account locks for {lock} min after {max} failed attempts</p>
  </div>
</div>
{i18n}
</body>
</html>"#,
        css = shell_css(),
        favicon = FAVICON_LINK,
        lang_switch = LANG_SWITCH_HTML,
        err_block = err_block,
        disabled = disabled,
        max = MAX_FAILS,
        lock = LOCKOUT.as_secs() / 60,
        i18n = i18n_js(),
    )
}

/// Structured login error so the client can localize it.
enum LoginError {
    BadCred { attempts_left: u32 },
    BadCredLocked { attempts: u32 },
}

impl LoginError {
    fn key(&self) -> &'static str {
        match self {
            LoginError::BadCred { .. } => "err.bad_cred",
            LoginError::BadCredLocked { .. } => "err.bad_cred_locked",
        }
    }
    fn args_json(&self) -> String {
        match self {
            LoginError::BadCred { attempts_left } => {
                format!(r#"{{"n":{attempts_left}}}"#)
            }
            LoginError::BadCredLocked { attempts } => {
                format!(r#"{{"n":{attempts}}}"#)
            }
        }
    }
    fn default_text(&self) -> String {
        match self {
            LoginError::BadCred { attempts_left } => {
                format!("Wrong username or password ({attempts_left} attempts left)")
            }
            LoginError::BadCredLocked { attempts } => format!(
                "Wrong username or password. {attempts} failed attempts — account temporarily locked."
            ),
        }
    }
}

async fn login_page(
    State(state): State<Arc<EdgeState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    if is_authed(&state, &headers) {
        return Redirect::to("/tunnels").into_response();
    }
    let ip = client_ip(&state, &headers, Some(ConnectInfo(addr)));
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
    let ip = client_ip(&state, &headers, Some(ConnectInfo(addr)));

    if let Some(rem) = state.panel_auth.is_locked(&ip) {
        return Html(login_html(None, Some(rem.as_secs()))).into_response();
    }

    // Constant-time comparison of both fields regardless of which one mismatches.
    let ok = ct_eq(&form.username, &state.config.panel_user)
        && ct_eq(&form.password, &state.config.panel_pass);

    if !ok {
        let (count, locked) = state.panel_auth.record_failure(&ip);
        tracing::warn!("panel login failed from {ip} (attempt {count}/{MAX_FAILS})");
        let err = if locked {
            LoginError::BadCredLocked { attempts: count }
        } else {
            LoginError::BadCred {
                attempts_left: MAX_FAILS.saturating_sub(count),
            }
        };
        let locked_secs = if locked {
            Some(LOCKOUT.as_secs())
        } else {
            None
        };
        return Html(login_html(Some(&err), locked_secs)).into_response();
    }

    state.panel_auth.clear_failures(&ip);
    let token = state.panel_auth.create_session(&form.username);
    tracing::info!("panel login ok from {ip} user={}", form.username);

    let mut res = Redirect::to("/tunnels").into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        set_session_cookie(&token, state.config.secure_cookie)
            .parse()
            .unwrap(),
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
        clear_session_cookie(state.config.secure_cookie)
            .parse()
            .unwrap(),
    );
    res
}

fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · tunnelx</title>
{favicon}
<style>{css}</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <div class="brand"><span class="logo-dot"></span>tunnelx <span class="muted">Edge</span></div>
    <div class="topbar-actions">
      {lang_switch}
      <form method="post" action="/logout" style="margin:0">
        <button type="submit" class="secondary small" data-i18n="topbar.logout">Log out</button>
      </form>
    </div>
  </div>
  {body}
</div>
{i18n}
</body>
</html>"#,
        title = title,
        css = shell_css(),
        favicon = FAVICON_LINK,
        lang_switch = LANG_SWITCH_HTML,
        body = body,
        i18n = i18n_js(),
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
              <td data-label="Name" data-i18n-label="th.name"><a href="/tunnels/{id}">{name}</a></td>
              <td data-label="Token" data-i18n-label="th.token"><code>{token}</code></td>
              <td data-label="Status" data-i18n-label="th.status">{badge}</td>
              <td class="no-label">
                <form method="post" action="/tunnels/{id}" style="display:inline"
                  onsubmit="return i18nConfirm('confirm.del_tunnel')">
                  <button type="submit" class="danger small" data-i18n="btn.delete">Delete</button>
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
        r#"<tr><td colspan="4" class="muted" style="text-align:center;padding:1.5rem 0" data-i18n="tunnels.empty">
             No tunnels yet — create one above
           </td></tr>"#
    } else {
        ""
    };
    let body = format!(
        r#"<div class="page-head"><h1>Tunnels</h1></div>
<div class="card">
  <form method="post" action="/tunnels" class="row" style="margin:0">
    <input name="name" placeholder="New tunnel name" data-i18n-ph="ph.tunnel_name" required style="flex:1;min-width:200px">
    <button type="submit" class="btn-grow" data-i18n="tunnels.create">Create tunnel</button>
  </form>
</div>
<div class="card">
  <table>
    <thead><tr><th data-i18n="th.name">Name</th><th data-i18n="th.token">Token</th><th data-i18n="th.status">Status</th><th></th></tr></thead>
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
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error".to_string(),
        )
            .into_response(),
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
        let status_key = if enabled { "rule.on" } else { "rule.off" };
        let toggle_key = if enabled { "rule.disable" } else { "rule.enable" };
        let status_cls = if enabled {
            "badge-online"
        } else {
            "badge-offline"
        };
        rule_rows.push_str(&format!(
            r#"<tr>
            <td data-label="Type" data-i18n-label="th.type">{pill}</td>
            <td data-label="Hostname" data-i18n-label="th.hostname">{host}</td>
            <td data-label="Public port" data-i18n-label="th.port">{port}</td>
            <td data-label="Target" data-i18n-label="th.target"><code>{target}</code></td>
            <td data-label="Status" data-i18n-label="th.status">
              <span class="badge {status_cls}"><span class="dot"></span><span data-i18n="{status_key}">{status_text}</span></span>
            </td>
            <td class="no-label" style="white-space:nowrap">
              <form method="post" action="/rules/{rid}/toggle" style="display:inline">
                <button type="submit" class="secondary small" data-i18n="{toggle_key}">{toggle_text}</button>
              </form>
              <form method="post" action="/rules/{rid}/delete" style="display:inline"
                onsubmit="return i18nConfirm('confirm.del_rule')">
                <button type="submit" class="danger small" data-i18n="btn.delete">Delete</button>
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
            status_cls = status_cls,
            status_key = status_key,
            status_text = if enabled { "Enabled" } else { "Disabled" },
            toggle_key = toggle_key,
            toggle_text = if enabled { "Disable" } else { "Enable" },
        ));
    }
    let empty_rules = if rule_rows.is_empty() {
        r#"<tr><td colspan="6" class="muted" style="text-align:center;padding:1.5rem 0" data-i18n="rules.empty">
             No rules yet — add the first one below
           </td></tr>"#
    } else {
        ""
    };
    let body = format!(
        r#"<p style="margin:0"><a href="/tunnels" data-i18n="detail.back">&larr; Back to list</a></p>
<div class="page-head">
  <h1>{name}</h1>
  {badge}
</div>

<div class="card">
  <div class="card-head"><h2 data-i18n="detail.agent_h2">Agent access</h2></div>
  <p class="muted" style="margin-top:0">Token</p>
  <p class="token-row"><code>{token}</code></p>
  <p class="muted" data-i18n="detail.cmd_label">Agent start command</p>
  <pre>./tunnelx agent --server EDGE_IP:QUIC_PORT --token {token}</pre>
  <p class="field-hint" data-i18n="detail.agent_hint">Only one Agent can occupy a tunnel at a time; duplicate connections are rejected.</p>
</div>

<div class="card">
  <div class="card-head"><h2 data-i18n="detail.rules_h2">Rules</h2></div>
  <table>
    <thead><tr><th data-i18n="th.type">Type</th><th data-i18n="th.hostname">Hostname</th><th data-i18n="th.port">Public port</th><th data-i18n="th.target">Target</th><th data-i18n="th.status">Status</th><th></th></tr></thead>
    <tbody>
    {rule_rows}
    {empty_rules}
    </tbody>
  </table>
</div>

<div class="card">
  <div class="card-head"><h2 data-i18n="detail.add_h2">Add rule</h2></div>
  <form method="post" action="/tunnels/{id}/rules" class="form-grid">
    <div>
      <label for="stype" data-i18n="label.stype">Type</label>
      <select id="stype" name="service_type" onchange="updFields()">
        <option value="http" data-i18n="opt.http">HTTP (route by hostname)</option>
        <option value="tcp" data-i18n="opt.tcp">TCP (route by port)</option>
        <option value="udp" data-i18n="opt.udp">UDP (route by port)</option>
      </select>
    </div>
    <div id="f-host">
      <label for="hostname" data-i18n="label.hostname">Hostname</label>
      <input id="hostname" name="hostname" placeholder="app.example.com" required>
    </div>
    <div id="f-port" style="display:none">
      <label for="public_port" data-i18n="label.port">Public port</label>
      <input id="public_port" name="public_port" type="number" min="1" max="65535" placeholder="e.g. 2222" data-i18n-ph="ph.port">
    </div>
    <div>
      <label for="target" data-i18n="label.target">Target address</label>
      <input id="target" name="target" placeholder="127.0.0.1:8080" required>
      <p class="field-hint" id="target-hint" data-i18n="hint.target_http">Just host:port — no http:// prefix needed</p>
    </div>
    <button type="submit" data-i18n="btn.add_rule">Add rule</button>
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
  var hint = document.getElementById('target-hint');
  if (http) {{
    hint.setAttribute('data-i18n', 'hint.target_http');
    hint.textContent = i18nTx('hint.target_http');
  }} else {{
    hint.setAttribute('data-i18n', 'hint.target_x');
    hint.setAttribute('data-args', JSON.stringify({{t: t}}));
    hint.textContent = i18nTx('hint.target_x', {{t: t}});
  }}
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
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error".to_string(),
        )
            .into_response(),
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
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    };
    let new_enabled = rule.enabled == 0;
    if state.db.set_rule_enabled(&id, new_enabled).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
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
