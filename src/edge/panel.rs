use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Form, Router,
};
use axum_extra::headers::{authorization::Basic, Authorization};
use axum_extra::TypedHeader;
use serde::Deserialize;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;
use uuid::Uuid;

use super::EdgeState;
use crate::protocol::ServiceType;

pub async fn run_panel(state: Arc<EdgeState>) -> Result<()> {
    let app = Router::new()
        .route("/", get(index))
        .route("/tunnels", get(list_tunnels).post(create_tunnel))
        .route("/tunnels/:id", get(tunnel_detail).post(delete_tunnel))
        .route("/tunnels/:id/rules", post(add_rule))
        .route("/rules/:id/delete", post(delete_rule))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(state.config.panel_addr).await?;
    info!("Management panel at http://{}", state.config.panel_addr);
    info!("  login: {} / {}", state.config.panel_user, state.config.panel_pass);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn check_auth(state: &EdgeState, auth: Option<TypedHeader<Authorization<Basic>>>) -> Result<(), StatusCode> {
    match auth {
        Some(TypedHeader(Authorization(basic)))
            if basic.username() == state.config.panel_user && basic.password() == state.config.panel_pass => Ok(()),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

fn unauthorized() -> impl IntoResponse {
    (StatusCode::UNAUTHORIZED, [("WWW-Authenticate", "Basic realm=\"tunnelx\"")], "Unauthorized")
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('\"', "&quot;")
}

async fn index(State(state): State<Arc<EdgeState>>, auth: Option<TypedHeader<Authorization<Basic>>>) -> impl IntoResponse {
    if check_auth(&state, auth).await.is_err() { return unauthorized().into_response(); }
    Redirect::to("/tunnels").into_response()
}

async fn list_tunnels(State(state): State<Arc<EdgeState>>, auth: Option<TypedHeader<Authorization<Basic>>>) -> impl IntoResponse {
    if check_auth(&state, auth).await.is_err() { return unauthorized().into_response(); }
    let tunnels = state.db.list_tunnels().await.unwrap_or_default();
    let mut rows = String::new();
    for t in &tunnels {
        let n = state.agents.count(&Uuid::parse_str(&t.id).unwrap_or_default());
        rows.push_str(&format!(
            "<tr><td><a href=\"/tunnels/{}\">{}</a></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            t.id, esc(&t.name), &t.token[..16.min(t.token.len())], n, t.created_at
        ));
    }
    Html(format!(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>tunnelx</title>
<style>body{{font-family:system-ui;max-width:960px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}
th{{background:#f4f4f4}}code{{background:#f0f0f0;padding:2px 6px}}form{{margin:1.5rem 0}}
input,button{{padding:6px 10px;margin-right:6px}}.btn{{background:#2563eb;color:#fff;border:none;border-radius:4px;cursor:pointer}}
.btn-danger{{background:#dc2626}}</style></head><body>
<h1>tunnelx Edge</h1><p>Self-hosted Cloudflare Tunnel alternative</p>
<h2>Tunnels</h2><table><tr><th>Name</th><th>Token</th><th>Agents</th><th>Created</th></tr>
{rows}</table>
<h3>Create Tunnel</h3>
<form method="post" action="/tunnels"><input name="name" placeholder="my-tunnel" required>
<button class="btn" type="submit">Create</button></form>
</body></html>"#, rows=rows)).into_response()
}

#[derive(Deserialize)]
struct CreateTunnelForm { name: String }

async fn create_tunnel(State(state): State<Arc<EdgeState>>, auth: Option<TypedHeader<Authorization<Basic>>>, Form(form): Form<CreateTunnelForm>) -> impl IntoResponse {
    if check_auth(&state, auth).await.is_err() { return unauthorized().into_response(); }
    match state.db.create_tunnel(&form.name).await {
        Ok(t) => { info!("created tunnel {} ({})", t.name, t.id); Redirect::to(&format!("/tunnels/{}", t.id)).into_response() }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("error: {e:#}")).into_response(),
    }
}

async fn tunnel_detail(State(state): State<Arc<EdgeState>>, Path(id): Path<String>, auth: Option<TypedHeader<Authorization<Basic>>>) -> impl IntoResponse {
    if check_auth(&state, auth).await.is_err() { return unauthorized().into_response(); }
    let tunnel = match state.db.get_tunnel(&id).await {
        Ok(Some(t)) => t,
        _ => return (StatusCode::NOT_FOUND, "tunnel not found").into_response(),
    };
    let rules = state.db.list_rules(&id).await.unwrap_or_default();
    let agents = state.agents.count(&Uuid::parse_str(&id).unwrap_or_default());
    let mut rule_rows = String::new();
    for r in &rules {
        rule_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>
            <form method=\"post\" action=\"/rules/{}/delete\" style=\"display:inline\">
            <button class=\"btn btn-danger\" type=\"submit\">Delete</button></form></td></tr>",
            r.service_type, r.hostname.as_deref().unwrap_or("-"), esc(&r.target),
            r.public_port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()), r.id
        ));
    }
    Html(format!(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{name} – tunnelx</title>
<style>body{{font-family:system-ui;max-width:960px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px}}
th{{background:#f4f4f4}}code{{background:#f0f0f0;padding:2px 6px;word-break:break-all}}
form{{margin:1rem 0}}input,button{{padding:6px 10px;margin:4px}}
.btn{{background:#2563eb;color:#fff;border:none;border-radius:4px;cursor:pointer}}
.btn-danger{{background:#dc2626}}.token{{background:#fef3c7;padding:8px;border-radius:4px}}</style></head><body>
<p><a href="/tunnels">← Back</a></p><h1>{name}</h1>
<p>Agents online: <strong>{agents}</strong></p>
<div class="token"><strong>Token</strong>:<br><code>{token}</code></div>
<h2>Ingress Rules</h2>
<table><tr><th>Type</th><th>Hostname</th><th>Target</th><th>Port</th><th></th></tr>
{rule_rows}</table>
<h3>Add HTTP Rule</h3>
<form method="post" action="/tunnels/{id}/rules">
<input type="hidden" name="service_type" value="http">
<input name="hostname" placeholder="app.example.com" required>
<input name="target" placeholder="http://127.0.0.1:3000" required>
<button class="btn" type="submit">Add HTTP</button></form>
<h3>Add TCP Rule</h3>
<form method="post" action="/tunnels/{id}/rules">
<input type="hidden" name="service_type" value="tcp">
<input name="target" placeholder="tcp://127.0.0.1:22" required>
<input name="public_port" type="number" placeholder="2222" required>
<button class="btn" type="submit">Add TCP</button></form>
<h3>Add UDP Rule</h3>
<form method="post" action="/tunnels/{id}/rules">
<input type="hidden" name="service_type" value="udp">
<input name="target" placeholder="udp://127.0.0.1:51820" required>
<input name="public_port" type="number" placeholder="51820" required>
<button class="btn" type="submit">Add UDP</button></form>
<form method="post" action="/tunnels/{id}" onsubmit="return confirm('Delete?')">
<button class="btn btn-danger" type="submit">Delete Tunnel</button></form>
</body></html>"#,
        name=esc(&tunnel.name), agents=agents, token=tunnel.token, id=id, rule_rows=rule_rows
    )).into_response()
}

#[derive(Deserialize)]
struct AddRuleForm {
    service_type: String,
    hostname: Option<String>,
    target: String,
    public_port: Option<u16>,
}

async fn add_rule(State(state): State<Arc<EdgeState>>, Path(tunnel_id): Path<String>,
    auth: Option<TypedHeader<Authorization<Basic>>>, Form(form): Form<AddRuleForm>) -> impl IntoResponse {
    if check_auth(&state, auth).await.is_err() { return unauthorized().into_response(); }
    let st = match form.service_type.as_str() {
        "tcp" => ServiceType::Tcp,
        "udp" => ServiceType::Udp,
        _ => ServiceType::Http,
    };
    match state.db.add_rule(&tunnel_id, form.hostname.as_deref(), None, st, &form.target, form.public_port).await {
        Ok(rule) => {
            *state.config_version.write().await += 1;
            if st == ServiceType::Tcp {
                if let Some(port) = form.public_port {
                    let st2 = state.clone();
                    let rid = Uuid::parse_str(&rule.id).unwrap();
                    let target = rule.target.clone();
                    tokio::spawn(async move {
                        if let Err(e) = super::routing::run_tcp_listener(st2, rid, port, target).await {
                            tracing::error!("TCP listener :{port}: {e:#}");
                        }
                    });
                }
            }
            if st == ServiceType::Udp {
                if let Some(port) = form.public_port {
                    let st2 = state.clone();
                    let rid = Uuid::parse_str(&rule.id).unwrap();
                    let target = rule.target.clone();
                    tokio::spawn(async move {
                        if let Err(e) = super::routing::run_udp_listener(st2, rid, port, target).await {
                            tracing::error!("UDP listener :{port}: {e:#}");
                        }
                    });
                }
            }
            Redirect::to(&format!("/tunnels/{tunnel_id}")).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
}

async fn delete_rule(State(state): State<Arc<EdgeState>>, Path(id): Path<String>,
    auth: Option<TypedHeader<Authorization<Basic>>>) -> impl IntoResponse {
    if check_auth(&state, auth).await.is_err() { return unauthorized().into_response(); }
    let _ = state.db.delete_rule(&id).await;
    *state.config_version.write().await += 1;
    Redirect::to("/tunnels").into_response()
}

async fn delete_tunnel(State(state): State<Arc<EdgeState>>, Path(id): Path<String>,
    auth: Option<TypedHeader<Authorization<Basic>>>) -> impl IntoResponse {
    if check_auth(&state, auth).await.is_err() { return unauthorized().into_response(); }
    let _ = state.db.delete_tunnel(&id).await;
    Redirect::to("/tunnels").into_response()
}
