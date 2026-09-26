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
        .route("/rules/:id/toggle", post(toggle_rule))
        .with_state(state.clone())
        .layer(TraceLayer::new_for_http());

    let addr = state.config.panel_addr;
    info!("panel listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn check_auth(
    state: &EdgeState,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<(), ()> {
    let TypedHeader(Authorization(basic)) = auth.ok_or(())?;
    if basic.username() == state.config.panel_user && basic.password() == state.config.panel_pass {
        Ok(())
    } else {
        Err(())
    }
}

fn unauthorized() -> impl IntoResponse {
    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", "Basic realm=\"tunnelx\"")],
        "unauthorized",
    )
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
        let agents = state.agents.count(&Uuid::parse_str(&t.id).unwrap_or_default());
        rows.push_str(&format!(
            r#"<tr><td><a href="/tunnels/{id}">{name}</a></td><td><code>{token}</code></td><td>{agents}</td>
            <td><form method="post" action="/tunnels/{id}" style="display:inline" onsubmit="return confirm('Delete?')">
            <button type="submit">Delete</button></form></td></tr>"#,
            id = t.id, name = t.name, token = t.token, agents = agents,
        ));
    }
    Html(format!(r#"<!DOCTYPE html><html><head><title>tunnelx</title>
<style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:8px;text-align:left}}code{{font-size:0.85em;word-break:break-all}}</style></head>
<body><h1>Tunnels</h1>
<form method="post" action="/tunnels"><input name="name" placeholder="tunnel name" required> <button type="submit">Create</button></form>
<table><tr><th>Name</th><th>Token</th><th>Agents</th><th></th></tr>{rows}</table>
</body></html>"#)).into_response()
}

#[derive(Deserialize)]
struct CreateTunnelForm { name: String }

async fn create_tunnel(State(state): State<Arc<EdgeState>>, auth: Option<TypedHeader<Authorization<Basic>>>, Form(form): Form<CreateTunnelForm>) -> impl IntoResponse {
    if check_auth(&state, auth).await.is_err() { return unauthorized().into_response(); }
    match state.db.create_tunnel(&form.name).await {
        Ok(t) => Redirect::to(&format!("/tunnels/{}", t.id)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
}

async fn tunnel_detail(State(state): State<Arc<EdgeState>>, Path(id): Path<String>, auth: Option<TypedHeader<Authorization<Basic>>>) -> impl IntoResponse {
    if check_auth(&state, auth).await.is_err() { return unauthorized().into_response(); }
    let tunnel = match state.db.get_tunnel(&id).await {
        Ok(Some(t)) => t,
        _ => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let rules = state.db.list_rules(&id).await.unwrap_or_default();
    let agents = state.agents.count(&Uuid::parse_str(&id).unwrap_or_default());
    let mut rule_rows = String::new();
    for r in &rules {
        let enabled = r.enabled != 0;
        let status = if enabled { "启用" } else { "停用" };
        let toggle_label = if enabled { "停用" } else { "启用" };
        let status_style = if enabled { "color:green" } else { "color:#999" };
        rule_rows.push_str(&format!(
            r#"<tr>
            <td>{stype}</td>
            <td>{host}</td>
            <td>{port}</td>
            <td><code>{target}</code></td>
            <td style="{status_style}">{status}</td>
            <td style="white-space:nowrap">
              <form method="post" action="/rules/{rid}/toggle" style="display:inline">
                <button type="submit">{toggle_label}</button>
              </form>
              <form method="post" action="/rules/{rid}/delete" style="display:inline" onsubmit="return confirm('Delete rule?')">
                <button type="submit">删除</button>
              </form>
            </td>
            </tr>"#,
            stype = r.service_type,
            host = r.hostname.as_deref().unwrap_or("-"),
            port = r.public_port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            target = r.target,
            rid = r.id,
            status = status,
            status_style = status_style,
            toggle_label = toggle_label,
        ));
    }
    Html(format!(r#"<!DOCTYPE html><html><head><title>{name}</title>
<style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:8px}}code{{font-size:0.85em}}fieldset{{margin:1rem 0;padding:1rem}}</style></head>
<body><p><a href="/tunnels">&larr; Back</a></p>
<h1>{name}</h1>
<p>Token: <code>{token}</code></p>
<p>Online agents: <b>{agents}</b></p>
<p>Agent command:</p>
<pre>./tunnelx agent --server EDGE_IP:QUIC_PORT --token {token}</pre>

<h2>Rules</h2>
<table><tr><th>Type</th><th>Hostname</th><th>Public Port</th><th>Target</th><th>状态</th><th>操作</th></tr>{rule_rows}</table>

<h2>Add HTTP Rule</h2>
<form method="post" action="/tunnels/{id}/rules">
<input type="hidden" name="service_type" value="http">
<input name="hostname" placeholder="app.example.com" required>
<input name="target" placeholder="http://127.0.0.1:8080" required>
<button type="submit">Add HTTP</button>
</form>

<h2>Add TCP Rule</h2>
<form method="post" action="/tunnels/{id}/rules">
<input type="hidden" name="service_type" value="tcp">
<input name="target" placeholder="tcp://127.0.0.1:22" required>
<input name="public_port" type="number" placeholder="public port e.g. 2222" required>
<button type="submit">Add TCP</button>
</form>

<h2>Add UDP Rule</h2>
<form method="post" action="/tunnels/{id}/rules">
<input type="hidden" name="service_type" value="udp">
<input name="target" placeholder="udp://127.0.0.1:53" required>
<input name="public_port" type="number" placeholder="public port e.g. 5353" required>
<button type="submit">Add UDP</button>
</form>
</body></html>"#,
        name = tunnel.name, token = tunnel.token, agents = agents, id = id, rule_rows = rule_rows,
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
                    if let Ok(rid) = Uuid::parse_str(&rule.id) {
                        state.listeners.start_tcp(state.clone(), rid, port, rule.target.clone());
                    }
                }
            }
            if st == ServiceType::Udp {
                if let Some(port) = form.public_port {
                    if let Ok(rid) = Uuid::parse_str(&rule.id) {
                        state.listeners.start_udp(state.clone(), rid, port, rule.target.clone());
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

async fn toggle_rule(State(state): State<Arc<EdgeState>>, Path(id): Path<String>,
    auth: Option<TypedHeader<Authorization<Basic>>>) -> impl IntoResponse {
    if check_auth(&state, auth).await.is_err() { return unauthorized().into_response(); }
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
                    "tcp" => state.listeners.start_tcp(state.clone(), rid, port, rule.target.clone()),
                    "udp" => state.listeners.start_udp(state.clone(), rid, port, rule.target.clone()),
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
            state.agents.broadcast_config(
                &tid,
                crate::protocol::ConfigUpdate { version, rules },
            );
        }
    }
    Redirect::to(&format!("/tunnels/{}", rule.tunnel_id)).into_response()
}

async fn delete_rule(State(state): State<Arc<EdgeState>>, Path(id): Path<String>,
    auth: Option<TypedHeader<Authorization<Basic>>>) -> impl IntoResponse {
    if check_auth(&state, auth).await.is_err() { return unauthorized().into_response(); }
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
            if let (Ok(tid), Ok(rules)) = (Uuid::parse_str(&t.id), state.db.rules_for_tunnel(&t.id).await) {
                state.agents.broadcast_config(&tid, crate::protocol::ConfigUpdate { version, rules });
            }
        }
    }
    Redirect::to("/tunnels").into_response()
}

async fn delete_tunnel(State(state): State<Arc<EdgeState>>, Path(id): Path<String>,
    auth: Option<TypedHeader<Authorization<Basic>>>) -> impl IntoResponse {
    if check_auth(&state, auth).await.is_err() { return unauthorized().into_response(); }
    // Stop all listeners for rules under this tunnel before delete
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
