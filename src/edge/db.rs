use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::path::Path;
use uuid::Uuid;

use crate::common::generate_token;
use crate::protocol::{IngressRule, ServiceType};

#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TunnelRow {
    pub id: String,
    pub name: String,
    pub token: String,
    pub created_at: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IngressRuleRow {
    pub id: String,
    pub tunnel_id: String,
    pub hostname: Option<String>,
    pub path_prefix: Option<String>,
    pub service_type: String,
    pub target: String,
    pub public_port: Option<i64>,
    pub enabled: i64,
    pub created_at: String,
}

impl Db {
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let url = format!("sqlite:{}?mode=rwc", path.display());
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .context("connect sqlite")?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS tunnels (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ingress_rules (
                id TEXT PRIMARY KEY,
                tunnel_id TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
                hostname TEXT,
                path_prefix TEXT,
                service_type TEXT NOT NULL,
                target TEXT NOT NULL,
                public_port INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rules_tunnel ON ingress_rules(tunnel_id);
            CREATE INDEX IF NOT EXISTS idx_rules_hostname ON ingress_rules(hostname);
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_tunnels(&self) -> Result<Vec<TunnelRow>> {
        let rows = sqlx::query_as::<_, TunnelRow>("SELECT * FROM tunnels ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    pub async fn create_tunnel(&self, name: &str) -> Result<TunnelRow> {
        let id = Uuid::new_v4().to_string();
        let token = generate_token();
        let now = Utc::now().to_rfc3339();
        sqlx::query("INSERT INTO tunnels (id, name, token, created_at) VALUES (?, ?, ?, ?)")
            .bind(&id)
            .bind(name)
            .bind(&token)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(TunnelRow {
            id,
            name: name.to_string(),
            token,
            created_at: now,
        })
    }

    pub async fn get_tunnel(&self, id: &str) -> Result<Option<TunnelRow>> {
        let row = sqlx::query_as::<_, TunnelRow>("SELECT * FROM tunnels WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    pub async fn get_tunnel_by_token(&self, token: &str) -> Result<Option<TunnelRow>> {
        let row = sqlx::query_as::<_, TunnelRow>("SELECT * FROM tunnels WHERE token = ?")
            .bind(token)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    pub async fn delete_tunnel(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM tunnels WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn add_rule(
        &self,
        tunnel_id: &str,
        hostname: Option<&str>,
        path_prefix: Option<&str>,
        service_type: ServiceType,
        target: &str,
        public_port: Option<u16>,
    ) -> Result<IngressRuleRow> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let st = match service_type {
            ServiceType::Http => "http",
            ServiceType::Tcp => "tcp",
            ServiceType::Udp => "udp",
        };
        sqlx::query(
            r#"INSERT INTO ingress_rules
               (id, tunnel_id, hostname, path_prefix, service_type, target, public_port, enabled, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)"#,
        )
        .bind(&id)
        .bind(tunnel_id)
        .bind(hostname)
        .bind(path_prefix)
        .bind(st)
        .bind(target)
        .bind(public_port.map(|p| p as i64))
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(IngressRuleRow {
            id,
            tunnel_id: tunnel_id.to_string(),
            hostname: hostname.map(|s| s.to_string()),
            path_prefix: path_prefix.map(|s| s.to_string()),
            service_type: st.to_string(),
            target: target.to_string(),
            public_port: public_port.map(|p| p as i64),
            enabled: 1,
            created_at: now,
        })
    }

    pub async fn delete_rule(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM ingress_rules WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_rules(&self, tunnel_id: &str) -> Result<Vec<IngressRuleRow>> {
        let rows = sqlx::query_as::<_, IngressRuleRow>(
            "SELECT * FROM ingress_rules WHERE tunnel_id = ? ORDER BY hostname",
        )
        .bind(tunnel_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn rules_for_tunnel(&self, tunnel_id: &str) -> Result<Vec<IngressRule>> {
        let rows = sqlx::query_as::<_, IngressRuleRow>(
            "SELECT * FROM ingress_rules WHERE tunnel_id = ? AND enabled = 1",
        )
        .bind(tunnel_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().filter_map(|r| row_to_rule(r).ok()).collect())
    }

    pub async fn list_all_tcp_rules(&self) -> Result<Vec<IngressRuleRow>> {
        let rows = sqlx::query_as::<_, IngressRuleRow>(
            "SELECT * FROM ingress_rules WHERE service_type = 'tcp' AND enabled = 1",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn list_all_udp_rules(&self) -> Result<Vec<IngressRuleRow>> {
        let rows = sqlx::query_as::<_, IngressRuleRow>(
            "SELECT * FROM ingress_rules WHERE service_type = 'udp' AND enabled = 1",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn find_http_rule(&self, hostname: &str) -> Result<Option<IngressRuleRow>> {
        let row = sqlx::query_as::<_, IngressRuleRow>(
            r#"SELECT * FROM ingress_rules
               WHERE service_type = 'http' AND enabled = 1 AND hostname = ?
               LIMIT 1"#,
        )
        .bind(hostname)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }
}

fn row_to_rule(r: IngressRuleRow) -> Result<IngressRule> {
    let service_type = match r.service_type.as_str() {
        "tcp" => ServiceType::Tcp,
        "udp" => ServiceType::Udp,
        _ => ServiceType::Http,
    };
    Ok(IngressRule {
        id: Uuid::parse_str(&r.id)?,
        hostname: r.hostname,
        path_prefix: r.path_prefix,
        service_type,
        target: r.target,
        public_port: r.public_port.map(|p| p as u16),
        enabled: r.enabled != 0,
    })
}
