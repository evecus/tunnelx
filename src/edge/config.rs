//! Edge TOML configuration (`config.toml` under data dir).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::EdgeConfig;

/// On-disk TOML schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileConfig {
    pub listen: ListenConfig,
    pub panel: PanelConfig,
    pub certs: CertsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    /// QUIC address for Agents (e.g. "0.0.0.0:7844")
    pub quic: String,
    /// Management panel HTTP address
    pub panel: String,
    /// Public HTTP/HTTPS front (one port). TLS if certs.https_enabled.
    pub http: String,
    /// Deprecated: ignored. Kept so old config.toml still loads.
    #[serde(default, skip_serializing)]
    pub https: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelConfig {
    pub user: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertsConfig {
    /// Relative to data_dir, or absolute
    pub quic_cert: String,
    pub quic_key: String,
    /// If true and quic cert files missing, generate self-signed
    pub quic_auto_self_signed: bool,
    pub https_cert: String,
    pub https_key: String,
    /// If false, HTTPS listener is not started even if certs exist
    pub https_enabled: bool,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            listen: ListenConfig {
                quic: "0.0.0.0:7844".into(),
                panel: "0.0.0.0:8080".into(),
                http: "0.0.0.0:80".into(),
                https: None,
            },
            panel: PanelConfig {
                user: "admin".into(),
                password: "tunnelx".into(),
            },
            certs: CertsConfig {
                quic_cert: "certs/quic-cert.pem".into(),
                quic_key: "certs/quic-key.pem".into(),
                quic_auto_self_signed: true,
                https_cert: "certs/fullchain.pem".into(),
                https_key: "certs/privkey.pem".into(),
                https_enabled: true,
            },
        }
    }
}

impl FileConfig {
    pub fn default_toml() -> String {
        r#"# tunnelx Edge configuration
# Auto-generated on first start. Edit and restart Edge to apply.

[listen]
quic  = "0.0.0.0:7844"   # Agent QUIC
panel = "0.0.0.0:8080"   # Web management UI
http  = "0.0.0.0:80"     # Public HTTP(S) front. Port 443 + https_enabled also binds :80 redirect

[panel]
user     = "admin"
password = "tunnelx"

[certs]
# Paths are relative to the data directory unless absolute.
quic_cert             = "certs/quic-cert.pem"
quic_key              = "certs/quic-key.pem"
quic_auto_self_signed = true

https_cert    = "certs/fullchain.pem"
https_key     = "certs/privkey.pem"
https_enabled = true
"#
        .to_string()
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
            let cfg: Self = toml::from_str(&text)
                .with_context(|| format!("parse {}", path.display()))?;
            return Ok(cfg);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = Self::default_toml();
        std::fs::write(path, &text).with_context(|| format!("write {}", path.display()))?;
        tracing::info!("wrote default config {}", path.display());
        Ok(Self::default())
    }

    fn resolve(data_dir: &Path, p: &str) -> PathBuf {
        let path = Path::new(p);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            data_dir.join(path)
        }
    }

    pub fn into_edge_config(self, data_dir: PathBuf) -> Result<EdgeConfig> {
        Ok(EdgeConfig {
            quic_addr: self.listen.quic.parse().context("listen.quic")?,
            panel_addr: self.listen.panel.parse().context("listen.panel")?,
            http_addr: self.listen.http.parse().context("listen.http")?,
            panel_user: self.panel.user,
            panel_pass: self.panel.password,
            quic_cert: Self::resolve(&data_dir, &self.certs.quic_cert),
            quic_key: Self::resolve(&data_dir, &self.certs.quic_key),
            quic_auto_self_signed: self.certs.quic_auto_self_signed,
            https_cert: Self::resolve(&data_dir, &self.certs.https_cert),
            https_key: Self::resolve(&data_dir, &self.certs.https_key),
            https_enabled: self.certs.https_enabled,
            data_dir,
        })
    }
}

/// Optional CLI overrides applied on top of FileConfig.
#[derive(Debug, Default)]
pub struct CliOverrides {
    pub quic_addr: Option<String>,
    pub panel_addr: Option<String>,
    pub http_addr: Option<String>,
    pub panel_user: Option<String>,
    pub panel_pass: Option<String>,
}

impl CliOverrides {
    pub fn apply(self, mut file: FileConfig) -> FileConfig {
        if let Some(v) = self.quic_addr {
            file.listen.quic = v;
        }
        if let Some(v) = self.panel_addr {
            file.listen.panel = v;
        }
        if let Some(v) = self.http_addr {
            file.listen.http = v;
        }
        if let Some(v) = self.panel_user {
            file.panel.user = v;
        }
        if let Some(v) = self.panel_pass {
            file.panel.password = v;
        }
        file
    }
}

/// Load `{data_dir}/config.toml` (create default if missing), apply CLI overrides.
pub fn load_edge_config(data_dir: PathBuf, overrides: CliOverrides) -> Result<EdgeConfig> {
    let path = data_dir.join("config.toml");
    let file = FileConfig::load_or_create(&path)?;
    let file = overrides.apply(file);
    file.into_edge_config(data_dir)
}
