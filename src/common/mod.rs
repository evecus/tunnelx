//! Shared utilities.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Install the ring CryptoProvider once (required by rustls 0.23).
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Load or generate a self-signed certificate for the QUIC endpoint.
pub fn load_or_generate_quic_cert(
    cert_path: &Path,
    key_path: &Path,
    auto_self_signed: bool,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    if cert_path.exists() && key_path.exists() {
        let cert_pem = fs::read(cert_path).context("read cert")?;
        let key_pem = fs::read(key_path).context("read key")?;
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<_, _>>()
            .context("parse certs")?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .context("parse key")?
            .context("no private key found")?;
        return Ok((certs, key));
    }

    if !auto_self_signed {
        anyhow::bail!(
            "QUIC certs not found at {} / {} and quic_auto_self_signed=false",
            cert_path.display(),
            key_path.display()
        );
    }
    tracing::info!("generating self-signed QUIC certificate");
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into(), "tunnelx".into()])?;
    let cert_der = certified.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());

    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(cert_path, certified.cert.pem())?;
    fs::write(key_path, certified.key_pair.serialize_pem())?;

    Ok((vec![cert_der], key_der))
}

pub fn make_quic_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig> {
    install_crypto_provider();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = vec![b"tunnelx".to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    server_config.transport = Arc::new({
        let mut t = quinn::TransportConfig::default();
        t.max_concurrent_bidi_streams(1024u32.into());
        t.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
        t
    });
    Ok(server_config)
}

pub fn make_quic_client_config() -> Result<quinn::ClientConfig> {
    install_crypto_provider();
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"tunnelx".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    Ok(client_config)
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Load HTTPS server TLS config from PEM files (fullchain + privkey).
pub fn load_https_server_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<rustls::ServerConfig>> {
    let cert_pem = fs::read(cert_path)
        .with_context(|| format!("read cert {}", cert_path.display()))?;
    let key_pem = fs::read(key_path)
        .with_context(|| format!("read key {}", key_path.display()))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()
        .context("parse certificate PEM")?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .context("parse private key PEM")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;

    install_crypto_provider();

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build rustls ServerConfig")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
