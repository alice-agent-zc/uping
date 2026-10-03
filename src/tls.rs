//! SNI-aware certificate selection for the HTTPS listener.
//!
//! Pingora 0.9 dropped `TlsSettings::add_cert`, so a multi-domain listener
//! picks its certificate during the handshake via the [`TlsAccept`] callback.
//! We pre-load every configured cert/key pair once at startup and look it up
//! by the requested SNI hostname.
//!
//! NOTE: dynamic certificate callbacks are only supported on the OpenSSL /
//! BoringSSL backends. The rustls backend logs a warning and ignores them.

use std::collections::HashMap;

use async_trait::async_trait;
use log::{error, warn};
use pingora::listeners::TlsAccept;
use pingora::protocols::tls::TlsRef;
use pingora::tls::{ext, pkey, ssl, x509};

use crate::config::Server;

/// A parsed certificate + private key, ready to hand to OpenSSL.
type CertKey = (x509::X509, pkey::PKey<pkey::Private>);

/// Resolves a certificate from the client's SNI hostname.
pub struct SniResolver {
    /// Lowercased domain -> (cert, key).
    certs: HashMap<String, CertKey>,
    /// Certificate used when SNI matches nothing (first configured domain).
    default_domain: String,
}

impl SniResolver {
    /// Load every cert/key pair from the config up front.
    pub fn from_servers(servers: &[Server]) -> anyhow::Result<Self> {
        let mut certs = HashMap::new();

        for s in servers {
            let cert_pem = std::fs::read(&s.pub_pem).map_err(|e| {
                anyhow::anyhow!("reading cert `{}` for {}: {e}", s.pub_pem, s.domain)
            })?;
            let key_pem = std::fs::read(&s.priv_pem).map_err(|e| {
                anyhow::anyhow!("reading key `{}` for {}: {e}", s.priv_pem, s.domain)
            })?;

            let cert = x509::X509::from_pem(&cert_pem)
                .map_err(|e| anyhow::anyhow!("parsing cert `{}`: {e}", s.pub_pem))?;
            let key = pkey::PKey::private_key_from_pem(&key_pem)
                .map_err(|e| anyhow::anyhow!("parsing key `{}`: {e}", s.priv_pem))?;

            certs.insert(s.domain.to_ascii_lowercase(), (cert, key));
        }

        let default_domain = servers[0].domain.to_ascii_lowercase();
        Ok(Self {
            certs,
            default_domain,
        })
    }
}

#[async_trait]
impl TlsAccept for SniResolver {
    async fn certificate_callback(&self, ssl_ref: &mut TlsRef) {
        let sni = ssl_ref
            .servername(ssl::NameType::HOST_NAME)
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();

        let selected = self.certs.get(&sni).or_else(|| {
            if sni.is_empty() {
                None
            } else {
                warn!("no certificate configured for SNI `{sni}`, using default");
                self.certs.get(&self.default_domain)
            }
        });

        let Some((cert, key)) = selected else {
            error!("no certificate available for SNI `{sni}`; TLS handshake will fail");
            return;
        };

        if let Err(e) = ext::ssl_use_certificate(ssl_ref, cert) {
            error!("failed to set certificate for `{sni}`: {e}");
        }
        if let Err(e) = ext::ssl_use_private_key(ssl_ref, key) {
            error!("failed to set private key for `{sni}`: {e}");
        }
    }
}
