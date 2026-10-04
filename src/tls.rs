//! SNI-aware certificate selection for the HTTPS listener.
//!
//! Pingora 0.9 dropped `TlsSettings::add_cert`, so a multi-domain listener
//! picks its certificate during the handshake via the [`TlsAccept`] callback.
//! We pre-load every configured cert/key pair once at startup and look it up
//! by the requested SNI hostname.
//!
//! The listener starts with **no** certificate installed at all: whatever the
//! callback leaves behind is the only cert OpenSSL can use. If we install
//! nothing, the handshake dies with `no suitable signature algorithm` /
//! `no shared cipher`. That matters in the real world: internet-wide scanners
//! connect to port 443 by raw IP, and an IP literal is forbidden in SNI
//! (RFC 6066), so every such probe arrives with an empty SNI. See
//! [`crate::config::Tls::fallback_cert`] for how we keep that quiet.
//!
//! NOTE: dynamic certificate callbacks are only supported on the OpenSSL /
//! BoringSSL backends. The rustls backend logs a warning and ignores them.

use std::collections::HashMap;

use async_trait::async_trait;
use log::{debug, error};
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
    /// Serve `default_domain` when SNI is absent or unknown.
    fallback: bool,
}

impl SniResolver {
    /// Load every cert/key pair from the config up front.
    pub fn from_servers(servers: &[Server], fallback: bool) -> anyhow::Result<Self> {
        let mut certs = HashMap::new();

        for s in servers {
            let cert_pem = std::fs::read(&s.pub_key).map_err(|e| {
                anyhow::anyhow!("reading cert `{}` for {}: {e}", s.pub_key, s.domain)
            })?;
            let key_pem = std::fs::read(&s.priv_key).map_err(|e| {
                anyhow::anyhow!("reading key `{}` for {}: {e}", s.priv_key, s.domain)
            })?;

            let cert = x509::X509::from_pem(&cert_pem)
                .map_err(|e| anyhow::anyhow!("parsing cert `{}`: {e}", s.pub_key))?;
            let key = pkey::PKey::private_key_from_pem(&key_pem)
                .map_err(|e| anyhow::anyhow!("parsing key `{}`: {e}", s.priv_key))?;

            certs.insert(s.domain.to_ascii_lowercase(), (cert, key));
        }

        let default_domain = servers[0].domain.to_ascii_lowercase();
        Ok(Self {
            certs,
            default_domain,
            fallback,
        })
    }

    /// Pick the certificate key to use for a given SNI hostname.
    ///
    /// * exact (case-insensitive) match -> that domain
    /// * empty or unknown SNI -> the default domain, when `fallback_cert` is on
    /// * otherwise -> `None`, i.e. no certificate is installed and the
    ///   handshake is expected to fail
    fn resolve_key(&self, sni: &str) -> Option<String> {
        let sni = sni.to_ascii_lowercase();

        if self.certs.contains_key(&sni) {
            return Some(sni);
        }
        if self.fallback && self.certs.contains_key(&self.default_domain) {
            debug!("no certificate configured for SNI `{sni}`, using default");
            return Some(self.default_domain.clone());
        }
        None
    }
}

#[async_trait]
impl TlsAccept for SniResolver {
    async fn certificate_callback(&self, ssl_ref: &mut TlsRef) {
        let sni = ssl_ref
            .servername(ssl::NameType::HOST_NAME)
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();

        let Some(domain) = self.resolve_key(&sni) else {
            error!("no certificate available for SNI `{sni}`; TLS handshake will fail");
            return;
        };

        let (cert, key) = &self.certs[&domain];

        if let Err(e) = ext::ssl_use_certificate(ssl_ref, cert) {
            error!("failed to set certificate for `{sni}`: {e}");
        }
        if let Err(e) = ext::ssl_use_private_key(ssl_ref, key) {
            error!("failed to set private key for `{sni}`: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A self-signed certificate for `test.local`, generated on first use.
    ///
    /// The repository ships no certificates (see CONTRIBUTING.md), so the tests
    /// mint their own and write them to the temp directory.
    fn pair() -> &'static (String, String) {
        static PAIR: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

        PAIR.get_or_init(|| {
            use openssl::asn1::Asn1Time;
            use openssl::hash::MessageDigest;
            use openssl::rsa::Rsa;

            let key = pkey::PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

            let mut name = x509::X509NameBuilder::new().unwrap();
            name.append_entry_by_text("CN", "test.local").unwrap();
            let name = name.build();

            let mut cert = x509::X509::builder().unwrap();
            cert.set_version(2).unwrap();
            cert.set_subject_name(&name).unwrap();
            cert.set_issuer_name(&name).unwrap();
            cert.set_pubkey(&key).unwrap();
            cert.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
            cert.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
            cert.sign(&key, MessageDigest::sha256()).unwrap();
            let cert = cert.build();

            let dir = std::env::temp_dir().join(format!("uping-tls-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let cert_path = dir.join("test.local.crt");
            let key_path = dir.join("test.local.key");
            std::fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
            std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();

            (cert_path.display().to_string(), key_path.display().to_string())
        })
    }

    fn test_server(domain: &str) -> Server {
        let (cert, key) = pair();
        Server {
            domain: domain.to_string(),
            pub_key: cert.clone(),
            priv_key: key.clone(),
            upstream: "127.0.0.1:8080".to_string(),
        }
    }

    fn write_temp(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("uping-tls-{}-{}", std::process::id(), name));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents).unwrap();
        path
    }

    #[test]
    fn loads_the_test_certificate() {
        let resolver = SniResolver::from_servers(&[test_server("test.local")], true).unwrap();
        assert!(resolver.certs.contains_key("test.local"));
    }

    #[test]
    fn domain_keys_are_lowercased() {
        let resolver = SniResolver::from_servers(&[test_server("TEST.Local")], true).unwrap();
        assert!(resolver.certs.contains_key("test.local"));
        assert_eq!(resolver.default_domain, "test.local");
    }

    #[test]
    fn resolve_key_matches_sni_case_insensitively() {
        let resolver = SniResolver::from_servers(&[test_server("test.local")], true).unwrap();
        assert_eq!(resolver.resolve_key("test.local").as_deref(), Some("test.local"));
        assert_eq!(resolver.resolve_key("TEST.LOCAL").as_deref(), Some("test.local"));
    }

    #[test]
    fn resolve_key_falls_back_to_the_default_domain() {
        let resolver = SniResolver::from_servers(
            &[test_server("test.local"), test_server("other.local")],
            true,
        )
        .unwrap();
        assert_eq!(
            resolver.resolve_key("unknown.local").as_deref(),
            Some("test.local")
        );
    }

    /// The v0.1.0 bug: a scanner connecting by raw IP sends no SNI, and we
    /// failed the handshake loudly. Now we hand it the default certificate.
    #[test]
    fn resolve_key_uses_the_default_for_empty_sni_when_fallback_is_on() {
        let resolver = SniResolver::from_servers(&[test_server("test.local")], true).unwrap();
        assert_eq!(resolver.resolve_key("").as_deref(), Some("test.local"));
    }

    #[test]
    fn resolve_key_returns_none_for_empty_sni_when_fallback_is_off() {
        let resolver = SniResolver::from_servers(&[test_server("test.local")], false).unwrap();
        assert_eq!(resolver.resolve_key(""), None);
    }

    #[test]
    fn resolve_key_returns_none_for_unknown_sni_when_fallback_is_off() {
        let resolver = SniResolver::from_servers(&[test_server("test.local")], false).unwrap();
        assert_eq!(resolver.resolve_key("unknown.local"), None);
    }

    #[test]
    fn fallback_never_overrides_an_exact_match() {
        let resolver =
            SniResolver::from_servers(&[test_server("test.local"), test_server("other.local")], true)
                .unwrap();
        assert_eq!(resolver.resolve_key("other.local").as_deref(), Some("other.local"));
    }

    #[test]
    fn missing_cert_file_is_reported() {
        let mut server = test_server("test.local");
        server.pub_key = "does-not-exist.pem".to_string();
        let err = SniResolver::from_servers(&[server], true)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("reading cert"), "unexpected error: {err}");
    }

    #[test]
    fn missing_key_file_is_reported() {
        let mut server = test_server("test.local");
        server.priv_key = "does-not-exist.key".to_string();
        let err = SniResolver::from_servers(&[server], true)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("reading key"), "unexpected error: {err}");
    }

    #[test]
    fn malformed_cert_pem_is_reported() {
        let bad = write_temp("bad.pem", b"not a certificate");
        let mut server = test_server("test.local");
        server.pub_key = bad.display().to_string();
        let err = SniResolver::from_servers(&[server], true)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("parsing cert"), "unexpected error: {err}");
        let _ = std::fs::remove_file(bad);
    }
}
