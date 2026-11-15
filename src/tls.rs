//! SNI-aware certificate selection for the HTTPS listener.
//!
//! Pingora 0.9 dropped `TlsSettings::add_cert`, so a multi-domain listener
//! picks its certificate during the handshake via the [`TlsAccept`] callback.
//! The map is loaded at startup and replaced atomically on a config reload or
//! an ACME renewal; the callback looks the requested SNI hostname up in it.
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
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use log::{debug, error};
use pingora::listeners::TlsAccept;
use pingora::protocols::tls::TlsRef;
use pingora::tls::{ext, pkey, ssl, x509};

use crate::config::{Config, KeyMode, Server};

/// A parsed leaf + its intermediate chain + private key, ready for OpenSSL.
struct CertKey {
    leaf: x509::X509,
    /// Intermediates, in the order they appear after the leaf in fullchain.pem.
    chain: Vec<x509::X509>,
    key: pkey::PKey<pkey::Private>,
}

/// Resolves a certificate from the client's SNI hostname.
///
/// The map sits behind a lock because `keys = "auto"` replaces an entry when a
/// renewal lands. The callback only ever reads it, and the write is a handful of
/// pointer moves, so a writer never delays a handshake meaningfully.
#[derive(Clone)]
pub struct SniResolver {
    /// Lowercased domain -> (cert, key).
    certs: Arc<RwLock<HashMap<String, Arc<CertKey>>>>,
    /// Certificate used when SNI matches nothing (first configured domain).
    default_domain: Arc<RwLock<String>>,
    /// Serve `default_domain` when SNI is absent or unknown.
    fallback: Arc<AtomicBool>,
}

impl SniResolver {
    /// An empty resolver. Fill it with [`SniResolver::load_files`] or
    /// [`SniResolver::install`].
    pub fn empty(default_domain: impl Into<String>, fallback: bool) -> Self {
        Self {
            certs: Arc::new(RwLock::new(HashMap::new())),
            default_domain: Arc::new(RwLock::new(default_domain.into().to_ascii_lowercase())),
            fallback: Arc::new(AtomicBool::new(fallback)),
        }
    }

    /// Build a resolver for a whole config, and return the `auto` servers whose
    /// pair does not exist yet. A missing `manual` pair is an error: the
    /// operator promised two files and uping cannot conjure them.
    ///
    /// This never touches the network and writes nothing, so it is also what
    /// `--check` and a reload candidate use.
    pub fn from_config(cfg: &Config) -> anyhow::Result<(Self, Vec<Server>)> {
        let default_domain = cfg
            .servers
            .first()
            .map(|s| s.domain.to_ascii_lowercase())
            .unwrap_or_default();
        let resolver = SniResolver::empty(default_domain, cfg.tls.fallback_cert);
        let mut pending = Vec::new();

        for s in &cfg.servers {
            let (cert, key) = cfg.key_paths(s);
            if cert.is_file() && key.is_file() {
                resolver.load_files(&s.domain, &cert, &key)?;
            } else {
                match s.key_mode() {
                    KeyMode::Manual => anyhow::bail!(
                        "`{}` is manual and its certificate is missing: `{}` / `{}`",
                        s.domain,
                        cert.display(),
                        key.display()
                    ),
                    KeyMode::Auto => pending.push(s.clone()),
                }
            }
        }
        Ok((resolver, pending))
    }

    /// Load every cert/key pair from the explicit `pub_key`/`priv_key` fields.
    /// Kept for the unit tests.
    #[cfg(test)]
    pub fn from_servers(servers: &[Server], fallback: bool) -> anyhow::Result<Self> {
        let default_domain = servers
            .first()
            .map(|s| s.domain.to_ascii_lowercase())
            .unwrap_or_default();
        let resolver = SniResolver::empty(default_domain, fallback);
        for s in servers {
            resolver.load_files(&s.domain, Path::new(&s.pub_key), Path::new(&s.priv_key))?;
        }
        Ok(resolver)
    }

    /// Replace this resolver's live state with `other`'s. Used after a reload
    /// has built and validated a complete candidate.
    pub fn adopt(&self, other: &Self) {
        let certs = {
            let source = other.certs.read().unwrap_or_else(|e| e.into_inner());
            source.clone()
        };
        *self.certs.write().unwrap_or_else(|e| e.into_inner()) = certs;

        let default = other
            .default_domain
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        *self
            .default_domain
            .write()
            .unwrap_or_else(|e| e.into_inner()) = default;
        self.fallback
            .store(other.fallback.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    /// Read and parse one pair from disk, replacing any current entry.
    pub fn load_files(&self, domain: &str, cert: &Path, key: &Path) -> anyhow::Result<()> {
        let cert_pem = std::fs::read(cert)
            .map_err(|e| anyhow::anyhow!("reading cert `{}` for {domain}: {e}", cert.display()))?;
        let key_pem = std::fs::read(key)
            .map_err(|e| anyhow::anyhow!("reading key `{}` for {domain}: {e}", key.display()))?;
        self.install(domain, &cert_pem, &key_pem)
            .map_err(|e| anyhow::anyhow!("{e} (`{}` / `{}`)", cert.display(), key.display()))
    }

    /// Parse a PEM pair and swap it into the live map. `cert_pem` may hold the
    /// full chain: the first certificate is the leaf, the rest are sent as
    /// intermediates. Dropping the chain would break clients that do not chase
    /// the leaf's AIA extension.
    pub fn install(&self, domain: &str, cert_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<()> {
        let domain = domain.trim().to_ascii_lowercase();
        let mut certs = x509::X509::stack_from_pem(cert_pem)
            .map_err(|e| anyhow::anyhow!("parsing cert for {domain}: {e}"))?;
        if certs.is_empty() {
            anyhow::bail!("no certificate found in the PEM for {domain}");
        }
        let leaf = certs.remove(0);
        let key = pkey::PKey::private_key_from_pem(key_pem)
            .map_err(|e| anyhow::anyhow!("parsing key for {domain}: {e}"))?;
        let mut live = self.certs.write().unwrap_or_else(|e| e.into_inner());
        live.insert(
            domain,
            Arc::new(CertKey {
                leaf,
                chain: certs,
                key,
            }),
        );
        Ok(())
    }

    /// Number of intermediates held for `domain`. Tests only.
    #[cfg(test)]
    pub fn chain_len(&self, domain: &str) -> Option<usize> {
        self.certs
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&domain.to_ascii_lowercase())
            .map(|pair| pair.chain.len())
    }

    /// Does this resolver hold a certificate for `domain`?
    #[cfg(test)]
    pub fn has(&self, domain: &str) -> bool {
        self.certs
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&domain.to_ascii_lowercase())
    }

    /// Pick the certificate key to use for a given SNI hostname.
    ///
    /// * exact (case-insensitive) match -> that domain
    /// * empty or unknown SNI -> the default domain, when `fallback_cert` is on
    /// * otherwise -> `None`, i.e. no certificate is installed and the
    ///   handshake is expected to fail
    fn resolve_key(&self, sni: &str) -> Option<String> {
        let sni = sni.trim_end_matches('.').to_ascii_lowercase();
        let certs = self.certs.read().unwrap_or_else(|e| e.into_inner());

        if certs.contains_key(&sni) {
            return Some(sni);
        }
        if self.fallback.load(Ordering::Relaxed) {
            let default = self
                .default_domain
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if certs.contains_key(&default) {
                debug!("no certificate configured for SNI `{sni}`, using default");
                return Some(default);
            }
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

        let pair = {
            let certs = self.certs.read().unwrap_or_else(|e| e.into_inner());
            certs.get(&domain).cloned()
        };
        let Some(pair) = pair else {
            error!("certificate for `{domain}` disappeared during the handshake");
            return;
        };

        if let Err(e) = ext::ssl_use_certificate(ssl_ref, &pair.leaf) {
            error!("failed to set certificate for `{sni}`: {e}");
        }
        for intermediate in &pair.chain {
            if let Err(e) = ext::ssl_add_chain_cert(ssl_ref, intermediate) {
                error!("failed to add an intermediate for `{sni}`: {e}");
            }
        }
        if let Err(e) = ext::ssl_use_private_key(ssl_ref, &pair.key) {
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
            cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            cert.set_not_after(&Asn1Time::days_from_now(365).unwrap())
                .unwrap();
            cert.sign(&key, MessageDigest::sha256()).unwrap();
            let cert = cert.build();

            let dir = std::env::temp_dir().join(format!("uping-tls-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let cert_path = dir.join("test.local.crt");
            let key_path = dir.join("test.local.key");
            std::fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
            std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();

            (
                cert_path.display().to_string(),
                key_path.display().to_string(),
            )
        })
    }

    fn test_server(domain: &str) -> Server {
        let (cert, key) = pair();
        Server {
            domain: domain.to_string(),
            https_listen: String::new(),
            https_listen6: String::new(),
            serve_http: true,
            health: true,
            keys: None,
            pub_key: cert.clone(),
            priv_key: key.clone(),
            upstream: "127.0.0.1:8080".to_string(),
            upstream_tls: false,
            upstream_sni: String::new(),
            upstream_verify: true,
            upstream_ca: String::new(),
            root: String::new(),
            index: "index.html".to_string(),
            routes: Vec::new(),
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
        assert!(resolver.has("test.local"));
    }

    /// A `fullchain.pem` has more than one certificate in it. The leaf is used
    /// as the server certificate; the rest must be sent as the chain, or a
    /// client that cannot chase the leaf's AIA extension fails the handshake.
    #[test]
    fn a_fullchain_keeps_its_intermediates() {
        let (cert_path, key_path) = pair();
        let leaf = std::fs::read(cert_path).unwrap();
        let key = std::fs::read(key_path).unwrap();

        let mut fullchain = leaf.clone();
        fullchain.extend_from_slice(&leaf); // a second cert is enough to parse

        let resolver = SniResolver::empty("test.local", true);
        resolver.install("test.local", &fullchain, &key).unwrap();

        assert_eq!(resolver.chain_len("test.local"), Some(1));
        assert_eq!(
            resolver.resolve_key("test.local").as_deref(),
            Some("test.local")
        );
    }

    #[test]
    fn an_install_without_a_certificate_is_refused() {
        let (_, key_path) = pair();
        let key = std::fs::read(key_path).unwrap();
        let resolver = SniResolver::empty("test.local", true);
        let err = resolver
            .install("test.local", b"", &key)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no certificate found") || err.contains("parsing cert"),
            "{err}"
        );
    }

    #[test]
    fn domain_keys_are_lowercased() {
        let resolver = SniResolver::from_servers(&[test_server("TEST.Local")], true).unwrap();
        assert!(resolver.has("test.local"));
        assert_eq!(*resolver.default_domain.read().unwrap(), "test.local");
    }

    #[test]
    fn resolve_key_matches_sni_case_insensitively() {
        let resolver = SniResolver::from_servers(&[test_server("test.local")], true).unwrap();
        assert_eq!(
            resolver.resolve_key("test.local").as_deref(),
            Some("test.local")
        );
        assert_eq!(
            resolver.resolve_key("TEST.LOCAL").as_deref(),
            Some("test.local")
        );
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
        let resolver = SniResolver::from_servers(
            &[test_server("test.local"), test_server("other.local")],
            true,
        )
        .unwrap();
        assert_eq!(
            resolver.resolve_key("other.local").as_deref(),
            Some("other.local")
        );
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
        assert!(
            err.contains("parsing cert") || err.contains("no certificate found"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(bad);
    }
}
