//! uping's own certificate authority (`keys = "internal"`).
//!
//! There is no ACME server here: the first start with an `[internal]` table
//! generates a root pair under `ca_dir`, and every `keys = "internal"` server
//! gets a leaf signed by it on first start and renewed before it expires. The
//! root is the only thing a client has to install, exactly as it would have
//! installed a private ACME CA's root — minus that CA's daemon, its DNS and its
//! port 80.
//!
//! Files follow the ACME layout so an operator has one mental model:
//!
//! ```text
//! <ca_dir>/root.crt      0644  public trust anchor
//! <ca_dir>/root.key      0600  signing key
//! <cert_dir>/<domain>/fullchain.pem   leaf, then the root
//! <cert_dir>/<domain>/privkey.pem     0600
//! ```
//!
//! Everything is best-effort at runtime: a domain whose leaf cannot be written
//! is logged and skipped, and the other domains keep serving. A missing root is
//! never regenerated silently — that would break every client that installed
//! the old one, so the operator is told to restore or remove both files.

use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use log::{info, warn};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::{X509NameBuilder, X509};

use crate::acme::cert_is_due;
use crate::config::{Config, Internal, KeyKind, Server};
use crate::tls::SniResolver;

/// The local CA: its settings, its two paths, and the live resolver it feeds.
#[derive(Clone)]
pub struct LocalCa {
    cfg: Internal,
    ca_cert: PathBuf,
    ca_key: PathBuf,
    cert_dir: PathBuf,
    resolver: SniResolver,
    /// One issuance at a time: a renewal and a reload can both find the same
    /// leaf due, and two writers must not interleave a pair on disk.
    lock: Arc<Mutex<()>>,
}

impl LocalCa {
    pub fn new(cfg: &Config, resolver: SniResolver) -> Self {
        let (ca_cert, ca_key) = cfg.ca_paths();
        Self {
            cfg: cfg.internal.clone(),
            ca_cert,
            ca_key,
            cert_dir: cfg.internal_cert_dir(),
            resolver,
            lock: Arc::new(Mutex::new(())),
        }
    }

    /// `(fullchain.pem, privkey.pem)` for one domain.
    pub fn leaf_paths(&self, server: &Server) -> (PathBuf, PathBuf) {
        let dir = self
            .cert_dir
            .join(server.domain.trim().to_ascii_lowercase());
        (dir.join("fullchain.pem"), dir.join("privkey.pem"))
    }

    /// The root certificate, as published to clients.
    #[cfg(test)]
    pub fn root_pem(&self) -> Result<Vec<u8>> {
        fs::read(&self.ca_cert)
            .with_context(|| format!("reading the local CA root `{}`", self.ca_cert.display()))
    }

    /// Make sure one domain has a usable leaf signed by the current root.
    ///
    /// Issues when the pair is missing, unparseable, signed by another root,
    /// due for renewal, or does not carry the SANs the config now asks for.
    /// Otherwise it only reads the files and installs them in the resolver.
    pub fn ensure(&self, server: &Server) -> Result<()> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let (root, root_key) = self.ensure_root()?;
        let (cert_path, key_path) = self.leaf_paths(server);

        if cert_path.is_file() && key_path.is_file() {
            let pem = fs::read(&cert_path)
                .with_context(|| format!("reading `{}`", cert_path.display()))?;
            match self.pair_is_current(&pem, &root, server) {
                Ok(true) => {
                    self.resolver
                        .load_files(server.domain.trim(), &cert_path, &key_path)?;
                    return Ok(());
                }
                Ok(false) => info!(
                    "internal CA: reissuing `{}` (expired, other root, or new SANs)",
                    server.domain.trim()
                ),
                Err(e) => warn!(
                    "internal CA: `{}` is not usable ({e:#}); reissuing",
                    cert_path.display()
                ),
            }
        }

        let (leaf, key) = new_leaf(&self.cfg, &root, &root_key, server)?;
        let mut fullchain = leaf.to_pem().context("encoding the leaf")?;
        fullchain.extend_from_slice(&root.to_pem().context("encoding the root")?);

        write_atomic(&cert_path, &fullchain, 0o644)?;
        write_atomic(
            &key_path,
            &key.private_key_to_pem_pkcs8()
                .context("encoding the leaf key")?,
            0o600,
        )?;
        self.resolver
            .load_files(server.domain.trim(), &cert_path, &key_path)?;
        info!(
            "internal CA: issued `{}` (SANs: {})",
            server.domain.trim(),
            sans(server).join(", ")
        );
        Ok(())
    }

    /// Ensure every `keys = "internal"` server. A failure is logged and that
    /// domain is skipped; the rest keep being prepared.
    pub fn ensure_all(&self, servers: &[Server]) -> bool {
        let mut all_ok = true;
        for s in servers.iter().filter(|s| s.key_mode().is_local_ca()) {
            if let Err(e) = self.ensure(s) {
                warn!(
                    "internal CA: `{}` is skipped (the other domains keep running): {e:#}",
                    s.domain.trim()
                );
                all_ok = false;
            }
        }
        all_ok
    }

    /// Create the root on first use, then reuse it forever.
    fn ensure_root(&self) -> Result<(X509, PKey<Private>)> {
        let cert_exists = self.ca_cert.is_file();
        let key_exists = self.ca_key.is_file();

        match (cert_exists, key_exists) {
            (true, true) => {
                let pem = fs::read(&self.ca_cert)
                    .with_context(|| format!("reading `{}`", self.ca_cert.display()))?;
                let root = X509::from_pem(&pem).with_context(|| {
                    format!("parsing the local CA root `{}`", self.ca_cert.display())
                })?;
                let key_pem = fs::read(&self.ca_key)
                    .with_context(|| format!("reading `{}`", self.ca_key.display()))?;
                let key = PKey::private_key_from_pem(&key_pem).with_context(|| {
                    format!("parsing the local CA key `{}`", self.ca_key.display())
                })?;
                let public = root
                    .public_key()
                    .context("reading the local CA public key")?;
                if !public.public_eq(&key) {
                    anyhow::bail!(
                        "the local CA root `{}` and key `{}` do not match; restore the \
                         pair or remove both to create a new CA (clients would have to \
                         trust the new root)",
                        self.ca_cert.display(),
                        self.ca_key.display()
                    );
                }
                Ok((root, key))
            }
            (true, false) => anyhow::bail!(
                "`{}` exists but `{}` does not: restore the key, or remove the root as \
                 well if you intend to create a new CA",
                self.ca_cert.display(),
                self.ca_key.display()
            ),
            (false, true) => anyhow::bail!(
                "`{}` exists but `{}` does not: restore the root, or remove the key as \
                 well if you intend to create a new CA",
                self.ca_key.display(),
                self.ca_cert.display()
            ),
            (false, false) => {
                let (root, key) = new_root(&self.cfg)?;
                write_atomic(
                    &self.ca_cert,
                    &root.to_pem().context("encoding the root")?,
                    0o644,
                )?;
                write_atomic(
                    &self.ca_key,
                    &key.private_key_to_pem_pkcs8()
                        .context("encoding the root key")?,
                    0o600,
                )?;
                info!(
                    "internal CA: created `{}` ({:?} root, {} days); install it on the \
                     clients that must trust these names",
                    self.ca_cert.display(),
                    self.cfg.key_type,
                    self.cfg.ca_days
                );
                Ok((root, key))
            }
        }
    }

    /// Is the pair on disk still exactly what this server needs?
    fn pair_is_current(&self, pem: &[u8], root: &X509, server: &Server) -> Result<bool> {
        if cert_is_due(pem, self.cfg.renew_before_days)? {
            return Ok(false);
        }
        let leaf = X509::from_pem(pem).context("parsing the leaf certificate")?;
        let public = root.public_key().context("reading the root public key")?;
        if !leaf
            .verify(&public)
            .context("verifying the leaf signature")?
        {
            return Ok(false);
        }
        let sanctioned: Vec<String> = sans(server)
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let actual = leaf
            .subject_alt_names()
            .map(|names| {
                names
                    .iter()
                    .filter_map(|n| n.dnsname().map(|s| s.to_ascii_lowercase()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(actual == sanctioned)
    }

    /// Publish `root.crt` over plain HTTP when `serve_root` names an address.
    ///
    /// Best-effort by design: the VPN address may not exist before the tunnel
    /// is up, and that must not stop the rest of uping. The caller logs the
    /// error and carries on.
    pub fn spawn_root_server(&self) -> Result<()> {
        let raw = self.cfg.serve_root.trim();
        if raw.is_empty() {
            return Ok(());
        }
        let addr: SocketAddr = raw
            .parse()
            .with_context(|| format!("`[internal] serve_root` `{raw}` is not an `IP:port`"))?;
        let listener = std::net::TcpListener::bind(addr)
            .with_context(|| format!("binding `[internal] serve_root` {addr}"))?;
        let local = listener.local_addr().unwrap_or(addr);
        let cert_path = self.ca_cert.clone();
        std::thread::Builder::new()
            .name("uping-root-http".into())
            .spawn(move || {
                info!(
                    "internal CA: root published on http://{local}/root.crt \
                     (from `{}`)",
                    cert_path.display()
                );
                for stream in listener.incoming() {
                    match stream {
                        Ok(stream) => {
                            if let Err(e) = serve_root_request(stream, &cert_path) {
                                warn!("internal CA: root request failed: {e}");
                            }
                        }
                        Err(e) => warn!("internal CA: accepting a root request: {e}"),
                    }
                }
            })
            .context("starting the root-certificate server")?;
        Ok(())
    }
}

/// The DNS names a leaf must carry, in config order, `domain` first.
fn sans(server: &Server) -> Vec<String> {
    let domain = server.domain.trim().to_string();
    let mut out = vec![domain.clone()];
    for name in &server.alt_names {
        let name = name.trim().trim_end_matches('.').to_string();
        if !name.is_empty() && !out.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
            out.push(name);
        }
    }
    out
}

fn new_key(kind: KeyKind) -> Result<PKey<Private>> {
    Ok(match kind {
        KeyKind::Ed25519 => PKey::generate_ed25519().context("generating an Ed25519 key")?,
        KeyKind::P256 => {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                .context("selecting the P-256 curve")?;
            let key = EcKey::generate(&group).context("generating a P-256 key")?;
            PKey::from_ec_key(key).context("wrapping the P-256 key")?
        }
        KeyKind::Rsa2048 => PKey::from_rsa(Rsa::generate(2048).context("generating an RSA key")?)
            .context("wrapping the RSA key")?,
    })
}

/// Ed25519 signs the message itself, so OpenSSL must be given a null digest for
/// it; the other two algorithms use SHA-256.
fn digest(kind: KeyKind) -> MessageDigest {
    match kind {
        KeyKind::Ed25519 => MessageDigest::null(),
        KeyKind::P256 | KeyKind::Rsa2048 => MessageDigest::sha256(),
    }
}

fn when_in(seconds: i64) -> Result<Asn1Time> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Asn1Time::from_unix(now + seconds).context("building a certificate date")
}

fn random_serial() -> Result<openssl::asn1::Asn1Integer> {
    let mut serial = BigNum::new().context("allocating a serial")?;
    serial
        .rand(159, MsbOption::MAYBE_ZERO, false)
        .context("drawing a serial")?;
    openssl::asn1::Asn1Integer::from_bn(&serial).context("encoding a serial")
}

fn new_root(cfg: &Internal) -> Result<(X509, PKey<Private>)> {
    let key = new_key(cfg.key_type)?;

    let mut name = X509NameBuilder::new().context("building the root name")?;
    name.append_entry_by_text("CN", cfg.common_name.trim())
        .context("setting the root CN")?;
    if !cfg.organization.trim().is_empty() {
        name.append_entry_by_text("O", cfg.organization.trim())
            .context("setting the root O")?;
    }
    let name = name.build();

    let mut cert = X509::builder().context("creating the root certificate")?;
    cert.set_version(2).context("setting the root version")?;
    let serial = random_serial()?;
    cert.set_serial_number(&serial)
        .context("setting the root serial")?;
    cert.set_subject_name(&name)
        .context("setting the root subject")?;
    cert.set_issuer_name(&name)
        .context("setting the root issuer")?;
    cert.set_pubkey(&key).context("setting the root key")?;
    // A day of backdating keeps a client with a slightly slow clock happy.
    let not_before = when_in(-86_400)?;
    cert.set_not_before(&not_before)
        .context("setting the root not-before")?;
    let not_after = when_in((cfg.ca_days as i64) * 86_400)?;
    cert.set_not_after(&not_after)
        .context("setting the root not-after")?;
    cert.append_extension(
        BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .context("building the root basic constraints")?,
    )
    .context("adding the root basic constraints")?;
    cert.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .digital_signature()
            .build()
            .context("building the root key usage")?,
    )
    .context("adding the root key usage")?;
    cert.sign(&key, digest(cfg.key_type))
        .context("signing the root")?;
    Ok((cert.build(), key))
}

fn new_leaf(
    cfg: &Internal,
    root: &X509,
    root_key: &PKey<Private>,
    server: &Server,
) -> Result<(X509, PKey<Private>)> {
    let key = new_key(cfg.key_type)?;
    let names = sans(server);

    let mut name = X509NameBuilder::new().context("building the leaf name")?;
    name.append_entry_by_text("CN", &names[0])
        .context("setting the leaf CN")?;
    if !cfg.organization.trim().is_empty() {
        name.append_entry_by_text("O", cfg.organization.trim())
            .context("setting the leaf O")?;
    }
    let name = name.build();

    let mut cert = X509::builder().context("creating the leaf certificate")?;
    cert.set_version(2).context("setting the leaf version")?;
    let serial = random_serial()?;
    cert.set_serial_number(&serial)
        .context("setting the leaf serial")?;
    cert.set_subject_name(&name)
        .context("setting the leaf subject")?;
    cert.set_issuer_name(root.subject_name())
        .context("setting the leaf issuer")?;
    cert.set_pubkey(&key).context("setting the leaf key")?;
    let not_before = when_in(-3_600)?;
    cert.set_not_before(&not_before)
        .context("setting the leaf not-before")?;
    let not_after = when_in((cfg.leaf_days as i64) * 86_400)?;
    cert.set_not_after(&not_after)
        .context("setting the leaf not-after")?;
    cert.append_extension(
        BasicConstraints::new()
            .critical()
            .build()
            .context("building the leaf basic constraints")?,
    )
    .context("adding the leaf basic constraints")?;
    let mut key_usage = KeyUsage::new();
    key_usage.critical().digital_signature();
    if cfg.key_type == KeyKind::Rsa2048 {
        // Neither Ed25519 nor ECDSA enciphers a key, so only RSA gets this.
        key_usage.key_encipherment();
    }
    cert.append_extension(key_usage.build().context("building the leaf key usage")?)
        .context("adding the leaf key usage")?;
    cert.append_extension(
        ExtendedKeyUsage::new()
            .server_auth()
            .build()
            .context("building the leaf extended key usage")?,
    )
    .context("adding the leaf extended key usage")?;

    let san = {
        let mut builder = SubjectAlternativeName::new();
        for name in &names {
            builder.dns(name);
        }
        builder
            .build(&cert.x509v3_context(Some(root), None))
            .context("building the leaf SAN extension")?
    };
    cert.append_extension(san)
        .context("adding the leaf SAN extension")?;

    cert.sign(root_key, digest(cfg.key_type))
        .context("signing the leaf")?;
    Ok((cert.build(), key))
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let dir = path
        .parent()
        .with_context(|| format!("`{}` has no parent directory", path.display()))?;
    fs::create_dir_all(dir).with_context(|| format!("creating `{}`", dir.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "tmp".into()),
        std::process::id()
    ));
    fs::write(&tmp, bytes).with_context(|| format!("writing `{}`", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting the mode of `{}`", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("renaming into `{}`", path.display()))?;
    Ok(())
}

/// One request on the root-certificate listener. No keep-alive, no HEAD body:
/// this exists so a client can fetch one small public file.
fn serve_root_request(mut stream: std::net::TcpStream, cert: &Path) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while request.len() < 4096 {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..n]);
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let head = String::from_utf8_lossy(&request);
    let mut line = head.lines().next().unwrap_or("").split_whitespace();
    let method = line.next().unwrap_or("");
    let target = line.next().unwrap_or("/");

    let (status, content_type, body): (&str, &str, Vec<u8>) = match method {
        "GET" | "HEAD" if target == "/" || target == "/root.crt" => match fs::read(cert) {
            Ok(pem) => ("200 OK", "application/x-pem-file", pem),
            Err(_) => (
                "503 Service Unavailable",
                "text/plain",
                b"the local CA root does not exist yet\n".to_vec(),
            ),
        },
        "GET" | "HEAD" => (
            "404 Not Found",
            "text/plain",
            b"only /root.crt is served here\n".to_vec(),
        ),
        _ => (
            "405 Method Not Allowed",
            "text/plain",
            b"GET or HEAD only\n".to_vec(),
        ),
    };

    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    if method != "HEAD" {
        stream.write_all(&body)?;
    }
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Server};
    use std::io::BufRead;

    fn server(domain: &str, alt: &[&str]) -> Server {
        Server {
            domain: domain.to_string(),
            https_listen: String::new(),
            https_listen6: String::new(),
            serve_http: false,
            health: Default::default(),
            limits: None,
            keys: Some(crate::config::KeyMode::Internal),
            pub_key: String::new(),
            priv_key: String::new(),
            alt_names: alt.iter().map(|s| s.to_string()).collect(),
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

    fn ca(dir: &Path, key_type: KeyKind) -> (LocalCa, SniResolver) {
        let mut cfg = Config::default_for_tests(dir.to_path_buf());
        cfg.internal.key_type = key_type;
        cfg.internal.ca_dir = "ca".to_string();
        cfg.internal.cert_dir = "leaves".to_string();
        let resolver = SniResolver::empty("", false);
        (LocalCa::new(&cfg, resolver.clone()), resolver)
    }

    #[test]
    fn the_default_is_ed25519() {
        assert_eq!(KeyKind::default(), KeyKind::Ed25519);
    }

    #[test]
    fn a_first_run_creates_a_root_and_a_leaf_that_chains() {
        let dir = std::env::temp_dir().join(format!("uping-ca-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (local, _) = ca(&dir, KeyKind::Ed25519);
        local.ensure(&server("app.internal", &[])).unwrap();

        let root = X509::from_pem(&local.root_pem().unwrap()).unwrap();
        let cn = root
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .to_string()
            .unwrap();
        assert_eq!(cn, "uping local CA");

        let (cert_path, key_path) = local.leaf_paths(&server("app.internal", &[]));
        let pem = fs::read(&cert_path).unwrap();
        let leaf = X509::from_pem(&pem).unwrap();
        let public = root.public_key().unwrap();
        assert!(leaf.verify(&public).unwrap());
        assert!(key_path.is_file());
        let key_mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode, 0o600);

        let names: Vec<String> = leaf
            .subject_alt_names()
            .unwrap()
            .iter()
            .filter_map(|n| n.dnsname().map(|s| s.to_string()))
            .collect();
        assert_eq!(names, vec!["app.internal".to_string()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn alternate_names_go_into_the_same_leaf() {
        let dir = std::env::temp_dir().join(format!("uping-ca-alt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (local, _) = ca(&dir, KeyKind::P256);
        local
            .ensure(&server("app.internal", &["vpn.internal", "APP.internal"]))
            .unwrap();
        let (cert_path, _) = local.leaf_paths(&server("app.internal", &[]));
        let leaf = X509::from_pem(&fs::read(cert_path).unwrap()).unwrap();
        let names: Vec<String> = leaf
            .subject_alt_names()
            .unwrap()
            .iter()
            .filter_map(|n| n.dnsname().map(|s| s.to_string()))
            .collect();
        assert_eq!(
            names,
            vec!["app.internal".to_string(), "vpn.internal".to_string()]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensuring_twice_reuses_the_pair() {
        let dir = std::env::temp_dir().join(format!("uping-ca-twice-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (local, _) = ca(&dir, KeyKind::Ed25519);
        let s = server("app.internal", &[]);
        local.ensure(&s).unwrap();
        let (cert_path, _) = local.leaf_paths(&s);
        let first = fs::read(&cert_path).unwrap();
        local.ensure(&s).unwrap();
        assert_eq!(first, fs::read(&cert_path).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pair_signed_by_another_root_is_replaced() {
        let dir = std::env::temp_dir().join(format!("uping-ca-root-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (local, _) = ca(&dir, KeyKind::Ed25519);
        let s = server("app.internal", &[]);
        local.ensure(&s).unwrap();
        let (cert_path, _) = local.leaf_paths(&s);
        let first = fs::read(&cert_path).unwrap();

        // A fresh CA at the same paths: the leaf must not survive.
        fs::remove_file(dir.join("ca").join("root.key")).unwrap();
        fs::remove_file(dir.join("ca").join("root.crt")).unwrap();
        local.ensure(&s).unwrap();
        assert_ne!(first, fs::read(&cert_path).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_half_root_pair_is_an_error_not_a_new_ca() {
        let dir = std::env::temp_dir().join(format!("uping-ca-half-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (local, _) = ca(&dir, KeyKind::Ed25519);
        local.ensure(&server("app.internal", &[])).unwrap();
        fs::remove_file(dir.join("ca").join("root.key")).unwrap();
        let err = local
            .ensure(&server("app.internal", &[]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("exists but"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_root_is_served_over_http_without_binding_a_global_address() {
        let dir = std::env::temp_dir().join(format!("uping-ca-serve-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut cfg = Config::default_for_tests(dir.clone());
        cfg.internal.ca_dir = "ca".to_string();
        cfg.internal.cert_dir = "leaves".to_string();
        cfg.internal.serve_root = "127.0.0.1:0".to_string();
        let local = LocalCa::new(&cfg, SniResolver::empty("", false));
        local.ensure(&server("app.internal", &[])).unwrap();

        // Port 0 is refused by the loader but useful here: bind it directly.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cert = local.ca_cert.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(1).flatten() {
                serve_root_request(stream, &cert).unwrap();
            }
        });

        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .write_all(b"GET /root.crt HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut reader = std::io::BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status).unwrap();
        assert!(status.contains("200 OK"), "{status}");

        let mut body = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line.trim().is_empty() {
                break;
            }
        }
        let _ = std::io::Read::read_to_string(&mut reader, &mut body);
        assert!(body.contains("BEGIN CERTIFICATE"), "{body}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_path_is_404() {
        let dir = std::env::temp_dir().join(format!("uping-ca-404-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (local, _) = ca(&dir, KeyKind::Ed25519);
        local.ensure(&server("app.internal", &[])).unwrap();
        let cert = local.ca_cert.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(1).flatten() {
                serve_root_request(stream, &cert).unwrap();
            }
        });
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .write_all(b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut reader = std::io::BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status).unwrap();
        assert!(status.contains("404"), "{status}");
        let _ = fs::remove_dir_all(&dir);
    }
}
