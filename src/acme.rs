//! Certificate acquisition and renewal for `keys = "auto"`.
//!
//! The flow is RFC 8555 HTTP-01 against Let's Encrypt (or any compatible CA):
//! create or load an account, order one certificate per domain, publish each
//! token at `/.well-known/acme-challenge/<token>`, let the CA fetch it, then
//! write `fullchain.pem` and `privkey.pem` under `{uping_root}/cert/<domain>/`.
//!
//! Two things make this fit uping's shape:
//!
//! * **Before the first start** there is no HTTPS listener and no redirect
//!   service to answer the challenge, so [`CertManager::obtain_missing`] binds
//!   the configured HTTP address itself for the duration of the order.
//! * **After startup** the plain-HTTP listener is already running, so renewal
//!   reuses it through the shared [`ChallengeStore`] the redirect proxy reads.
//!   A renewed pair is swapped into the live [`SniResolver`] in place; the
//!   process does not restart and does not drop a connection.
//!
//! The account key lives beside the certificates, named after a hash of the
//! ACME directory URL so production and staging cannot collide. It is written
//! `0600`, like every private key here.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use log::{debug, error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::{Acme as AcmeConfig, Config, KeyMode, Server};
use crate::tls::SniResolver;

/// Challenge tokens currently expected, token -> key authorization.
///
/// Shared by whoever runs the order (the startup probe or the renewal thread)
/// and the HTTP listener that answers the CA. Empty outside an order, so a
/// stale token cannot be served after the order ends.
#[derive(Clone, Debug, Default)]
pub struct ChallengeStore {
    tokens: Arc<RwLock<HashMap<String, String>>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, token: &str, key_authorization: String) {
        self.tokens
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token.to_string(), key_authorization);
    }

    pub fn get(&self, token: &str) -> Option<String> {
        self.tokens
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(token)
            .cloned()
    }

    pub fn remove(&self, token: &str) {
        self.tokens
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token);
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.tokens
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }
}

/// Owns the certificate files, the ACME account and the renewal thread.
#[derive(Clone)]
pub struct CertManager {
    acme: AcmeConfig,
    root_dir: PathBuf,
    cert_dir: PathBuf,
    resolver: SniResolver,
    challenges: ChallengeStore,
    /// One ACME order at a time. A renewal and a reload can both find work for
    /// the same account; serialising avoids two orders racing the same token.
    issue_lock: Arc<tokio::sync::Mutex<()>>,
}

impl CertManager {
    pub fn new(cfg: &Config, resolver: SniResolver, challenges: ChallengeStore) -> Self {
        Self {
            acme: cfg.acme.clone(),
            root_dir: cfg.root_dir.clone(),
            cert_dir: cfg.cert_dir(),
            resolver,
            challenges,
            issue_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// The certificate and key files for one server. Mirrors
    /// [`Config::key_paths`], kept here so the manager does not need the whole
    /// config once the renewal thread owns it.
    fn key_paths(&self, server: &Server) -> (PathBuf, PathBuf) {
        if !server.pub_key.trim().is_empty() {
            (
                resolve(&self.root_dir, &server.pub_key),
                resolve(&self.root_dir, &server.priv_key),
            )
        } else {
            let dir = self
                .cert_dir
                .join(server.domain.trim().to_ascii_lowercase());
            (dir.join("fullchain.pem"), dir.join("privkey.pem"))
        }
    }

    /// Request every pending certificate at startup. The HTTP challenge
    /// listener is bound only if there is something to request, and is released
    /// before the caller starts pingora.
    pub fn obtain_missing(&self, pending: &[Server], http_addrs: &[String]) -> Result<()> {
        if pending.is_empty() {
            return Ok(());
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("creating the ACME runtime")?;

        runtime.block_on(async {
            let listener = ChallengeServer::bind(http_addrs, self.challenges.clone()).await?;
            let mut first_error: Option<anyhow::Error> = None;

            for s in pending {
                info!(
                    "acme: requesting a certificate for {} ({})",
                    s.domain,
                    self.acme.directory_url()
                );
                if let Err(e) = self.issue(s).await {
                    error!("acme: {} failed: {e:#}", s.domain);
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }

            listener.shutdown().await;
            match first_error {
                Some(e) => Err(e),
                None => Ok(()),
            }
        })
    }

    /// Request pending certificates while the real HTTP listener is already
    /// running. Used by a reload that adds an `auto` domain: the challenge is
    /// served by the live redirect proxy, so nothing binds port 80 a second
    /// time.
    pub fn obtain_missing_live(&self, pending: &[Server]) {
        if pending.is_empty() {
            return;
        }
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(e) => {
                error!("acme: cannot create a renewal runtime: {e}");
                return;
            }
        };

        runtime.block_on(async {
            for s in pending {
                info!(
                    "acme: requesting a certificate for {} ({})",
                    s.domain,
                    self.acme.directory_url()
                );
                if let Err(e) = self.issue(s).await {
                    error!("acme: {} failed: {e:#}", s.domain);
                }
            }
        });
    }

    /// Start the renewal thread. It checks once an hour; a certificate is only
    /// reissued when it is inside the `renew_before_days` window, so the hourly
    /// wake-up is just a local file read.
    pub fn spawn_renewal(
        self: Arc<Self>,
        servers: Arc<std::sync::RwLock<Vec<Server>>>,
    ) -> Result<()> {
        std::thread::Builder::new()
            .name("uping-acme".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(e) => {
                        error!("acme: cannot create the renewal runtime: {e}");
                        return;
                    }
                };

                // Let pingora finish binding the HTTP listener before a due
                // certificate is renewed through it; the first check is not
                // urgent by a few seconds.
                std::thread::sleep(Duration::from_secs(30));

                loop {
                    // The reload thread swaps this list in place; snapshot it so
                    // a renewal never holds the lock across an await.
                    let snapshot = servers.read().unwrap_or_else(|e| e.into_inner()).clone();
                    runtime.block_on(self.renew_due(&snapshot));
                    std::thread::sleep(Duration::from_secs(60 * 60));
                }
            })
            .context("starting the ACME renewal thread")?;
        Ok(())
    }

    async fn renew_due(&self, servers: &[Server]) {
        for s in servers {
            if s.key_mode() != KeyMode::Auto {
                continue;
            }
            let (cert_path, key_path) = self.key_paths(s);
            if !cert_path.is_file() || !key_path.is_file() {
                warn!(
                    "acme: {} is missing a certificate file; requesting one",
                    s.domain
                );
                self.renew_one(s).await;
                continue;
            }

            let pem = match tokio::fs::read(&cert_path).await {
                Ok(pem) => pem,
                Err(e) => {
                    warn!(
                        "acme: cannot read `{}` for {}: {e}; requesting a new one",
                        cert_path.display(),
                        s.domain
                    );
                    self.renew_one(s).await;
                    continue;
                }
            };

            match cert_is_due(&pem, self.acme.renew_before_days) {
                Ok(true) => {
                    info!(
                        "acme: {} expires within {} days; renewing",
                        s.domain, self.acme.renew_before_days
                    );
                    self.renew_one(s).await;
                }
                Ok(false) => debug!("acme: {} is not due for renewal", s.domain),
                Err(e) => {
                    warn!(
                        "acme: cannot parse `{}`: {e}; requesting a new one",
                        cert_path.display()
                    );
                    self.renew_one(s).await;
                }
            }
        }
    }

    async fn renew_one(&self, server: &Server) {
        if let Err(e) = self.issue(server).await {
            error!(
                "acme: renewal for {} failed (will retry in an hour): {e:#}",
                server.domain
            );
        }
    }

    /// Run one order end to end and install the result.
    async fn issue(&self, server: &Server) -> Result<()> {
        let _guard = self.issue_lock.lock().await;
        let domain = server.domain.trim().to_ascii_lowercase();

        // Another thread may have issued this pair while we waited for the
        // lock (renewal vs. a reload queue). Re-check under the lock and skip a
        // duplicate order when a valid pair is already on disk.
        let (cert_path, key_path) = self.key_paths(server);
        if cert_path.is_file() && key_path.is_file() {
            if let Ok(pem) = std::fs::read(&cert_path) {
                if matches!(cert_is_due(&pem, self.acme.renew_before_days), Ok(false)) {
                    if let Err(e) = self
                        .resolver
                        .load_files(&server.domain, &cert_path, &key_path)
                    {
                        debug!(
                            "acme: {} has a valid pair but could not load it: {e}",
                            server.domain
                        );
                    } else {
                        debug!(
                            "acme: {} already has a valid certificate; skipping",
                            server.domain
                        );
                        return Ok(());
                    }
                }
            }
        }

        let account = self.account().await?;
        let identifiers = [Identifier::Dns(domain.clone())];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .with_context(|| format!("creating an ACME order for {domain}"))?;

        let mut tokens: Vec<String> = Vec::new();
        let outcome: Result<()> = async {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authz =
                    result.with_context(|| format!("reading the {domain} authorization"))?;
                match authz.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    other => anyhow::bail!("{domain}: authorization is {other:?}, not pending"),
                }

                let mut challenge = authz.challenge(ChallengeType::Http01).ok_or_else(|| {
                    anyhow::anyhow!("{domain}: the CA offered no http-01 challenge")
                })?;
                let token = challenge.token.clone();
                let key_authorization = challenge.key_authorization().as_str().to_string();
                debug!("acme: publishing challenge {token} for {domain}");
                self.challenges.insert(&token, key_authorization);
                tokens.push(token);
                challenge
                    .set_ready()
                    .await
                    .with_context(|| format!("marking the {domain} challenge ready"))?;
            }

            let policy = RetryPolicy::default().timeout(Duration::from_secs(120));
            let status = order
                .poll_ready(&policy)
                .await
                .with_context(|| format!("waiting for the {domain} order"))?;
            if status != OrderStatus::Ready {
                anyhow::bail!("{domain}: order ended in state {status:?}");
            }

            let key_pem = order
                .finalize()
                .await
                .with_context(|| format!("finalizing the {domain} order"))?;
            let cert_pem = order
                .poll_certificate(&policy)
                .await
                .with_context(|| format!("downloading the {domain} certificate"))?;

            self.store(server, &cert_pem, &key_pem)?;
            self.resolver
                .install(&domain, cert_pem.as_bytes(), key_pem.as_bytes())?;
            info!("acme: certificate for {domain} installed");
            Ok(())
        }
        .await;

        for token in &tokens {
            self.challenges.remove(token);
        }
        outcome
    }

    /// Write the pair where `keys = "auto"` expects it, atomically, before the
    /// live resolver starts using it.
    fn store(&self, server: &Server, cert_pem: &str, key_pem: &str) -> Result<()> {
        let (cert_path, key_path) = self.key_paths(server);
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating `{}`", parent.display()))?;
        }
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating `{}`", parent.display()))?;
        }
        write_atomic(&cert_path, cert_pem.as_bytes(), 0o644)?;
        write_atomic(&key_path, key_pem.as_bytes(), 0o600)?;
        Ok(())
    }

    /// Load the stored account for this directory, or create one.
    async fn account(&self) -> Result<Account> {
        let dir = &self.cert_dir;
        tokio::fs::create_dir_all(dir)
            .await
            .with_context(|| format!("creating `{}`", dir.display()))?;

        let path = dir.join(format!(
            "acme-account-{:016x}.json",
            stable_hash(self.acme.directory_url())
        ));

        if path.is_file() {
            let raw = tokio::fs::read(&path)
                .await
                .with_context(|| format!("reading `{}`", path.display()))?;
            let credentials: AccountCredentials = serde_json::from_slice(&raw)
                .with_context(|| format!("parsing `{}`", path.display()))?;
            return self
                .builder()?
                .from_credentials(credentials)
                .await
                .with_context(|| format!("restoring the ACME account from `{}`", path.display()));
        }

        let contact = self.contact();
        let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
        let (account, credentials) = self
            .builder()?
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.acme.directory_url().to_string(),
                None,
            )
            .await
            .context("creating the ACME account")?;

        let json =
            serde_json::to_vec_pretty(&credentials).context("serializing ACME credentials")?;
        write_atomic(&path, &json, 0o600)?;
        info!("acme: account created at `{}`", path.display());
        Ok(account)
    }

    fn contact(&self) -> Vec<String> {
        let email = self.acme.email.trim();
        if email.is_empty() {
            Vec::new()
        } else {
            vec![format!("mailto:{email}")]
        }
    }

    /// The account builder, trusting `ca_bundle` when one is configured.
    fn builder(&self) -> Result<instant_acme::AccountBuilder> {
        let bundle = self.acme.ca_bundle.trim();
        if bundle.is_empty() {
            return Account::builder().context("creating the ACME client");
        }
        let path = resolve(&self.root_dir, bundle);
        Account::builder_with_root(&path)
            .with_context(|| format!("loading the ACME CA bundle `{}`", path.display()))
    }
}

/// The request-path prefix the CA fetches for http-01.
pub const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// A temporary HTTP listener that answers only challenge requests.
///
/// Used before pingora starts, when the real redirect service cannot exist yet.
struct ChallengeServer {
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ChallengeServer {
    async fn bind(addrs: &[String], store: ChallengeStore) -> Result<Self> {
        let mut tasks = Vec::new();
        for addr in addrs {
            let listener = TcpListener::bind(addr).await.with_context(|| {
                format!(
                    "ACME http-01 needs to bind `{addr}` for a moment; \
                     stop whatever holds it (another web server?) and retry"
                )
            })?;
            let store = store.clone();
            let label = addr.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            tokio::spawn(handle_challenge(stream, store.clone()));
                        }
                        Err(e) => {
                            warn!("acme: challenge listener on {label} stopped: {e}");
                            break;
                        }
                    }
                }
            }));
        }
        Ok(Self { tasks })
    }

    async fn shutdown(self) {
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

async fn handle_challenge(mut stream: TcpStream, store: ChallengeStore) {
    let mut buf = vec![0u8; 8192];
    let mut used = 0usize;
    let deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(deadline);

    loop {
        if used == buf.len() || headers_complete(&buf[..used]) {
            break;
        }
        tokio::select! {
            _ = &mut deadline => break,
            read = stream.read(&mut buf[used..]) => match read {
                Ok(0) => break,
                Ok(n) => used += n,
                Err(_) => return,
            },
        }
    }

    let request = String::from_utf8_lossy(&buf[..used]);
    let mut parts = request.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let path = target.split('?').next().unwrap_or("");

    if method != "GET" && method != "HEAD" {
        let _ = respond(
            &mut stream,
            405,
            "Method Not Allowed",
            "Allow: GET, HEAD\r\n",
            "",
        )
        .await;
        return;
    }

    let token = path.strip_prefix(CHALLENGE_PREFIX);
    let body = token.and_then(|token| store.get(token));
    match body {
        Some(body) => {
            let _ = respond(&mut stream, 200, "OK", "", &body).await;
            if method != "HEAD" {
                let _ = stream.write_all(body.as_bytes()).await;
            }
            let _ = stream.shutdown().await;
        }
        None => {
            let _ = respond(&mut stream, 404, "Not Found", "", "").await;
        }
    }
}

async fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    extra: &str,
    body: &str,
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    if body.is_empty() {
        stream.shutdown().await?;
    }
    Ok(())
}

fn headers_complete(buf: &[u8]) -> bool {
    buf.windows(4).any(|window| window == b"\r\n\r\n")
}

/// Is `pem` due for renewal? `days` is the window before expiry.
fn cert_is_due(pem: &[u8], days: u64) -> Result<bool> {
    use openssl::asn1::Asn1Time;
    use openssl::x509::X509;

    let cert = X509::from_pem(pem).context("parsing the certificate")?;
    let threshold = Asn1Time::days_from_now(days as u32).context("computing the renewal date")?;
    let ordering = cert
        .not_after()
        .compare(&threshold)
        .context("comparing certificate dates")?;
    Ok(ordering == std::cmp::Ordering::Less)
}

fn resolve(root_dir: &Path, raw: &str) -> PathBuf {
    let path = Path::new(raw.trim());
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root_dir.join(path)
    }
}

/// FNV-1a, not `DefaultHasher`: the account file name must stay the same across
/// Rust upgrades, or every upgrade would create a fresh ACME account.
fn stable_hash(value: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Write `bytes` to `path` through a sibling temporary file, then rename.
/// A crash leaves either the old pair or the new one, never half of each.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("uping");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    // `create_new` rather than truncate: a predictable temp name in a
    // world-writable directory would otherwise be a symlink target for another
    // local user. Retry a few names in the unlikely event of a collision.
    for attempt in 0..10 {
        let tmp = parent.join(format!(
            ".{name}.tmp.{}.{nanos}.{attempt}",
            std::process::id()
        ));
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp);

        let mut file = match opened {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("creating `{}`", tmp.display()));
            }
        };

        let written = file
            .write_all(bytes)
            .with_context(|| format!("writing `{}`", tmp.display()))
            .and_then(|()| {
                file.sync_all()
                    .with_context(|| format!("flushing `{}`", tmp.display()))
            });
        drop(file);
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }

        if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("setting permissions on `{}`", tmp.display()));
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("replacing `{}`", path.display()));
        }
        return Ok(());
    }

    anyhow::bail!(
        "could not create a temporary file next to `{}`: too many name collisions",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::rsa::Rsa;

    fn cert_with_days_left(days: u32) -> Vec<u8> {
        let not_after = Asn1Time::days_from_now(days).unwrap();
        cert_expiring_at(not_after)
    }

    fn cert_expiring_at(not_after: Asn1Time) -> Vec<u8> {
        let key = openssl::pkey::PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test.local").unwrap();
        let name = name.build();

        let mut cert = openssl::x509::X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::from_unix(1_600_000_000).unwrap())
            .unwrap();
        cert.set_not_after(&not_after).unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        cert.build().to_pem().unwrap()
    }

    #[test]
    fn a_certificate_inside_the_window_is_due() {
        assert!(cert_is_due(&cert_with_days_left(10), 30).unwrap());
    }

    #[test]
    fn a_certificate_outside_the_window_is_not_due() {
        assert!(!cert_is_due(&cert_with_days_left(60), 30).unwrap());
    }

    #[test]
    fn an_expired_certificate_is_due() {
        let expired = Asn1Time::from_unix(1_700_000_000).unwrap(); // Nov 2023
        assert!(cert_is_due(&cert_expiring_at(expired), 30).unwrap());
    }

    #[test]
    fn a_non_certificate_is_an_error_not_a_rotation() {
        assert!(cert_is_due(b"not a certificate", 30).is_err());
    }

    #[test]
    fn the_challenge_store_round_trips_and_clears() {
        let store = ChallengeStore::new();
        assert!(store.is_empty());
        store.insert("token", "token.thumbprint".to_string());
        assert_eq!(store.get("token").as_deref(), Some("token.thumbprint"));
        store.remove("token");
        assert!(store.get("token").is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn a_challenge_prefix_is_stripped_exactly() {
        assert_eq!(
            "/.well-known/acme-challenge/abc"
                .strip_prefix(CHALLENGE_PREFIX)
                .unwrap(),
            "abc"
        );
        assert!("/.well-known/other/abc"
            .strip_prefix(CHALLENGE_PREFIX)
            .is_none());
    }

    #[test]
    fn headers_complete_needs_the_blank_line() {
        assert!(!headers_complete(b"GET / HTTP/1.1\r\nHost: x\r\n"));
        assert!(headers_complete(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
    }

    #[test]
    fn the_temporary_challenge_server_answers_only_known_tokens() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let store = ChallengeStore::new();
            store.insert("known", "known.thumbprint".to_string());

            let serve = tokio::spawn(async move {
                for _ in 0..2 {
                    let (stream, _) = listener.accept().await.unwrap();
                    let store = store.clone();
                    tokio::spawn(handle_challenge(stream, store));
                }
            });

            let mut good = TcpStream::connect(addr).await.unwrap();
            good.write_all(b"GET /.well-known/acme-challenge/known HTTP/1.1\r\nHost: ca\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            good.read_to_end(&mut response).await.unwrap();
            let text = String::from_utf8_lossy(&response);
            assert!(text.starts_with("HTTP/1.1 200"), "{text}");
            assert!(text.ends_with("known.thumbprint"), "{text}");

            let mut missing = TcpStream::connect(addr).await.unwrap();
            missing
                .write_all(b"GET /.well-known/acme-challenge/other HTTP/1.1\r\nHost: ca\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            missing.read_to_end(&mut response).await.unwrap();
            let text = String::from_utf8_lossy(&response);
            assert!(text.starts_with("HTTP/1.1 404"), "{text}");

            serve.await.unwrap();
        });
    }

    #[test]
    fn atomic_writes_leave_one_complete_file() {
        let dir = std::env::temp_dir().join(format!("uping-acme-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fullchain.pem");
        write_atomic(&path, b"first", 0o644).unwrap();
        write_atomic(&path, b"second", 0o644).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        let _ = std::fs::remove_dir_all(dir);
    }
}
