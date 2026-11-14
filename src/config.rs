//! uping configuration model.
//!
//! The whole config stays small. Relative paths — manual key files, static
//! roots, the certificate directory — are resolved against the directory that
//! holds `config.toml`, so the process can be started from anywhere.
//!
//! ```toml
//! # Optional. Listener addresses. `ipv6 = true` widens the wildcard to the
//! # dual-stack `[::]:port`; an IPv6 literal is also accepted directly.
//! [listen]
//! http  = "0.0.0.0:80"
//! https = "0.0.0.0:443"
//! ipv6  = true
//!
//! # Optional. ACME / Let's Encrypt, used by `keys = "auto"`.
//! [acme]
//! email             = "ops@example.com"
//! staging           = false
//! cert_dir          = "cert"          # <config dir>/cert/<domain>/
//! renew_before_days = 30              # clamped to 1..=89
//!
//! # Optional. Abuse protection. Each limit can be disabled with 0.
//! [limits]
//! per_ip_rps         = 300        # sustained requests/sec from one client IP
//! per_ip_conns_per_sec = 100      # new TCP connections/sec from one client IP
//! max_body_bytes     = 10485760   # largest accepted request body (0 = unlimited)
//!
//! # Optional. TLS behaviour.
//! [tls]
//! fallback_cert = true            # serve the first cert when SNI is absent/unknown
//!
//! [[server]]
//! domain   = "www.example.com"
//! keys     = "auto"                    # default when no key paths are given
//! upstream = "127.0.0.1:8080"          # catch-all
//!
//! # Or serve files instead of proxying; one of upstream/root.
//! [[server]]
//! domain = "static.example.com"
//! root   = "public"                    # relative to config.toml
//! index  = "index.html"
//!
//! # Optional. One target per path prefix; the longest prefix wins.
//! [[server.route]]
//! path     = "/mcp"
//! upstream = "127.0.0.1:8081"
//!
//! [[server.route]]
//! path         = "/assets"
//! root         = "public/assets"
//! strip_prefix = true
//!
//! # Experimental. Raw TCP forwarding, one listener per entry.
//! [[stream]]
//! name     = "smtp"                    # log label, optional
//! listen   = "*:25"                    # `*` = every IPv4 interface = 0.0.0.0
//! upstream = "127.0.0.1:10025"         # the port the service really listens on
//! connect_timeout_ms = 5000            # default 5000, clamped to 100..30000
//! ```

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Top level configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Directory the config file lives in. Every relative path in the file —
    /// static roots, manual key paths, the certificate directory — is resolved
    /// against it, so `uping /etc/uping/config.toml` behaves the same whatever
    /// the current directory is. Not deserialized.
    #[serde(skip)]
    pub root_dir: PathBuf,

    /// Listening addresses. Defaults to :80 / :443, so most users never set this.
    #[serde(default)]
    pub listen: Listen,

    /// Abuse protection.
    #[serde(default)]
    pub limits: Limits,

    /// TLS behaviour.
    #[serde(default)]
    pub tls: Tls,

    /// Certificate acquisition and storage (`keys = "auto"`).
    #[serde(default)]
    pub acme: Acme,

    /// One entry per reverse-proxied domain.
    #[serde(rename = "server", default)]
    pub servers: Vec<Server>,

    /// Path routes shared by several domains (`[[route]]`). A route with an
    /// empty `hosts` list serves every `[[server]]`.
    #[serde(rename = "route", default)]
    pub routes: Vec<Route>,

    /// Raw TCP forwarders (`[[stream]]`). Each entry binds one port and pipes
    /// every byte to `upstream` — no HTTP, no TLS termination.
    #[serde(rename = "stream", default)]
    pub streams: Vec<Stream>,
}

/// Where uping binds. Defaults to the standard HTTP/HTTPS ports.
///
/// Both fields accept `*:port` as shorthand for `0.0.0.0:port`; the wildcard is
/// canonicalised at load time. An IPv6 literal is written the usual way, e.g.
/// `"[::]:443"`.
///
/// `ipv6 = true` widens the common wildcard cases: `0.0.0.0:port` becomes the
/// dual-stack `[::]:port` (one socket serving both families), and a loopback
/// `127.0.0.1:port` gains `[::1]:port` beside it. A concrete IPv4 address is
/// left alone — write the IPv6 address you want explicitly instead.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    #[serde(default = "default_http")]
    pub http: String,
    #[serde(default = "default_https")]
    pub https: String,
    #[serde(default)]
    pub ipv6: bool,
}

impl Default for Listen {
    fn default() -> Self {
        Listen {
            http: default_http(),
            https: default_https(),
            ipv6: false,
        }
    }
}

impl Listen {
    /// The HTTP addresses to bind, after the `ipv6` convenience is applied.
    pub fn http_addrs(&self) -> Vec<String> {
        bind_set(&self.http, self.ipv6)
    }

    /// The HTTPS addresses to bind, after the `ipv6` convenience is applied.
    pub fn https_addrs(&self) -> Vec<String> {
        bind_set(&self.https, self.ipv6)
    }
}

/// Expand one configured bind address into the addresses to actually bind.
fn bind_set(raw: &str, ipv6: bool) -> Vec<String> {
    if !ipv6 {
        return vec![raw.to_string()];
    }
    let Ok(addr) = raw.parse::<SocketAddr>() else {
        // Validation reports the syntax error later; leave the string alone.
        return vec![raw.to_string()];
    };
    match addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => {
            // Linux binds `[::]` dual-stack by default, so this one socket also
            // answers IPv4. Listing 0.0.0.0 beside it would fail with EADDRINUSE.
            vec![format!("[::]:{}", addr.port())]
        }
        IpAddr::V4(v4) if v4.is_loopback() => {
            vec![raw.to_string(), format!("[::1]:{}", addr.port())]
        }
        // A concrete address has no derivable v6 sibling.
        _ => vec![raw.to_string()],
    }
}

fn default_http() -> String {
    "0.0.0.0:80".to_string()
}

fn default_https() -> String {
    "0.0.0.0:443".to_string()
}

/// Abuse protection.
///
/// Every limit counts a fixed one-second window per client IP, and every limit
/// can be turned off by setting it to `0`.
///
/// The defaults are deliberately generous: they are sized to let a normal
/// browser session (a page load pulls dozens of assets at once) and a chatty
/// API through untouched, while still capping what a single source can do.
/// A single-IP flood of tens of thousands of requests per second is stopped;
/// a burst of a few hundred is not.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Sustained HTTP requests per second from one client IP, across all
    /// domains. Above this the request is answered with `429 Too Many Requests`.
    #[serde(default = "default_per_ip_rps")]
    pub per_ip_rps: usize,

    /// New TCP connections per second from one client IP. Above this the
    /// connection is dropped at the socket level, before any TLS work happens.
    #[serde(default = "default_per_ip_conns_per_sec")]
    pub per_ip_conns_per_sec: usize,

    /// Largest request body accepted, in bytes. Larger requests are answered
    /// with `413 Payload Too Large`. `0` disables the check.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            per_ip_rps: default_per_ip_rps(),
            per_ip_conns_per_sec: default_per_ip_conns_per_sec(),
            max_body_bytes: default_max_body_bytes(),
        }
    }
}

fn default_per_ip_rps() -> usize {
    300
}

fn default_per_ip_conns_per_sec() -> usize {
    100
}

fn default_max_body_bytes() -> usize {
    10 * 1024 * 1024
}

/// TLS behaviour.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    /// When a client sends no SNI, or an SNI that matches no `[[server]]`, serve
    /// the first configured certificate instead of failing the handshake.
    ///
    /// This is what keeps internet-wide scanners from filling the log with
    /// `no certificate available for SNI` errors. Set to `false` for strict
    /// behaviour: an unmatched SNI then fails the handshake outright.
    #[serde(default = "default_true")]
    pub fallback_cert: bool,
}

impl Default for Tls {
    fn default() -> Self {
        Tls {
            fallback_cert: default_true(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// How a domain's certificate is obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyMode {
    /// Request and renew the certificate through ACME. This is the default for
    /// a `[[server]]` that names no key paths.
    Auto,
    /// Read the two PEM files named by `pub_key` and `priv_key`; renew them
    /// yourself (certbot, an ACME client, a paid CA, …).
    Manual,
}

/// Let's Encrypt / ACME settings, used when a `[[server]]` is in `auto` mode.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acme {
    /// Contact address sent to the CA. Optional — the CA accepts an empty
    /// contact — but without it you get no expiry warning if renewal fails.
    #[serde(default)]
    pub email: String,

    /// Use the Let's Encrypt staging directory. Certificates from it are not
    /// trusted by browsers; it exists so a misconfiguration can be debugged
    /// without burning the production rate limit.
    #[serde(default)]
    pub staging: bool,

    /// A custom ACME directory URL. Empty means Let's Encrypt (production or
    /// staging, per `staging`).
    #[serde(default)]
    pub directory: String,

    /// PEM root certificate to trust for an `https://` `directory` that is not
    /// signed by a public CA — a private ACME server (step-ca, Pebble, an
    /// internal CA). Empty means the system trust store.
    #[serde(default)]
    pub ca_bundle: String,

    /// Where generated certificates live, relative to the config file (or
    /// absolute). One subdirectory per domain:
    /// `<cert_dir>/<domain>/{fullchain,privkey}.pem`. Default `cert`.
    #[serde(default = "default_cert_dir")]
    pub cert_dir: String,

    /// Renew when the certificate has fewer than this many days left. Clamped
    /// to `1..=89` (Let's Encrypt certificates live 90 days).
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u64,
}

impl Default for Acme {
    fn default() -> Self {
        Acme {
            email: String::new(),
            staging: false,
            directory: String::new(),
            ca_bundle: String::new(),
            cert_dir: default_cert_dir(),
            renew_before_days: default_renew_before_days(),
        }
    }
}

impl Acme {
    /// The directory URL the client should talk to.
    pub fn directory_url(&self) -> &str {
        let custom = self.directory.trim();
        if !custom.is_empty() {
            custom
        } else if self.staging {
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        } else {
            "https://acme-v02.api.letsencrypt.org/directory"
        }
    }
}

fn default_cert_dir() -> String {
    "cert".to_string()
}

fn default_renew_before_days() -> u64 {
    30
}

fn default_index() -> String {
    "index.html".to_string()
}

/// A single reverse-proxied domain.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    /// The public domain name, e.g. `www.example.com`. Matched case-insensitively
    /// against the TLS SNI name and the HTTP `Host` header.
    pub domain: String,

    /// `auto` (ACME) or `manual` (read `pub_key`/`priv_key`). When omitted,
    /// naming both key paths selects `manual`; naming neither selects `auto`.
    #[serde(default)]
    pub keys: Option<KeyMode>,

    /// Path to the PEM certificate (leaf first, then any intermediates /
    /// fullchain). Required in `manual` mode; in `auto` mode it optionally
    /// overrides where the generated certificate is written.
    #[serde(default)]
    pub pub_key: String,

    /// Path to the PEM private key. Same rules as `pub_key`.
    #[serde(default)]
    pub priv_key: String,

    /// Where to forward traffic, e.g. `127.0.0.1:8080` or `localhost:3000`.
    /// Exactly one of `upstream` and `root` must be set.
    #[serde(default)]
    pub upstream: String,

    /// Serve static files from this directory when no route matches, instead
    /// of proxying. Relative to the config file. Exactly one of `upstream` and
    /// `root` must be set.
    #[serde(default)]
    pub root: String,

    /// File served for a directory request. Default `index.html`.
    #[serde(default = "default_index")]
    pub index: String,

    /// Optional path routes (`[[server.route]]`). The longest matching `path`
    /// wins; everything else falls through to this server's `upstream`/`root`.
    #[serde(rename = "route", default)]
    pub routes: Vec<Route>,
}

impl Server {
    /// The effective certificate mode, applying the backwards-compatible
    /// inference described on `keys`.
    pub fn key_mode(&self) -> KeyMode {
        self.keys.unwrap_or_else(|| {
            if self.pub_key.trim().is_empty() && self.priv_key.trim().is_empty() {
                KeyMode::Auto
            } else {
                KeyMode::Manual
            }
        })
    }
}

/// One path-prefix route.
///
/// Declared as `[[server.route]]` it belongs to that one domain; declared as a
/// top-level `[[route]]` it serves every domain named in `hosts` — or every
/// `[[server]]` when `hosts` is empty.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Path prefix, e.g. `/mcp` or `/assets/`.
    pub path: String,

    /// Where requests matching `path` are forwarded. Exactly one of `upstream`
    /// and `root` must be set.
    #[serde(default)]
    pub upstream: String,

    /// Serve static files under this directory instead of proxying. Relative
    /// to the config file. Exactly one of `upstream` and `root` must be set.
    #[serde(default)]
    pub root: String,

    /// File served for a directory request. Default `index.html`.
    #[serde(default = "default_index")]
    pub index: String,

    /// Remove `path` from the request path before forwarding it (or before
    /// resolving it under `root`).
    #[serde(default)]
    pub strip_prefix: bool,

    /// Domains this route applies to. Empty, or a `"*"` entry, means every
    /// `[[server]]`. Only meaningful on a top-level `[[route]]`.
    #[serde(default)]
    pub hosts: Vec<String>,
}

impl Route {
    /// Does this route apply to `domain`? Case-insensitive; an empty `hosts`
    /// list or a `"*"` entry matches every domain.
    pub fn applies_to(&self, domain: &str) -> bool {
        self.hosts.is_empty()
            || self.hosts.iter().any(|h| {
                let h = h.trim();
                h == "*" || h.eq_ignore_ascii_case(domain.trim())
            })
    }

    /// The prefix with a trailing `/` removed, so `/assets/` and `/assets`
    /// match the same requests.
    pub fn prefix(&self) -> &str {
        let trimmed = self.path.trim_end_matches('/');
        if trimmed.is_empty() {
            "/"
        } else {
            trimmed
        }
    }
}

/// One raw TCP forwarder (`[[stream]]`).
///
/// Bound once at startup and never re-resolved: whatever the client sends is
/// copied to `upstream` and back, byte for byte. This is what a mail port needs
/// — the TLS inside the stream belongs to the mail server, not to uping.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    /// Log label. Falls back to the `listen` address when empty.
    #[serde(default)]
    pub name: String,

    /// Local address to bind, e.g. `0.0.0.0:25`, `*:25` or `127.0.0.1:8080`.
    /// `*:port` is canonicalised to `0.0.0.0:port` at load time.
    pub listen: String,

    /// Where to forward, e.g. `127.0.0.1:10025` — usually a daemon on this
    /// host's loopback, not a service uping knows anything about.
    pub upstream: String,

    /// How long to wait for the upstream TCP handshake before giving up.
    /// Default 5000 ms, clamped to 100..=30000.
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
}

pub const MIN_STREAM_TIMEOUT_MS: u64 = 100;
pub const MAX_STREAM_TIMEOUT_MS: u64 = 30_000;

fn default_connect_timeout_ms() -> u64 {
    5000
}

impl Stream {
    /// The label used in every log line about this forwarder.
    pub fn label(&self) -> &str {
        if self.name.trim().is_empty() {
            self.listen.trim()
        } else {
            self.name.trim()
        }
    }
}

impl Config {
    /// The effective route table for one server: its own `[[server.route]]`
    /// first, then every top-level `[[route]]` that applies and whose prefix
    /// the server does not already define. On an identical prefix the server's
    /// own route wins — explicit beats shared.
    pub fn routes_for<'a>(&'a self, server: &'a Server) -> Vec<&'a Route> {
        let mut effective: Vec<&Route> = server.routes.iter().collect();
        for r in &self.routes {
            if r.applies_to(&server.domain) && !effective.iter().any(|e| e.prefix() == r.prefix()) {
                effective.push(r);
            }
        }
        effective
    }

    /// True when nothing would be served: no domain to terminate TLS for and no
    /// raw stream to forward. Uping refuses to start in that state.
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty() && self.streams.is_empty()
    }

    /// Resolve a configured path: absolute paths are kept, relative ones are
    /// taken from the directory holding `config.toml`.
    pub fn resolve(&self, raw: &str) -> PathBuf {
        resolve_path(&self.root_dir, raw)
    }

    /// Where `keys = "auto"` writes certificates.
    pub fn cert_dir(&self) -> PathBuf {
        self.resolve(&self.acme.cert_dir)
    }

    /// The certificate and key paths for one server. In `auto` mode they are
    /// either the optional `pub_key`/`priv_key` overrides or
    /// `<cert_dir>/<domain>/{fullchain,privkey}.pem`.
    #[cfg(test)]
    pub fn key_paths(&self, server: &Server) -> (PathBuf, PathBuf) {
        if !server.pub_key.trim().is_empty() {
            (
                self.resolve(&server.pub_key),
                self.resolve(&server.priv_key),
            )
        } else {
            let dir = self
                .cert_dir()
                .join(server.domain.trim().to_ascii_lowercase());
            (dir.join("fullchain.pem"), dir.join("privkey.pem"))
        }
    }

    /// Read and parse a TOML config file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file `{}`", path.display()))?;
        let mut cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("parsing TOML in `{}`", path.display()))?;
        cfg.root_dir = absolute_parent(path)?;

        if cfg.is_empty() {
            anyhow::bail!(
                "no [[server]] or [[stream]] entries found in `{}`",
                path.display()
            );
        }
        for s in &mut cfg.servers {
            // The same trimmed value must be what routing stores, not just
            // what validation looks at.
            s.domain = s.domain.trim().to_string();
            s.index = s.index.trim().to_string();
            for r in &mut s.routes {
                r.path = r.path.trim().to_string();
                r.index = r.index.trim().to_string();
            }
            validate_server(s, &cfg.root_dir)?;
        }
        for r in &mut cfg.routes {
            r.path = r.path.trim().to_string();
            r.index = r.index.trim().to_string();
        }
        validate_routes(&cfg.routes, "global", &cfg.root_dir)?;
        validate_global_hosts(&cfg)?;
        cfg.acme.renew_before_days = cfg.acme.renew_before_days.clamp(1, 89);
        validate_acme(&cfg.acme, &cfg.root_dir)?;
        validate_streams(&mut cfg)?;
        Ok(cfg)
    }
}

/// The directory of `path`, made absolute. `Path::parent` returns an empty path
/// for a bare filename, which is not useful for resolving config-relative files.
fn absolute_parent(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let abs = if parent.as_os_str().is_empty() {
        std::env::current_dir().context("reading the current directory")?
    } else if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()
            .context("reading the current directory")?
            .join(parent)
    };
    Ok(abs)
}

fn resolve_path(root_dir: &Path, raw: &str) -> PathBuf {
    let p = Path::new(raw.trim());
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root_dir.join(p)
    }
}

/// One `[[server]]`: a domain, a certificate mode, and one catch-all target.
fn validate_server(s: &Server, root_dir: &Path) -> Result<()> {
    if s.domain.trim().is_empty() {
        anyhow::bail!("a [[server]] entry has an empty `domain`");
    }
    let domain = s.domain.trim();
    if domain.contains('/')
        || domain.contains(':')
        || domain.contains(char::is_whitespace)
        || domain.contains('*')
    {
        anyhow::bail!("`{domain}` is not a hostname: no scheme, path, port or wildcard");
    }

    validate_target(&s.upstream, &s.root, root_dir, &format!("`{domain}`"))?;
    validate_index(&s.index, &format!("`{domain}`"))?;

    let mode = s.key_mode();
    let pub_set = !s.pub_key.trim().is_empty();
    let priv_set = !s.priv_key.trim().is_empty();
    match mode {
        KeyMode::Manual if !pub_set => anyhow::bail!("`{domain}` has an empty `pub_key`"),
        KeyMode::Manual if !priv_set => anyhow::bail!("`{domain}` has an empty `priv_key`"),
        KeyMode::Auto if pub_set != priv_set => anyhow::bail!(
            "`{domain}`: give both `pub_key` and `priv_key` to override the certificate paths, or neither"
        ),
        _ => {}
    }

    validate_routes(&s.routes, &format!("`{domain}`"), root_dir)?;
    Ok(())
}

/// Exactly one of `upstream` and `root`, and it has to be usable now.
fn validate_target(upstream: &str, root: &str, root_dir: &Path, owner: &str) -> Result<()> {
    let has_upstream = !upstream.trim().is_empty();
    let has_root = !root.trim().is_empty();

    match (has_upstream, has_root) {
        (false, false) => anyhow::bail!("{owner} needs an `upstream` or a `root`"),
        (true, true) => {
            anyhow::bail!("{owner} has both `upstream` and `root`; a request has one destination")
        }
        (true, false) => {
            validate_upstream(upstream, &format!("{owner} `upstream`"))?;
            Ok(())
        }
        (false, true) => validate_static_root(root, root_dir, &format!("{owner} `root`")),
    }
}

fn validate_static_root(raw: &str, root_dir: &Path, what: &str) -> Result<()> {
    let path = resolve_path(root_dir, raw);
    let meta = std::fs::metadata(&path)
        .with_context(|| format!("{what} `{}` is not a readable directory", path.display()))?;
    if !meta.is_dir() {
        anyhow::bail!("{what} `{}` is not a directory", path.display());
    }
    Ok(())
}

fn validate_index(index: &str, owner: &str) -> Result<()> {
    let index = index.trim();
    if index.is_empty() {
        anyhow::bail!("{owner} has an empty `index`");
    }
    if index.contains('/') || index.contains('\\') || index == ".." || index == "." {
        anyhow::bail!("{owner}: `index = \"{index}\"` must be a plain file name");
    }
    Ok(())
}

fn validate_acme(acme: &Acme, root_dir: &Path) -> Result<()> {
    let url = acme.directory.trim();
    if !url.is_empty() && !(url.starts_with("https://") || url.starts_with("http://")) {
        anyhow::bail!("`[acme] directory = \"{url}\"` must be an http(s) URL");
    }
    let bundle = acme.ca_bundle.trim();
    if !bundle.is_empty() {
        let path = resolve_path(root_dir, bundle);
        if !path.is_file() {
            anyhow::bail!(
                "`[acme] ca_bundle = \"{bundle}\"` is not a readable PEM file (`{}`)",
                path.display()
            );
        }
    }
    if !acme.email.trim().is_empty() && !acme.email.contains('@') {
        anyhow::bail!(
            "`[acme] email = \"{}\"` does not look like an address",
            acme.email
        );
    }
    Ok(())
}

/// Reject route tables that would be ambiguous or unusable at request time.
fn validate_routes(routes: &[Route], owner: &str, root_dir: &Path) -> Result<()> {
    let mut seen = std::collections::HashSet::new();

    for r in routes {
        let path = r.path.trim();
        let where_ = format!("{owner} route `{path}`");

        validate_target(&r.upstream, &r.root, root_dir, &where_)?;
        validate_index(&r.index, &where_)?;
        if !path.starts_with('/') {
            anyhow::bail!("{where_}: `path` must start with `/`");
        }
        if path.contains('?') || path.contains('#') {
            anyhow::bail!("{where_}: `path` is a path prefix, not a URI");
        }
        if r.prefix() == "/" {
            anyhow::bail!("{where_}: `/` is the catch-all, use the server's `upstream` or `root`");
        }
        if !seen.insert(r.prefix().to_string()) {
            anyhow::bail!("{owner} has two routes for `{}`", r.prefix());
        }
    }
    Ok(())
}

/// A top-level route may only name domains that exist, and two global routes
/// for the same prefix must address disjoint domains.
fn validate_global_hosts(cfg: &Config) -> Result<()> {
    for r in &cfg.routes {
        for h in &r.hosts {
            let h = h.trim();
            if h.is_empty() {
                anyhow::bail!("global route `{}` has an empty `hosts` entry", r.path);
            }
            if h == "*" {
                continue;
            }
            if !cfg.servers.iter().any(|s| s.domain.eq_ignore_ascii_case(h)) {
                anyhow::bail!(
                    "global route `{}` names host `{h}`, which is not a configured [[server]] domain",
                    r.path
                );
            }
        }
    }

    for (i, a) in cfg.routes.iter().enumerate() {
        for b in &cfg.routes[i + 1..] {
            if a.prefix() == b.prefix() && hosts_overlap(a, b) {
                anyhow::bail!(
                    "global routes for `{}` overlap; give them disjoint `hosts`",
                    a.prefix()
                );
            }
        }
    }
    Ok(())
}

/// Whether two global routes can apply to the same domain.
fn hosts_overlap(a: &Route, b: &Route) -> bool {
    let all = |r: &Route| r.hosts.is_empty() || r.hosts.iter().any(|h| h.trim() == "*");
    all(a)
        || all(b)
        || a.hosts.iter().any(|x| {
            b.hosts
                .iter()
                .any(|y| x.trim().eq_ignore_ascii_case(y.trim()))
        })
}

/// Reject `[[stream]]` entries that cannot bind, and refuse two listeners that
/// would fight over the same socket. A silent second bind is worse than a
/// refusal at startup: one of the two ports would keep working and the operator
/// would have no way to know which.
fn validate_streams(cfg: &mut Config) -> Result<()> {
    // Canonicalise first, so everything below — conflict checks, the
    // privileged-port warning, the log line, the actual bind — sees one form.
    cfg.listen.http = canonical_bind(&cfg.listen.http, "`[listen] http`")?;
    cfg.listen.https = canonical_bind(&cfg.listen.https, "`[listen] https`")?;

    let http = parse_all(&cfg.listen.http_addrs(), "`[listen] http`")?;
    let https = parse_all(&cfg.listen.https_addrs(), "`[listen] https`")?;
    let http_bound = !cfg.servers.is_empty();
    let https_bound = !cfg.servers.is_empty();

    // The two HTTP-facing listeners must not fight over one socket either.
    if http_bound && https_bound {
        for a in &http {
            for b in &https {
                if addrs_conflict(a, b) {
                    anyhow::bail!(
                        "`[listen] http` {} clashes with `[listen] https` {}",
                        cfg.listen.http.trim(),
                        cfg.listen.https.trim()
                    );
                }
            }
        }
    }

    let mut seen: Vec<(SocketAddr, String)> = Vec::new();

    for s in &mut cfg.streams {
        let where_ = format!("[[stream]] `{}`", s.label());

        if s.listen.trim().is_empty() {
            anyhow::bail!("{where_} has an empty `listen`");
        }
        if s.upstream.trim().is_empty() {
            anyhow::bail!("{where_} has an empty `upstream`");
        }

        s.listen = canonical_bind(&s.listen, &format!("{where_} `listen`"))?;

        let listen = parse_addr(&s.listen, &format!("{where_} `listen`"))?;
        validate_upstream(&s.upstream, &format!("{where_} `upstream`"))?;

        if http_bound && http.iter().any(|a| addrs_conflict(&listen, a)) {
            anyhow::bail!(
                "{where_}: `listen` {} clashes with `[listen] http` {}",
                s.listen.trim(),
                cfg.listen.http.trim()
            );
        }
        if https_bound && https.iter().any(|a| addrs_conflict(&listen, a)) {
            anyhow::bail!(
                "{where_}: `listen` {} clashes with `[listen] https` {}",
                s.listen.trim(),
                cfg.listen.https.trim()
            );
        }
        for (other, other_label) in &seen {
            if addrs_conflict(&listen, other) {
                anyhow::bail!(
                    "{where_}: `listen` {} clashes with [[stream]] `{other_label}`",
                    s.listen.trim()
                );
            }
        }
        seen.push((listen, s.label().to_string()));

        s.connect_timeout_ms = s
            .connect_timeout_ms
            .clamp(MIN_STREAM_TIMEOUT_MS, MAX_STREAM_TIMEOUT_MS);
    }
    Ok(())
}

fn parse_all(raw: &[String], what: &str) -> Result<Vec<SocketAddr>> {
    raw.iter().map(|a| parse_addr(a, what)).collect()
}

fn parse_addr(raw: &str, what: &str) -> Result<std::net::SocketAddr> {
    let addr = raw
        .trim()
        .parse::<std::net::SocketAddr>()
        .map_err(|e| anyhow::anyhow!("{what} `{}` is not a `IP:port` address: {e}", raw.trim()))?;
    if addr.port() == 0 {
        anyhow::bail!(
            "{what} `{}`: port 0 binds an ephemeral port, never the one you meant",
            raw.trim()
        );
    }
    Ok(addr)
}

/// An upstream names exactly one peer.
///
/// `IP:port` is the written form; a DNS name (`localhost:3000`) is accepted
/// because pingora and tokio resolve it at connect time. A wildcard is not: it
/// is a listen address, and an upstream that means "every interface" is not an
/// address at all. An IPv6 literal must be bracketed — `::1:443` has no port,
/// only `[::1]:443` does. Port 0 is never a destination.
///
/// One rule, called from all three upstream sites (`[[server]]`, `[[route]]`,
/// `[[stream]]`): a destination that cannot be dialled must fail at load, not
/// at the first request.
fn validate_upstream(raw: &str, what: &str) -> Result<()> {
    let raw = raw.trim();

    if raw.starts_with('*') {
        anyhow::bail!("{what} `{raw}`: `*` is a listen address; an upstream must name one peer");
    }

    if let Ok(addr) = raw.parse::<std::net::SocketAddr>() {
        if addr.port() == 0 {
            anyhow::bail!("{what} `{raw}`: port 0 is not a port a service listens on");
        }
        return Ok(());
    }

    match raw.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => {
            let port: u16 = port
                .parse()
                .map_err(|e| anyhow::anyhow!("{what} `{raw}`: bad port `{port}`: {e}"))?;
            if port == 0 {
                anyhow::bail!("{what} `{raw}`: port 0 is not a port a service listens on");
            }
            Ok(())
        }
        // No port at all, or an unbracketed IPv6 literal: let `parse_addr`
        // report the syntax and quote the offender.
        _ => parse_addr(raw, what).map(|_| ()),
    }
}

/// Canonical form of a *bind* address: `*:port` means every IPv4 interface.
///
/// Only listening addresses may carry the wildcard — an upstream must name a
/// peer, so `*` there stays an error. The canonical string is written back into
/// the config, so the value that gets validated, the one the log prints and the
/// one pingora binds are the same bytes.
fn canonical_bind(raw: &str, what: &str) -> Result<String> {
    let raw = raw.trim();
    let canon = match raw.strip_prefix('*') {
        Some(rest) if rest.starts_with(':') => format!("0.0.0.0{rest}"),
        Some(_) => {
            anyhow::bail!("{what} `{raw}`: a wildcard address is written `*:port`, e.g. `*:25`")
        }
        None => raw.to_string(),
    };
    canon
        .parse::<std::net::SocketAddr>()
        .map_err(|e| anyhow::anyhow!("{what} `{raw}` is not a `IP:port` address: {e}"))?;
    Ok(canon)
}

/// Two listen addresses clash when they name the same port and their IPs can be
/// the same socket — the same address, or one side unspecified (`0.0.0.0`).
/// Different concrete IPs on one port are legal and are left alone.
fn addrs_conflict(a: &std::net::SocketAddr, b: &std::net::SocketAddr) -> bool {
    a.port() == b.port() && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const MINIMAL: &str = r#"
[[server]]
domain   = "test.local"
pub_key  = "certs/test.local.crt"
priv_key = "certs/test.local.key"
upstream = "127.0.0.1:8080"
"#;

    fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
        // `std::env::temp_dir()` is fine on a normal machine; tests here only
        // ever touch a local temp file and remove it again.
        let mut path = std::env::temp_dir();
        path.push(format!("uping-cfg-{}-{}", std::process::id(), name));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn parses_a_minimal_config() {
        let path = write_temp("minimal.toml", MINIMAL);
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].domain, "test.local");
        assert_eq!(cfg.servers[0].upstream, "127.0.0.1:8080");
        assert_eq!(cfg.servers[0].pub_key, "certs/test.local.crt");
        assert_eq!(cfg.servers[0].priv_key, "certs/test.local.key");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn listen_defaults_to_standard_ports() {
        let path = write_temp("defaults.toml", MINIMAL);
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.listen.http, "0.0.0.0:80");
        assert_eq!(cfg.listen.https, "0.0.0.0:443");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn limits_default_to_protection_on() {
        let path = write_temp("limits-default.toml", MINIMAL);
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.limits.per_ip_rps, 300);
        assert_eq!(cfg.limits.per_ip_conns_per_sec, 100);
        assert_eq!(cfg.limits.max_body_bytes, 10 * 1024 * 1024);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_explicit_limits_section_wins() {
        let path = write_temp(
            "limits.toml",
            &format!(
                "[limits]\nper_ip_rps = 0\nper_ip_conns_per_sec = 7\nmax_body_bytes = 4096\n{MINIMAL}"
            ),
        );
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.limits.per_ip_rps, 0);
        assert_eq!(cfg.limits.per_ip_conns_per_sec, 7);
        assert_eq!(cfg.limits.max_body_bytes, 4096);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tls_fallback_is_on_by_default_and_can_be_disabled() {
        let path = write_temp("tls-default.toml", MINIMAL);
        assert!(Config::load(&path).unwrap().tls.fallback_cert);
        let _ = std::fs::remove_file(path);

        let path = write_temp(
            "tls-off.toml",
            &format!("[tls]\nfallback_cert = false\n{MINIMAL}"),
        );
        assert!(!Config::load(&path).unwrap().tls.fallback_cert);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn honours_an_explicit_listen_section() {
        let path = write_temp(
            "listen.toml",
            &format!("[listen]\nhttp  = \"127.0.0.1:8088\"\nhttps = \"127.0.0.1:8443\"\n{MINIMAL}"),
        );
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.listen.http, "127.0.0.1:8088");
        assert_eq!(cfg.listen.https, "127.0.0.1:8443");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn accepts_multiple_servers() {
        let path = write_temp(
            "multi.toml",
            &format!(
                "{MINIMAL}\n[[server]]\ndomain = \"other.local\"\npub_key = \"a.pem\"\npriv_key = \"a.key\"\nupstream = \"127.0.0.1:9000\"\n"
            ),
        );
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.servers.len(), 2);
        assert_eq!(cfg.servers[1].domain, "other.local");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_a_config_without_servers() {
        let path = write_temp("empty.toml", "[listen]\nhttp = \"127.0.0.1:8088\"\n");
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("no [[server]] or [[stream]] entries"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_an_empty_domain() {
        let path = write_temp("bad-domain.toml", &MINIMAL.replace("test.local", "   "));
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(err.contains("empty `domain`"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_an_empty_upstream() {
        let path = write_temp(
            "bad-upstream.toml",
            &MINIMAL.replace("127.0.0.1:8080", "  "),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("needs an `upstream` or a `root`"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_an_empty_pub_key() {
        let path = write_temp(
            "bad-pubkey.toml",
            &MINIMAL.replace("certs/test.local.crt", "  "),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(err.contains("empty `pub_key`"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_an_empty_priv_key() {
        let path = write_temp(
            "bad-privkey.toml",
            &MINIMAL.replace("certs/test.local.key", "  "),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(err.contains("empty `priv_key`"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn the_old_pem_keys_are_no_longer_accepted() {
        let legacy = MINIMAL
            .replace("pub_key", "pub_pem")
            .replace("priv_key", "priv_pem");
        let path = write_temp("legacy.toml", &legacy);
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(err.contains("parsing TOML"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    const WITH_ROUTES: &str = r#"
[[server]]
domain   = "aaa.local"
pub_key  = "certs/test.local.crt"
priv_key = "certs/test.local.key"
upstream = "127.0.0.1:8080"

[[server.route]]
path     = "/mcp"
upstream = "127.0.0.1:8081"

[[server.route]]
path         = "/assets/"
upstream     = "127.0.0.1:8085"
strip_prefix = true
"#;

    #[test]
    fn parses_path_routes() {
        let path = write_temp("routes.toml", WITH_ROUTES);
        let cfg = Config::load(&path).unwrap();
        let routes = &cfg.servers[0].routes;

        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].path, "/mcp");
        assert_eq!(routes[0].upstream, "127.0.0.1:8081");
        assert!(!routes[0].strip_prefix);
        assert_eq!(routes[1].prefix(), "/assets");
        assert!(routes[1].strip_prefix);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_server_without_routes_has_an_empty_list() {
        let path = write_temp("no-routes.toml", MINIMAL);
        assert!(Config::load(&path).unwrap().servers[0].routes.is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_a_route_path_without_a_leading_slash() {
        let path = write_temp(
            "route-noslash.toml",
            &format!(
                "{MINIMAL}\n[[server.route]]\npath = \"mcp\"\nupstream = \"127.0.0.1:8081\"\n"
            ),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("must start with `/`"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_the_root_path_as_a_route() {
        let path = write_temp(
            "route-root.toml",
            &format!("{MINIMAL}\n[[server.route]]\npath = \"/\"\nupstream = \"127.0.0.1:8081\"\n"),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(err.contains("the catch-all"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_two_routes_for_the_same_prefix() {
        let path = write_temp(
            "route-dup.toml",
            &format!(
                "{MINIMAL}\n[[server.route]]\npath = \"/assets\"\nupstream = \"127.0.0.1:8085\"\n                 \n[[server.route]]\npath = \"/assets/\"\nupstream = \"127.0.0.1:8086\"\n"
            ),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("two routes for `/assets`"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_a_route_with_an_empty_upstream() {
        let path = write_temp(
            "route-empty.toml",
            &format!("{MINIMAL}\n[[server.route]]\npath = \"/mcp\"\nupstream = \"  \"\n"),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("needs an `upstream` or a `root`"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_a_route_path_that_carries_a_query() {
        let path = write_temp(
            "route-query.toml",
            &format!(
                "{MINIMAL}\n[[server.route]]\npath = \"/mcp?x=1\"\nupstream = \"127.0.0.1:8081\"\n"
            ),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(err.contains("not a URI"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reports_a_missing_file() {
        let err = Config::load("/nonexistent/uping.toml")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("reading config file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reports_malformed_toml() {
        let path = write_temp("malformed.toml", "this is not = = toml");
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(err.contains("parsing TOML"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    const TWO_SERVERS: &str = r#"
[[server]]
domain   = "a.example"
pub_key  = "certs/a.pem"
priv_key = "certs/a.key"
upstream = "127.0.0.1:8080"

[[server]]
domain   = "b.example"
pub_key  = "certs/b.pem"
priv_key = "certs/b.key"
upstream = "127.0.0.1:8090"
"#;

    #[test]
    fn a_global_route_answers_on_two_servers() {
        let path = write_temp(
            "global-all.toml",
            &format!("{TWO_SERVERS}\n[[route]]\npath = \"/mcp\"\nupstream = \"127.0.0.1:9000\"\n"),
        );
        let cfg = Config::load(&path).unwrap();

        for server in &cfg.servers {
            let routes = cfg.routes_for(server);
            assert_eq!(routes.len(), 1, "{}", server.domain);
            assert_eq!(routes[0].path, "/mcp");
            assert_eq!(routes[0].upstream, "127.0.0.1:9000");
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_scoped_global_route_applies_only_to_its_hosts() {
        let path = write_temp(
            "global-scoped.toml",
            &format!(
                "{TWO_SERVERS}\n[[route]]\npath = \"/api\"\nupstream = \"127.0.0.1:9001\"\nhosts = [\"A.example\"]\n"
            ),
        );
        let cfg = Config::load(&path).unwrap();

        let a = cfg.routes_for(&cfg.servers[0]);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].prefix(), "/api");

        // `b.example` falls through to its own upstream.
        let b = cfg.routes_for(&cfg.servers[1]);
        assert!(b.is_empty(), "unexpected routes on b: {b:?}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_server_route_wins_over_a_global_route_on_the_same_prefix() {
        let path = write_temp(
            "global-precedence.toml",
            &format!(
                "{TWO_SERVERS}\n[[route]]\npath = \"/mcp\"\nupstream = \"127.0.0.1:9000\"\n\n[[server.route]]\npath = \"/mcp/\"\nupstream = \"127.0.0.1:9002\"\n"
            ),
        );
        let cfg = Config::load(&path).unwrap();

        // The server-local route on `b.example` beats the shared one.
        let b = cfg.routes_for(&cfg.servers[1]);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].upstream, "127.0.0.1:9002");

        // `a.example` has no local route, so the global one still applies.
        let a = cfg.routes_for(&cfg.servers[0]);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].upstream, "127.0.0.1:9000");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_a_global_route_naming_an_unknown_host() {
        let path = write_temp(
            "global-badhost.toml",
            &format!(
                "{TWO_SERVERS}\n[[route]]\npath = \"/api\"\nupstream = \"127.0.0.1:9001\"\nhosts = [\"nope.example\"]\n"
            ),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("not a configured [[server]] domain"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_config_without_global_routes_behaves_as_before() {
        let path = write_temp("no-global.toml", WITH_ROUTES);
        let cfg = Config::load(&path).unwrap();

        assert!(cfg.routes.is_empty());
        let effective = cfg.routes_for(&cfg.servers[0]);
        assert_eq!(effective.len(), cfg.servers[0].routes.len());
        for (got, own) in effective.iter().zip(&cfg.servers[0].routes) {
            assert_eq!(got.prefix(), own.prefix());
            assert_eq!(got.upstream, own.upstream);
        }
        let _ = std::fs::remove_file(path);
    }

    const STREAM: &str = r#"
[[stream]]
name     = "smtp"
listen   = "0.0.0.0:2525"
upstream = "127.0.0.1:10025"
"#;

    #[test]
    fn parses_a_stream_and_defaults_its_timeout() {
        let path = write_temp("stream.toml", &format!("{MINIMAL}{STREAM}"));
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.streams.len(), 1);
        let s = &cfg.streams[0];
        assert_eq!(s.name, "smtp");
        assert_eq!(s.listen, "0.0.0.0:2525");
        assert_eq!(s.upstream, "127.0.0.1:10025");
        assert_eq!(s.connect_timeout_ms, 5000);
        assert_eq!(s.label(), "smtp");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_stream_only_config_is_accepted() {
        // No TLS to terminate, nothing to redirect: a pure pipe is a valid uping.
        let path = write_temp("stream-only.toml", STREAM);
        let cfg = Config::load(&path).unwrap();

        assert!(cfg.servers.is_empty());
        assert_eq!(cfg.streams.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_stream_without_a_name_labels_itself_by_listen_address() {
        let path = write_temp(
            "stream-noname.toml",
            "[[stream]]\nlisten = \"127.0.0.1:2526\"\nupstream = \"127.0.0.1:10026\"\n",
        );
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.streams[0].name, "");
        assert_eq!(cfg.streams[0].label(), "127.0.0.1:2526");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_stream_connect_timeout_is_clamped_from_below() {
        let path = write_temp(
            "stream-clamp-low.toml",
            &format!("{STREAM}connect_timeout_ms = 5\n"),
        );
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.streams[0].connect_timeout_ms, MIN_STREAM_TIMEOUT_MS);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_stream_connect_timeout_is_clamped_from_above() {
        let path = write_temp(
            "stream-clamp-high.toml",
            &format!("{STREAM}connect_timeout_ms = 999999\n"),
        );
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.streams[0].connect_timeout_ms, MAX_STREAM_TIMEOUT_MS);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_two_streams_on_the_same_socket() {
        let path = write_temp(
            "stream-dup.toml",
            &format!(
                "{MINIMAL}{STREAM}\n[[stream]]\nlisten = \"0.0.0.0:2525\"\nupstream = \"127.0.0.1:10026\"\n"
            ),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("clashes with [[stream]]"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_wildcard_stream_listener_clashes_with_a_specific_one() {
        let path = write_temp(
            "stream-wildcard.toml",
            &format!(
                "{MINIMAL}{STREAM}\n[[stream]]\nlisten = \"127.0.0.1:2525\"\nupstream = \"127.0.0.1:10026\"\n"
            ),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("clashes with [[stream]]"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_wildcard_stream_listen_is_canonicalised() {
        let path = write_temp(
            "stream-star.toml",
            &format!(
                "{MINIMAL}\n[[stream]]\nlisten = \"*:2525\"\nupstream = \"127.0.0.1:10025\"\n"
            ),
        );
        let cfg = Config::load(&path).unwrap();

        assert_eq!(
            cfg.streams[0].listen, "0.0.0.0:2525",
            "`*:2525` must reach the binder as `0.0.0.0:2525`"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_wildcard_stream_listen_clashes_with_a_loopback_one() {
        let path = write_temp(
            "stream-star-clash.toml",
            &format!(
                "{MINIMAL}[[stream]]\nlisten = \"*:2525\"\nupstream = \"127.0.0.1:10025\"\n\
                 \n[[stream]]\nlisten = \"127.0.0.1:2525\"\nupstream = \"127.0.0.1:10026\"\n"
            ),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("clashes with [[stream]]"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_wildcard_http_listen_is_canonicalised() {
        let path = write_temp(
            "listen-star.toml",
            &format!("[listen]\nhttp = \"*:8088\"\nhttps = \"127.0.0.1:8443\"\n{MINIMAL}"),
        );
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.listen.http, "0.0.0.0:8088");
        assert_eq!(cfg.listen.https, "127.0.0.1:8443");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_wildcard_upstream_is_refused() {
        let path = write_temp(
            "upstream-star.toml",
            &format!("{MINIMAL}[[stream]]\nlisten = \"*:2525\"\nupstream = \"*:10025\"\n"),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("`*` is a listen address"),
            "an upstream must name a real peer, got: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_bare_asterisk_says_how_to_write_it() {
        let path = write_temp(
            "stream-bare-star.toml",
            &format!("{MINIMAL}[[stream]]\nlisten = \"*\"\nupstream = \"127.0.0.1:10025\"\n"),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("`*:port`"),
            "the error must show the accepted form, got: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn two_concrete_ips_on_one_port_do_not_clash() {
        let path = write_temp(
            "stream-two-ips.toml",
            &format!(
                "{MINIMAL}{STREAM}\n[[stream]]\nlisten = \"127.0.0.1:2525\"\nupstream = \"127.0.0.1:10026\"\n"
            )
            .replace("0.0.0.0:2525", "127.0.0.2:2525"),
        );
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.streams.len(), 2);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_stream_may_not_steal_a_listened_http_port() {
        let path = write_temp(
            "stream-vs-https.toml",
            &format!(
                "{MINIMAL}[[stream]]\nlisten = \"0.0.0.0:443\"\nupstream = \"127.0.0.1:10025\"\n"
            ),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(err.contains("`[listen] https`"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_stream_only_config_may_use_the_default_http_ports() {
        // Nothing is listening on :80/:443 without a [[server]], so a pipe on
        // one of them is not a clash. The runtime skips those listeners too.
        let path = write_temp(
            "stream-on-443.toml",
            "[[stream]]\nlisten = \"127.0.0.1:443\"\nupstream = \"127.0.0.1:10025\"\n",
        );
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.streams.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_a_stream_listen_that_is_not_an_address() {
        let path = write_temp(
            "stream-badaddr.toml",
            &format!("{MINIMAL}[[stream]]\nlisten = \"smtp\"\nupstream = \"127.0.0.1:10025\"\n"),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("is not a `IP:port` address"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_a_stream_with_an_empty_upstream() {
        let path = write_temp(
            "stream-emptyup.toml",
            &format!("{MINIMAL}[[stream]]\nlisten = \"127.0.0.1:2525\"\nupstream = \"  \"\n"),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(err.contains("empty `upstream`"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_a_config_with_neither_server_nor_stream() {
        let path = write_temp("nothing.toml", "[limits]\nper_ip_rps = 1\n");
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("no [[server]] or [[stream]] entries"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    // -----------------------------------------------------------------------
    // Certificate modes
    // -----------------------------------------------------------------------

    const AUTO_SERVER: &str = r#"
[[server]]
domain   = "auto.local"
upstream = "127.0.0.1:8080"
"#;

    #[test]
    fn a_server_without_key_paths_defaults_to_auto() {
        let path = write_temp("auto-default.toml", AUTO_SERVER);
        let cfg = Config::load(&path).unwrap();
        let s = &cfg.servers[0];

        assert_eq!(s.key_mode(), KeyMode::Auto);
        let (cert, key) = cfg.key_paths(s);
        assert!(cert.ends_with("cert/auto.local/fullchain.pem"), "{cert:?}");
        assert!(key.ends_with("cert/auto.local/privkey.pem"), "{key:?}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_server_with_both_key_paths_defaults_to_manual() {
        let path = write_temp("manual-default.toml", MINIMAL);
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.servers[0].key_mode(), KeyMode::Manual);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_explicit_auto_mode_may_override_the_storage_paths() {
        let path = write_temp(
            "auto-paths.toml",
            r#"
[[server]]
domain   = "auto.local"
keys     = "auto"
pub_key  = "mine/fullchain.pem"
priv_key = "mine/privkey.pem"
upstream = "127.0.0.1:8080"
"#,
        );
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.servers[0].key_mode(), KeyMode::Auto);
        let (cert, key) = cfg.key_paths(&cfg.servers[0]);
        assert!(cert.ends_with("mine/fullchain.pem"));
        assert!(key.ends_with("mine/privkey.pem"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn manual_mode_requires_both_key_paths() {
        let path = write_temp(
            "manual-half.toml",
            r#"
[[server]]
domain   = "manual.local"
keys     = "manual"
pub_key  = "only-cert.pem"
upstream = "127.0.0.1:8080"
"#,
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(err.contains("empty `priv_key`"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn auto_mode_refuses_a_half_overridden_pair() {
        let path = write_temp(
            "auto-half.toml",
            r#"
[[server]]
domain   = "auto.local"
keys     = "auto"
pub_key  = "only-cert.pem"
upstream = "127.0.0.1:8080"
"#,
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("give both `pub_key` and `priv_key`"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn the_certificate_directory_defaults_beside_the_config() {
        let path = write_temp("cert-dir.toml", AUTO_SERVER);
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.cert_dir(), std::env::temp_dir().join("cert"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn acme_settings_are_clamped_and_defaulted() {
        let path = write_temp(
            "acme.toml",
            &format!(
                "[acme]\nrenew_before_days = 300\ncert_dir = \"tls\"\nstaging = true\n{AUTO_SERVER}"
            ),
        );
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.acme.renew_before_days, 89);
        assert_eq!(cfg.acme.cert_dir, "tls");
        assert!(cfg.acme.directory_url().contains("staging"));
        assert_eq!(cfg.cert_dir(), std::env::temp_dir().join("tls"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_bad_acme_directory_is_refused() {
        let path = write_temp(
            "acme-bad.toml",
            &format!("[acme]\ndirectory = \"not-a-url\"\n{AUTO_SERVER}"),
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(err.contains("http(s) URL"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    // -----------------------------------------------------------------------
    // Static roots
    // -----------------------------------------------------------------------

    fn static_root(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("uping-cfg-root-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), b"hello").unwrap();
        dir
    }

    #[test]
    fn a_server_may_serve_static_files_instead_of_proxying() {
        let root = static_root("server");
        let path = write_temp(
            "static-server.toml",
            &format!(
                "[[server]]\ndomain = \"static.local\"\nroot = \"{}\"\nindex = \"index.html\"\n",
                root.display()
            ),
        );
        let cfg = Config::load(&path).unwrap();
        assert!(cfg.servers[0].upstream.is_empty());
        assert_eq!(cfg.servers[0].index, "index.html");
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_route_may_serve_static_files_and_strip_its_prefix() {
        let root = static_root("route");
        let path = write_temp(
            "static-route.toml",
            &format!(
                "{MINIMAL}\n[[server.route]]\npath = \"/assets\"\nroot = \"{}\"\nstrip_prefix = true\n",
                root.display()
            ),
        );
        let cfg = Config::load(&path).unwrap();
        let route = &cfg.servers[0].routes[0];
        assert_eq!(route.prefix(), "/assets");
        assert!(route.upstream.is_empty());
        assert!(route.strip_prefix);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_static_root_that_does_not_exist_is_refused() {
        let path = write_temp(
            "static-missing.toml",
            "[[server]]\ndomain = \"static.local\"\nroot = \"/nonexistent/uping-root\"\n",
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("not a readable directory"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn upstream_and_root_are_mutually_exclusive() {
        let root = static_root("both");
        let path = write_temp(
            "static-both.toml",
            &format!(
                "[[server]]\ndomain = \"both.local\"\nupstream = \"127.0.0.1:8080\"\nroot = \"{}\"\n",
                root.display()
            ),
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("both `upstream` and `root`"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(root);
    }

    // -----------------------------------------------------------------------
    // IPv6
    // -----------------------------------------------------------------------

    #[test]
    fn an_ipv6_literal_is_accepted_in_both_listener_slots() {
        let path = write_temp(
            "ipv6-literal.toml",
            &format!("[listen]\nhttp = \"[::1]:8088\"\nhttps = \"[::]:8443\"\n{MINIMAL}"),
        );
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.listen.http_addrs(), vec!["[::1]:8088"]);
        assert_eq!(cfg.listen.https_addrs(), vec!["[::]:8443"]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ipv6_widens_the_wildcard_into_one_dual_stack_socket() {
        let path = write_temp(
            "ipv6-wild.toml",
            &format!("[listen]\nhttp = \"0.0.0.0:8088\"\nhttps = \"0.0.0.0:8443\"\nipv6 = true\n{MINIMAL}"),
        );
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.listen.http_addrs(), vec!["[::]:8088"]);
        assert_eq!(cfg.listen.https_addrs(), vec!["[::]:8443"]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ipv6_adds_the_v6_loopback_beside_the_v4_one() {
        let path = write_temp(
            "ipv6-loop.toml",
            &format!("[listen]\nhttp = \"127.0.0.1:8088\"\nhttps = \"127.0.0.1:8443\"\nipv6 = true\n{MINIMAL}"),
        );
        let cfg = Config::load(&path).unwrap();
        assert_eq!(
            cfg.listen.http_addrs(),
            vec!["127.0.0.1:8088", "[::1]:8088"]
        );
        assert_eq!(
            cfg.listen.https_addrs(),
            vec!["127.0.0.1:8443", "[::1]:8443"]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ipv6_leaves_a_concrete_v4_address_alone() {
        let path = write_temp(
            "ipv6-concrete.toml",
            &format!("[listen]\nhttp = \"10.0.0.1:8088\"\nipv6 = true\n{MINIMAL}"),
        );
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.listen.http_addrs(), vec!["10.0.0.1:8088"]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn http_and_https_may_not_share_a_socket() {
        let path = write_temp(
            "listen-same.toml",
            &format!("[listen]\nhttp = \"127.0.0.1:8443\"\nhttps = \"127.0.0.1:8443\"\n{MINIMAL}"),
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("clashes with `[listen] https`"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }
}
