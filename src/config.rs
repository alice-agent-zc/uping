//! uping configuration model.
//!
//! The whole config stays small. Relative paths — manual key files, static
//! roots, the certificate directory — are resolved against the directory that
//! holds `config.toml`, so the process can be started from anywhere.
//!
//! ```toml
//! # Optional. The host-wide listeners: one address per family, one port per
//! # protocol. A server can override its HTTPS socket with listen/listen6.
//! [listen]
//! ipv4  = "0.0.0.0"                    # default
//! ipv6  = ""                           # e.g. "2001:db8::1"; empty = no IPv6
//! http  = 80                           # default
//! https = 443                          # default
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
//! # Optional. One target per path prefix; the longest prefix wins. Routes are
//! # nested under the server that owns them, so there is no shared route table.
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
//! listen   = "0.0.0.0:25"              # one concrete IP:port; no wildcard
//! upstream = "127.0.0.1:10025"         # the port the service really listens on
//! connect_timeout_ms = 5000            # default 5000, clamped to 100..30000
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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

    /// Raw TCP forwarders (`[[stream]]`). Each entry binds one port and pipes
    /// every byte to `upstream` — no HTTP, no TLS termination.
    #[serde(rename = "stream", default)]
    pub streams: Vec<Stream>,
}

/// Where uping binds, globally.
///
/// `ipv4` is one IPv4 address (default `0.0.0.0`). `ipv6` is one IPv6 address,
/// written bare (`"2001:db8::1"`, no brackets and no port); empty means "do not
/// listen on IPv6". `http` and `https` are single ports, default 80 and 443.
///
/// There is deliberately no wildcard syntax and no address list: a listener is
/// one concrete address. A host that owns several addresses lists them on the
/// `[[server]]` entries that need them with `listen` / `listen6`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    #[serde(default = "default_ipv4")]
    pub ipv4: String,
    #[serde(default)]
    pub ipv6: String,
    #[serde(default = "default_http")]
    pub http: u16,
    #[serde(default = "default_https")]
    pub https: u16,
}

impl Default for Listen {
    fn default() -> Self {
        Listen {
            ipv4: default_ipv4(),
            ipv6: String::new(),
            http: default_http(),
            https: default_https(),
        }
    }
}

impl Listen {
    /// The global IPv4 address, validated at load time.
    pub fn ipv4_addr(&self) -> Result<Ipv4Addr> {
        self.ipv4.trim().parse().map_err(|e| {
            anyhow::anyhow!(
                "`[listen] ipv4` `{}` is not an IPv4 address: {e}",
                self.ipv4
            )
        })
    }

    /// The global IPv6 address, or `None` when `ipv6` is empty.
    pub fn ipv6_addr(&self) -> Result<Option<Ipv6Addr>> {
        let raw = self.ipv6.trim();
        if raw.is_empty() {
            return Ok(None);
        }
        raw.parse()
            .map(Some)
            .map_err(|e| anyhow::anyhow!("`[listen] ipv6` `{raw}` is not an IPv6 address: {e}"))
    }

    /// The HTTP sockets: the global IPv4 address and, when configured, the
    /// global IPv6 one. `http` is never per-server: port 80 is what the ACME
    /// http-01 challenge needs, so it stays in one place.
    pub fn http_addrs(&self) -> Result<Vec<SocketAddr>> {
        let mut out = vec![SocketAddr::new(IpAddr::V4(self.ipv4_addr()?), self.http)];
        if let Some(v6) = self.ipv6_addr()? {
            out.push(SocketAddr::new(IpAddr::V6(v6), self.http));
        }
        Ok(out)
    }

    /// The sockets of the default HTTPS group, for servers that do not
    /// override `listen`/`listen6`.
    pub fn https_addrs(&self) -> Result<Vec<SocketAddr>> {
        let mut out = vec![SocketAddr::new(IpAddr::V4(self.ipv4_addr()?), self.https)];
        if let Some(v6) = self.ipv6_addr()? {
            out.push(SocketAddr::new(IpAddr::V6(v6), self.https));
        }
        Ok(out)
    }
}

/// The sockets one HTTPS service listens on. Servers that do not override
/// `listen`/`listen6` share the default group; every distinct override becomes
/// its own group (and its own listener), because a socket cannot be bound twice.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupKey {
    pub v4: Option<SocketAddr>,
    pub v6: Option<SocketAddr>,
}

/// One HTTPS listener and the domains it is allowed to answer.
#[derive(Debug)]
pub struct HttpsGroup {
    pub key: GroupKey,
    pub addrs: Vec<SocketAddr>,
    /// Lowercased domains served through these listeners.
    pub domains: Vec<String>,
}

impl GroupKey {
    pub fn addrs(&self) -> Vec<SocketAddr> {
        [self.v4, self.v6].into_iter().flatten().collect()
    }
}

fn default_ipv4() -> String {
    "0.0.0.0".to_string()
}

fn default_http() -> u16 {
    80
}

fn default_https() -> u16 {
    443
}

/// Parse one `listen` / `listen6` value.
///
/// The port is optional and defaults to the global `https` port. An IPv6
/// address with an explicit port must be bracketed (`"[2001:db8::1]:8443"`):
/// `"2001:db8::1:8443"` is a valid address on its own, so the port would be
/// silently swallowed into it.
fn parse_bind(
    raw: &str,
    default_port: u16,
    family: Family,
    what: &str,
) -> Result<Option<SocketAddr>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let addr = match family {
        Family::V4 => {
            if raw.contains(':') {
                let addr = raw.parse::<SocketAddr>().map_err(|e| {
                    anyhow::anyhow!("{what} `{raw}` is not an `IPv4:port` address: {e}")
                })?;
                if !addr.is_ipv4() {
                    anyhow::bail!("{what} `{raw}` is IPv6; use `listen6` for that address");
                }
                addr
            } else {
                let ip = raw
                    .parse::<Ipv4Addr>()
                    .map_err(|e| anyhow::anyhow!("{what} `{raw}` is not an IPv4 address: {e}"))?;
                SocketAddr::new(IpAddr::V4(ip), default_port)
            }
        }
        Family::V6 => {
            if raw.starts_with('[') {
                let addr = raw.parse::<SocketAddr>().map_err(|e| {
                    anyhow::anyhow!("{what} `{raw}` is not a `[IPv6]:port` address: {e}")
                })?;
                if !addr.is_ipv6() {
                    anyhow::bail!("{what} `{raw}` is IPv4; use `listen` for that address");
                }
                addr
            } else {
                let ip = raw.parse::<Ipv6Addr>().map_err(|_| {
                    anyhow::anyhow!(
                        "{what} `{raw}` is not an IPv6 address; an explicit port needs \
                         brackets, e.g. `[{raw}]:8443`"
                    )
                })?;
                SocketAddr::new(IpAddr::V6(ip), default_port)
            }
        }
    };
    if addr.port() == 0 {
        anyhow::bail!("{what} `{raw}`: port 0 binds an ephemeral port, never the one you meant");
    }
    Ok(Some(addr))
}

#[derive(Debug, Clone, Copy)]
enum Family {
    V4,
    V6,
}

impl Server {
    /// The HTTPS sockets this server overrides, or `(None, None)` when it uses
    /// the global default group.
    pub fn binds(&self, https_port: u16) -> Result<(Option<SocketAddr>, Option<SocketAddr>)> {
        let v4 = parse_bind(&self.listen, https_port, Family::V4, "`listen`")?;
        let v6 = parse_bind(&self.listen6, https_port, Family::V6, "`listen6`")?;
        Ok((v4, v6))
    }
}

impl Config {
    /// Group the servers by the HTTPS socket they belong to. The default group
    /// exists only when at least one server does not override its listener.
    pub fn https_groups(&self) -> Result<Vec<HttpsGroup>> {
        let default_v4 = SocketAddr::new(IpAddr::V4(self.listen.ipv4_addr()?), self.listen.https);
        let default_v6 = self
            .listen
            .ipv6_addr()?
            .map(|ip| SocketAddr::new(IpAddr::V6(ip), self.listen.https));

        let mut groups: Vec<HttpsGroup> = Vec::new();
        for s in &self.servers {
            let (v4, v6) = s.binds(self.listen.https)?;
            let key = if v4.is_none() && v6.is_none() {
                GroupKey {
                    v4: Some(default_v4),
                    v6: default_v6,
                }
            } else {
                GroupKey { v4, v6 }
            };
            let domain = s.domain.to_ascii_lowercase();
            match groups.iter_mut().find(|g| g.key == key) {
                Some(group) => group.domains.push(domain),
                None => groups.push(HttpsGroup {
                    addrs: key.addrs(),
                    key,
                    domains: vec![domain],
                }),
            }
        }
        for g in &mut groups {
            g.domains.sort();
            g.domains.dedup();
        }
        groups.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(groups)
    }
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
    /// against the TLS SNI name and the HTTP `Host` header. In the map form
    /// (`[server."www.example.com"]`) it is the table key, and this field may be
    /// omitted; if both are present they must agree.
    #[serde(default)]
    pub domain: String,

    /// Optional IPv4 HTTPS listener for this server: an address, or
    /// `address:port` to override the global `https` port too. Overrides the
    /// global `[listen] ipv4` for this domain; `listen6` works the same for
    /// IPv6. When either is set, the server is served only on its own sockets.
    #[serde(default)]
    pub listen: String,

    /// Optional IPv6 HTTPS listener, e.g. `"2001:db8::1"` or
    /// `"[2001:db8::1]:8443"`. See `listen`.
    #[serde(default)]
    pub listen6: String,

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

/// One path-prefix route of one server (`[[server.route]]`).
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
}

impl Route {
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

    /// Local address to bind, one concrete `IP:port`, e.g. `0.0.0.0:25` or
    /// `127.0.0.1:8080`. The `*` wildcard is deliberately not accepted.
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
    /// The effective route table for one server. Routes are nested under the
    /// server (`[[server.route]]` or `[[server."domain".route]]`), so there is
    /// never a question of which domain a route belongs to.
    pub fn routes_for<'a>(&'a self, server: &'a Server) -> &'a [Route] {
        &server.routes
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
        let mut value: toml::Value = toml::from_str(&raw)
            .with_context(|| format!("parsing TOML in `{}`", path.display()))?;
        // `[server."domain"]` is deserialized as a table; turn it into the same
        // array the `[[server]]` form produces, with the key as `domain`.
        normalize_server_tables(&mut value)?;
        let mut cfg: Config = value
            .try_into()
            .with_context(|| format!("parsing TOML in `{}`", path.display()))?;
        cfg.root_dir = absolute_parent(path)?;

        if cfg.is_empty() {
            anyhow::bail!(
                "no [[server]] or [[stream]] entries found in `{}`",
                path.display()
            );
        }
        validate_listen(&cfg.listen)?;
        let mut seen = std::collections::HashSet::new();
        for s in &mut cfg.servers {
            // The same trimmed value must be what routing stores, not just
            // what validation looks at.
            s.domain = s.domain.trim().trim_end_matches('.').to_string();
            s.index = s.index.trim().to_string();
            s.listen = s.listen.trim().to_string();
            s.listen6 = s.listen6.trim().to_string();
            for r in &mut s.routes {
                r.path = r.path.trim().to_string();
                r.index = r.index.trim().to_string();
            }
            validate_server(s, &cfg.root_dir, cfg.listen.https)?;
            if !seen.insert(s.domain.to_ascii_lowercase()) {
                anyhow::bail!("two [[server]] entries share the domain `{}`", s.domain);
            }
        }
        cfg.acme.renew_before_days = cfg.acme.renew_before_days.clamp(1, 89);
        validate_acme(&cfg.acme, &cfg.root_dir)?;
        validate_streams(&mut cfg)?;
        validate_listeners(&cfg)?;
        Ok(cfg)
    }
}

/// Accept both server forms.
///
/// ```toml
/// [[server]]                 # array form: the domain is a field
/// domain = "www.example.com"
///
/// [server."www.example.com"] # map form: the domain is the table key
/// ```
///
/// The map form is rewritten into the array form before deserialization, so
/// every later stage sees exactly one representation. The key is authoritative;
/// a `domain` field that disagrees is refused instead of silently winning.
fn normalize_server_tables(value: &mut toml::Value) -> Result<()> {
    let Some(server) = value.get_mut("server") else {
        return Ok(());
    };
    let Some(table) = server.as_table_mut() else {
        return Ok(());
    };
    let table = std::mem::take(table);
    let mut array = Vec::with_capacity(table.len());
    for (key, mut entry) in table {
        let Some(entry_table) = entry.as_table_mut() else {
            anyhow::bail!("`[server.{key}]` must be a table");
        };
        match entry_table.get("domain") {
            Some(toml::Value::String(domain)) if domain != &key => anyhow::bail!(
                "`[server.{key}]` also sets `domain = \"{domain}\"`; the table key and the field must agree"
            ),
            Some(toml::Value::String(_)) => {}
            Some(other) => anyhow::bail!(
                "`[server.{key}] domain` must be a string, not {}",
                other.type_str()
            ),
            None => {
                entry_table.insert("domain".to_string(), toml::Value::String(key.clone()));
            }
        }
        array.push(entry);
    }
    *server = toml::Value::Array(array);
    Ok(())
}

/// The global listener must name one valid address and two valid ports.
fn validate_listen(listen: &Listen) -> Result<()> {
    listen.ipv4_addr()?;
    listen.ipv6_addr()?;
    for (what, port) in [
        ("`[listen] http`", listen.http),
        ("`[listen] https`", listen.https),
    ] {
        if port == 0 {
            anyhow::bail!("{what} port 0 binds an ephemeral port, never the one you meant");
        }
    }
    Ok(())
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
fn validate_server(s: &Server, root_dir: &Path, https_port: u16) -> Result<()> {
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
    s.binds(https_port)
        .with_context(|| format!("`{domain}` listener override"))?;

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

/// Reject `[[stream]]` entries that cannot bind, and refuse two listeners that
/// would fight over the same socket. A silent second bind is worse than a
/// refusal at startup: one of the two ports would keep working and the operator
/// would have no way to know which.
fn validate_streams(cfg: &mut Config) -> Result<()> {
    let http = cfg.listen.http_addrs()?;
    let https = cfg.listen.https_addrs()?;
    let bound = !cfg.servers.is_empty();

    let mut seen: Vec<(SocketAddr, String)> = Vec::new();

    for s in &mut cfg.streams {
        let where_ = format!("[[stream]] `{}`", s.label());

        if s.listen.trim().is_empty() {
            anyhow::bail!("{where_} has an empty `listen`");
        }
        if s.upstream.trim().is_empty() {
            anyhow::bail!("{where_} has an empty `upstream`");
        }
        if s.listen.trim_start().starts_with('*') {
            anyhow::bail!(
                "{where_}: the `*` wildcard was removed; write `0.0.0.0:{}` instead",
                s.listen.trim_start().trim_start_matches("*:")
            );
        }

        let listen = parse_addr(&s.listen, &format!("{where_} `listen`"))?;
        s.listen = listen.to_string();
        validate_upstream(&s.upstream, &format!("{where_} `upstream`"))?;

        if bound {
            for (what, addr) in [("`[listen] http`", &http), ("`[listen] https`", &https)] {
                if addr.iter().any(|a| addrs_conflict(&listen, a)) {
                    anyhow::bail!("{where_}: `listen` {} clashes with {what}", s.listen.trim(),);
                }
            }
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

/// The HTTP, HTTPS and stream sockets must be pairwise distinct.
///
/// A server's `listen`/`listen6` can create a second HTTPS listener; binding it
/// twice would fail at startup with a bare `EADDRINUSE`, so the config loader
/// rejects the overlap first and names both sides.
fn validate_listeners(cfg: &Config) -> Result<()> {
    let http = cfg.listen.http_addrs()?;
    let groups = cfg.https_groups()?;

    for (i, g) in groups.iter().enumerate() {
        for (n, addr) in g.addrs.iter().enumerate() {
            for other in &g.addrs[n + 1..] {
                if addrs_conflict(addr, other) {
                    anyhow::bail!(
                        "one HTTPS listener would bind both {addr} and {other}; \
                         in particular `ipv6 = \"::\"` and `ipv4 = \"0.0.0.0\"` on the same \
                         port are one dual-stack socket, not two"
                    );
                }
            }
        }
        for addr in &g.addrs {
            for h in &http {
                if addrs_conflict(addr, h) {
                    anyhow::bail!(
                        "the HTTPS listener {addr} clashes with `[listen] http` {h}; \
                         use different ports"
                    );
                }
            }
            for st in &cfg.streams {
                if let Ok(sa) = st.listen.parse::<SocketAddr>() {
                    if addrs_conflict(addr, &sa) {
                        anyhow::bail!(
                            "the HTTPS listener {addr} clashes with [[stream]] `{}` on {}",
                            st.label(),
                            st.listen
                        );
                    }
                }
            }
            for other in &groups[i + 1..] {
                if other.addrs.iter().any(|o| addrs_conflict(addr, o)) {
                    anyhow::bail!(
                        "two HTTPS listeners want {addr}; a server's `listen`/`listen6` \
                         must name an address the global `[listen]` does not already bind"
                    );
                }
            }
        }
    }
    if !cfg.servers.is_empty() && groups.is_empty() {
        anyhow::bail!("servers are configured but no HTTPS listener was produced");
    }
    Ok(())
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

        assert_eq!(cfg.listen.ipv4, "0.0.0.0");
        assert!(cfg.listen.ipv6.is_empty());
        assert_eq!(cfg.listen.http, 80);
        assert_eq!(cfg.listen.https, 443);
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
            &format!("[listen]\nipv4 = \"127.0.0.1\"\nhttp = 8088\nhttps = 8443\n{MINIMAL}"),
        );
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.listen.ipv4, "127.0.0.1");
        assert_eq!(cfg.listen.http, 8088);
        assert_eq!(cfg.listen.https, 8443);
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
        let path = write_temp(
            "empty.toml",
            "[listen]\nipv4 = \"127.0.0.1\"\nhttp = 8088\n",
        );
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

    #[test]
    fn a_server_can_be_addressed_by_its_table_key() {
        let path = write_temp(
            "server-map.toml",
            r#"
[server."www.example.com"]
upstream = "127.0.0.1:8080"

[[server."www.example.com".route]]
path = "/mcp"
upstream = "127.0.0.1:8081"
"#,
        );
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].domain, "www.example.com");
        assert_eq!(cfg.servers[0].upstream, "127.0.0.1:8080");
        // The route is nested under the domain: there is no ambiguity about
        // which server it belongs to.
        assert_eq!(cfg.servers[0].routes.len(), 1);
        assert_eq!(cfg.servers[0].routes[0].path, "/mcp");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_map_key_and_a_domain_field_must_agree() {
        let path = write_temp(
            "server-map-conflict.toml",
            r#"
[server."www.example.com"]
domain = "api.example.com"
upstream = "127.0.0.1:8080"
"#,
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(err.contains("must agree"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn two_servers_may_not_share_a_domain() {
        let path = write_temp(
            "duplicate-domain.toml",
            r#"
[[server]]
domain = "a.example"
upstream = "127.0.0.1:8080"

[[server]]
domain = "A.example"
upstream = "127.0.0.1:8081"
"#,
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(err.contains("share the domain"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_server_listen_override_forms_its_own_group() {
        let path = write_temp(
            "server-listen.toml",
            &format!(
                "[listen]\nipv4 = \"10.0.0.1\"\nhttps = 8443\n{MINIMAL}\n\
                 [[server]]\ndomain = \"private.local\"\n\
                 pub_key = \"certs/p.crt\"\npriv_key = \"certs/p.key\"\n\
                 upstream = \"127.0.0.1:9000\"\n\
                 listen = \"74.56.12.45\"\nlisten6 = \"[2001:db8::1]:9443\"\n"
            ),
        );
        let cfg = Config::load(&path).unwrap();
        let groups = cfg.https_groups().unwrap();

        assert_eq!(
            groups.len(),
            2,
            "default group plus one override: {groups:?}"
        );
        let own = groups
            .iter()
            .find(|g| g.domains == ["private.local"])
            .expect("the overriding server has its own group");
        assert_eq!(own.addrs.len(), 2);
        assert_eq!(own.addrs[0].to_string(), "74.56.12.45:8443");
        assert_eq!(own.addrs[1].to_string(), "[2001:db8::1]:9443");

        let default = groups
            .iter()
            .find(|g| g.domains == ["test.local"])
            .expect("the other server stays on the default group");
        assert_eq!(default.addrs[0].to_string(), "10.0.0.1:8443");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_listen_override_must_not_rebind_the_global_socket() {
        let path = write_temp(
            "server-listen-clash.toml",
            &format!(
                "{MINIMAL}\n[[server]]\ndomain = \"private.local\"\n\
                 pub_key = \"certs/p.crt\"\npriv_key = \"certs/p.key\"\n\
                 upstream = \"127.0.0.1:9000\"\nlisten = \"127.0.0.1:443\"\n"
            ),
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("two HTTPS listeners want"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_listen6_port_needs_brackets() {
        let path = write_temp(
            "listen6-unbracketed.toml",
            r#"
[[server]]
domain = "v6.example"
upstream = "127.0.0.1:8080"
listen6 = "[2001:db8::1]:9443"
"#,
        );
        assert!(Config::load(&path).is_ok());
        let _ = std::fs::remove_file(path);

        let path = write_temp(
            "listen6-raw-port.toml",
            r#"
[[server]]
domain = "v6.example"
upstream = "127.0.0.1:8080"
listen6 = "2001:db8::1:9443"
"#,
        );
        // That string is a valid IPv6 address, so it is taken as one; the only
        // way to write a port is the bracketed form.
        let cfg = Config::load(&path).unwrap();
        let group = cfg.https_groups().unwrap().remove(0);
        let v6 = group.key.v6.expect("a v6 listener");
        assert_eq!(v6.port(), 443);
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
    fn a_stream_listen_cannot_use_the_removed_wildcard() {
        let path = write_temp(
            "stream-star.toml",
            &format!(
                "{MINIMAL}\n[[stream]]\nlisten = \"*:2525\"\nupstream = \"127.0.0.1:10025\"\n"
            ),
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("wildcard was removed"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);

        let path = write_temp(
            "stream-bare-star.toml",
            &format!("{MINIMAL}\n[[stream]]\nlisten = \"*\"\nupstream = \"127.0.0.1:10025\"\n"),
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("wildcard was removed"),
            "a bare `*` must say what to write instead, got: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_wildcard_upstream_is_refused() {
        let path = write_temp(
            "upstream-star.toml",
            &format!("{MINIMAL}\n[[stream]]\nlisten = \"0.0.0.0:2525\"\nupstream = \"*:10025\"\n"),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(
            err.contains("`*` is a listen address"),
            "an upstream must name a real peer, got: {err}"
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
    // IPv6 and the global listener
    // -----------------------------------------------------------------------

    #[test]
    fn ipv6_is_one_explicit_address() {
        let path = write_temp(
            "ipv6-address.toml",
            &format!(
                "[listen]\nipv4 = \"127.0.0.1\"\nipv6 = \"2607:f1c0:f031:4500::1\"\n\
                 http = 8088\nhttps = 8443\n{MINIMAL}"
            ),
        );
        let cfg = Config::load(&path).unwrap();
        let http: Vec<String> = cfg
            .listen
            .http_addrs()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            http,
            vec!["127.0.0.1:8088", "[2607:f1c0:f031:4500::1]:8088"]
        );
        let https: Vec<String> = cfg
            .listen
            .https_addrs()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            https,
            vec!["127.0.0.1:8443", "[2607:f1c0:f031:4500::1]:8443"]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ipv6_must_be_written_without_brackets() {
        let path = write_temp(
            "ipv6-brackets.toml",
            &format!("[listen]\nipv6 = \"[::1]\"\n{MINIMAL}"),
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("not an IPv6 address"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ipv4_must_be_an_ipv4_address() {
        let path = write_temp(
            "ipv4-v6.toml",
            &format!("[listen]\nipv4 = \"::1\"\n{MINIMAL}"),
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("not an IPv4 address"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn the_two_wildcards_on_one_port_are_one_socket() {
        let path = write_temp(
            "dual-stack-wild.toml",
            &format!("[listen]\nipv6 = \"::\"\nhttps = 8443\n{MINIMAL}"),
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("one dual-stack socket"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn http_and_https_may_not_share_a_socket() {
        let path = write_temp(
            "listen-same.toml",
            &format!("[listen]\nipv4 = \"127.0.0.1\"\nhttp = 8443\nhttps = 8443\n{MINIMAL}"),
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("clashes with `[listen] http`"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn the_old_listen_syntax_is_refused() {
        // Explicit is the whole point: no string addresses, no `ipv6 = true`.
        let path = write_temp(
            "listen-old.toml",
            &format!("[listen]\nhttp = \"0.0.0.0:8088\"\n{MINIMAL}"),
        );
        assert!(Config::load(&path).is_err());
        let _ = std::fs::remove_file(path);

        let path = write_temp(
            "listen-old-bool.toml",
            &format!("[listen]\nipv6 = true\n{MINIMAL}"),
        );
        assert!(Config::load(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
}
