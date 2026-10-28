//! uping configuration model.
//!
//! The whole config stays small, but v0.1.1 adds two optional sections:
//!
//! ```toml
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
//! pub_key  = "certs/www.example.com/fullchain.pem"
//! priv_key = "certs/www.example.com/privkey.pem"
//! upstream = "127.0.0.1:8080"          # catch-all
//!
//! # Optional. One upstream per path prefix; the longest prefix wins.
//! [[server.route]]
//! path     = "/mcp"                    # segment prefix: /mcp, /mcp/…
//! upstream = "127.0.0.1:8081"
//!
//! [[server.route]]
//! path         = "/assets/"
//! upstream     = "127.0.0.1:8085"
//! strip_prefix = true                  # backend sees /app.css, not /assets/app.css
//!
//! # Optional. Raw TCP forwarding, one listener per entry (v0.2.0).
//! [[stream]]
//! name     = "smtp"                    # log label, optional
//! listen   = "*:25"                    # `*` = every IPv4 interface = 0.0.0.0
//! upstream = "127.0.0.1:10025"         # the port the service really listens on
//! connect_timeout_ms = 5000            # default 5000, clamped to 100..30000
//! ```

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Top level configuration.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Listening addresses. Defaults to :80 / :443, so most users never set this.
    #[serde(default)]
    pub listen: Listen,

    /// Abuse protection.
    #[serde(default)]
    pub limits: Limits,

    /// TLS behaviour.
    #[serde(default)]
    pub tls: Tls,

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
/// canonicalised at load time.
#[derive(Debug, Deserialize)]
pub struct Listen {
    #[serde(default = "default_http")]
    pub http: String,
    #[serde(default = "default_https")]
    pub https: String,
}

impl Default for Listen {
    fn default() -> Self {
        Listen {
            http: default_http(),
            https: default_https(),
        }
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

/// A single reverse-proxied domain.
#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    /// The public domain name, e.g. `www.example.com`. Matched case-insensitively
    /// against the TLS SNI name and the HTTP `Host` header.
    pub domain: String,

    /// Path to the PEM certificate (leaf first, then any intermediates / fullchain).
    pub pub_key: String,

    /// Path to the PEM private key.
    pub priv_key: String,

    /// Where to forward traffic, e.g. `127.0.0.1:8080` or `localhost:3000`.
    pub upstream: String,

    /// Optional path routes (`[[server.route]]`). The longest matching `path`
    /// wins; everything else falls through to `upstream`.
    #[serde(rename = "route", default)]
    pub routes: Vec<Route>,
}

/// One path-prefix route.
///
/// Declared as `[[server.route]]` it belongs to that one domain; declared as a
/// top-level `[[route]]` it serves every domain named in `hosts` — or every
/// `[[server]]` when `hosts` is empty.
#[derive(Debug, Clone, Deserialize)]
pub struct Route {
    /// Path prefix, e.g. `/mcp` or `/assets/`.
    pub path: String,

    /// Where requests matching `path` are forwarded.
    pub upstream: String,

    /// Remove `path` from the request path before forwarding it.
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

    /// Read and parse a TOML config file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file `{}`", path.display()))?;
        let mut cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("parsing TOML in `{}`", path.display()))?;

        if cfg.is_empty() {
            anyhow::bail!(
                "no [[server]] or [[stream]] entries found in `{}`",
                path.display()
            );
        }
        for s in &cfg.servers {
            if s.domain.trim().is_empty() {
                anyhow::bail!("a [[server]] entry has an empty `domain`");
            }
            if s.upstream.trim().is_empty() {
                anyhow::bail!("`{}` has an empty `upstream`", s.domain);
            }
            validate_upstream(&s.upstream, &format!("`{}` `upstream`", s.domain))?;
            if s.pub_key.trim().is_empty() {
                anyhow::bail!("`{}` has an empty `pub_key`", s.domain);
            }
            if s.priv_key.trim().is_empty() {
                anyhow::bail!("`{}` has an empty `priv_key`", s.domain);
            }
            validate_routes(&s.routes, &format!("`{}`", s.domain))?;
        }
        validate_routes(&cfg.routes, "global")?;
        validate_global_hosts(&cfg)?;
        validate_streams(&mut cfg)?;
        Ok(cfg)
    }
}

/// Reject route tables that would be ambiguous or unusable at request time.
fn validate_routes(routes: &[Route], owner: &str) -> Result<()> {
    let mut seen = std::collections::HashSet::new();

    for r in routes {
        let path = r.path.trim();
        let where_ = format!("{owner} route `{path}`");

        if r.upstream.trim().is_empty() {
            anyhow::bail!("{where_} has an empty `upstream`");
        }
        validate_upstream(&r.upstream, &format!("{where_} `upstream`"))?;
        if !path.starts_with('/') {
            anyhow::bail!("{where_}: `path` must start with `/`");
        }
        if path.contains('?') || path.contains('#') {
            anyhow::bail!("{where_}: `path` is a path prefix, not a URI");
        }
        if r.prefix() == "/" {
            anyhow::bail!("{where_}: `/` is the catch-all, use the server's `upstream`");
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

    let http = parse_addr(&cfg.listen.http, "`[listen] http`")?;
    let https = parse_addr(&cfg.listen.https, "`[listen] https`")?;
    let http_bound = !cfg.servers.is_empty();
    let https_bound = !cfg.servers.is_empty();

    let mut seen: Vec<(std::net::SocketAddr, String)> = Vec::new();

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

        if http_bound && addrs_conflict(&listen, &http) {
            anyhow::bail!(
                "{where_}: `listen` {} clashes with `[listen] http` {}",
                s.listen.trim(),
                cfg.listen.http.trim()
            );
        }
        if https_bound && addrs_conflict(&listen, &https) {
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
        Some(_) => anyhow::bail!(
            "{what} `{raw}`: a wildcard address is written `*:port`, e.g. `*:25`"
        ),
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

        assert!(err.contains("empty `upstream`"), "unexpected error: {err}");
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

        assert!(err.contains("empty `upstream`"), "unexpected error: {err}");
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
            &format!("{MINIMAL}\n[[stream]]\nlisten = \"*:2525\"\nupstream = \"127.0.0.1:10025\"\n"),
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
}
