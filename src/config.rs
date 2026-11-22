//! uping configuration model.
//!
//! The whole config stays small. Relative paths — manual key files, static
//! roots, the certificate directory — are resolved against the directory that
//! holds `config.toml`; an absolute path is used exactly as written.
//!
//! `[listen]`, `[limits]`, `[tls]` and `[health]` are defaults for every
//! `[[server]]`. `limits` and `health` can be overridden per server:
//!
//! ```toml
//! [listen]
//! ipv4  = "0.0.0.0"                    # default
//! # ipv6 = "2001:db8::1"               # omit for no IPv6
//! http  = 80                           # default
//! https = 443                          # default
//!
//! [limits]
//! per_ip_rps           = 300           # requests/sec per client IP
//! per_ip_conns_per_sec = 100           # new TCP connections/sec per client IP
//! max_body_bytes       = 10485760      # largest request body (0 = unlimited)
//!
//! [tls]
//! fallback_cert = true                 # listener-wide, not per domain
//!
//! [health]
//! interval_ms = 5000                   # 0 disables the active probe
//! timeout_ms  = 2000
//! failures    = 2
//!
//! [acme]
//! email             = "ops@rao-nagos.pf"
//! cert_dir          = "cert"           # <config dir>/cert/<domain>/
//! renew_before_days = 30               # clamped to 1..=89
//!
//! # Optional: uping's own CA. `keys = "internal"` selects it. No ACME server,
//! # no network: uping generates the root once and issues the leaves itself,
//! # for `domain` and its subdomains only.
//! [internal]
//! domain      = "internal.rao-nagos.pf"  # the only zone this CA signs
//! ca_dir      = "cert/internal/ca"     # root.crt (public) + root.key (0600)
//! cert_dir    = "cert/internal"        # <cert_dir>/<domain>/{fullchain,privkey}.pem
//! key_type    = "ed25519"              # ed25519 | p256 | rsa2048
//! serve_root  = "https://internal.rao-nagos.pf:9000"  # serves /root.crt; empty = off
//!
//! [[server]]
//! domain   = "www.rao-nagos.pf"
//! keys     = "auto"                    # auto | internal | manual
//! upstream = "127.0.0.1:8080"          # catch-all
//! limits   = { per_ip_rps = 1220 }     # override [limits] for this domain
//! health   = { interval_ms = 10000 }   # or `health = false` to skip the 503 gate
//! # https_listen = "203.0.113.10"     # own HTTPS socket instead of the global one
//! # serve_http   = false              # no :80 at all (manual and internal keys)
//!
//! # One target per path prefix; the longest prefix wins.
//! routes = [
//!   { path = "/mcp", upstream = "127.0.0.1:8081" },
//!   { path = "/assets", root = "public/assets", strip_prefix = true },
//! ]
//!
//! [[stream]]
//! name     = "smtp"                    # log label, optional
//! listen   = "0.0.0.0:25"              # one concrete IP:port; no wildcard
//! upstream = "127.0.0.1:10025"
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

    /// Upstream liveness checks.
    #[serde(default)]
    pub health: Health,

    /// Certificate acquisition and storage (`keys = "auto"`).
    #[serde(default)]
    pub acme: Acme,

    /// uping's own certificate authority and the leaves it issues for
    /// `keys = "internal"`. No ACME server is involved.
    #[serde(default)]
    pub internal: Internal,

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
/// There is deliberately no address list: a listener is one concrete address.
/// A host that owns several addresses lists them on the `[[server]]` entries
/// that need them with `https_listen` / `https_listen6`. The HTTP listener
/// also follows an ACME server onto that address; see [`Config::http_addrs`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    #[serde(default = "default_ipv4")]
    pub ipv4: String,
    /// `None` (the field omitted) means "no IPv6 listener". An empty string is
    /// an error, not a second spelling of "off".
    #[serde(default)]
    pub ipv6: Option<String>,
    #[serde(default = "default_http")]
    pub http: u16,
    #[serde(default = "default_https")]
    pub https: u16,
}

impl Default for Listen {
    fn default() -> Self {
        Listen {
            ipv4: default_ipv4(),
            ipv6: None,
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

    /// The global IPv6 address, or `None` when `ipv6` is omitted.
    pub fn ipv6_addr(&self) -> Result<Option<Ipv6Addr>> {
        let Some(raw) = &self.ipv6 else {
            return Ok(None);
        };
        let raw = raw.trim();
        if raw.is_empty() {
            anyhow::bail!("`[listen] ipv6` is empty; omit the field entirely to disable IPv6");
        }
        raw.parse()
            .map(Some)
            .map_err(|e| anyhow::anyhow!("`[listen] ipv6` `{raw}` is not an IPv6 address: {e}"))
    }

    /// The sockets on one port: the global IPv4 address and, when configured,
    /// the global IPv6 one.
    fn addrs(&self, port: u16) -> Result<Vec<SocketAddr>> {
        let mut out = vec![SocketAddr::new(IpAddr::V4(self.ipv4_addr()?), port)];
        if let Some(v6) = self.ipv6_addr()? {
            out.push(SocketAddr::new(IpAddr::V6(v6), port));
        }
        Ok(out)
    }

    /// `http` is never per-server: port 80 is what the ACME http-01 challenge
    /// needs, so it stays in one place.
    pub fn http_addrs(&self) -> Result<Vec<SocketAddr>> {
        self.addrs(self.http)
    }

    /// The sockets of the default HTTPS group, for servers that do not
    /// override `https_listen`/`https_listen6`.
    pub fn https_addrs(&self) -> Result<Vec<SocketAddr>> {
        self.addrs(self.https)
    }
}

/// The sockets one HTTPS service listens on. Servers that do not override
/// `https_listen`/`https_listen6` share the default group; every distinct
/// override becomes
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

/// Parse one `https_listen` / `https_listen6` value.
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
                    anyhow::bail!("{what} `{raw}` is IPv6; use `https_listen6` for that address");
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
        let v4 = parse_bind(&self.https_listen, https_port, Family::V4, "`https_listen`")?;
        let v6 = parse_bind(
            &self.https_listen6,
            https_port,
            Family::V6,
            "`https_listen6`",
        )?;
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

    /// The sockets of the host-wide HTTP listener.
    ///
    /// It starts with `[listen] ipv4` / `ipv6` and adds, for every ACME server
    /// with an explicit HTTPS address, the same IP on `[listen] http`. http-01
    /// always uses the HTTP port, even when the domain's TLS listener is on a
    /// different address or port: a private proof on `10.8.0.1:443` needs
    /// `10.8.0.1:80`, not another setting. A derived socket already covered by
    /// the global listener (same address, or a wildcard) is not added twice.
    pub fn http_addrs(&self) -> Result<Vec<SocketAddr>> {
        let mut out = self.listen.http_addrs()?;
        for s in &self.servers {
            if !s.serve_http || !s.key_mode().is_acme() {
                continue;
            }
            let (v4, v6) = s.binds(self.listen.https)?;
            for addr in [v4, v6].into_iter().flatten() {
                let http = SocketAddr::new(addr.ip(), self.listen.http);
                if !out.iter().any(|existing| addrs_conflict(existing, &http)) {
                    out.push(http);
                }
            }
        }
        Ok(out)
    }
}

/// Active upstream liveness checks.
///
/// A periodic probe (TCP connect, plus a TLS handshake when the upstream speaks
/// HTTPS) marks a backend down after `failures` consecutive failures. A down
/// backend is answered with `503` immediately instead of waiting for a connect
/// timeout. `interval_ms = 0` disables the active probe; the address is still
/// resolved at startup and on reload.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    #[serde(default = "default_health_interval_ms")]
    pub interval_ms: u64,
    #[serde(default = "default_health_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_health_failures")]
    pub failures: usize,
}

impl Default for Health {
    fn default() -> Self {
        Health {
            interval_ms: default_health_interval_ms(),
            timeout_ms: default_health_timeout_ms(),
            failures: default_health_failures(),
        }
    }
}

fn default_health_interval_ms() -> u64 {
    5_000
}

fn default_health_timeout_ms() -> u64 {
    2_000
}

fn default_health_failures() -> usize {
    2
}

/// The resolved health settings of one backend: the global `[health]` table
/// with the server's and then the route's overrides applied.
#[derive(Debug, Clone, Copy)]
pub struct EffectiveHealth {
    /// Answer `503` when the backend is down. `health = false` clears it.
    pub gate: bool,
    /// `0` keeps the resolver refresh but disables the active TCP/TLS probe.
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub failures: usize,
}

impl Default for EffectiveHealth {
    fn default() -> Self {
        Health::default().effective()
    }
}

impl Health {
    pub fn effective(&self) -> EffectiveHealth {
        EffectiveHealth {
            gate: true,
            interval_ms: self.interval_ms,
            timeout_ms: self.timeout_ms,
            failures: self.failures,
        }
    }
}

/// `health = false`, `health = true`, or `health = { ... }`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum HealthOverride {
    Enabled(bool),
    Settings(HealthFields),
}

impl Default for HealthOverride {
    fn default() -> Self {
        Self::Enabled(true)
    }
}

/// A partial `[health]` table on a server or route.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthFields {
    #[serde(default)]
    pub interval_ms: Option<u64>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub failures: Option<usize>,
}

impl HealthOverride {
    /// Resolve this override against the inherited settings. A settings table
    /// re-enables the gate: writing `health = { ... }` is an opt-in.
    pub fn resolve(&self, base: EffectiveHealth) -> EffectiveHealth {
        match self {
            Self::Enabled(enabled) => EffectiveHealth {
                gate: *enabled,
                ..base
            },
            Self::Settings(fields) => EffectiveHealth {
                gate: true,
                interval_ms: fields.interval_ms.unwrap_or(base.interval_ms),
                timeout_ms: fields.timeout_ms.unwrap_or(base.timeout_ms),
                failures: fields.failures.unwrap_or(base.failures),
            },
        }
    }
}

/// The upstream-TLS knobs of one server or route, borrowed for validation.
#[derive(Debug, Clone, Copy)]
pub struct UpstreamTls<'a> {
    pub tls: bool,
    pub sni: &'a str,
    pub verify: bool,
    pub ca: &'a str,
}

impl Server {
    pub fn upstream_tls(&self) -> UpstreamTls<'_> {
        UpstreamTls {
            tls: self.upstream_tls,
            sni: &self.upstream_sni,
            verify: self.upstream_verify,
            ca: &self.upstream_ca,
        }
    }
}

impl Route {
    pub fn upstream_tls(&self) -> UpstreamTls<'_> {
        UpstreamTls {
            tls: self.upstream_tls,
            sni: &self.upstream_sni,
            verify: self.upstream_verify,
            ca: &self.upstream_ca,
        }
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

/// The per-server form, `limits = { per_ip_rps = 1220 }`. Every field is
/// optional: omitted ones keep the `[limits]` value. `per_ip_conns_per_sec` is
/// accepted only to explain why it cannot work here — it is enforced at TCP
/// accept time, before the `Host` header exists.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsOverride {
    #[serde(default)]
    pub per_ip_rps: Option<usize>,
    #[serde(default)]
    pub per_ip_conns_per_sec: Option<usize>,
    #[serde(default)]
    pub max_body_bytes: Option<usize>,
}

impl Limits {
    /// Apply a `[[server]] limits = { ... }` table on top of the global values.
    pub fn merged(&self, over: Option<&LimitsOverride>) -> Limits {
        let Some(over) = over else {
            return self.clone();
        };
        Limits {
            per_ip_rps: over.per_ip_rps.unwrap_or(self.per_ip_rps),
            per_ip_conns_per_sec: over
                .per_ip_conns_per_sec
                .unwrap_or(self.per_ip_conns_per_sec),
            max_body_bytes: over.max_body_bytes.unwrap_or(self.max_body_bytes),
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
    /// Request and renew through the default ACME directory (Let's Encrypt, or
    /// `[acme] directory`). This is the default when no key paths are given.
    Auto,
    /// Issued by uping's own CA (`[internal]`): generated locally on first
    /// start, renewed locally, no ACME server and no network. Clients trust the
    /// root once. This used to mean "a private ACME CA"; that profile was
    /// removed in v0.4.0.
    Internal,
    /// Read the two PEM files named by `pub_key` and `priv_key`; renew them
    /// yourself (certbot, an ACME client, a paid CA, …).
    Manual,
}

impl KeyMode {
    /// True for the modes that talk ACME and therefore may need a certificate
    /// requested at startup.
    pub fn is_acme(self) -> bool {
        matches!(self, Self::Auto)
    }

    /// True for the mode whose leaves uping issues and renews itself.
    pub fn is_local_ca(self) -> bool {
        matches!(self, Self::Internal)
    }
}

/// Let's Encrypt / ACME settings.
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
    /// signed by a public CA — a private ACME server (Pebble, an internal CA).
    /// Empty means the system trust store.
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

/// Which key algorithm the local CA uses for the root and the leaves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKind {
    /// Ed25519: small, fast, no parameters, and every current TLS stack
    /// supports it. The default.
    #[default]
    Ed25519,
    /// ECDSA P-256: wider legacy support than Ed25519 on old stacks.
    P256,
    /// RSA-2048: only for clients that cannot do either of the above.
    Rsa2048,
}

/// uping's own certificate authority (`keys = "internal"`).
///
/// Unlike `[acme]`, nothing here leaves the host: the root is generated once
/// and the leaves are signed locally. Clients trust the root once — the same
/// install step a private ACME CA required, without the extra daemon.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Internal {
    /// The zone this CA signs: `internal.rao-nagos.pf` signs that name and any
    /// subdomain of it (`dsh.internal.rao-nagos.pf`), and nothing else. Empty
    /// until a `keys = "internal"` server actually needs it.
    #[serde(default)]
    pub domain: String,

    /// Where the root lives: `root.crt` (public, 0644) and `root.key` (0600).
    /// Created on first start; an existing pair is reused, never regenerated.
    #[serde(default = "default_internal_ca_dir")]
    pub ca_dir: String,

    /// Where the leaves live, one subdirectory per domain:
    /// `<cert_dir>/<domain>/{fullchain,privkey}.pem`.
    #[serde(default = "default_internal_cert_dir")]
    pub cert_dir: String,

    /// Subject CN of the root certificate. Informational; it is not a hostname.
    #[serde(default = "default_internal_common_name")]
    pub common_name: String,

    /// Subject O of the root certificate.
    #[serde(default = "default_internal_organization")]
    pub organization: String,

    /// Root lifetime in days.
    #[serde(default = "default_internal_ca_days")]
    pub ca_days: u64,

    /// Leaf lifetime in days. 397 is the Apple/Safari ceiling.
    #[serde(default = "default_internal_leaf_days")]
    pub leaf_days: u64,

    /// Renew a leaf with fewer than this many days left.
    #[serde(default = "default_internal_renew_before_days")]
    pub renew_before_days: u64,

    /// Key algorithm for the root and every leaf.
    #[serde(default)]
    pub key_type: KeyKind,

    /// HTTPS URL that publishes `root.crt`, e.g.
    /// `"https://internal.rao-nagos.pf:9000"`. The host must live inside
    /// `domain`; it gets a leaf from this CA, so a client fetches
    /// `<serve_root>/root.crt` (with `curl -k` the first time, since the root it
    /// downloads is what makes that name trusted). Empty means off. Binding is
    /// best-effort: a host that does not resolve yet is logged and skipped.
    #[serde(default)]
    pub serve_root: String,
}

impl Default for Internal {
    fn default() -> Self {
        Internal {
            domain: String::new(),
            ca_dir: default_internal_ca_dir(),
            cert_dir: default_internal_cert_dir(),
            common_name: default_internal_common_name(),
            organization: default_internal_organization(),
            ca_days: default_internal_ca_days(),
            leaf_days: default_internal_leaf_days(),
            renew_before_days: default_internal_renew_before_days(),
            key_type: KeyKind::default(),
            serve_root: String::new(),
        }
    }
}

fn default_internal_ca_dir() -> String {
    "cert/internal/ca".to_string()
}

fn default_internal_cert_dir() -> String {
    "cert/internal".to_string()
}

fn default_internal_common_name() -> String {
    "uping local CA".to_string()
}

fn default_internal_organization() -> String {
    "uping".to_string()
}

fn default_internal_ca_days() -> u64 {
    3650
}

fn default_internal_leaf_days() -> u64 {
    397
}

fn default_internal_renew_before_days() -> u64 {
    30
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

/// The directory, trust root and contact an ACME order uses. Built once per
/// certificate request, so a process can serve public and internal names.
#[derive(Debug, Clone)]
pub struct AcmeProfile {
    pub directory: String,
    pub ca_bundle: String,
}

impl Acme {
    /// The directory URL of the default (public) profile.
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

    /// The ACME profile a server's key mode selects.
    pub fn profile(&self, mode: KeyMode) -> Result<AcmeProfile> {
        match mode {
            KeyMode::Auto => Ok(AcmeProfile {
                directory: self.directory_url().to_string(),
                ca_bundle: self.ca_bundle.clone(),
            }),
            KeyMode::Internal => anyhow::bail!(
                "`keys = \"internal\"` selects uping's own CA in `[internal]`, not an \
                 ACME directory"
            ),
            KeyMode::Manual => anyhow::bail!("`manual` mode has no ACME directory"),
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
    /// The public domain name, e.g. `www.rao-nagos.pf`. Matched
    /// case-insensitively against the TLS SNI name and the HTTP `Host` header.
    #[serde(default)]
    pub domain: String,

    /// Optional IPv4 HTTPS listener for this server: an address, or
    /// `address:port` to override the global `https` port too. Overrides the
    /// global `[listen] ipv4` for this domain; `https_listen6` works the same
    /// for IPv6. When either is set, the server is served only on its own
    /// sockets.
    #[serde(default)]
    pub https_listen: String,

    /// Optional IPv6 HTTPS listener, e.g. `"2001:db8::1"` or
    /// `"[2001:db8::1]:8443"`. See `https_listen`.
    #[serde(default)]
    pub https_listen6: String,

    /// Answer plain HTTP for this domain (the redirect and the ACME http-01
    /// challenge). Default `true`. `false` means the domain exists only behind
    /// HTTPS: a request for it on port 80 gets `404`, and any ACME mode is
    /// refused because http-01 needs that listener.
    ///
    /// Named `serve_http`, not `http`: `[listen] http` is a port, and one word
    /// must not mean two types in two tables.
    #[serde(default = "default_true")]
    pub serve_http: bool,

    /// `false` opts this backend out of the `503` gate; a table overrides
    /// `[health] interval_ms`/`timeout_ms`/`failures` for this domain:
    ///
    /// ```toml
    /// health = false
    /// health = { interval_ms = 10000, failures = 3 }
    /// ```
    #[serde(default)]
    pub health: HealthOverride,

    /// Per-domain `[limits]` override. `per_ip_conns_per_sec` is refused here:
    /// it runs at TCP accept, before the `Host` header is known.
    #[serde(default)]
    pub limits: Option<LimitsOverride>,

    /// `auto` (default ACME), `internal` (uping's own CA, `[internal]`) or
    /// `manual` (read `pub_key`/`priv_key`). When omitted, naming both key
    /// paths selects `manual`; naming neither selects `auto`.
    #[serde(default)]
    pub keys: Option<KeyMode>,

    /// Path to the PEM certificate (leaf first, then any intermediates /
    /// fullchain). Required in `manual` mode; in `auto` mode it optionally
    /// overrides where the generated certificate is written. Refused in
    /// `internal` mode, which stores its own pair.
    #[serde(default)]
    pub pub_key: String,

    /// Path to the PEM private key. Same rules as `pub_key`.
    #[serde(default)]
    pub priv_key: String,

    /// Extra names that go into the leaf's SAN list, in addition to `domain`.
    /// Only meaningful with `keys = "internal"`; a wildcard is refused because
    /// SNI resolution is an exact match. Example:
    /// `alt_names = ["www.rao-nagos.pf"]`.
    #[serde(default)]
    pub alt_names: Vec<String>,

    /// Where to forward traffic, e.g. `127.0.0.1:8080` or `localhost:3000`.
    /// Exactly one of `upstream` and `root` must be set.
    #[serde(default)]
    pub upstream: String,

    /// Speak HTTPS to the upstream instead of plain HTTP.
    #[serde(default)]
    pub upstream_tls: bool,

    /// SNI (and hostname to verify) for the upstream TLS handshake. Empty means
    /// the upstream host when it is a DNS name, or this server's `domain` when
    /// the upstream is an IP literal.
    #[serde(default)]
    pub upstream_sni: String,

    /// Verify the upstream certificate. `false` accepts any certificate; pair it
    /// with a private network, never with the public internet.
    #[serde(default = "default_true")]
    pub upstream_verify: bool,

    /// PEM bundle of roots for the upstream certificate. Empty uses the system
    /// roots. Only meaningful with `upstream_tls`.
    #[serde(default)]
    pub upstream_ca: String,

    /// Serve static files from this directory when no route matches, instead
    /// of proxying. Relative to the config file. Exactly one of `upstream` and
    /// `root` must be set.
    #[serde(default)]
    pub root: String,

    /// File served for a directory request. Default `index.html`.
    #[serde(default = "default_index")]
    pub index: String,

    /// Optional path routes. The longest matching `path` wins; everything else
    /// falls through to this server's `upstream`/`root`. Always an inline
    /// array: `routes = [{ path = "/mcp", upstream = "..." }]`.
    #[serde(rename = "routes", default)]
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

/// One path-prefix route of one server (`routes = [...]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Path prefix, e.g. `/mcp` or `/assets/`.
    pub path: String,

    /// Where requests matching `path` are forwarded. Exactly one of `upstream`
    /// and `root` must be set.
    #[serde(default)]
    pub upstream: String,

    /// Probe this route's backend and fail fast with `503` when it is down.
    /// Inherits the server's effective `[health]` settings; see `health`.
    #[serde(default)]
    pub health: HealthOverride,

    /// Speak HTTPS to this route's upstream. See the server-level fields.
    #[serde(default)]
    pub upstream_tls: bool,
    #[serde(default)]
    pub upstream_sni: String,
    #[serde(default = "default_true")]
    pub upstream_verify: bool,
    #[serde(default)]
    pub upstream_ca: String,

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

    /// Where `keys = "internal"` writes leaves.
    pub fn internal_cert_dir(&self) -> PathBuf {
        self.resolve(&self.internal.cert_dir)
    }

    /// The local CA's `(root.crt, root.key)`.
    pub fn ca_paths(&self) -> (PathBuf, PathBuf) {
        let dir = self.resolve(&self.internal.ca_dir);
        (dir.join("root.crt"), dir.join("root.key"))
    }

    /// The effective `[health]` defaults for one server.
    pub fn health_for(&self, server: &Server) -> EffectiveHealth {
        server.health.resolve(self.health.effective())
    }

    /// The effective `[limits]` for one server.
    pub fn limits_for(&self, server: &Server) -> Limits {
        self.limits.merged(server.limits.as_ref())
    }

    /// The certificate and key paths for one server. In `auto`/`internal` mode
    /// they are either the optional `pub_key`/`priv_key` overrides or
    /// `<cert_dir>/<domain>/{fullchain,privkey}.pem`; `internal` uses
    /// `[internal] cert_dir`, the ACME modes use `[acme] cert_dir`.
    pub fn key_paths(&self, server: &Server) -> (PathBuf, PathBuf) {
        if !server.pub_key.trim().is_empty() {
            (
                self.resolve(&server.pub_key),
                self.resolve(&server.priv_key),
            )
        } else if server.key_mode().is_local_ca() {
            let dir = self
                .internal_cert_dir()
                .join(server.domain.trim().to_ascii_lowercase());
            (dir.join("fullchain.pem"), dir.join("privkey.pem"))
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
        let value: toml::Value = toml::from_str(&raw)
            .with_context(|| format!("parsing TOML in `{}`", path.display()))?;
        if matches!(value.get("server"), Some(toml::Value::Table(_))) {
            anyhow::bail!(
                "the `[server.\"domain\"]` map form was removed; use `[[server]]` with \
                 `domain = \"...\"` instead"
            );
        }
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
        let health_defaults = cfg.health.effective();
        validate_health(&health_defaults, "`[health]`")?;
        let mut seen = std::collections::HashSet::new();
        for s in &mut cfg.servers {
            // The same trimmed value must be what routing stores, not just
            // what validation looks at.
            s.domain = s.domain.trim().trim_end_matches('.').to_string();
            s.index = s.index.trim().to_string();
            s.https_listen = s.https_listen.trim().to_string();
            s.https_listen6 = s.https_listen6.trim().to_string();
            for name in &mut s.alt_names {
                *name = name.trim().trim_end_matches('.').to_string();
            }
            for r in &mut s.routes {
                r.path = r.path.trim().to_string();
                r.index = r.index.trim().to_string();
            }
            let health = s.health.resolve(health_defaults);
            validate_health(&health, &format!("`{}`", s.domain))?;
            validate_server(s, &cfg.root_dir, cfg.listen.https, &cfg.acme, health)?;
            if !seen.insert(s.domain.to_ascii_lowercase()) {
                anyhow::bail!("two [[server]] entries share the domain `{}`", s.domain);
            }
        }
        cfg.acme.renew_before_days = cfg.acme.renew_before_days.clamp(1, 89);
        validate_acme(&cfg.acme, &cfg.root_dir)?;
        validate_internal(&mut cfg.internal, &cfg.root_dir)?;
        validate_internal_zone(&cfg)?;
        validate_streams(&mut cfg)?;
        validate_listeners(&cfg)?;
        Ok(cfg)
    }
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
fn validate_server(
    s: &Server,
    root_dir: &Path,
    https_port: u16,
    acme: &Acme,
    health: EffectiveHealth,
) -> Result<()> {
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

    validate_target(
        &s.upstream,
        &s.root,
        root_dir,
        &format!("`{domain}`"),
        s.upstream_tls(),
    )?;
    validate_index(&s.index, &format!("`{domain}`"))?;
    s.binds(https_port)
        .with_context(|| format!("`{domain}` listener override"))?;

    if s.limits
        .as_ref()
        .and_then(|l| l.per_ip_conns_per_sec)
        .is_some()
    {
        anyhow::bail!(
            "`{domain}`: `limits.per_ip_conns_per_sec` is host-wide — it runs at TCP \
             accept, before the Host header is known; set it in `[limits]`"
        );
    }

    let mode = s.key_mode();
    let pub_set = !s.pub_key.trim().is_empty();
    let priv_set = !s.priv_key.trim().is_empty();
    match mode {
        KeyMode::Manual if !pub_set => anyhow::bail!("`{domain}` has an empty `pub_key`"),
        KeyMode::Manual if !priv_set => anyhow::bail!("`{domain}` has an empty `priv_key`"),
        KeyMode::Internal if pub_set || priv_set => anyhow::bail!(
            "`{domain}`: `keys = \"internal\"` issues and stores its own certificate; \
             remove `pub_key`/`priv_key`"
        ),
        KeyMode::Auto if pub_set != priv_set => anyhow::bail!(
            "`{domain}`: give both `pub_key` and `priv_key` to override the certificate paths, or neither"
        ),
        _ => {}
    }
    if mode.is_acme() {
        acme.profile(mode)
            .with_context(|| format!("`{domain}` certificate mode"))?;
    }
    validate_alt_names(s, mode)?;

    if !s.serve_http && mode.is_acme() {
        anyhow::bail!(
            "`{domain}` sets `serve_http = false` but uses an ACME key mode: the ACME \
             http-01 challenge needs the HTTP listener. Use `keys = \"internal\"` for \
             a local certificate, or `keys = \"manual\"` with an external one."
        );
    }

    validate_routes(&s.routes, &format!("`{domain}`"), root_dir, health)?;
    Ok(())
}

/// `alt_names` are extra SANs for a locally issued leaf. They only make sense
/// with `keys = "internal"`, and they must be exact hostnames: SNI resolution
/// is an exact match, so a wildcard SAN could never be selected.
fn validate_alt_names(s: &Server, mode: KeyMode) -> Result<()> {
    if s.alt_names.is_empty() {
        return Ok(());
    }
    if !mode.is_local_ca() {
        anyhow::bail!(
            "`{}`: `alt_names` only applies to `keys = \"internal\"`; the other modes \
             name their certificate themselves",
            s.domain.trim()
        );
    }
    let domain = s.domain.trim().to_ascii_lowercase();
    let mut seen = std::collections::HashSet::new();
    for raw in &s.alt_names {
        let name = raw.trim().trim_end_matches('.');
        if name.is_empty() {
            anyhow::bail!("`{}` has an empty `alt_names` entry", s.domain.trim());
        }
        if name.contains('/')
            || name.contains(':')
            || name.contains(char::is_whitespace)
            || name.contains('*')
        {
            anyhow::bail!(
                "`{}`: `alt_names` entry `{name}` is not a hostname: no scheme, path, \
                 port or wildcard",
                s.domain.trim()
            );
        }
        let name = name.to_ascii_lowercase();
        if name == domain {
            continue;
        }
        if !seen.insert(name.clone()) {
            anyhow::bail!("`{}` repeats the SAN `{name}`", s.domain.trim());
        }
    }
    Ok(())
}

/// The local CA settings must produce an oath of trust that lasts: a leaf
/// cannot outlive the root that signs it, and renewal has to happen before
/// expiry.
/// The parsed `[internal] serve_root` URL: the name to serve and the port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeRoot {
    pub host: String,
    pub port: u16,
}

impl ServeRoot {
    /// `https://host:port` as written in the config, without a trailing slash.
    pub fn url(&self) -> String {
        format!("https://{}:{}", self.host, self.port)
    }
}

/// `serve_root` is an HTTPS URL, not an address: the endpoint is a name inside
/// the internal zone, so it gets a certificate from the same CA whose root it
/// publishes. `https` is required — publishing a trust anchor in clear text
/// would hand it to anyone on the path. The port defaults to 9000.
pub fn parse_serve_root(raw: &str) -> Result<ServeRoot> {
    let raw = raw.trim();
    if raw.is_empty() {
        anyhow::bail!("`[internal] serve_root` is empty");
    }
    let rest = raw.strip_prefix("https://").with_context(|| {
        format!(
            "`[internal] serve_root` `{raw}` must be an https:// URL, e.g. \
                 `https://internal.rao-nagos.pf:9000` (the root it publishes is \
                 what makes that name trusted, so a first `curl -k` is expected)"
        )
    })?;
    let rest = rest.trim_end_matches('/');
    if rest.is_empty() || rest.contains('/') {
        anyhow::bail!(
            "`[internal] serve_root` `{raw}` must name only a host and a port; \
             uping serves `/root.crt` itself"
        );
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (host, port),
        None => (rest, "9000"),
    };
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty()
        || host.contains('*')
        || host.contains('[')
        || host.contains(']')
        || host.contains(char::is_whitespace)
    {
        anyhow::bail!("`[internal] serve_root` host `{host}` is not a hostname");
    }
    let port: u16 = port
        .trim()
        .parse()
        .with_context(|| format!("`[internal] serve_root` port `{port}` is not a number"))?;
    if port == 0 {
        anyhow::bail!(
            "`[internal] serve_root` port 0 binds an ephemeral port, never the one you meant"
        );
    }
    Ok(ServeRoot { host, port })
}

/// Is `name` the zone itself or a subdomain of it? Case-insensitive; a trailing
/// dot is the root label and ignored.
pub fn in_zone(name: &str, zone: &str) -> bool {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let zone = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    name == zone || (!zone.is_empty() && name.ends_with(&format!(".{zone}")))
}

fn validate_internal(internal: &mut Internal, root_dir: &Path) -> Result<()> {
    if internal.ca_dir.trim().is_empty() {
        anyhow::bail!("`[internal] ca_dir` is empty; give a directory or omit the field");
    }
    if internal.cert_dir.trim().is_empty() {
        anyhow::bail!("`[internal] cert_dir` is empty; give a directory or omit the field");
    }
    if internal.common_name.trim().is_empty() {
        anyhow::bail!("`[internal] common_name` is empty; give a name or omit the field");
    }
    internal.domain = internal
        .domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if !internal.domain.is_empty()
        && (internal.domain.contains('/')
            || internal.domain.contains(':')
            || internal.domain.contains(char::is_whitespace)
            || internal.domain.contains('*'))
    {
        anyhow::bail!(
            "`[internal] domain` `{}` is not a hostname: no scheme, path, port or wildcard",
            internal.domain
        );
    }
    if !internal.serve_root.trim().is_empty() {
        parse_serve_root(&internal.serve_root)?;
    }

    internal.leaf_days = internal.leaf_days.clamp(1, 825);
    internal.ca_days = internal.ca_days.clamp(internal.leaf_days, 7300);
    internal.renew_before_days = internal
        .renew_before_days
        .clamp(1, internal.leaf_days.saturating_sub(1).max(1));

    // Touch the resolved paths here so a relative `ca_dir` is reported against
    // the directory that will actually hold it, not against the current one.
    let (root_cert, root_key) = (
        resolve_path(root_dir, &internal.ca_dir).join("root.crt"),
        resolve_path(root_dir, &internal.ca_dir).join("root.key"),
    );
    if root_cert == root_key {
        anyhow::bail!("`[internal] ca_dir` resolves to the same file for cert and key");
    }
    Ok(())
}

/// The local CA signs one zone: every `keys = "internal"` name (and every SAN)
/// must be that zone or a subdomain of it. Enforced here as well as at
/// issuance, so a typo is a config error instead of a harness the clients
/// refuse.
fn validate_internal_zone(cfg: &Config) -> Result<()> {
    let zone = cfg.internal.domain.trim().to_ascii_lowercase();
    for s in &cfg.servers {
        if !s.key_mode().is_local_ca() {
            continue;
        }
        if zone.is_empty() {
            anyhow::bail!(
                "`{}` uses `keys = \"internal\"` but `[internal] domain` is empty; \
                 set the zone this CA signs, e.g. domain = \"internal.rao-nagos.pf\"",
                s.domain
            );
        }
        if !in_zone(&s.domain, &zone) {
            anyhow::bail!(
                "`{}` is outside `[internal] domain` `{zone}`: the local CA signs \
                 only `{zone}` and its subdomains",
                s.domain
            );
        }
        for alt in &s.alt_names {
            if !in_zone(alt, &zone) {
                anyhow::bail!(
                    "`{}`: `alt_names` entry `{alt}` is outside `[internal] domain` \
                     `{zone}`",
                    s.domain
                );
            }
        }
    }
    if !cfg.internal.serve_root.trim().is_empty() {
        if zone.is_empty() {
            anyhow::bail!("`[internal] serve_root` needs `[internal] domain`: it serves a name inside the zone");
        }
        let root = parse_serve_root(&cfg.internal.serve_root)?;
        if !in_zone(&root.host, &zone) {
            anyhow::bail!(
                "`[internal] serve_root` host `{}` is outside `[internal] domain` `{zone}`",
                root.host
            );
        }
    }
    Ok(())
}

/// Exactly one of `upstream` and `root`, and it has to be usable now.
fn validate_target(
    upstream: &str,
    root: &str,
    root_dir: &Path,
    owner: &str,
    tls: UpstreamTls<'_>,
) -> Result<()> {
    let has_upstream = !upstream.trim().is_empty();
    let has_root = !root.trim().is_empty();

    match (has_upstream, has_root) {
        (false, false) => anyhow::bail!("{owner} needs an `upstream` or a `root`"),
        (true, true) => {
            anyhow::bail!("{owner} has both `upstream` and `root`; a request has one destination")
        }
        (true, false) => {
            validate_upstream(upstream, &format!("{owner} `upstream`"))?;
            validate_upstream_tls(tls, owner, root_dir)
        }
        (false, true) => {
            if tls.tls || !tls.sni.trim().is_empty() || !tls.ca.trim().is_empty() || !tls.verify {
                anyhow::bail!("{owner}: `upstream_tls`/`upstream_sni`/`upstream_ca` need an `upstream`, not a `root`");
            }
            validate_static_root(root, root_dir, &format!("{owner} `root`"))
        }
    }
}

/// Validate the optional TLS-to-the-backend settings.
///
/// The PEM bundle is parsed here, so `uping --check` catches a broken CA before
/// the first request. The parsed copy used for connections is built later, in
/// the route table.
fn validate_upstream_tls(tls: UpstreamTls<'_>, owner: &str, root_dir: &Path) -> Result<()> {
    let sni = tls.sni.trim();
    if !sni.is_empty() {
        if !tls.tls {
            anyhow::bail!("{owner}: `upstream_sni` only applies with `upstream_tls = true`");
        }
        if sni.contains('/') || sni.contains(':') || sni.contains(char::is_whitespace) {
            anyhow::bail!("{owner}: `upstream_sni = \"{sni}\"` is not a hostname");
        }
    }
    if !tls.tls {
        if !tls.ca.trim().is_empty() {
            anyhow::bail!("{owner}: `upstream_ca` only applies with `upstream_tls = true`");
        }
        if !tls.verify {
            anyhow::bail!(
                "{owner}: `upstream_verify = false` only applies with `upstream_tls = true`"
            );
        }
        return Ok(());
    }
    if !tls.ca.trim().is_empty() {
        let path = resolve_path(root_dir, tls.ca);
        let pem = std::fs::read(&path)
            .with_context(|| format!("{owner}: reading `upstream_ca` `{}`", path.display()))?;
        let certs = openssl::x509::X509::stack_from_pem(&pem)
            .with_context(|| format!("{owner}: parsing `upstream_ca` `{}`", path.display()))?;
        if certs.is_empty() {
            anyhow::bail!(
                "{owner}: `upstream_ca` `{}` holds no certificate",
                path.display()
            );
        }
    }
    Ok(())
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
    validate_acme_ca(
        acme.directory.trim(),
        acme.ca_bundle.trim(),
        acme.email.trim(),
        "`[acme]`",
        root_dir,
    )?;
    Ok(())
}

/// One ACME directory/bundle/contact triple. `directory` may be empty only for
/// the default profile, where it means "Let's Encrypt".
fn validate_acme_ca(
    directory: &str,
    bundle: &str,
    email: &str,
    owner: &str,
    root_dir: &Path,
) -> Result<()> {
    if !directory.is_empty()
        && !(directory.starts_with("https://") || directory.starts_with("http://"))
    {
        anyhow::bail!("{owner} `directory = \"{directory}\"` must be an http(s) URL");
    }
    if !bundle.is_empty() {
        let path = resolve_path(root_dir, bundle);
        if !path.is_file() {
            anyhow::bail!(
                "{owner} `ca_bundle = \"{bundle}\"` is not a readable PEM file (`{}`)",
                path.display()
            );
        }
    }
    if !email.is_empty() && !email.contains('@') {
        anyhow::bail!("{owner} `email = \"{email}\"` does not look like an address");
    }
    Ok(())
}

/// The `[health]` ranges are checked on the *effective* values, so a bad
/// per-server override is reported with its domain and never silently clamped.
fn validate_health(health: &EffectiveHealth, owner: &str) -> Result<()> {
    if health.interval_ms != 0 && !(100..=3_600_000).contains(&health.interval_ms) {
        anyhow::bail!(
            "{owner}: `health.interval_ms = {}` is out of range: use 0 to disable the \
             probe, or a value between 100 and 3600000",
            health.interval_ms
        );
    }
    if !(50..=30_000).contains(&health.timeout_ms) {
        anyhow::bail!(
            "{owner}: `health.timeout_ms = {}` is out of range: use 50..=30000",
            health.timeout_ms
        );
    }
    if !(1..=100).contains(&health.failures) {
        anyhow::bail!(
            "{owner}: `health.failures = {}` is out of range: use 1..=100 \
             (a backend must fail at least once to be marked down)",
            health.failures
        );
    }
    Ok(())
}

/// Reject route tables that would be ambiguous or unusable at request time.
fn validate_routes(
    routes: &[Route],
    owner: &str,
    root_dir: &Path,
    server_health: EffectiveHealth,
) -> Result<()> {
    let mut seen = std::collections::HashSet::new();

    for r in routes {
        let path = r.path.trim();
        let where_ = format!("{owner} route `{path}`");

        validate_target(&r.upstream, &r.root, root_dir, &where_, r.upstream_tls())?;
        validate_index(&r.index, &where_)?;
        validate_health(&r.health.resolve(server_health), &where_)?;
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
    let http = cfg.http_addrs()?;
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
    let http = cfg.http_addrs()?;
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
    // `[internal] serve_root` names a host, not a socket: it binds the
    // address that host resolves to, so a clash with a literal listener is
    // only knowable at startup. A failed bind is a warning there.
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
/// the same socket.
///
/// Within one family that means the same address, or one side unspecified
/// (`0.0.0.0` / `::`). Across families only the IPv6 wildcard is a conflict:
/// Linux binds `[::]` dual-stack, so it already owns every IPv4 address on that
/// port. `0.0.0.0` and a concrete IPv6 address are two independent sockets and
/// are left alone.
fn addrs_conflict(a: &std::net::SocketAddr, b: &std::net::SocketAddr) -> bool {
    if a.port() != b.port() {
        return false;
    }
    match (a.ip(), b.ip()) {
        (std::net::IpAddr::V4(x), std::net::IpAddr::V4(y)) => {
            x == y || x.is_unspecified() || y.is_unspecified()
        }
        (std::net::IpAddr::V6(x), std::net::IpAddr::V6(y)) => {
            x == y || x.is_unspecified() || y.is_unspecified()
        }
        (std::net::IpAddr::V4(_), std::net::IpAddr::V6(v6))
        | (std::net::IpAddr::V6(v6), std::net::IpAddr::V4(_)) => v6.is_unspecified(),
    }
}

/// A minimal config for unit tests: real defaults, empty tables, no servers.
#[cfg(test)]
impl Config {
    pub fn default_for_tests(root_dir: std::path::PathBuf) -> Self {
        Config {
            root_dir,
            listen: Listen::default(),
            limits: Limits::default(),
            tls: Tls::default(),
            health: Health::default(),
            acme: Acme::default(),
            internal: Internal::default(),
            servers: Vec::new(),
            streams: Vec::new(),
        }
    }
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
        assert!(cfg.listen.ipv6.is_none());
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

    fn with_routes(entries: &str) -> String {
        format!("{MINIMAL}routes = [{entries}]\n")
    }

    const WITH_ROUTES: &str = r#"
[[server]]
domain   = "aaa.local"
pub_key  = "certs/test.local.crt"
priv_key = "certs/test.local.key"
upstream = "127.0.0.1:8080"
routes = [
  { path = "/mcp", upstream = "127.0.0.1:8081" },
  { path = "/assets/", upstream = "127.0.0.1:8085", strip_prefix = true },
]
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
    fn the_removed_route_table_form_is_refused() {
        let path = write_temp(
            "route-table.toml",
            &format!(
                "{MINIMAL}\n[[server.route]]\npath = \"/mcp\"\nupstream = \"127.0.0.1:8081\"\n"
            ),
        );
        let err = format!("{:#}", Config::load(&path).unwrap_err());
        assert!(
            err.contains("unknown field `route`"),
            "unexpected error: {err}"
        );
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
            &with_routes(r#"{ path = "mcp", upstream = "127.0.0.1:8081" }"#),
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
            &with_routes(r#"{ path = "/", upstream = "127.0.0.1:8081" }"#),
        );
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(err.contains("the catch-all"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_two_routes_for_the_same_prefix() {
        let path = write_temp(
            "route-dup.toml",
            &with_routes(
                r#"{ path = "/assets", upstream = "127.0.0.1:8085" },
  { path = "/assets/", upstream = "127.0.0.1:8086" }"#,
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
            &with_routes(r#"{ path = "/mcp", upstream = "  " }"#),
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
            &with_routes(r#"{ path = "/mcp?x=1", upstream = "127.0.0.1:8081" }"#),
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
    fn the_map_server_form_is_refused() {
        let path = write_temp(
            "server-map.toml",
            r#"
[server."www.rao-nagos.pf"]
upstream = "127.0.0.1:8080"
"#,
        );
        let err = format!("{:#}", Config::load(&path).unwrap_err());
        assert!(
            err.contains("map form was removed"),
            "unexpected error: {err}"
        );
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
    fn a_server_https_listen_override_forms_its_own_group() {
        let path = write_temp(
            "server-listen.toml",
            &format!(
                "[listen]\nipv4 = \"10.0.0.1\"\nhttps = 8443\n{MINIMAL}\n\
                 [[server]]\ndomain = \"private.local\"\n\
                 pub_key = \"certs/p.crt\"\npriv_key = \"certs/p.key\"\n\
                 upstream = \"127.0.0.1:9000\"\n\
                 https_listen = \"74.56.12.45\"\nhttps_listen6 = \"[2001:db8::1]:9443\"\n"
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
    fn an_https_listen_override_must_not_rebind_the_global_socket() {
        let path = write_temp(
            "server-listen-clash.toml",
            &format!(
                "{MINIMAL}\n[[server]]\ndomain = \"private.local\"\n\
                 pub_key = \"certs/p.crt\"\npriv_key = \"certs/p.key\"\n\
                 upstream = \"127.0.0.1:9000\"\nhttps_listen = \"127.0.0.1:443\"\n"
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
    fn an_https_listen6_port_needs_brackets() {
        let path = write_temp(
            "listen6-unbracketed.toml",
            r#"
[[server]]
domain = "v6.example"
upstream = "127.0.0.1:8080"
https_listen6 = "[2001:db8::1]:9443"
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
https_listen6 = "2001:db8::1:9443"
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

    #[test]
    fn health_defaults_and_rejects_out_of_range_values() {
        let path = write_temp("health-default.toml", MINIMAL);
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.health.interval_ms, 5_000);
        assert_eq!(cfg.health.timeout_ms, 2_000);
        assert_eq!(cfg.health.failures, 2);
        let _ = std::fs::remove_file(path);

        // 0 is the only way to disable the probe; it is not a default.
        let path = write_temp(
            "health-off.toml",
            &format!("[health]\ninterval_ms = 0\n{MINIMAL}"),
        );
        assert_eq!(Config::load(&path).unwrap().health.interval_ms, 0);
        let _ = std::fs::remove_file(path);

        for (name, body, needle) in [
            (
                "health-interval.toml",
                "[health]\ninterval_ms = 10\n",
                "0 to disable",
            ),
            (
                "health-timeout.toml",
                "[health]\ntimeout_ms = 0\n",
                "timeout_ms",
            ),
            (
                "health-failures.toml",
                "[health]\nfailures = 0\n",
                "failures",
            ),
        ] {
            let path = write_temp(name, &format!("{body}{MINIMAL}"));
            let err = Config::load(&path).unwrap_err().to_string();
            assert!(err.contains(needle), "{name}: unexpected error: {err}");
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn upstream_tls_only_makes_sense_with_an_upstream() {
        let path = write_temp(
            "tls-static.toml",
            "[[server]]\ndomain = \"s.local\"\nroot = \"public\"\nupstream_tls = true\n",
        );
        assert!(
            Config::load(&path).is_err(),
            "upstream_tls on a static root"
        );
        let _ = std::fs::remove_file(path);

        let path = write_temp(
            "verify-no-tls.toml",
            "[[server]]\ndomain = \"s.local\"\nupstream = \"127.0.0.1:8080\"\nupstream_verify = false\n",
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("only applies with `upstream_tls = true`"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn serve_http_false_needs_a_manual_certificate() {
        let path = write_temp(
            "http-off-auto.toml",
            "[[server]]\ndomain = \"private.local\"\nupstream = \"127.0.0.1:8080\"\nserve_http = false\n",
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("http-01 challenge needs the HTTP listener"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);

        let path = write_temp(
            "http-off-manual.toml",
            "[[server]]\ndomain = \"private.local\"\nkeys = \"manual\"\n\
             pub_key = \"p.crt\"\npriv_key = \"p.key\"\nupstream = \"127.0.0.1:8080\"\nserve_http = false\n",
        );
        let cfg = Config::load(&path).unwrap();
        assert!(!cfg.servers[0].serve_http);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_missing_upstream_ca_is_refused() {
        let path = write_temp(
            "tls-ca-missing.toml",
            "[[server]]\ndomain = \"s.local\"\nupstream = \"127.0.0.1:8443\"\n\
             upstream_tls = true\nupstream_ca = \"does-not-exist.pem\"\n",
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("reading `upstream_ca`"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_route_inherits_nothing_but_carries_its_own_upstream_tls() {
        let path = write_temp(
            "route-tls.toml",
            "[[server]]\ndomain = \"s.local\"\nupstream = \"127.0.0.1:8080\"\n\
             routes = [{ path = \"/api\", upstream = \"127.0.0.1:8443\", \
                         upstream_tls = true, upstream_sni = \"api.local\" }]\n",
        );
        let cfg = Config::load(&path).unwrap();
        assert!(!cfg.servers[0].upstream_tls);
        assert!(cfg.servers[0].routes[0].upstream_tls);
        assert_eq!(cfg.servers[0].routes[0].upstream_sni, "api.local");
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
            &with_routes(&format!(
                r#"{{ path = "/assets", root = "{}", strip_prefix = true }}"#,
                root.display()
            )),
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
    fn absolute_paths_are_kept_and_relative_ones_follow_the_config() {
        let root = static_root("absolute");
        let path = write_temp(
            "absolute.toml",
            &format!(
                "[[server]]\ndomain = \"static.local\"\nroot = \"{}\"\n",
                root.display()
            ),
        );
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.resolve(&root.display().to_string()), root);
        assert_eq!(
            cfg.resolve("public"),
            std::env::temp_dir().join("public"),
            "a relative path follows the config file"
        );
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
    fn ipv6_empty_is_an_error_not_a_second_off_switch() {
        let path = write_temp(
            "ipv6-empty.toml",
            &format!("[listen]\nipv6 = \"\"\n{MINIMAL}"),
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("omit the field entirely"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);

        let path = write_temp(
            "ipv6-absent.toml",
            &format!("[listen]\nipv4 = \"127.0.0.1\"\n{MINIMAL}"),
        );
        assert!(Config::load(&path).unwrap().listen.ipv6.is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_acme_https_listen_also_binds_http_on_the_same_ip() {
        let path = write_temp(
            "http-follows-acme.toml",
            "[listen]\nipv4 = \"203.0.113.10\"\nhttp = 80\nhttps = 443\n\
             [[server]]\ndomain = \"site1.example.pf\"\nkeys = \"auto\"\n\
             https_listen = \"10.8.0.1\"\nhttps_listen6 = \"2001:db8::10\"\n\
             upstream = \"127.0.0.1:8080\"\n",
        );
        let cfg = Config::load(&path).unwrap();
        let http: Vec<String> = cfg
            .http_addrs()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            http,
            vec!["203.0.113.10:80", "10.8.0.1:80", "[2001:db8::10]:80"]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_internal_site_needs_no_http_listener() {
        let path = write_temp(
            "internal-private.toml",
            "[listen]\nipv4 = \"10.8.0.1\"\n\
             [internal]\ndomain = \"vpn.internal\"\n\
             [[server]]\ndomain = \"app.vpn.internal\"\nkeys = \"internal\"\n\
             serve_http = false\nhttps_listen = \"10.8.0.1\"\n\
             upstream = \"127.0.0.1:8080\"\n",
        );
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.servers[0].key_mode(), KeyMode::Internal);
        // Only the global :80 socket: an internal site publishes no challenge.
        assert_eq!(
            cfg.http_addrs().unwrap(),
            vec!["10.8.0.1:80".parse().unwrap()]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_manual_https_listen_does_not_add_http() {
        let path = write_temp(
            "http-follows-manual.toml",
            "[listen]\nipv4 = \"127.0.0.1\"\nhttp = 8080\nhttps = 8443\n\
             [[server]]\ndomain = \"manual.local\"\nkeys = \"manual\"\n\
             pub_key = \"certs/manual.local.crt\"\npriv_key = \"certs/manual.local.key\"\n\
             https_listen = \"127.0.0.2\"\nupstream = \"127.0.0.1:8080\"\n",
        );
        let cfg = Config::load(&path).unwrap();
        let http: Vec<String> = cfg
            .http_addrs()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(http, vec!["127.0.0.1:8080"]);
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

    // -----------------------------------------------------------------------
    // Per-server overrides, private ACME and the route spellings
    // -----------------------------------------------------------------------

    #[test]
    fn per_server_limits_and_health_override_the_global_tables() {
        let path = write_temp(
            "server-overrides.toml",
            r#"
[limits]
per_ip_rps = 100
per_ip_conns_per_sec = 10
max_body_bytes = 4096

[health]
interval_ms = 5000
timeout_ms = 2000
failures = 2

[[server]]
domain = "a.local"
upstream = "127.0.0.1:8080"
limits = { per_ip_rps = 1220 }
health = { interval_ms = 10000, failures = 3 }
"#,
        );
        let cfg = Config::load(&path).unwrap();
        let s = &cfg.servers[0];

        let limits = cfg.limits_for(s);
        assert_eq!(limits.per_ip_rps, 1220);
        assert_eq!(limits.per_ip_conns_per_sec, 10);
        assert_eq!(limits.max_body_bytes, 4096);

        let health = cfg.health_for(s);
        assert!(health.gate);
        assert_eq!(health.interval_ms, 10_000);
        assert_eq!(health.timeout_ms, 2_000);
        assert_eq!(health.failures, 3);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn health_false_and_a_settings_table_are_both_accepted() {
        let path = write_temp(
            "health-forms.toml",
            r#"
[health]
interval_ms = 6000

[[server]]
domain = "off.local"
upstream = "127.0.0.1:8080"
health = false

[[server]]
domain = "table.local"
upstream = "127.0.0.1:8081"
health = { timeout_ms = 1000 }
routes = [{ path = "/x", upstream = "127.0.0.1:8082", health = false }]
"#,
        );
        let cfg = Config::load(&path).unwrap();
        assert!(!cfg.health_for(&cfg.servers[0]).gate);

        let server_health = cfg.health_for(&cfg.servers[1]);
        assert!(server_health.gate);
        assert_eq!(server_health.interval_ms, 6000);
        assert_eq!(server_health.timeout_ms, 1000);
        assert!(!cfg.servers[1].routes[0].health.resolve(server_health).gate);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_per_server_connection_limit_is_refused() {
        let path = write_temp(
            "server-conns.toml",
            r#"
[[server]]
domain = "a.local"
upstream = "127.0.0.1:8080"
limits = { per_ip_conns_per_sec = 1 }
"#,
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(err.contains("host-wide"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn internal_mode_uses_the_local_ca_defaults() {
        let path = write_temp(
            "internal.toml",
            r#"
[internal]
domain = "internal.test"

[[server]]
domain = "app.internal.test"
keys = "internal"
upstream = "127.0.0.1:8080"
"#,
        );
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.servers[0].key_mode(), KeyMode::Internal);
        assert_eq!(cfg.internal.key_type, KeyKind::Ed25519);
        assert_eq!(cfg.internal.leaf_days, 397);
        assert_eq!(cfg.internal.renew_before_days, 30);
        let (cert, key) = cfg.key_paths(&cfg.servers[0]);
        assert!(
            cert.ends_with("cert/internal/app.internal.test/fullchain.pem"),
            "{cert:?}"
        );
        assert!(
            key.ends_with("cert/internal/app.internal.test/privkey.pem"),
            "{key:?}"
        );
        let (root, root_key) = cfg.ca_paths();
        assert!(root.ends_with("cert/internal/ca/root.crt"), "{root:?}");
        assert!(
            root_key.ends_with("cert/internal/ca/root.key"),
            "{root_key:?}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn internal_mode_rejects_explicit_key_paths() {
        let path = write_temp(
            "internal-paths.toml",
            r#"
[internal]
domain = "private.local"

[[server]]
domain = "private.local"
keys = "internal"
pub_key = "a.pem"
priv_key = "b.pem"
upstream = "127.0.0.1:8080"
"#,
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("issues and stores its own"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn alt_names_are_for_internal_leaves_only_and_must_be_hostnames() {
        let good = write_temp(
            "alt-good.toml",
            r#"
[internal]
domain = "private.local"

[[server]]
domain = "private.local"
keys = "internal"
alt_names = ["vpn.private.local", "Private.local."]
upstream = "127.0.0.1:8080"
"#,
        );
        let cfg = Config::load(&good).unwrap();
        assert_eq!(
            cfg.servers[0].alt_names,
            vec!["vpn.private.local", "Private.local"]
        );
        let _ = std::fs::remove_file(good);

        let wrong_mode = write_temp(
            "alt-auto.toml",
            "[acme]\nemail = \"a@b.c\"\n[[server]]\ndomain = \"a.local\"\n\
             alt_names = [\"b.local\"]\nupstream = \"127.0.0.1:8080\"\n",
        );
        let err = Config::load(&wrong_mode).unwrap_err().to_string();
        assert!(
            err.contains("only applies to `keys = \"internal\"`"),
            "{err}"
        );
        let _ = std::fs::remove_file(wrong_mode);

        let wildcard = write_temp(
            "alt-wild.toml",
            "[internal]\ndomain = \"a.local\"\n[[server]]\ndomain = \"a.local\"\n\
             keys = \"internal\"\n\
             alt_names = [\"*.a.local\"]\nupstream = \"127.0.0.1:8080\"\n",
        );
        let err = Config::load(&wildcard).unwrap_err().to_string();
        assert!(err.contains("not a hostname"), "{err}");
        let _ = std::fs::remove_file(wildcard);
    }

    #[test]
    fn serve_root_is_an_https_url_inside_the_zone() {
        let ok = write_temp(
            "root-ok.toml",
            "[internal]\ndomain = \"internal.local\"\n\
             serve_root = \"https://internal.local:9000\"\n\
             [[server]]\ndomain = \"internal.local\"\nkeys = \"internal\"\n\
             upstream = \"127.0.0.1:8080\"\n",
        );
        let cfg = Config::load(&ok).unwrap();
        let root = parse_serve_root(&cfg.internal.serve_root).unwrap();
        assert_eq!(root.host, "internal.local");
        assert_eq!(root.port, 9000);
        assert_eq!(root.url(), "https://internal.local:9000");
        let _ = std::fs::remove_file(ok);

        let default_port = parse_serve_root("https://internal.local").unwrap();
        assert_eq!(default_port.port, 9000);

        for (name, value, needle) in [
            ("root-http.toml", "http://internal.local:9000", "https://"),
            ("root-zero.toml", "https://internal.local:0", "port 0"),
            (
                "root-path.toml",
                "https://internal.local:9000/root.crt",
                "host and a port",
            ),
            ("root-outside.toml", "https://other.local:9000", "outside"),
        ] {
            let path = write_temp(
                name,
                &format!(
                    "[internal]\ndomain = \"internal.local\"\nserve_root = \"{value}\"\n\
                     [[server]]\ndomain = \"internal.local\"\nkeys = \"internal\"\n\
                     upstream = \"127.0.0.1:8080\"\n"
                ),
            );
            let err = format!("{:#}", Config::load(&path).unwrap_err());
            assert!(err.contains(needle), "{name}: {err}");
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn an_internal_server_must_live_inside_the_zone() {
        let path = write_temp(
            "internal-outside.toml",
            "[internal]\ndomain = \"internal.local\"\n\
             [[server]]\ndomain = \"dsh.other.local\"\nkeys = \"internal\"\n\
             upstream = \"127.0.0.1:8080\"\n",
        );
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(err.contains("outside `[internal] domain`"), "{err}");
        let _ = std::fs::remove_file(path);

        let missing = write_temp(
            "internal-no-zone.toml",
            "[[server]]\ndomain = \"dsh.internal.local\"\nkeys = \"internal\"\n\
             upstream = \"127.0.0.1:8080\"\n",
        );
        let err = Config::load(&missing).unwrap_err().to_string();
        assert!(err.contains("[internal] domain"), "{err}");
        let _ = std::fs::remove_file(missing);

        assert!(in_zone("dsh.internal.local", "internal.local"));
        assert!(in_zone("INTERNAL.LOCAL.", "internal.local"));
        assert!(!in_zone("internal.local.evil", "internal.local"));
        assert!(!in_zone("notinternal.local", "internal.local"));
    }

    #[test]
    fn internal_lifetimes_are_clamped_and_the_leaf_never_outlives_the_root() {
        let path = write_temp(
            "internal-days.toml",
            "[[server]]\ndomain = \"a.local\"\nkeys = \"internal\"\n\
             upstream = \"127.0.0.1:8080\"\n\
             [internal]\ndomain = \"a.local\"\n\
             leaf_days = 900\nca_days = 400\nrenew_before_days = 900\n",
        );
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.internal.leaf_days, 825);
        assert_eq!(cfg.internal.ca_days, 825);
        assert_eq!(cfg.internal.renew_before_days, 824);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn routes_stay_inside_their_server() {
        let path = write_temp(
            "route-forms.toml",
            r#"
[[server]]
domain = "www.rao-nagos.pf"
upstream = "127.0.0.1:8080"
routes = [{ path = "/mcp", upstream = "127.0.0.1:8081" }]

[[server]]
domain = "inline.example.com"
upstream = "127.0.0.1:9000"
routes = [{ path = "/api", upstream = "127.0.0.1:9001" }]
"#,
        );
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.servers[0].routes.len(), 1);
        assert_eq!(cfg.servers[0].routes[0].path, "/mcp");
        assert_eq!(cfg.servers[1].routes.len(), 1);
        assert_eq!(cfg.servers[1].routes[0].path, "/api");
        let _ = std::fs::remove_file(path);
    }
}
