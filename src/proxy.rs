//! The two `ProxyHttp` implementations that make up uping.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use log::{debug, error, warn};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::protocols::tls::CaType;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorType, Result};

use crate::acme::{ChallengeStore, CHALLENGE_PREFIX};
use crate::config::{EffectiveHealth, Limits, UpstreamTls};
use crate::health::HealthTracker;
use crate::limits::RequestLimiter;
use crate::static_files::{self, StaticSite};

/// How long an idle HTTP/1.1 connection is kept for the next request.
/// Pingora has no global default for this; 75 s matches nginx's default.
const KEEPALIVE_TIMEOUT_SECS: u64 = 75;

/// Lowercase a `host[:port]` value, dropping any port suffix.
///
/// An IPv6 authority is bracketed (`[2001:db8::1]:443`); splitting on the first
/// colon would otherwise reduce it to `[`.
fn normalize_host(raw: &str) -> String {
    let raw = raw.trim();
    let host = if let Some(rest) = raw.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        raw.split(':').next().unwrap_or(raw)
    };
    // `example.com.` is the same name as `example.com`; a trailing dot in a
    // Host header must not turn into a 404 (or a route mismatch).
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Pick the effective hostname: the `Host` header wins, the request URI
/// authority is the fallback (absolute-form requests / HTTP/2 `:authority`).
fn select_host(header: Option<&str>, uri_host: Option<&str>) -> Option<String> {
    match header {
        Some(raw) => Some(normalize_host(raw)),
        None => uri_host.map(normalize_host),
    }
}

/// Extract the lowercased hostname from a request.
fn request_host(session: &Session) -> Option<String> {
    let header = session
        .req_header()
        .headers
        .get("host")
        .and_then(|h| h.to_str().ok());
    let uri_host = session.req_header().uri.host();
    select_host(header, uri_host)
}

/// Read a declared request body size, if the client sent a valid
/// `Content-Length`. Chunked bodies carry no length until they stream in; those
/// are caught by [`HttpsProxy::request_body_filter`] instead.
fn declared_content_length(session: &Session) -> Option<u64> {
    session
        .req_header()
        .headers
        .get("content-length")?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Build the HTTPS URL a plain-HTTP request is redirected to.
///
/// `host` has already been normalized (brackets stripped), so an IPv6 literal
/// has to be put back between brackets or the URL is not parseable.
fn redirect_location(host: &str, path: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("https://[{host}]{path}")
    } else {
        format!("https://{host}{path}")
    }
}

/// Does `path` fall under `prefix`? A prefix matches on a segment boundary, so
/// `/mcp` covers `/mcp` and `/mcp/sse` but not `/mcpx`.
fn matches_prefix(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    match path.strip_prefix(prefix) {
        Some(rest) => rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

/// Remove `prefix` from `path`, keeping a leading `/` on what is left.
fn strip_prefix_path<'a>(path: &'a str, prefix: &str) -> &'a str {
    match path.strip_prefix(prefix) {
        Some("") => "/",
        Some(rest) if rest.starts_with('/') => rest,
        _ => path,
    }
}

/// The path and query to forward after stripping `prefix`.
fn rewrite_path_and_query(path: &str, query: Option<&str>, prefix: &str) -> String {
    let path = strip_prefix_path(path, prefix);
    match query {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    }
}

/// One HTTP backend. Shared behind an `Arc`, so a request clone is an atomic
/// increment rather than a string copy.
pub struct Upstream {
    /// The configured `host:port`, as written.
    pub address: Arc<str>,
    /// Speak HTTPS to the backend.
    pub tls: bool,
    /// SNI sent in the upstream handshake (also the name verified).
    pub sni: Arc<str>,
    /// Verify the backend certificate.
    pub verify: bool,
    /// Roots for that verification; `None` uses the system store.
    pub ca: Option<Arc<CaType>>,
    /// Probe the backend and answer `503` when it is down. `false` makes the
    /// registry resolve the address but never reject the request.
    pub health: bool,
    /// Run the active TCP/TLS probe. `false` keeps only the resolver refresh.
    pub active_probe: bool,
    /// How often this backend is probed (or its DNS refreshed).
    pub health_interval: Duration,
    pub health_timeout: Duration,
    pub health_failures: usize,
    /// Pre-built OpenSSL connector for the health probe. `None` means plain TCP.
    pub probe: Option<Arc<openssl::ssl::SslConnector>>,
    /// Identity used by the health registry (address + TLS settings).
    key: Arc<str>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("address", &self.address)
            .field("tls", &self.tls)
            .field("sni", &self.sni)
            .field("verify", &self.verify)
            .finish()
    }
}

impl Upstream {
    pub fn key(&self) -> &Arc<str> {
        &self.key
    }
}

/// The parts of a server/route that describe its backend.
pub struct UpstreamSpec<'a> {
    pub address: &'a str,
    pub tls: UpstreamTls<'a>,
    /// Used as the SNI when the backend is an IP literal and no `upstream_sni`
    /// is written: a loopback backend usually serves the public certificate.
    pub default_sni: &'a str,
    /// The effective `[health]` settings for this backend.
    pub health: EffectiveHealth,
}

impl Upstream {
    fn from_config(spec: &UpstreamSpec<'_>, root_dir: &Path) -> anyhow::Result<Self> {
        let address = spec.address.trim();
        let tls = spec.tls;
        let health = spec.health;
        let host = host_of(address);
        let sni = if !tls.sni.trim().is_empty() {
            tls.sni.trim().to_string()
        } else if host.parse::<IpAddr>().is_ok() {
            spec.default_sni.trim().to_string()
        } else {
            host.to_string()
        };

        let path = if tls.ca.trim().is_empty() {
            None
        } else if Path::new(tls.ca.trim()).is_absolute() {
            Some(std::path::PathBuf::from(tls.ca.trim()))
        } else {
            Some(root_dir.join(tls.ca.trim()))
        };

        let ca = match &path {
            None => None,
            Some(path) => {
                let pem = std::fs::read(path)
                    .with_context(|| format!("reading `upstream_ca` `{}`", path.display()))?;
                let certs = openssl::x509::X509::stack_from_pem(&pem)
                    .with_context(|| format!("parsing `upstream_ca` `{}`", path.display()))?;
                if certs.is_empty() {
                    anyhow::bail!("`upstream_ca` `{}` holds no certificate", path.display());
                }
                Some(std::sync::Arc::new(certs.into_boxed_slice()))
            }
        };

        let probe = if tls.tls {
            let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
                .context("building the upstream TLS probe")?;
            if !tls.verify {
                builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
            } else if let Some(path) = &path {
                builder
                    .set_ca_file(path)
                    .with_context(|| format!("loading `upstream_ca` `{}`", path.display()))?;
            }
            Some(std::sync::Arc::new(builder.build()))
        } else {
            None
        };

        let active_probe = health.gate && health.interval_ms != 0;
        let key = format!(
            "{address}|tls={}|sni={sni}|verify={}|gate={}|interval={}|timeout={}|failures={}",
            tls.tls,
            tls.verify,
            health.gate,
            health.interval_ms,
            health.timeout_ms,
            health.failures
        );
        let refresh_ms = if active_probe {
            health.interval_ms
        } else {
            60_000
        };
        Ok(Self {
            address: std::sync::Arc::from(address),
            tls: tls.tls,
            sni: std::sync::Arc::from(sni.as_str()),
            verify: tls.verify,
            ca,
            probe,
            health: health.gate,
            active_probe,
            health_interval: Duration::from_millis(refresh_ms),
            health_timeout: Duration::from_millis(health.timeout_ms),
            health_failures: health.failures,
            key: std::sync::Arc::from(key.as_str()),
        })
    }
}

/// The host part of a `host:port` or `[v6]:port` string.
fn host_of(address: &str) -> &str {
    if let Some(rest) = address.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    address
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(address)
}

/// Where one request goes.
#[derive(Debug, Clone)]
pub enum Target {
    /// Forward it to an HTTP(S) backend.
    Proxy(std::sync::Arc<Upstream>),
    /// Serve it from a directory on this host.
    Static(StaticSite),
}

impl Target {
    pub fn from_config(
        spec: &UpstreamSpec<'_>,
        root: &str,
        index: &str,
        root_dir: &std::path::Path,
    ) -> anyhow::Result<Self> {
        if !spec.address.trim().is_empty() {
            return Upstream::from_config(spec, root_dir)
                .map(|u| Target::Proxy(std::sync::Arc::new(u)));
        }
        let path = if std::path::Path::new(root.trim()).is_absolute() {
            std::path::PathBuf::from(root.trim())
        } else {
            root_dir.join(root.trim())
        };
        Ok(Target::Static(StaticSite::new(path, index)?))
    }
}

/// One path route, ready for matching.
#[derive(Debug, Clone)]
pub struct PathRoute {
    /// Prefix with no trailing `/`.
    pub prefix: String,
    pub target: Target,
    pub strip_prefix: bool,
}

impl PathRoute {
    pub fn from_config(
        route: &crate::config::Route,
        domain: &str,
        root_dir: &std::path::Path,
        inherited: EffectiveHealth,
    ) -> anyhow::Result<Self> {
        let spec = UpstreamSpec {
            address: &route.upstream,
            tls: route.upstream_tls(),
            default_sni: domain,
            health: route.health.resolve(inherited),
        };
        Ok(Self {
            prefix: route.prefix().to_string(),
            target: Target::from_config(&spec, &route.root, &route.index, root_dir)?,
            strip_prefix: route.strip_prefix,
        })
    }
}

/// The destination a request resolved to.
#[derive(Debug)]
pub struct Resolved<'a> {
    pub target: &'a Target,
    /// Prefix to remove from the path before using it, if the route asked.
    pub strip: Option<&'a str>,
}

/// The routes of one domain: a catch-all target plus optional path routes,
/// longest prefix first, and the limits that apply to this domain.
#[derive(Debug)]
pub struct SiteRoutes {
    catch_all: Target,
    routes: Vec<PathRoute>,
    pub limits: Limits,
}

impl SiteRoutes {
    #[cfg(test)]
    pub fn new(catch_all: Target, routes: impl IntoIterator<Item = PathRoute>) -> Self {
        Self::with_limits(catch_all, routes, Limits::default())
    }

    pub fn with_limits(
        catch_all: Target,
        routes: impl IntoIterator<Item = PathRoute>,
        limits: Limits,
    ) -> Self {
        let mut routes: Vec<PathRoute> = routes.into_iter().collect();
        // Longest first: `/assets/` is looked at before `/`.
        routes.sort_by_key(|r| std::cmp::Reverse(r.prefix.len()));
        Self {
            catch_all,
            routes,
            limits,
        }
    }

    /// Every target this domain can reach, catch-all included.
    pub fn targets(&self) -> impl Iterator<Item = &Target> {
        std::iter::once(&self.catch_all).chain(self.routes.iter().map(|r| &r.target))
    }

    /// Pick the route for `path`. Always succeeds: the catch-all is the floor.
    pub fn resolve(&self, path: &str) -> Resolved<'_> {
        for r in &self.routes {
            if matches_prefix(&r.prefix, path) {
                return Resolved {
                    target: &r.target,
                    strip: r.strip_prefix.then_some(r.prefix.as_str()),
                };
            }
        }
        Resolved {
            target: &self.catch_all,
            strip: None,
        }
    }
}

/// domain -> [`SiteRoutes`].
#[derive(Debug, Default)]
pub struct RouteTable {
    sites: HashMap<String, SiteRoutes>,
}

impl RouteTable {
    pub fn new(sites: HashMap<String, SiteRoutes>) -> Self {
        Self { sites }
    }

    /// Build the table from a validated config. The config loader has already
    /// checked every target; this second pass canonicalises static roots and is
    /// the only place a reload can fail after `Config::load`.
    pub fn from_config(cfg: &crate::config::Config) -> anyhow::Result<Self> {
        let mut sites = HashMap::new();
        for s in &cfg.servers {
            let health = cfg.health_for(s);
            let spec = UpstreamSpec {
                address: &s.upstream,
                tls: s.upstream_tls(),
                default_sni: &s.domain,
                health,
            };
            let catch_all = Target::from_config(&spec, &s.root, &s.index, &cfg.root_dir)
                .with_context(|| format!("building the catch-all for `{}`", s.domain))?;
            let mut routes = Vec::new();
            for r in &s.routes {
                routes.push(
                    PathRoute::from_config(r, &s.domain, &cfg.root_dir, health).with_context(
                        || format!("building route `{}` for `{}`", r.path, s.domain),
                    )?,
                );
            }
            let limits = cfg.limits_for(s);
            sites.insert(
                s.domain.to_ascii_lowercase(),
                SiteRoutes::with_limits(catch_all, routes, limits),
            );
        }
        Ok(Self::new(sites))
    }

    pub fn get(&self, host: &str) -> Option<&SiteRoutes> {
        self.sites.get(host)
    }

    /// Total number of non-catch-all routes, for the startup log.
    pub fn route_count(&self) -> usize {
        self.sites.values().map(|s| s.routes.len()).sum()
    }

    /// Every distinct proxy backend in the table, for health checks.
    pub fn upstreams(&self) -> Vec<Arc<Upstream>> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for site in self.sites.values() {
            for target in site.targets() {
                if let Target::Proxy(upstream) = target {
                    if seen.insert(upstream.key().clone()) {
                        out.push(upstream.clone());
                    }
                }
            }
        }
        out
    }
}

/// Per-request state carried between the `ProxyHttp` phases.
#[derive(Default)]
pub struct ProxyCtx {
    /// Upstream chosen for this request in `request_filter`.
    upstream: Option<Arc<Upstream>>,
    /// Normalized host, so `upstream_peer` does not parse the header again.
    host: Option<String>,
    /// Prefix the matched route wants removed before forwarding.
    strip_prefix: Option<String>,
    /// Effective `max_body_bytes` for this domain; `None` means "not resolved
    /// yet", not "unlimited".
    max_body: Option<usize>,
    /// Bytes of request body seen so far, for chunked uploads.
    body_bytes: u64,
}

/// The page a healthy-looking request gets when its backend is down.
///
/// Static on purpose: no host, no upstream address, nothing a client could
/// reflect back. It is served with `503` and `Retry-After`, and the probe keeps
/// running, so the next request after recovery is proxied normally.
const UNAVAILABLE_PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Service temporarily unavailable</title>
  <style>
    :root { color-scheme: light dark; }
    body {
      margin: 0; min-height: 100vh; display: grid; place-items: center;
      background: #0f1115; color: #e8eaf0;
      font: 16px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif;
    }
    main { max-width: 34rem; padding: 2.5rem 1.5rem; text-align: center; }
    .badge {
      display: inline-block; margin-bottom: 1.25rem; padding: .25rem .75rem;
      border: 1px solid #3a4150; border-radius: 999px;
      color: #9aa4b8; font-size: .8rem; letter-spacing: .08em;
      text-transform: uppercase;
    }
    h1 { margin: 0 0 .75rem; font-size: 1.6rem; font-weight: 600; }
    p { margin: .5rem 0; color: #b6bdcc; }
    .hint { margin-top: 1.75rem; color: #7b8497; font-size: .9rem; }
  </style>
</head>
<body>
  <main>
    <span class="badge">503 &middot; temporarily unavailable</span>
    <h1>The service behind this domain is taking a break.</h1>
    <p>uping cannot reach the application right now. It keeps checking in the
       background and will route traffic again the moment the service answers.</p>
    <p class="hint">Nothing to fix on your side &mdash; try again in a few seconds.</p>
  </main>
</body>
</html>
"#;

/// Write the 503 page, honouring `HEAD` like the rest of the proxy.
async fn respond_unavailable(session: &mut Session) -> Result<()> {
    let head = session.req_header().method == http::Method::HEAD;
    let mut resp = ResponseHeader::build(503, Some(4))?;
    resp.insert_header("Content-Type", "text/html; charset=utf-8")?;
    resp.insert_header("Content-Length", UNAVAILABLE_PAGE.len().to_string())?;
    resp.insert_header("Cache-Control", "no-store")?;
    resp.insert_header("Retry-After", "5")?;
    session.write_response_header(Box::new(resp), head).await?;
    if !head {
        session
            .write_response_body(Some(Bytes::from_static(UNAVAILABLE_PAGE.as_bytes())), true)
            .await?;
    }
    Ok(())
}

/// Terminates TLS and forwards to the upstream of the matching domain and path.
pub struct HttpsProxy {
    /// Swapped whole on a reload; readers clone the current `Arc`.
    routes: Arc<RwLock<Arc<RouteTable>>>,
    /// Per-IP request budget; its counters survive a reload.
    limiter: Arc<RequestLimiter>,
    /// Largest request body we accept; `0` disables the check.
    max_body_bytes: Arc<AtomicUsize>,
    /// Domains this listener is allowed to answer. A server with its own
    /// `listen`/`listen6` lives in its own group; a request for a domain from
    /// another group is misdirected, even though routes and certificates are
    /// shared. Swapped on reload with the rest of the config.
    allowed: Arc<RwLock<Arc<HashSet<String>>>>,
    /// Upstream liveness, shared by every listener and the probe thread.
    health: Arc<HealthTracker>,
}

impl HttpsProxy {
    pub fn new(
        routes: Arc<RwLock<Arc<RouteTable>>>,
        limiter: Arc<RequestLimiter>,
        max_body_bytes: Arc<AtomicUsize>,
        allowed: Arc<RwLock<Arc<HashSet<String>>>>,
        health: Arc<HealthTracker>,
    ) -> Self {
        Self {
            routes,
            limiter,
            max_body_bytes,
            allowed,
            health,
        }
    }
}

#[async_trait]
impl ProxyHttp for HttpsProxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCtx::default()
    }

    /// Runs before the request is forwarded: route, rate limit, size check.
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        session.set_keepalive(Some(KEEPALIVE_TIMEOUT_SECS));

        // 1. Resolve the domain first: its own `limits` may differ from the
        //    global budget. An unknown host still gets the global budget, so a
        //    flood of bogus Host headers is not free.
        let host = request_host(session).unwrap_or_default();
        let routes = {
            let live = self.routes.read().unwrap_or_else(|e| e.into_inner());
            live.clone()
        };
        let site = routes.get(&host);
        if let Some(addr) = session.client_addr().and_then(|a| a.as_inet()) {
            let budget = site.map_or_else(|| self.limiter.budget(), |s| s.limits.per_ip_rps);
            let domain = if site.is_some() { host.as_str() } else { "" };
            if !self.limiter.check_with(domain, &addr.ip(), budget) {
                warn!(
                    "rate limit: {} exceeded {budget} req/s, answering 429",
                    addr.ip()
                );
                session.respond_error(429).await?;
                return Ok(true);
            }
        }
        let Some(site) = site else {
            debug!("no [[server]] entry for host `{host}`, answering 404");
            session.respond_error(404).await?;
            return Ok(true);
        };

        // A known domain can still be misdirected: it exists, but its own
        // `listen`/`listen6` is a different socket.
        let permitted = {
            let allowed = self.allowed.read().unwrap_or_else(|e| e.into_inner());
            allowed.contains(&host)
        };
        if !permitted {
            debug!("host `{host}` is not served by this listener, answering 421");
            session.respond_error(421).await?;
            return Ok(true);
        }

        // The body cap is per domain too. Remember it for the chunked-body
        // filter, where there is no `Content-Length` to check upfront.
        let max_body = site.limits.max_body_bytes;
        ctx.max_body = Some(max_body);

        // `Resolved` borrows only the route table, so the request path can stay
        // borrowed from the session until the static branch clones it.
        let resolved = site.resolve(session.req_header().uri.path());

        match resolved.target {
            // A static target answers right here and never reaches
            // `upstream_peer`.
            Target::Static(target) => {
                let uri = &session.req_header().uri;
                let path = uri.path().to_string();
                let query = uri.query().map(str::to_string);
                static_files::serve(session, target, &path, query.as_deref(), resolved.strip)
                    .await?;
                return Ok(true);
            }
            Target::Proxy(upstream) => {
                if self.health.down(upstream) {
                    warn!(
                        "upstream {} is down; answering 503 for {}",
                        upstream.address, host
                    );
                    respond_unavailable(session).await?;
                    return Ok(true);
                }
                ctx.upstream = Some(upstream.clone());
                ctx.host = Some(host);
                ctx.strip_prefix = resolved.strip.map(str::to_string);
            }
        }

        // 2. Reject obviously oversized bodies before reading anything.
        if max_body > 0 {
            if let Some(len) = declared_content_length(session) {
                if len > max_body as u64 {
                    let host = ctx.host.as_deref().unwrap_or_default();
                    warn!("rejecting {len}-byte body from host `{host}` (limit {max_body})");
                    session.respond_error(413).await?;
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // `request_filter` always fills this in; if it is missing the request
        // was answered early and never reaches here. `take` avoids a clone on
        // every request: the context is not used again for this field.
        let upstream = ctx.upstream.take().ok_or_else(|| {
            Error::new_str("internal error: no upstream resolved for this request")
        })?;
        let host = ctx.host.take().unwrap_or_default();
        let addr = self.health.addr(&upstream).ok_or_else(|| {
            Error::new_str("internal error: the upstream has no resolved address")
        })?;

        debug!(
            "proxying {host} -> {}{}",
            upstream.address,
            if upstream.tls { " over TLS" } else { "" }
        );
        let mut peer = HttpPeer::new(addr, upstream.tls, upstream.sni.to_string());
        if upstream.tls {
            peer.options.verify_cert = upstream.verify;
            peer.options.verify_hostname = upstream.verify;
            if let Some(ca) = &upstream.ca {
                peer.options.ca = Some(ca.clone());
            }
        }
        Ok(Box::new(peer))
    }

    /// Tell the backend where the request really came from.
    ///
    /// Pingora forwards the client's headers through unchanged (minus
    /// hop-by-hop fields), but it does *not* synthesize any `X-Forwarded-*`
    /// headers for you — so the backend would otherwise see a plain-HTTP
    /// request from `127.0.0.1` and have no way to know it arrived over HTTPS.
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Strip the matched route's prefix, e.g. `/assets/app.css` -> `/app.css`.
        // The query string is part of the URI and has to survive the rewrite.
        if let Some(prefix) = &ctx.strip_prefix {
            let uri = &upstream_request.uri;
            let rewritten = rewrite_path_and_query(uri.path(), uri.query(), prefix);
            debug!("rewriting request path to `{rewritten}`");
            match rewritten.parse() {
                Ok(uri) => upstream_request.set_uri(uri),
                Err(e) => {
                    // Unreachable for a path that arrived over HTTP, but a
                    // rewrite must never silently forward the wrong path.
                    error!("cannot rewrite the request path to `{rewritten}`: {e}");
                    return Err(Error::new_str("invalid rewritten request path"));
                }
            }
        }

        if let Some(addr) = session.client_addr().and_then(|a| a.as_inet()) {
            let client = addr.ip().to_string();
            // Append rather than replace: if something else already proxied
            // this request, its chain must survive ours.
            let forwarded = upstream_request
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|existing| format!("{existing}, {client}"))
                .unwrap_or(client);
            upstream_request.insert_header("x-forwarded-for", forwarded)?;
        }

        upstream_request.insert_header("x-forwarded-proto", "https")?;

        // Preserve the hostname the client actually asked for, which is not
        // necessarily the same as the upstream address.
        if let Some(host) = upstream_request
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
        {
            upstream_request.insert_header("x-forwarded-host", host)?;
        }

        Ok(())
    }

    /// Catch chunked uploads, which arrive with no `Content-Length` to check.
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let max_body = ctx
            .max_body
            .unwrap_or_else(|| self.max_body_bytes.load(Ordering::Relaxed));
        if max_body == 0 {
            return Ok(());
        }
        if let Some(chunk) = body {
            ctx.body_bytes += chunk.len() as u64;
            if ctx.body_bytes > max_body as u64 {
                // Surfacing this as an HTTPStatus error makes Pingora's
                // `fail_to_proxy` answer the client with a real 413.
                return Err(Error::new(ErrorType::HTTPStatus(413)));
            }
        }
        Ok(())
    }
}

/// Answers plain-HTTP requests with a 301 to the HTTPS equivalent, except for
/// the ACME http-01 path, which must be served in the clear.
pub struct RedirectProxy {
    challenges: ChallengeStore,
    /// Domains configured with `serve_http = false`: they exist only behind HTTPS, so
    /// a request for one on port 80 is a plain `404`, not a redirect.
    disabled: Arc<RwLock<Arc<HashSet<String>>>>,
}

impl RedirectProxy {
    pub fn new(challenges: ChallengeStore, disabled: Arc<RwLock<Arc<HashSet<String>>>>) -> Self {
        Self {
            challenges,
            disabled,
        }
    }
}

#[async_trait]
impl ProxyHttp for RedirectProxy {
    type CTX = ();
    fn new_ctx(&self) {}

    /// Never actually reached: `request_filter` always answers early.
    /// `ProxyHttp` has no default impl for this, so we provide one anyway.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Err(pingora::Error::new_str(
            "redirect-only service has no upstream",
        ))
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        session.set_keepalive(Some(KEEPALIVE_TIMEOUT_SECS));
        let host = request_host(session).unwrap_or_default();
        let disabled = {
            let set = self.disabled.read().unwrap_or_else(|e| e.into_inner());
            set.contains(&host)
        };
        if disabled {
            debug!("no HTTP vhost for `{host}` (`serve_http = false`), answering 404");
            session.respond_error(404).await?;
            return Ok(true);
        }

        let path = session.req_header().uri.path().to_string();

        if let Some(token) = path.strip_prefix(CHALLENGE_PREFIX) {
            let token = token.split('/').next().unwrap_or(token);
            match self.challenges.get(token) {
                Some(body) => {
                    let mut resp = ResponseHeader::build(200, Some(2))?;
                    resp.insert_header("Content-Type", "text/plain")?;
                    resp.insert_header("Content-Length", body.len().to_string())?;
                    let head = session.req_header().method == http::Method::HEAD;
                    session.write_response_header(Box::new(resp), head).await?;
                    if !head {
                        session
                            .write_response_body(Some(Bytes::from(body)), true)
                            .await?;
                    }
                }
                None => {
                    debug!("acme: no challenge for token `{token}`");
                    session.respond_error(404).await?;
                }
            }
            return Ok(true);
        }

        let path = session
            .req_header()
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let location = redirect_location(&host, path);

        debug!("redirecting http -> {location}");

        let mut resp = ResponseHeader::build(301, Some(1))?;
        resp.insert_header("Location", location)?;
        // End of stream: no body follows.
        session.write_response_header(Box::new(resp), true).await?;

        // `true` = early return, the response is already written.
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_host_lowercases_and_drops_port() {
        assert_eq!(normalize_host("Example.COM:8443"), "example.com");
        assert_eq!(normalize_host("example.com"), "example.com");
        assert_eq!(normalize_host("  Example.com  "), "example.com");
    }

    #[test]
    fn normalize_host_keeps_a_bracketed_ipv6_literal_whole() {
        assert_eq!(normalize_host("[2001:DB8::1]:443"), "2001:db8::1");
        assert_eq!(normalize_host("[::1]"), "::1");
    }

    #[test]
    fn normalize_host_drops_a_trailing_root_dot() {
        assert_eq!(normalize_host("Example.COM."), "example.com");
        assert_eq!(normalize_host("example.com.:443"), "example.com");
    }

    #[test]
    fn select_host_prefers_the_host_header() {
        assert_eq!(
            select_host(Some("WWW.Example.com:80"), Some("ignored.example")),
            Some("www.example.com".to_string())
        );
    }

    #[test]
    fn select_host_falls_back_to_uri_authority() {
        assert_eq!(
            select_host(None, Some("API.Example.com")),
            Some("api.example.com".to_string())
        );
        assert_eq!(select_host(None, None), None);
    }

    #[test]
    fn select_host_preserves_empty_header_behaviour() {
        // An empty Host header is passed through (matching the original code),
        // rather than silently falling back to the URI authority.
        assert_eq!(
            select_host(Some(""), Some("example.com")),
            Some(String::new())
        );
    }

    fn proxy(upstream: &str) -> Target {
        let spec = UpstreamSpec {
            address: upstream,
            tls: UpstreamTls {
                tls: false,
                sni: "",
                verify: true,
                ca: "",
            },
            default_sni: "test.local",
            health: EffectiveHealth::default(),
        };
        Target::Proxy(Arc::new(
            Upstream::from_config(&spec, Path::new(".")).unwrap(),
        ))
    }

    fn site() -> SiteRoutes {
        SiteRoutes::new(
            proxy("127.0.0.1:8080"),
            [
                PathRoute {
                    prefix: "/mcp".to_string(),
                    target: proxy("127.0.0.1:8081"),
                    strip_prefix: false,
                },
                PathRoute {
                    prefix: "/assets".to_string(),
                    target: proxy("127.0.0.1:8085"),
                    strip_prefix: true,
                },
            ],
        )
    }

    fn upstream(site: &SiteRoutes, path: &str) -> String {
        match site.resolve(path).target {
            Target::Proxy(upstream) => upstream.address.to_string(),
            Target::Static(_) => panic!("expected a proxy target for {path}"),
        }
    }

    #[test]
    fn a_prefix_matches_on_a_segment_boundary() {
        assert!(matches_prefix("/mcp", "/mcp"));
        assert!(matches_prefix("/mcp", "/mcp/sse"));
        assert!(!matches_prefix("/mcp", "/mcpx"));
        assert!(!matches_prefix("/mcp", "/"));
    }

    #[test]
    fn the_longest_prefix_wins() {
        let site = site();
        assert_eq!(upstream(&site, "/assets/a.css"), "127.0.0.1:8085");
        assert_eq!(upstream(&site, "/mcp"), "127.0.0.1:8081");
    }

    #[test]
    fn an_unknown_path_falls_through_to_the_catch_all() {
        let site = site();
        let hit = site.resolve("/somewhere/else");
        assert_eq!(upstream(&site, "/somewhere/else"), "127.0.0.1:8080");
        assert_eq!(hit.strip, None);
    }

    #[test]
    fn only_routes_that_ask_for_it_strip_their_prefix() {
        let site = site();
        assert_eq!(site.resolve("/mcp").strip, None);
        assert_eq!(site.resolve("/assets/a.css").strip, Some("/assets"));
    }

    #[test]
    fn the_stripped_path_keeps_its_leading_slash() {
        assert_eq!(strip_prefix_path("/assets/a.css", "/assets"), "/a.css");
        // The bare prefix becomes the root of the upstream, not an empty path.
        assert_eq!(strip_prefix_path("/assets", "/assets"), "/");
        assert_eq!(strip_prefix_path("/assets/", "/assets"), "/");
    }

    #[test]
    fn stripping_keeps_the_query_string() {
        assert_eq!(
            rewrite_path_and_query("/assets/a.css", Some("v=2"), "/assets"),
            "/a.css?v=2"
        );
        assert_eq!(
            rewrite_path_and_query("/assets/a.css", None, "/assets"),
            "/a.css"
        );
        assert_eq!(
            rewrite_path_and_query("/assets", Some("v=2"), "/assets"),
            "/?v=2"
        );
    }

    #[test]
    fn routes_are_sorted_by_length_not_by_config_order() {
        let site = SiteRoutes::new(
            proxy("127.0.0.1:8080"),
            [
                PathRoute {
                    prefix: "/a".to_string(),
                    target: proxy("127.0.0.1:9001"),
                    strip_prefix: false,
                },
                PathRoute {
                    prefix: "/a/b/c".to_string(),
                    target: proxy("127.0.0.1:9003"),
                    strip_prefix: false,
                },
                PathRoute {
                    prefix: "/a/b".to_string(),
                    target: proxy("127.0.0.1:9002"),
                    strip_prefix: false,
                },
            ],
        );
        assert_eq!(upstream(&site, "/a/b/c/d"), "127.0.0.1:9003");
        assert_eq!(upstream(&site, "/a/b/d"), "127.0.0.1:9002");
        assert_eq!(upstream(&site, "/a/z"), "127.0.0.1:9001");
    }

    #[test]
    fn redirect_location_builds_https_url() {
        assert_eq!(
            redirect_location("example.com", "/some/path?x=1"),
            "https://example.com/some/path?x=1"
        );
        assert_eq!(
            redirect_location("example.com", "/"),
            "https://example.com/"
        );
    }

    #[test]
    fn redirect_location_rebrackets_an_ipv6_literal() {
        assert_eq!(
            redirect_location("2001:db8::1", "/x"),
            "https://[2001:db8::1]/x"
        );
    }
}
