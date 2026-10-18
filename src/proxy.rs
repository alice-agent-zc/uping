//! The two `ProxyHttp` implementations that make up uping.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use log::{debug, error, warn};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorType, Result};

use crate::limits::RequestLimiter;

/// Lowercase a `host[:port]` value, dropping any port suffix.
fn normalize_host(raw: &str) -> String {
    let host = raw.split(':').next().unwrap_or(raw);
    host.trim().to_ascii_lowercase()
}

/// Pick the effective hostname: the `Host` header wins, the request URI
/// authority is the fallback (absolute-form requests / HTTP/2 `:authority`).
fn select_host(header: Option<&str>, uri_host: Option<&str>) -> Option<String> {
    match header {
        Some(raw) => Some(normalize_host(raw)),
        None => uri_host.map(|h| h.to_ascii_lowercase()),
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
fn redirect_location(host: &str, path: &str) -> String {
    format!("https://{host}{path}")
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

/// One path route, ready for matching.
#[derive(Debug, Clone)]
pub struct PathRoute {
    /// Prefix with no trailing `/`.
    pub prefix: String,
    pub upstream: String,
    pub strip_prefix: bool,
}

impl PathRoute {
    pub fn from_config(route: &crate::config::Route) -> Self {
        Self {
            prefix: route.prefix().to_string(),
            upstream: route.upstream.clone(),
            strip_prefix: route.strip_prefix,
        }
    }
}

/// The upstream a request resolved to.
#[derive(Debug, PartialEq, Eq)]
pub struct Resolved<'a> {
    pub upstream: &'a str,
    /// Prefix to remove from the path before forwarding it, if the route asked.
    pub strip: Option<&'a str>,
}

/// The routes of one domain: a catch-all upstream plus optional path routes,
/// longest prefix first.
#[derive(Debug)]
pub struct SiteRoutes {
    catch_all: String,
    routes: Vec<PathRoute>,
}

impl SiteRoutes {
    pub fn new(catch_all: String, routes: impl IntoIterator<Item = PathRoute>) -> Self {
        let mut routes: Vec<PathRoute> = routes.into_iter().collect();
        // Longest first: `/assets/` is looked at before `/`.
        routes.sort_by_key(|r| std::cmp::Reverse(r.prefix.len()));
        Self { catch_all, routes }
    }

    /// Pick the route for `path`. Always succeeds: the catch-all is the floor.
    pub fn resolve(&self, path: &str) -> Resolved<'_> {
        for r in &self.routes {
            if matches_prefix(&r.prefix, path) {
                return Resolved {
                    upstream: &r.upstream,
                    strip: r.strip_prefix.then_some(r.prefix.as_str()),
                };
            }
        }
        Resolved {
            upstream: &self.catch_all,
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

    pub fn get(&self, host: &str) -> Option<&SiteRoutes> {
        self.sites.get(host)
    }

    /// Total number of non-catch-all routes, for the startup log.
    pub fn route_count(&self) -> usize {
        self.sites.values().map(|s| s.routes.len()).sum()
    }
}

/// Per-request state carried between the `ProxyHttp` phases.
#[derive(Default)]
pub struct ProxyCtx {
    /// Upstream chosen for this request in `request_filter`.
    upstream: Option<String>,
    /// Prefix the matched route wants removed before forwarding.
    strip_prefix: Option<String>,
    /// Bytes of request body seen so far, for chunked uploads.
    body_bytes: u64,
}

/// Terminates TLS and forwards to the upstream of the matching domain and path.
pub struct HttpsProxy {
    routes: Arc<RouteTable>,
    /// Per-IP request budget.
    limiter: RequestLimiter,
    /// Largest request body we accept; `0` disables the check.
    max_body_bytes: usize,
}

impl HttpsProxy {
    pub fn new(routes: Arc<RouteTable>, limiter: RequestLimiter, max_body_bytes: usize) -> Self {
        Self {
            routes,
            limiter,
            max_body_bytes,
        }
    }
}

#[async_trait]
impl ProxyHttp for HttpsProxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCtx::default()
    }

    /// Runs before the request is forwarded: rate limit, route, size check.
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // 1. Per-IP request budget. Counted for every request, including the
        //    ones we are about to reject, so a flood never gets a free pass.
        if let Some(addr) = session.client_addr().and_then(|a| a.as_inet()) {
            if !self.limiter.check(&addr.ip()) {
                warn!(
                    "rate limit: {} exceeded {} req/s, answering 429",
                    addr.ip(),
                    self.limiter.budget()
                );
                session.respond_error(429).await?;
                return Ok(true);
            }
        }

        // 2. Resolve the upstream now so an unrouted host gets a clean 404
        //    instead of a 500 from `upstream_peer`. An unknown *path* is not an
        //    error: it falls through to the server's catch-all upstream.
        let host = request_host(session).unwrap_or_default();
        let Some(site) = self.routes.get(&host) else {
            debug!("no [[server]] entry for host `{host}`, answering 404");
            session.respond_error(404).await?;
            return Ok(true);
        };

        let path = session.req_header().uri.path();
        let resolved = site.resolve(path);
        ctx.upstream = Some(resolved.upstream.to_string());
        ctx.strip_prefix = resolved.strip.map(str::to_string);

        // 3. Reject obviously oversized bodies before reading anything.
        if self.max_body_bytes > 0 {
            if let Some(len) = declared_content_length(session) {
                if len > self.max_body_bytes as u64 {
                    warn!(
                        "rejecting {len}-byte body from host `{host}` (limit {})",
                        self.max_body_bytes
                    );
                    session.respond_error(413).await?;
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // `request_filter` always fills this in; if it is missing the request
        // was answered early and never reaches here.
        let upstream = ctx.upstream.clone().ok_or_else(|| {
            Error::new_str("internal error: no upstream resolved for this request")
        })?;

        let host = request_host(session).unwrap_or_default();
        debug!("proxying {host} -> {upstream}");
        // `tls = false`: we forward to a plain-HTTP upstream.
        Ok(Box::new(HttpPeer::new(upstream.as_str(), false, host)))
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
        if self.max_body_bytes == 0 {
            return Ok(());
        }
        if let Some(chunk) = body {
            ctx.body_bytes += chunk.len() as u64;
            if ctx.body_bytes > self.max_body_bytes as u64 {
                // Surfacing this as an HTTPStatus error makes Pingora's
                // `fail_to_proxy` answer the client with a real 413.
                return Err(Error::new(ErrorType::HTTPStatus(413)));
            }
        }
        Ok(())
    }
}

/// Answers every plain-HTTP request with a 301 to the HTTPS equivalent.
pub struct RedirectProxy;

#[async_trait]
impl ProxyHttp for RedirectProxy {
    type CTX = ();
    fn new_ctx(&self) {}

    /// Never actually reached: `request_filter` always answers early with a 301.
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
        let host = request_host(session).unwrap_or_default();
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

    fn site() -> SiteRoutes {
        SiteRoutes::new(
            "127.0.0.1:8080".to_string(),
            [
                PathRoute {
                    prefix: "/mcp".to_string(),
                    upstream: "127.0.0.1:8081".to_string(),
                    strip_prefix: false,
                },
                PathRoute {
                    prefix: "/assets".to_string(),
                    upstream: "127.0.0.1:8085".to_string(),
                    strip_prefix: true,
                },
            ],
        )
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
        assert_eq!(site.resolve("/assets/a.css").upstream, "127.0.0.1:8085");
        assert_eq!(site.resolve("/mcp").upstream, "127.0.0.1:8081");
    }

    #[test]
    fn an_unknown_path_falls_through_to_the_catch_all() {
        let site = site();
        let hit = site.resolve("/somewhere/else");
        assert_eq!(hit.upstream, "127.0.0.1:8080");
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
            "127.0.0.1:8080".to_string(),
            [
                PathRoute {
                    prefix: "/a".to_string(),
                    upstream: "127.0.0.1:9001".to_string(),
                    strip_prefix: false,
                },
                PathRoute {
                    prefix: "/a/b/c".to_string(),
                    upstream: "127.0.0.1:9003".to_string(),
                    strip_prefix: false,
                },
                PathRoute {
                    prefix: "/a/b".to_string(),
                    upstream: "127.0.0.1:9002".to_string(),
                    strip_prefix: false,
                },
            ],
        );
        assert_eq!(site.resolve("/a/b/c/d").upstream, "127.0.0.1:9003");
        assert_eq!(site.resolve("/a/b/d").upstream, "127.0.0.1:9002");
        assert_eq!(site.resolve("/a/z").upstream, "127.0.0.1:9001");
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
}
