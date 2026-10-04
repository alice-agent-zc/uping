//! The two `ProxyHttp` implementations that make up uping.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use log::{debug, warn};
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

/// Per-request state carried between the `ProxyHttp` phases.
#[derive(Default)]
pub struct ProxyCtx {
    /// Upstream chosen for this request in `request_filter`.
    upstream: Option<String>,
    /// Bytes of request body seen so far, for chunked uploads.
    body_bytes: u64,
}

/// Terminates TLS and forwards to the `upstream` of the matching domain.
pub struct HttpsProxy {
    /// domain -> upstream address ("host:port").
    routes: Arc<HashMap<String, String>>,
    /// Per-IP request budget.
    limiter: RequestLimiter,
    /// Largest request body we accept; `0` disables the check.
    max_body_bytes: usize,
}

impl HttpsProxy {
    pub fn new(
        routes: Arc<HashMap<String, String>>,
        limiter: RequestLimiter,
        max_body_bytes: usize,
    ) -> Self {
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
        //    instead of a 500 from `upstream_peer`.
        let host = request_host(session).unwrap_or_default();
        match self.routes.get(&host) {
            Some(upstream) => ctx.upstream = Some(upstream.clone()),
            None => {
                debug!("no [[server]] entry for host `{host}`, answering 404");
                session.respond_error(404).await?;
                return Ok(true);
            }
        }

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
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
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
        assert_eq!(select_host(Some(""), Some("example.com")), Some(String::new()));
    }

    #[test]
    fn redirect_location_builds_https_url() {
        assert_eq!(
            redirect_location("example.com", "/some/path?x=1"),
            "https://example.com/some/path?x=1"
        );
        assert_eq!(redirect_location("example.com", "/"), "https://example.com/");
    }
}
