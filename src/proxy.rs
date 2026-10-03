//! The two `ProxyHttp` implementations that make up uping.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use log::debug;
use pingora::http::ResponseHeader;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::Result;

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

/// Build the HTTPS URL a plain-HTTP request is redirected to.
fn redirect_location(host: &str, path: &str) -> String {
    format!("https://{host}{path}")
}

/// Terminates TLS and forwards to the `upstream` of the matching domain.
pub struct HttpsProxy {
    /// domain -> upstream address ("host:port").
    routes: Arc<HashMap<String, String>>,
}

impl HttpsProxy {
    pub fn new(routes: Arc<HashMap<String, String>>) -> Self {
        Self { routes }
    }
}

#[async_trait]
impl ProxyHttp for HttpsProxy {
    type CTX = ();
    fn new_ctx(&self) {}

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let host = request_host(session).unwrap_or_default();
        let upstream = self
            .routes
            .get(&host)
            .ok_or_else(|| pingora::Error::new_str("no upstream configured for this host"))?;

        debug!("proxying {host} -> {upstream}");
        // `tls = false`: we forward to a plain-HTTP upstream.
        Ok(Box::new(HttpPeer::new(upstream.as_str(), false, host)))
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
