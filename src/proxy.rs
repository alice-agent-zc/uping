//! The two `ProxyHttp` implementations that make up uping.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use log::debug;
use pingora::http::ResponseHeader;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::Result;

/// Extract the lowercased hostname from a request, preferring the `Host`
/// header (origin-form requests) and falling back to the request URI
/// authority (absolute-form / HTTP/2 `:authority`).
fn request_host(session: &Session) -> Option<String> {
    if let Some(host) = session.req_header().headers.get("host") {
        if let Ok(host) = host.to_str() {
            let host = host.split(':').next().unwrap_or(host);
            return Some(host.to_ascii_lowercase());
        }
    }
    session
        .req_header()
        .uri
        .host()
        .map(|h| h.to_ascii_lowercase())
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
        let location = format!("https://{host}{path}");

        debug!("redirecting http -> {location}");

        let mut resp = ResponseHeader::build(301, Some(1))?;
        resp.insert_header("Location", location)?;
        // End of stream: no body follows.
        session.write_response_header(Box::new(resp), true).await?;

        // `true` = early return, the response is already written.
        Ok(true)
    }
}
