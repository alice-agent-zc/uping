//! uping — a tiny TOML-configured reverse proxy on Cloudflare Pingora.
//!
//! v0.1.0: read a config, load certs, serve HTTPS (SNI) on :443 and redirect
//! plain HTTP to HTTPS on :80.

mod config;
mod proxy;
mod tls;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use log::{info, warn};
use pingora::listeners::tls::TlsSettings;
use pingora::proxy::http_proxy_service;
use pingora::server::Server;

use crate::config::Config;
use crate::proxy::{HttpsProxy, RedirectProxy};
use crate::tls::SniResolver;

fn main() -> Result<()> {
    env_logger::init();

    // Usage: uping [config.toml]
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".into());
    let cfg = Config::load(&config_path)
        .with_context(|| format!("loading configuration from `{config_path}`"))?;

    // domain -> upstream
    let routes: HashMap<String, String> = cfg
        .servers
        .iter()
        .map(|s| (s.domain.to_ascii_lowercase(), s.upstream.clone()))
        .collect();
    let routes = Arc::new(routes);

    // Pre-load all cert/key pairs for SNI selection.
    let resolver = SniResolver::from_servers(&cfg.servers).context("loading TLS certificates")?;

    let mut server = Server::new(None).context("creating Pingora server")?;
    server.bootstrap();

    // --- HTTPS (TLS termination + reverse proxy) ---
    let mut https_service = http_proxy_service(&server.configuration, HttpsProxy::new(routes));
    let tls_settings =
        TlsSettings::with_callbacks(Box::new(resolver)).context("building TLS settings")?;
    https_service.add_tls_with_settings(&cfg.listen.https, None, tls_settings);
    server.add_service(https_service);
    info!("HTTPS listening on {}", cfg.listen.https);

    // --- HTTP (redirect to HTTPS) ---
    let mut http_service = http_proxy_service(&server.configuration, RedirectProxy);
    http_service.add_tcp(&cfg.listen.http);
    server.add_service(http_service);
    info!(
        "HTTP listening on {} (redirecting to HTTPS)",
        cfg.listen.http
    );

    for s in &cfg.servers {
        info!("  {} -> {}", s.domain, s.upstream);
    }

    if cfg.listen.http.ends_with(":80") || cfg.listen.https.ends_with(":443") {
        warn!("binding to ports 80/443 usually requires root or CAP_NET_BIND_SERVICE");
    }

    server.run_forever();
}
