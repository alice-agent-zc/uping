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
}

/// Where uping binds. Defaults to the standard HTTP/HTTPS ports.
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

/// One path-prefix route belonging to a [`Server`].
#[derive(Debug, Clone, Deserialize)]
pub struct Route {
    /// Path prefix, e.g. `/mcp` or `/assets/`.
    pub path: String,

    /// Where requests matching `path` are forwarded.
    pub upstream: String,

    /// Remove `path` from the request path before forwarding it.
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

impl Config {
    /// Read and parse a TOML config file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file `{}`", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("parsing TOML in `{}`", path.display()))?;

        if cfg.servers.is_empty() {
            anyhow::bail!("no [[server]] entries found in `{}`", path.display());
        }
        for s in &cfg.servers {
            if s.domain.trim().is_empty() {
                anyhow::bail!("a [[server]] entry has an empty `domain`");
            }
            if s.upstream.trim().is_empty() {
                anyhow::bail!("`{}` has an empty `upstream`", s.domain);
            }
            if s.pub_key.trim().is_empty() {
                anyhow::bail!("`{}` has an empty `pub_key`", s.domain);
            }
            if s.priv_key.trim().is_empty() {
                anyhow::bail!("`{}` has an empty `priv_key`", s.domain);
            }
            validate_routes(s)?;
        }
        Ok(cfg)
    }
}

/// Reject route tables that would be ambiguous or unusable at request time.
fn validate_routes(s: &Server) -> Result<()> {
    let mut seen = std::collections::HashSet::new();

    for r in &s.routes {
        let path = r.path.trim();
        let where_ = format!("`{}` route `{path}`", s.domain);

        if r.upstream.trim().is_empty() {
            anyhow::bail!("{where_} has an empty `upstream`");
        }
        if !path.starts_with('/') {
            anyhow::bail!("{where_}: `path` must start with `/`");
        }
        if path.contains('?') || path.contains('#') {
            anyhow::bail!("{where_}: `path` is a path prefix, not a URI");
        }
        if r.prefix() == "/" {
            anyhow::bail!(
                "`{}` route `{path}`: `/` is the catch-all, use the server's `upstream`",
                s.domain
            );
        }
        if !seen.insert(r.prefix().to_string()) {
            anyhow::bail!("`{}` has two routes for `{}`", s.domain, r.prefix());
        }
    }
    Ok(())
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
            err.contains("no [[server]] entries"),
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
}
