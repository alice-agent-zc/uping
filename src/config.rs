//! uping configuration model.
//!
//! The whole config is intentionally tiny for v0.1.0:
//!
//! ```toml
//! [[server]]
//! domain   = "www.example.com"
//! pub_pem  = "certs/www.example.com/fullchain.pem"
//! priv_pem = "certs/www.example.com/privkey.pem"
//! upstream = "127.0.0.1:8080"
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

/// A single reverse-proxied domain.
#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    /// The public domain name, e.g. `www.example.com`. Matched case-insensitively
    /// against the TLS SNI name and the HTTP `Host` header.
    pub domain: String,

    /// Path to the PEM certificate (leaf first, then any intermediates / fullchain).
    pub pub_pem: String,

    /// Path to the PEM private key.
    pub priv_pem: String,

    /// Where to forward traffic, e.g. `127.0.0.1:8080` or `localhost:3000`.
    pub upstream: String,
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
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const MINIMAL: &str = r#"
[[server]]
domain   = "test.local"
pub_pem  = "certs/test.local.crt"
priv_pem = "certs/test.local.key"
upstream = "127.0.0.1:8080"
"#;

    fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
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
    fn honours_an_explicit_listen_section() {
        let path = write_temp("listen.toml", &format!(
            "[listen]\nhttp  = \"127.0.0.1:8088\"\nhttps = \"127.0.0.1:8443\"\n{MINIMAL}"
        ));
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.listen.http, "127.0.0.1:8088");
        assert_eq!(cfg.listen.https, "127.0.0.1:8443");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn accepts_multiple_servers() {
        let path = write_temp("multi.toml", &format!(
            "{MINIMAL}\n[[server]]\ndomain = \"other.local\"\npub_pem = \"a.pem\"\npriv_pem = \"a.key\"\nupstream = \"127.0.0.1:9000\"\n"
        ));
        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.servers.len(), 2);
        assert_eq!(cfg.servers[1].domain, "other.local");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_a_config_without_servers() {
        let path = write_temp("empty.toml", "[listen]\nhttp = \"127.0.0.1:8088\"\n");
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(err.contains("no [[server]] entries"), "unexpected error: {err}");
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
    fn reports_a_missing_file() {
        let err = Config::load("/nonexistent/uping.toml")
            .unwrap_err()
            .to_string();

        assert!(err.contains("reading config file"), "unexpected error: {err}");
    }

    #[test]
    fn reports_malformed_toml() {
        let path = write_temp("malformed.toml", "this is not = = toml");
        let err = Config::load(&path).unwrap_err().to_string();

        assert!(err.contains("parsing TOML"), "unexpected error: {err}");
        let _ = std::fs::remove_file(path);
    }
}
