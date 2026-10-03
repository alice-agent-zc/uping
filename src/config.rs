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
