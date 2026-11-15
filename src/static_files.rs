//! Static file serving for `root = "…"` on a `[[server]]` or a route.
//!
//! A request is resolved under the configured directory, never above it:
//! `%2e%2e` is decoded before the check, and the final path is canonicalised
//! and compared with the canonical root, so a symlink cannot walk out either.
//! A file that does not exist is a `404`; it never falls through to a proxy
//! upstream, because a missing asset must not silently become an HTML page.
//!
//! Files are streamed in 64 KiB chunks rather than read whole: a video or a
//! tarball behind a static route should not decide the process's memory use.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use log::{debug, warn};
use percent_encoding::percent_decode_str;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use pingora::{Error, ErrorType, Result};
use tokio::io::AsyncReadExt;

/// One configured document root.
#[derive(Debug, Clone)]
pub struct StaticSite {
    /// Canonical root: every served path must start with it.
    root: PathBuf,
    /// File served for a directory request.
    index: String,
}

impl StaticSite {
    /// Canonicalise the root now. A missing or non-directory root is a startup
    /// error, not a 404 discovered on the first request.
    pub fn new(root: PathBuf, index: impl Into<String>) -> anyhow::Result<Self> {
        let root = std::fs::canonicalize(&root)
            .map_err(|e| anyhow::anyhow!("static root `{}`: {e}", root.display()))?;
        if !root.is_dir() {
            anyhow::bail!("static root `{}` is not a directory", root.display());
        }
        Ok(Self {
            root,
            index: index.into(),
        })
    }

    #[cfg(test)]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Serve `path` from `site`, writing the whole response.
///
/// `strip` is the matched route prefix to remove first, if the route asked for
/// it. Returns `Ok(())` in every handled case — the caller has already answered
/// the request and must not proxy it.
pub async fn serve(
    session: &mut Session,
    site: &StaticSite,
    path: &str,
    query: Option<&str>,
    strip: Option<&str>,
) -> Result<()> {
    let method = session.req_header().method.clone();
    if method != http::Method::GET && method != http::Method::HEAD {
        let mut resp = ResponseHeader::build(405, Some(1))?;
        resp.insert_header("Allow", "GET, HEAD")?;
        session.write_response_header(Box::new(resp), true).await?;
        return Ok(());
    }

    let raw = strip
        .map(|prefix| strip_prefix(path, prefix))
        .unwrap_or(path);
    let decoded = match percent_decode_str(raw).decode_utf8() {
        Ok(decoded) => decoded.into_owned(),
        Err(_) => {
            debug!("static: `{raw}` is not valid UTF-8 after percent-decoding");
            session.respond_error(400).await?;
            return Ok(());
        }
    };

    if decoded.contains('\0') || decoded.contains('\\') || has_parent_segment(&decoded) {
        warn!("static: refusing traversal-shaped path `{decoded}`");
        session.respond_error(400).await?;
        return Ok(());
    }

    let wants_dir = decoded.ends_with('/') || decoded.is_empty();
    let relative = components(&decoded);
    let mut candidate = site.root.join(relative.iter().collect::<PathBuf>());

    // A directory without the trailing slash gets one, so relative links resolve
    // the same way they do on every other web server.
    if wants_dir {
        candidate.push(&site.index);
    }
    debug!("static: `{raw}` -> `{}`", candidate.display());

    let canonical = match tokio::fs::canonicalize(&candidate).await {
        Ok(path) => path,
        Err(_) => {
            session.respond_error(404).await?;
            return Ok(());
        }
    };
    if !canonical.starts_with(&site.root) {
        warn!(
            "static: `{}` escapes `{}`; refusing",
            canonical.display(),
            site.root.display()
        );
        session.respond_error(404).await?;
        return Ok(());
    }

    if canonical.is_dir() {
        if !wants_dir {
            // Redirect to the *original* path: with `strip_prefix`, `raw` is
            // the upstream path (`/sub`), but the client still lives under the
            // route prefix (`/files/sub`). The slash comes before the query.
            let location = format!("{path}/");
            let location = match query {
                Some(query) => format!("{location}?{query}"),
                None => location,
            };
            debug!("static: redirecting `{path}` to `{location}`");
            let mut resp = ResponseHeader::build(301, Some(1))?;
            resp.insert_header("Location", location)?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(());
        }

        let index = canonical.join(&site.index);
        let index = match tokio::fs::canonicalize(&index).await {
            Ok(path) if path.starts_with(&site.root) => path,
            _ => {
                session.respond_error(404).await?;
                return Ok(());
            }
        };
        return serve_file(session, &index, &method).await;
    }

    serve_file(session, &canonical, &method).await
}

async fn serve_file(session: &mut Session, path: &Path, method: &http::Method) -> Result<()> {
    let meta = match tokio::fs::metadata(path).await {
        Ok(meta) if meta.is_file() => meta,
        _ => {
            session.respond_error(404).await?;
            return Ok(());
        }
    };

    let len = meta.len();
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    debug!("static: serving `{}` ({len} bytes, {mime})", path.display());
    let mut resp = ResponseHeader::build(200, Some(3))?;
    resp.insert_header("Content-Type", mime.as_ref())?;
    resp.insert_header("Content-Length", len.to_string())?;
    resp.insert_header("X-Content-Type-Options", "nosniff")?;

    let head = method == http::Method::HEAD;
    session.write_response_header(Box::new(resp), head).await?;
    if head {
        return Ok(());
    }

    // An empty file still needs the end-of-stream write, or the client waits
    // for a body that is never coming.
    if len == 0 {
        session.write_response_body(None, true).await?;
        return Ok(());
    }

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| Error::because(ErrorType::InternalError, "opening a static file", e))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut remaining = len;

    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = match file.read(&mut buf[..want]).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                warn!("static: reading `{}` failed: {e}", path.display());
                break;
            }
        };
        remaining -= n as u64;
        let end = remaining == 0;
        session
            .write_response_body(Some(Bytes::copy_from_slice(&buf[..n])), end)
            .await?;
    }

    // The file was shorter than its metadata promised (truncated while being
    // served). End the chunked stream rather than leave the client waiting.
    if remaining > 0 {
        session.write_response_body(None, true).await?;
    }
    Ok(())
}

/// Remove `prefix` from `path`, keeping a leading `/` on what is left.
fn strip_prefix<'a>(path: &'a str, prefix: &str) -> &'a str {
    match path.strip_prefix(prefix) {
        Some("") => "/",
        Some(rest) if rest.starts_with('/') => rest,
        _ => path,
    }
}

fn has_parent_segment(path: &str) -> bool {
    path.split('/').any(|part| part == "..")
}

fn components(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tree() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "uping-static-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("assets")).unwrap();
        std::fs::create_dir_all(root.join("empty")).unwrap();
        std::fs::write(root.join("index.html"), b"<h1>hello</h1>").unwrap();
        std::fs::write(root.join("assets/app.css"), b"body{}").unwrap();
        root
    }

    #[test]
    fn a_site_canonicalises_its_root_and_serves_under_it() {
        let root = write_tree();
        let site = StaticSite::new(root.clone(), "index.html").unwrap();
        assert_eq!(site.root(), std::fs::canonicalize(&root).unwrap());
        assert!(site.root().is_dir());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_missing_root_is_refused_at_construction() {
        let err = StaticSite::new(PathBuf::from("/nonexistent/uping-root"), "index.html")
            .unwrap_err()
            .to_string();
        assert!(err.contains("static root"), "unexpected error: {err}");
    }

    #[test]
    fn a_file_root_is_not_a_directory() {
        let root = write_tree();
        let file = root.join("index.html");
        let err = StaticSite::new(file, "index.html").unwrap_err().to_string();
        assert!(err.contains("not a directory"), "unexpected error: {err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parent_segments_are_detected_before_joining() {
        assert!(has_parent_segment("/../etc/passwd"));
        assert!(has_parent_segment("/assets/../../etc/passwd"));
        assert!(has_parent_segment("/assets/../app.css"));
        assert!(!has_parent_segment("/assets/..hidden/app.css"));
    }

    #[test]
    fn dot_segments_are_dropped() {
        assert_eq!(components("/assets/./app.css"), vec!["assets", "app.css"]);
    }

    #[test]
    fn the_strip_helper_keeps_a_leading_slash() {
        assert_eq!(strip_prefix("/assets/app.css", "/assets"), "/app.css");
        assert_eq!(strip_prefix("/assets", "/assets"), "/");
        assert_eq!(strip_prefix("/assets/", "/assets"), "/");
        assert_eq!(strip_prefix("/other", "/assets"), "/other");
    }
}
