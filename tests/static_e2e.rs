//! End-to-end checks for `root = "…"` static serving through the real binary.
//!
//! A temporary document tree, a throwaway self-signed certificate and `curl`:
//! what is proven is the request path a browser takes — TLS/SNI, the route
//! table, the file resolver's traversal guard, MIME types and redirects.
//!
//! High ports only; no root.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn workspace() -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("static-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("site/assets")).unwrap();
    std::fs::write(dir.join("site/index.html"), b"<h1>static home</h1>").unwrap();
    std::fs::write(dir.join("site/assets/app.css"), b"body { color: red }").unwrap();
    std::fs::write(dir.join("site/hello.txt"), b"hello").unwrap();
    std::fs::write(dir.join("site/empty.txt"), b"").unwrap();
    dir
}

/// A self-signed pair for `static.local`, minted at run time.
fn cert_pair(dir: &Path) -> (PathBuf, PathBuf) {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::rsa::Rsa;

    let key = openssl::pkey::PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "static.local").unwrap();
    let name = name.build();

    let mut cert = openssl::x509::X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = cert.build();

    let cert_path = dir.join("static.local.crt");
    let key_path = dir.join("static.local.key");
    std::fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
    std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    (cert_path, key_path)
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn start(cfg: &Path, log: &Path, https: u16) -> Server {
    let out = std::fs::File::create(log).unwrap();
    let err = out.try_clone().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_uping"))
        .arg(cfg)
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawning the uping binary");
    let server = Server(child);

    // The log line is printed before pingora's accept loop binds; wait for the
    // port itself, not just the message, or curl races the first request.
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        if text.contains("HTTPS listening") && TcpStream::connect(("127.0.0.1", https)).is_ok() {
            return server;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!(
        "uping never reported its HTTPS listener; log:\n{}",
        std::fs::read_to_string(log).unwrap_or_default()
    );
}

/// One HTTP response over TLS, using curl as the client. Returns
/// `(status, headers+body)`.
fn get(port: u16, path: &str, extra: &[&str]) -> (String, String) {
    let url = format!("https://static.local:{port}{path}");
    let resolve = format!("static.local:{port}:127.0.0.1");
    let mut cmd = Command::new("curl");
    cmd.args(["-sk", "-i", "--resolve", &resolve])
        .args(extra)
        .arg(url);
    let out = cmd.output().expect("curl is needed for the e2e tests");
    assert!(
        out.status.success(),
        "curl failed for {path}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let status = text
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();
    (status, text)
}

#[test]
fn static_files_are_served_with_mime_types_and_a_traversal_guard() {
    let dir = workspace();
    let (cert, key) = cert_pair(&dir);
    let http = free_port();
    let https = free_port();
    let site = dir.join("site");

    // A symlink that points outside the root: canonicalisation must reject it.
    std::os::unix::fs::symlink("/etc", site.join("leak")).unwrap();

    let cfg_path = dir.join("static.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "[listen]\nhttp = \"127.0.0.1:{http}\"\nhttps = \"127.0.0.1:{https}\"\n\
             [tls]\nfallback_cert = true\n\
             [[server]]\ndomain = \"static.local\"\nkeys = \"manual\"\n\
             pub_key = \"{}\"\npriv_key = \"{}\"\nroot = \"{}\"\n\
             [[server.route]]\npath = \"/files\"\nroot = \"{}\"\nstrip_prefix = true\n",
            cert.display(),
            key.display(),
            site.display(),
            site.join("assets").display(),
        ),
    )
    .unwrap();
    let log = dir.join("static.log");
    let _server = start(&cfg_path, &log, https);

    let (status, text) = get(https, "/", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.contains("static home"), "body missing: {text}");
    assert!(
        text.to_lowercase().contains("content-type: text/html"),
        "{text}"
    );

    let (status, text) = get(https, "/assets/app.css", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.contains("text/css"), "unexpected type: {text}");
    assert!(text.contains("body { color: red }"), "{text}");

    // A directory without its trailing slash redirects, as every static server does.
    let (status, text) = get(https, "/assets", &[]);
    assert_eq!(status, "301", "{text}");
    assert!(text.to_lowercase().contains("location: /assets/"), "{text}");

    // The route strips `/files` before resolving under its own root.
    let (status, text) = get(https, "/files/app.css", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.contains("body { color: red }"), "{text}");

    // A zero-byte file must still terminate the response.
    let (status, text) = get(https, "/empty.txt", &[]);
    assert_eq!(status, "200", "{text}");

    let (status, _) = get(https, "/does-not-exist", &[]);
    assert_eq!(status, "404");

    // `curl` would normally normalise `..`; --path-as-is sends it literally.
    let (status, _) = get(https, "/%2e%2e/%2e%2e/etc/passwd", &["--path-as-is"]);
    assert_eq!(status, "400", "a traversal-shaped path must be refused");

    let (status, _) = get(https, "/leak/passwd", &[]);
    assert_eq!(status, "404", "a symlink out of the root must not escape");

    // HTTP still redirects to HTTPS.
    let plain = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], http))).unwrap();
    plain
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    (&plain)
        .write_all(
            format!(
                "GET /assets/app.css HTTP/1.1\r\nHost: static.local:{http}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
    let mut buf = Vec::new();
    (&plain).read_to_end(&mut buf).unwrap();
    let response = String::from_utf8_lossy(&buf);
    assert!(response.starts_with("HTTP/1.1 301"), "{response}");
    assert!(
        response.contains("Location: https://static.local/assets/app.css"),
        "{response}"
    );

    let _ = std::fs::remove_dir_all(dir);
}
