//! `http = false` removes a domain from port 80 without touching its HTTPS.
//!
//! A private site behind WireGuard should not answer on the public redirect
//! listener at all: a request for it on :80 is a `404`, while :443 still works.

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

use support::*;

fn backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let body = "backend";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

fn config(dir: &Path, http: u16, https: u16, backend: u16) -> String {
    let cert = dir.join("private.local.crt");
    let key = dir.join("private.local.key");
    format!(
        "[listen]\nipv4 = \"127.0.0.1\"\nhttp = {http}\nhttps = {https}\n\
         [tls]\nfallback_cert = true\n\
         [[server]]\ndomain = \"public.local\"\nkeys = \"manual\"\n\
         pub_key = \"{}\"\npriv_key = \"{}\"\nupstream = \"127.0.0.1:{backend}\"\n\
         [[server]]\ndomain = \"private.local\"\nkeys = \"manual\"\n\
         pub_key = \"{}\"\npriv_key = \"{}\"\nupstream = \"127.0.0.1:{backend}\"\n\
         http = false\n",
        cert.display(),
        key.display(),
        cert.display(),
        key.display(),
    )
}

/// Plain-HTTP request through the redirect listener.
fn curl_http(port: u16, host: &str, path: &str) -> (String, String) {
    let url = format!("http://{host}:{port}{path}");
    let resolve = format!("{host}:{port}:127.0.0.1");
    let out = Command::new("curl")
        .args(["-s", "-i", "--resolve", &resolve])
        .arg(url)
        .output()
        .expect("curl is needed for the integration tests");
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
fn http_false_removes_the_domain_from_port_80_only() {
    let dir = workspace("private-http-e2e");
    let _ = cert_pair(&dir, "private.local");
    let backend = backend();
    let http = free_port();
    let https = free_port();
    let cfg = dir.join("config.toml");
    write(&cfg, &config(&dir, http, https, backend));
    let log = dir.join("private-http.log");
    let mut server = start(&cfg, &log, https);

    // The public domain keeps the usual redirect.
    let (status, text) = curl_http(http, "public.local", "/hello?x=1");
    assert_eq!(status, "301", "{text}");
    assert!(
        text.to_ascii_lowercase()
            .contains("location: https://public.local/hello?x=1"),
        "{text}"
    );

    // The private one is not an HTTP vhost at all.
    let (status, text) = curl_http(http, "private.local", "/");
    assert_eq!(status, "404", "{text}");

    // HTTPS is untouched.
    let (status, text) = curl(https, "private.local", "/", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("backend"), "{text}");

    assert!(server.is_alive());
    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}
