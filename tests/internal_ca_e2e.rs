//! `keys = "internal"`: uping signs its own leaves, publishes the root, and a
//! broken server only costs its own domain.
//!
//! This drives the real binary once, because three promises only exist at that
//! level: the generated chain is accepted by a TLS client that trusts nothing
//! but `root.crt`, `/root.crt` is fetchable over plain HTTP, and a listener
//! address that does not exist (here TEST-NET-1, as a VPN that is not up yet)
//! is a warning rather than a dead process.

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
            let body = "internal-backend";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

fn config(dir: &Path, http: u16, https: u16, root_port: u16, backend: u16) -> String {
    format!(
        "[listen]\nipv4 = \"127.0.0.1\"\nhttp = {http}\nhttps = {https}\n\
         [internal]\nca_dir = \"ca\"\ncert_dir = \"leaves\"\n\
         serve_root = \"127.0.0.1:{root_port}\"\n\
         [[server]]\ndomain = \"app.internal\"\nkeys = \"internal\"\n\
         serve_http = false\nhttps_listen = \"127.0.0.1:{https}\"\n\
         upstream = \"127.0.0.1:{backend}\"\n\
         [[server]]\ndomain = \"offline.internal\"\nkeys = \"internal\"\n\
         serve_http = false\nhttps_listen = \"192.0.2.1:{https}\"\n\
         upstream = \"127.0.0.1:9\"\n\
         [[server]]\ndomain = \"broken.local\"\nkeys = \"manual\"\n\
         pub_key = \"{}/missing.crt\"\npriv_key = \"{}/missing.key\"\n\
         upstream = \"127.0.0.1:9\"\n",
        dir.display(),
        dir.display(),
    )
}

/// HTTPS with no `-k`: the only trust anchor is the generated root, so this
/// fails if the leaf is self-signed, carries another SAN, or does not chain.
fn curl_with_root(port: u16, host: &str, path: &str, ca: &Path) -> (String, String) {
    let url = format!("https://{host}:{port}{path}");
    let resolve = format!("{host}:{port}:127.0.0.1");
    let out = Command::new("curl")
        .args(["-s", "-i", "--cacert"])
        .arg(ca)
        .args(["--resolve", &resolve])
        .arg(url)
        .output()
        .expect("curl is needed for the integration tests");
    assert!(
        out.status.success(),
        "curl rejected the local chain: {}",
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

fn fetch_plain(port: u16, path: &str) -> String {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .expect("the root-certificate listener must be up");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut body = String::new();
    stream.read_to_string(&mut body).unwrap();
    body
}

#[test]
fn a_local_leaf_is_trusted_by_its_root_and_a_broken_server_is_only_a_warning() {
    let dir = workspace("internal-ca-e2e");
    let backend = backend();
    let http = free_port();
    let mut https = free_port();
    while https == http {
        https = free_port();
    }
    let mut root_port = free_port();
    while root_port == http || root_port == https {
        root_port = free_port();
    }
    let cfg = dir.join("config.toml");
    write(&cfg, &config(&dir, http, https, root_port, backend));
    let log = dir.join("internal.log");
    let mut server = start(&cfg, &log, https);

    let ca_cert = dir.join("ca").join("root.crt");
    let ca_key = dir.join("ca").join("root.key");
    assert!(
        ca_cert.is_file(),
        "the root must be generated on first start"
    );
    assert!(ca_key.is_file());

    // The leaf lives under [internal] cert_dir, not the ACME one.
    let leaf_dir = dir.join("leaves").join("app.internal");
    assert!(leaf_dir.join("fullchain.pem").is_file());
    assert!(leaf_dir.join("privkey.pem").is_file());

    // A client that trusts only root.crt accepts the chain.
    let (status, text) = curl_with_root(https, "app.internal", "/", &ca_cert);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("internal-backend"), "{text}");

    // The root is published over plain HTTP for clients that have nothing yet.
    let plain = fetch_plain(root_port, "/root.crt");
    assert!(plain.contains("200 OK"), "{plain}");
    assert!(plain.contains("BEGIN CERTIFICATE"), "{plain}");
    assert_eq!(
        plain.split("\r\n\r\n").nth(1).unwrap_or(""),
        std::fs::read_to_string(&ca_cert).unwrap(),
    );

    // The VPN address was not available; the other domains must be unaffected.
    let text = wait_for_log(&log, "is not available");
    assert!(
        text.contains("192.0.2.1") && text.contains("skipping that listener"),
        "{text}"
    );
    assert!(text.contains("skipping `broken.local`"), "{text}");
    assert!(server.is_alive());

    // And the good domain still answers while the broken one did not kill it.
    let (status, text) = curl_with_root(https, "app.internal", "/again", &ca_cert);
    assert_eq!(status, "200", "{text}");

    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}
