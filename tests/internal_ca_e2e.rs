//! `keys = "internal"`: uping signs its own zone, publishes the root over TLS at
//! `[internal] serve_root`, and a broken server only costs its own domain.
//!
//! This drives the real binary once, because four promises only exist at that
//! level: the generated leaf chains through an intermediate to a root a TLS
//! client can trust, `/root.crt` is fetchable over TLS at the configured URL,
//! the subject carries the configured identity, and a listener address that
//! does not exist (here TEST-NET-1, as a VPN that is not up yet) is a warning
//! rather than a dead process.

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
         [internal]\ndomain = \"localhost\"\nca_dir = \"ca\"\ncert_dir = \"leaves\"\n\
         organization = \"rao-nagos\"\ncountry = \"PF\"\n\
         email = \"ops@rao-nagos.pf\"\n\
         serve_root = \"https://localhost:{root_port}\"\n\
         [[server]]\ndomain = \"app.localhost\"\nkeys = \"internal\"\n\
         serve_http = false\nhttps_listen = \"127.0.0.1:{https}\"\n\
         upstream = \"127.0.0.1:{backend}\"\n\
         [[server]]\ndomain = \"offline.localhost\"\nkeys = \"internal\"\n\
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

/// The root endpoint is TLS: fetch it with `-k`, because the root it serves is
/// what would make the name trusted in the first place.
fn fetch_root(port: u16, path: &str) -> String {
    let out = Command::new("curl")
        .args(["-sk", "--resolve", &format!("localhost:{port}:127.0.0.1")])
        .arg(format!("https://localhost:{port}{path}"))
        .output()
        .expect("curl is needed for the integration tests");
    assert!(
        out.status.success(),
        "curl failed on the root endpoint: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
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
    let leaf_dir = dir.join("leaves").join("app.localhost");
    assert!(leaf_dir.join("fullchain.pem").is_file());
    assert!(leaf_dir.join("privkey.pem").is_file());
    // The serve_root endpoint got a leaf for its own name from the same CA.
    assert!(dir
        .join("leaves")
        .join("localhost")
        .join("fullchain.pem")
        .is_file());
    // The hierarchy is root -> intermediate -> leaf, and the served chain is
    // leaf + intermediate: the root stays in the client's trust store.
    assert!(dir.join("ca").join("intermediate.crt").is_file());
    assert!(dir.join("ca").join("intermediate.key").is_file());
    let chain = std::fs::read_to_string(leaf_dir.join("fullchain.pem")).unwrap();
    assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2, "{chain}");

    // A client that trusts only root.crt accepts the chain, and the leaf shows
    // the configured identity.
    let (status, text) = curl_with_root(https, "app.localhost", "/", &ca_cert);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("internal-backend"), "{text}");
    // The default subject layout of the CLI is not stable across OpenSSL
    // releases: 3.0 prints `O = rao-nagos` and 3.5 prints `O=rao-nagos`, so
    // reading the default form made this test pass locally and fail on the
    // older runner. RFC2253 is the machine-readable form and does not change.
    let (subject_status, subject) = Command::new("openssl")
        .args([
            "x509",
            "-noout",
            "-subject",
            "-nameopt",
            "RFC2253",
            "-in",
            &leaf_dir.join("fullchain.pem").display().to_string(),
        ])
        .output()
        .map(|o| {
            (
                o.status.success(),
                String::from_utf8_lossy(&o.stdout).into_owned(),
            )
        })
        .unwrap_or((false, String::new()));
    if subject_status {
        assert!(subject.contains("O=rao-nagos"), "{subject}");
        assert!(subject.contains("C=PF"), "{subject}");
        assert!(
            subject.contains("emailAddress=ops@rao-nagos.pf"),
            "{subject}"
        );
    }

    // The root is published over TLS at https://<zone>:<port>/root.crt.
    let body = fetch_root(root_port, "/root.crt");
    assert!(body.contains("BEGIN CERTIFICATE"), "{body}");
    assert_eq!(body, std::fs::read_to_string(&ca_cert).unwrap());

    // The VPN address was not available; the other domains must be unaffected.
    let text = wait_for_log(&log, "is not available");
    assert!(
        text.contains("192.0.2.1") && text.contains("skipping that listener"),
        "{text}"
    );
    assert!(text.contains("skipping `broken.local`"), "{text}");
    assert!(server.is_alive());

    // And the good domain still answers while the broken one did not kill it.
    let (status, text) = curl_with_root(https, "app.localhost", "/again", &ca_cert);
    assert_eq!(status, "200", "{text}");

    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}
