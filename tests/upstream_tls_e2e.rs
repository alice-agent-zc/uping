//! HTTPS to the backend: verification, a private CA, SNI, and the opt-out.
//!
//! One TLS backend with a certificate for `tls.local`, three front domains:
//! `verify.local` verifies it against its CA, `insecure.local` disables
//! verification, and `mismatch.local` verifies but sends the wrong SNI, which
//! must fail.

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;

use support::*;

/// An HTTPS backend that answers `tls-backend <request-target>`.
fn tls_backend(cert: &Path, key: &Path) -> u16 {
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor
        .set_private_key_file(key, SslFiletype::PEM)
        .unwrap();
    acceptor.set_certificate_chain_file(cert).unwrap();
    acceptor.check_private_key().unwrap();
    let acceptor = Arc::new(acceptor.build());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let Ok(mut tls) = acceptor.accept(stream) else {
                continue;
            };
            let mut buf = [0u8; 4096];
            let mut used = 0;
            while used < buf.len() {
                match tls.read(&mut buf[used..]) {
                    Ok(0) => break,
                    Ok(n) => {
                        used += n;
                        if buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let request = String::from_utf8_lossy(&buf[..used]);
            let target = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");
            let body = format!("tls-backend {target}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = tls.write_all(response.as_bytes());
        }
    });
    port
}

fn config(dir: &Path, http: u16, https: u16, backend: u16) -> String {
    let cert = dir.join("tls.local.crt");
    let key = dir.join("tls.local.key");
    format!(
        "[listen]\nipv4 = \"127.0.0.1\"\nhttp = {http}\nhttps = {https}\n\
         [health]\ninterval_ms = 0\n\
         [server.\"verify.local\"]\nkeys = \"manual\"\n\
         pub_key = \"{}\"\npriv_key = \"{}\"\nupstream = \"127.0.0.1:{backend}\"\n\
         upstream_tls = true\nupstream_sni = \"tls.local\"\nupstream_ca = \"{}\"\n\
         [server.\"insecure.local\"]\nkeys = \"manual\"\n\
         pub_key = \"{}\"\npriv_key = \"{}\"\nupstream = \"127.0.0.1:{backend}\"\n\
         upstream_tls = true\nupstream_sni = \"wrong.local\"\nupstream_verify = false\n\
         [server.\"mismatch.local\"]\nkeys = \"manual\"\n\
         pub_key = \"{}\"\npriv_key = \"{}\"\nupstream = \"127.0.0.1:{backend}\"\n\
         upstream_tls = true\nupstream_sni = \"wrong.local\"\nupstream_ca = \"{}\"\n",
        cert.display(),
        key.display(),
        cert.display(),
        cert.display(),
        key.display(),
        cert.display(),
        key.display(),
        cert.display(),
    )
}

#[test]
fn upstream_tls_verifies_with_a_private_ca_and_can_be_opted_out() {
    let dir = workspace("upstream-tls-e2e");
    let (cert, key) = cert_pair(&dir, "tls.local");
    let backend = tls_backend(&cert, &key);

    let http = free_port();
    let https = free_port();
    let cfg = dir.join("config.toml");
    write(&cfg, &config(&dir, http, https, backend));
    let log = dir.join("upstream-tls.log");
    let mut server = start(&cfg, &log, https);

    // Verified against the private CA, with the matching SNI.
    let (status, text) = curl(https, "verify.local", "/a", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("tls-backend /a"), "{text}");

    // No verification, a deliberately wrong SNI: accepted.
    let (status, text) = curl(https, "insecure.local", "/b", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("tls-backend /b"), "{text}");

    // Verification on, wrong SNI: the handshake must fail, not fall through.
    let (status, text) = curl(https, "mismatch.local", "/c", &[]);
    assert_eq!(status, "502", "{text}");

    assert!(
        server.is_alive(),
        "server exited:\n{}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );

    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}
