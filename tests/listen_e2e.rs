//! A `[[server]]` that overrides `listen`/`listen6` gets its own socket, and
//! that socket answers only for its own domains.
//!
//! This is the whole point of the per-server listener: a domain can live on a
//! dedicated address/port instead of the global one. The second half — a domain
//! from another group answering `421 Misdirected Request` — proves the listener
//! is not merely decorative.

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

use support::*;

/// One HTTP backend that answers with its name.
fn backend(name: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = name;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

fn config(
    dir: &Path,
    http: u16,
    https: u16,
    private_https: u16,
    main_backend: u16,
    private_backend: u16,
) -> String {
    let cert = dir.join("listen.local.crt");
    let key = dir.join("listen.local.key");
    format!(
        "[listen]\nipv4 = \"127.0.0.1\"\nhttp = {http}\nhttps = {https}\n\
         [tls]\nfallback_cert = true\n\
         [[server]]\ndomain = \"main.local\"\nkeys = \"manual\"\n\
         pub_key = \"{}\"\npriv_key = \"{}\"\nupstream = \"127.0.0.1:{main_backend}\"\n\
         [[server]]\ndomain = \"private.local\"\nkeys = \"manual\"\n\
         pub_key = \"{}\"\npriv_key = \"{}\"\nupstream = \"127.0.0.1:{private_backend}\"\n\
         https_listen = \"127.0.0.2:{private_https}\"\n",
        cert.display(),
        key.display(),
        cert.display(),
        key.display(),
    )
}

/// `curl -sk` against a chosen IP; `--resolve` keeps the SNI/Host correct.
fn curl_at(ip: &str, port: u16, host: &str, path: &str) -> (String, String) {
    let url = format!("https://{host}:{port}{path}");
    let resolve = format!("{host}:{port}:{ip}");
    let out = Command::new("curl")
        .args(["-sk", "-i", "--resolve", &resolve])
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
fn a_per_server_listener_serves_only_its_own_domain() {
    let dir = workspace("listen-e2e");
    let _ = cert_pair(&dir, "listen.local");

    let main_backend = backend("main");
    let private_backend = backend("private");

    let http = free_port();
    let https = free_port();
    // 127.0.0.2 is loopback on Linux, so this is a real second address without
    // needing any interface configuration.
    let probe = TcpListener::bind("127.0.0.2:0").expect("127.0.0.2 must be bindable");
    let private_https = probe.local_addr().unwrap().port();
    drop(probe);

    let cfg = dir.join("config.toml");
    write(
        &cfg,
        &config(
            &dir,
            http,
            https,
            private_https,
            main_backend,
            private_backend,
        ),
    );
    let log = dir.join("listen.log");
    let mut server = start(&cfg, &log, https);
    wait_for_log(
        &log,
        &format!("HTTPS listening on 127.0.0.2:{private_https}"),
    );

    let (status, text) = curl_at("127.0.0.1", https, "main.local", "/");
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("main"), "{text}");

    let (status, text) = curl_at("127.0.0.2", private_https, "private.local", "/");
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("private"), "{text}");

    // The global socket does not answer for the dedicated domain...
    let (status, text) = curl_at("127.0.0.1", https, "private.local", "/");
    assert_eq!(status, "421", "{text}");

    // ...and the dedicated socket does not answer for a global domain.
    let (status, text) = curl_at("127.0.0.2", private_https, "main.local", "/");
    assert_eq!(status, "421", "{text}");

    assert!(
        server.is_alive(),
        "server exited:\n{}",
        std::fs::read_to_string(&log).unwrap()
    );

    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}
