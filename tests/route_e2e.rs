//! End-to-end checks for `[[server.route]]` and the `[server."domain"]` form.
//!
//! Three throwaway HTTP backends on loopback and one TLS front: what is proven
//! is the operator-visible behaviour — the catch-all, a prefix route, prefix
//! stripping with a query string, the segment boundary, and the fact that a
//! route is tied to exactly one domain.

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;

use support::*;

/// A tiny HTTP/1.1 server that answers `<name> <request-target>` and closes.
fn backend(name: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = vec![0u8; 8192];
            let mut used = 0;
            while used < buf.len() {
                match stream.read(&mut buf[used..]) {
                    Ok(0) => break,
                    Ok(n) => {
                        used += n;
                        if buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => return,
                }
            }
            let request = String::from_utf8_lossy(&buf[..used]);
            let target = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");
            let body = format!("{name} {target}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

fn config(dir: &Path, http: u16, https: u16, backends: [u16; 3], static_root: &Path) -> String {
    let [catch_all, api, other_api] = backends;
    let cert = dir.join("route.local.crt");
    let key = dir.join("route.local.key");
    // The map form names the domain in the table key, so a route nested below
    // it cannot be mistaken for another domain's route.
    format!(
        "[listen]\nipv4 = \"127.0.0.1\"\nhttp = {http}\nhttps = {https}\n\
         [tls]\nfallback_cert = true\n\
         [server.\"route.local\"]\nkeys = \"manual\"\n\
         pub_key = \"{}\"\npriv_key = \"{}\"\nupstream = \"127.0.0.1:{catch_all}\"\n\
         [[server.\"route.local\".route]]\npath = \"/api\"\nupstream = \"127.0.0.1:{api}\"\nstrip_prefix = true\n\
         [[server.\"route.local\".route]]\npath = \"/assets\"\nroot = \"{}\"\nstrip_prefix = true\n\
         [server.\"other.local\"]\nkeys = \"manual\"\n\
         pub_key = \"{}\"\npriv_key = \"{}\"\nupstream = \"127.0.0.1:{other_api}\"\n\
         [[server.\"other.local\".route]]\npath = \"/api\"\nupstream = \"127.0.0.1:{other_api}\"\n",
        cert.display(),
        key.display(),
        static_root.display(),
        cert.display(),
        key.display(),
    )
}

#[test]
fn a_route_belongs_to_exactly_one_domain() {
    let dir = workspace("route-e2e");
    let _ = cert_pair(&dir, "route.local");
    let site = dir.join("site");
    std::fs::create_dir_all(site.join("assets")).unwrap();
    std::fs::write(site.join("assets/app.css"), b"body{}").unwrap();

    let catch_all = backend("catch-all");
    let api = backend("api");
    let other_api = backend("other-api");

    let http = free_port();
    let https = free_port();
    let cfg = dir.join("config.toml");
    write(
        &cfg,
        &config(
            &dir,
            http,
            https,
            [catch_all, api, other_api],
            &site.join("assets"),
        ),
    );
    let log = dir.join("route.log");
    let mut server = start(&cfg, &log, https);

    let (status, text) = curl(https, "route.local", "/", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("catch-all /"), "{text}");

    // The prefix is stripped, and the query survives the rewrite.
    let (status, text) = curl(https, "route.local", "/api/v1?x=1", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("api /v1?x=1"), "{text}");

    // `/api` alone becomes the root of the route's backend.
    let (status, text) = curl(https, "route.local", "/api", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("api /"), "{text}");

    // The other domain's `/api` route goes to the other backend, not this one.
    let (status, text) = curl(https, "other.local", "/api/v1", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("other-api /api/v1"), "{text}");

    // A prefix matches whole segments only.
    let (status, text) = curl(https, "route.local", "/apix", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("catch-all /apix"), "{text}");

    // A static route takes precedence over an upstream with the same prefix.
    let (status, text) = curl(https, "route.local", "/assets/app.css", &[]);
    assert_eq!(status, "200", "{text}");
    assert!(text.ends_with("body{}"), "{text}");

    assert!(
        server.is_alive(),
        "server exited:\n{}",
        std::fs::read_to_string(&log).unwrap()
    );

    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}
