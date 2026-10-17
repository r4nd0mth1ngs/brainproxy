//! Per-parameter active rules ported from ZAP's ascanrules add-on (Apache License 2.0).

mod buffer_overflow;
mod common;
mod cross_site_scripting;
mod external_redirect;
mod format_string;
mod log4shell;
mod padding_oracle;
mod parameter_tamper;
mod path_traversal;
mod remote_file_include;
mod server_side_include;
mod ssti;
mod xpath_injection;
mod xxe;

use crate::scan::active::ActiveRule;

pub fn all() -> Vec<Box<dyn ActiveRule>> {
    vec![
        Box::new(cross_site_scripting::CrossSiteScripting),
        Box::new(path_traversal::PathTraversal),
        Box::new(remote_file_include::RemoteFileInclude),
        Box::new(server_side_include::ServerSideInclude),
        Box::new(ssti::Ssti),
        Box::new(xpath_injection::XpathInjection),
        Box::new(xxe::Xxe),
        Box::new(format_string::FormatString),
        Box::new(buffer_overflow::BufferOverflow),
        Box::new(external_redirect::ExternalRedirect),
        Box::new(parameter_tamper::ParameterTamper),
        Box::new(padding_oracle::PaddingOracle),
        Box::new(log4shell::Log4Shell),
    ]
}

#[cfg(test)]
mod e2e {
    //! The rules through the real engine against a tiny local app.
    use std::io::{Read, Write};
    use std::time::Duration;

    use crate::guard::{Guard, ScopeSpec};
    use crate::http::{SendOptions, Target};
    use crate::jobs::JobControl;
    use crate::scan::active::{run, ActiveConfig, ActiveSummary, PointOptions, ScanTarget, Strength};
    use crate::scan::message::url_decode;

    fn escape(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
    }

    fn respond(path: &str, query: &str) -> String {
        let param = |name: &str| -> String {
            query.split('&').find_map(|p| p.strip_prefix(&format!("{name}="))).map(url_decode).unwrap_or_default()
        };
        let ok = |ct: &str, body: String| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot found".to_string();
        match path {
            "/xss" => ok("text/html", format!("<html><body><p>Hello {}</p></body></html>", param("q"))),
            "/xss-safe" => ok("text/html", format!("<html><body><p>Hello {}</p></body></html>", escape(&param("q")))),
            "/file" => {
                let name = param("name");
                if name == "readme.txt" {
                    ok("text/plain", "read me".into())
                } else if name.ends_with("etc/passwd") {
                    ok("text/plain", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/bin/false\n".into())
                } else {
                    not_found
                }
            }
            "/file-safe" => {
                if param("name") == "readme.txt" {
                    ok("text/plain", "read me".into())
                } else {
                    not_found
                }
            }
            _ => not_found,
        }
    }

    fn spawn_app() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 65536];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let target = req.split(' ').nth(1).unwrap_or("/").to_string();
                    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                    let _ = s.write_all(respond(path, query).as_bytes());
                });
            }
        });
        port
    }

    fn fetch(port: u16, path: &str) -> (Vec<u8>, Vec<u8>) {
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").into_bytes();
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(&req).unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).unwrap();
        (req, resp)
    }

    async fn scan(name: &str, port: u16, paths: &[&str], rules: Option<Vec<u32>>) -> ActiveSummary {
        let project = std::env::temp_dir().join(format!("bp-params-{name}-{}.bpdb", std::process::id()));
        let _ = std::fs::remove_file(&project);
        let targets = paths
            .iter()
            .map(|p| {
                let (request, response) = fetch(port, p);
                let target = Target::from_url(&format!("http://127.0.0.1:{port}{p}")).unwrap();
                ScanTarget { history_id: None, target, request, response, duration_ms: None }
            })
            .collect();
        let guard =
            Guard::from_specs(vec![ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] }])
                .unwrap();
        let cfg = ActiveConfig {
            strength: Strength::Medium,
            concurrency: 4,
            rate: None,
            send: SendOptions { guard: Some(guard), timeout: Duration::from_secs(10), ..Default::default() },
            points: PointOptions::default(),
            rules,
            exclude_rules: vec![],
            max_duration: Some(Duration::from_secs(120)),
            auth: None,
            oob: None,
            oob_wait: std::time::Duration::ZERO,
        };
        let summary = run(&project, targets, cfg, JobControl::default()).await.unwrap();
        let _ = std::fs::remove_file(&project);
        summary
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn finds_xss_and_path_traversal() {
        let port = spawn_app();
        let s = scan("vuln", port, &["/xss?q=hi", "/file?name=readme.txt"], Some(vec![40012, 6])).await;
        assert_eq!(s.raised.get("40012"), Some(&1), "{s:?}");
        assert_eq!(s.raised.get("6-2"), Some(&1), "{s:?}");
        assert_eq!(s.raised.len(), 2, "{s:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn safe_endpoints_raise_nothing() {
        let port = spawn_app();
        let ids: Vec<u32> = super::all().iter().map(|r| r.id()).collect();
        let s = scan("safe", port, &["/xss-safe?q=hi", "/file-safe?name=readme.txt"], Some(ids)).await;
        assert!(s.raised.is_empty(), "false positives: {s:?}");
        assert!(s.requests > 20, "the rules did attack: {s:?}");
    }
}
