//! Request input shared by `send` and `fuzz`: a raw request (file or stdin) or a
//! curl-style --url request, plus where to send it and how.

use std::time::Duration;

use std::sync::Arc;

use brainproxy_core::guard::Guard;
use brainproxy_core::http::{RawRequest, SendOptions, Target};
use brainproxy_core::Error;

/// ASCII stand-in for a fuzz marker while a --url request is built, so URL
/// parsing doesn't percent-encode the marker. Lower case, as parsing makes a host.
const MARKER_SENTINEL: &str = "bpmarkerx7q";

/// Longest wait or timeout a seconds flag takes: a day, as `ws send --wait` and Replay tabs.
const MAX_SECS: f64 = crate::ws_cmd::MAX_WAIT_SECS;
/// Longest `--max-minutes`: a week.
const MAX_MINUTES: f64 = 7.0 * 24.0 * 60.0;

/// A seconds flag as a duration. A value that isn't from 0 to a day is refused:
/// `Duration::from_secs_f64` panics on a negative, NaN or huge one, and a longer
/// wait would hold a connection, or the caller, for years.
pub(crate) fn secs_arg(flag: &str, secs: f64) -> Result<Duration, Error> {
    if !(0.0..=MAX_SECS).contains(&secs) {
        return Err(Error::InvalidInput(format!("{flag}: 0 to {MAX_SECS} seconds (a day), not {secs:?}")));
    }
    Ok(Duration::from_secs_f64(secs))
}

/// A wait for a whole job (`job wait --timeout`) as a duration: up to a week, as long as
/// `--max-minutes` lets a scan run (see [`secs_arg`]).
pub(crate) fn job_wait_arg(flag: &str, secs: f64) -> Result<Duration, Error> {
    if !(0.0..=MAX_MINUTES * 60.0).contains(&secs) {
        return Err(Error::InvalidInput(format!("{flag}: 0 to {} seconds (a week), not {secs:?}", MAX_MINUTES * 60.0)));
    }
    Ok(Duration::from_secs_f64(secs))
}

/// `--max-minutes` as a duration, refused unless it is from 0 to a week (see [`secs_arg`]).
pub(crate) fn minutes_arg(flag: &str, minutes: f64) -> Result<Duration, Error> {
    if !(0.0..=MAX_MINUTES).contains(&minutes) {
        return Err(Error::InvalidInput(format!("{flag}: 0 to {MAX_MINUTES} minutes (a week), not {minutes:?}")));
    }
    Ok(Duration::from_secs_f64(minutes * 60.0))
}

/// Refuses a requests-per-second flag the engine's limiters can't space: they wait 1/rate
/// seconds between requests, which panics making a `Duration` for a tiny rate. 0 is no limit.
pub(crate) fn check_rate(flag: &str, rate: Option<f64>) -> Result<(), Error> {
    match rate {
        Some(r) if r != 0.0 && !(r.is_finite() && r >= 1.0 / MAX_SECS) => Err(Error::InvalidInput(format!(
            "{flag}: 0 (no limit) or at least one request a day (1/{MAX_SECS} per second), not {r:?}"
        ))),
        _ => Ok(()),
    }
}

#[derive(clap::Args, Clone)]
pub struct RequestArgs {
    /// Raw HTTP request file; '-' or omitted reads stdin (unless --url is given). Through MCP only a file in the project's folder.
    pub file: Option<String>,

    /// Build the request from a URL instead of a raw file.
    #[arg(long)]
    pub url: Option<String>,
    /// Method for --url.
    #[arg(short = 'X', long, default_value = "GET")]
    pub method: String,
    /// Header for --url requests, or set on a raw request ("Name: value"). Repeatable.
    #[arg(short = 'H', long = "header")]
    pub headers: Vec<String>,
    /// Body for --url requests.
    #[arg(short = 'd', long)]
    pub data: Option<String>,

    /// Where to send a raw request (scheme://host[:port]). Defaults to the Host header.
    #[arg(long)]
    pub target: Option<String>,
    /// Scheme used with the Host header when --target is not given.
    #[arg(long, default_value = "https", value_parser = ["http", "https"])]
    pub scheme: String,
    /// Remove a header from the request. Repeatable.
    #[arg(long)]
    pub remove_header: Vec<String>,
    /// Send bytes exactly as given: no line-ending normalization, no Content-Length update.
    #[arg(long)]
    pub verbatim: bool,

    /// Timeout in seconds.
    #[arg(long, default_value_t = 30.0)]
    pub timeout: f64,
    /// Verify the server certificate (off by default, as with most intercepting tools).
    #[arg(long)]
    pub verify_tls: bool,
    /// Override the TLS SNI host name. A name other than the target's must be listed by
    /// name in the scope: on a shared front end it picks the site as much as the address does.
    #[arg(long)]
    pub sni: Option<String>,
    /// Send over HTTP/2 (ALPN h2 for https, prior knowledge for http). A raw
    /// request whose request line says HTTP/2 is sent over HTTP/2 anyway.
    #[arg(long)]
    pub http2: bool,
    /// Send over HTTP/3 (QUIC) to an https target that offers it, on its own UDP port or the
    /// one its Alt-Svc header named (which must be in scope too); else over TCP, with a warning
    /// saying why. A raw request whose request line says HTTP/3 is tried over HTTP/3 anyway.
    #[arg(long)]
    pub http3: bool,
    /// The request's Host header (or absolute URL) deliberately names a host the scope doesn't
    /// list, for a Host-header test. Through MCP such a request is refused without it.
    #[arg(long)]
    pub host_header_test: bool,
}

impl RequestArgs {
    pub fn reads_stdin(&self) -> bool {
        self.url.is_none() && self.file.as_deref().is_none_or(|f| f == "-")
    }

    pub fn send_options(&self, guard: Arc<Guard>) -> Result<SendOptions, Error> {
        Ok(SendOptions {
            guard: Some(guard),
            timeout: secs_arg("--timeout", self.timeout)?.max(Duration::from_millis(1)),
            verify_tls: self.verify_tls,
            sni: self.sni.clone(),
            http2: self.http2,
            http3: self.http3,
            host: brainproxy_core::http::client::HostPolicy::for_process(self.host_header_test),
            stream: Default::default(),
        })
    }

    /// Through MCP, points FILE at the file it resolves to inside the project's folder, and
    /// refuses one elsewhere (see [`crate::mcp::local_document`]): its bytes go on the wire and
    /// into history as they are. A FILE beside --url is never read, so it isn't checked.
    pub fn resolve_file(&mut self, project: &std::path::Path) -> Result<(), Error> {
        if let (None, Some(file)) = (&self.url, &self.file) {
            self.file = Some(crate::mcp::local_file_arg(
                project,
                "FILE",
                file,
                "pass the request on stdin (-), or build it with --url",
            )?);
        }
        Ok(())
    }

    /// Builds the request and works out its target. With `template_marker`
    /// (fuzzing), markers are preserved, Content-Length is left for after payload
    /// substitution, and --url requests use keep-alive.
    pub fn prepare(&self, template_marker: Option<&str>) -> Result<(RawRequest, Target), Error> {
        let headers = self.headers.iter().map(|h| parse_header(h)).collect::<Result<Vec<_>, _>>()?;
        let (mut req, inferred) = if let Some(url) = &self.url {
            let protect = |s: &str| match template_marker {
                Some(m) => s.replace(m, MARKER_SENTINEL),
                None => s.to_string(),
            };
            let headers: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.clone(), protect(v))).collect();
            let data = protect(self.data.as_deref().unwrap_or(""));
            let (req, target) = RawRequest::build(&self.method, &protect(url), &headers, data.as_bytes())?;
            let req = match template_marker {
                Some(m) => {
                    let text = String::from_utf8_lossy(req.as_bytes()).replace(MARKER_SENTINEL, m);
                    let req = RawRequest::from_bytes(text.into_bytes());
                    if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("connection")) {
                        req
                    } else {
                        req.set_header("Connection", "keep-alive")
                    }
                }
                None => req,
            };
            (req, Some(target))
        } else {
            let bytes = match self.file.as_deref() {
                Some(path) if path != "-" => std::fs::read(path)
                    .map_err(|e| Error::InvalidInput(format!("cannot read request file {path:?}: {e}")))?,
                _ => crate::read_input(None)?,
            };
            if bytes.iter().all(u8::is_ascii_whitespace) {
                return Err(Error::InvalidInput("empty request; pass a FILE, stdin, or --url".into()));
            }
            let mut req = RawRequest::from_bytes(bytes);
            if !self.verbatim {
                req = req.normalize_line_endings();
            }
            for (k, v) in &headers {
                req = req.set_header(k, v);
            }
            (req, None)
        };
        for name in &self.remove_header {
            req = req.remove_header(name);
        }
        // A removed Content-Length stays removed: the update would add it back for any body.
        let keeps_length = !self.remove_header.iter().any(|h| h.eq_ignore_ascii_case("content-length"));
        if !self.verbatim && template_marker.is_none() && keeps_length {
            req = req.update_content_length();
        }
        let target = match (&self.target, inferred) {
            (Some(t), _) => Target::from_url(t)?,
            (None, Some(t)) => t,
            (None, None) => req.infer_target(&self.scheme)?,
        };
        Ok((req, target))
    }
}

/// `Name: value`, refused with a line break or NUL in it (see [`check_header`]).
///
/// [`check_header`]: brainproxy_core::http::request::check_header
pub fn parse_header(h: &str) -> Result<(String, String), Error> {
    let (k, v) = h
        .split_once(':')
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty())
        .ok_or_else(|| Error::InvalidInput(format!("header {h:?} must look like 'Name: value'")))?;
    brainproxy_core::http::request::check_header(&k, &v)?;
    Ok((k, v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Args {
        #[command(flatten)]
        req: RequestArgs,
    }

    fn args(argv: &[&str]) -> RequestArgs {
        Args::parse_from(std::iter::once("t").chain(argv.iter().copied())).req
    }

    #[test]
    fn a_marker_in_the_url_host_is_kept() {
        let (req, _) = args(&["--url", "http://§a§.local/§p§"]).prepare(Some("§")).unwrap();
        let text = String::from_utf8_lossy(req.as_bytes()).into_owned();
        assert!(text.starts_with("GET /§p§ HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("\r\nHost: §a§.local\r\n"), "{text}");
    }

    #[test]
    fn a_removed_content_length_stays_removed() {
        let file = std::env::temp_dir().join(format!("bp-remove-cl-{}.http", std::process::id()));
        let path = file.to_str().unwrap();
        let head = |request: &str, argv: &[&str]| {
            std::fs::write(&file, request).unwrap();
            let (req, _) = args(&[&[path], argv].concat()).prepare(None).unwrap();
            String::from_utf8_lossy(req.as_bytes()).to_ascii_lowercase()
        };
        let post = "POST / HTTP/1.1\nHost: a.test\nContent-Length: 2\n\nhello";
        assert!(!head(post, &["--remove-header", "content-length"]).contains("content-length"));
        // The update still applies otherwise, and to a request whose Transfer-Encoding is removed.
        assert!(head(post, &[]).contains("content-length: 5\r\n"));
        let chunked = "POST / HTTP/1.1\nHost: a.test\nTransfer-Encoding: chunked\n\nhello";
        assert!(!head(chunked, &[]).contains("content-length"));
        assert!(head(chunked, &["--remove-header", "Transfer-Encoding"]).contains("content-length: 5\r\n"));
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn seconds_and_rates_are_checked_not_panicked_on() {
        for bad in [f64::INFINITY, f64::NAN, -1.0, 1e300, MAX_SECS + 0.5] {
            let e = secs_arg("--timeout", bad).unwrap_err();
            assert!(e.to_string().contains("--timeout: 0 to 86400 seconds"), "{bad}: {e}");
            assert!(minutes_arg("--max-minutes", bad * 60.0).is_err(), "{bad}");
        }
        assert_eq!(secs_arg("--wait", 1.5).unwrap(), Duration::from_millis(1500));
        assert_eq!(minutes_arg("--max-minutes", 0.5).unwrap(), Duration::from_secs(30));
        // A job may run for as long as --max-minutes allows, so waiting for one may too.
        assert_eq!(job_wait_arg("--timeout", 100_000.0).unwrap(), Duration::from_secs(100_000));
        for bad in [-1.0, f64::INFINITY, f64::NAN, 604_801.0] {
            assert!(job_wait_arg("--timeout", bad).is_err(), "{bad}");
        }
        for bad in [1e-300, -1.0, f64::NAN, f64::INFINITY] {
            assert!(check_rate("--rate", Some(bad)).unwrap_err().to_string().contains("--rate:"), "{bad}");
        }
        for ok in [None, Some(0.0), Some(1.0 / MAX_SECS), Some(1000.0)] {
            assert!(check_rate("--rate", ok).is_ok(), "{ok:?}");
        }
    }
}
