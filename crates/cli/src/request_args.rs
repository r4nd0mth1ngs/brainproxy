//! Request input shared by `send` and `fuzz`: a raw request (file or stdin) or a
//! curl-style --url request, plus where to send it and how.

use std::time::Duration;

use std::sync::Arc;

use brainproxy_core::guard::Guard;
use brainproxy_core::http::{RawRequest, SendOptions, Target};
use brainproxy_core::Error;

/// ASCII stand-in for a fuzz marker while a --url request is built, so URL
/// parsing doesn't percent-encode the marker.
const MARKER_SENTINEL: &str = "BPMARKERx7q";

#[derive(clap::Args, Clone)]
pub struct RequestArgs {
    /// Raw HTTP request file; '-' or omitted reads stdin (unless --url is given).
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
    /// Override the TLS SNI host name.
    #[arg(long)]
    pub sni: Option<String>,
    /// Send over HTTP/2 (ALPN h2 for https, prior knowledge for http). A raw
    /// request whose request line says HTTP/2 is sent over HTTP/2 anyway.
    #[arg(long)]
    pub http2: bool,
}

impl RequestArgs {
    pub fn reads_stdin(&self) -> bool {
        self.url.is_none() && self.file.as_deref().is_none_or(|f| f == "-")
    }

    pub fn send_options(&self, guard: Arc<Guard>) -> SendOptions {
        SendOptions {
            guard: Some(guard),
            timeout: Duration::from_secs_f64(self.timeout.max(0.001)),
            verify_tls: self.verify_tls,
            sni: self.sni.clone(),
            http2: self.http2,
        }
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
        if !self.verbatim && template_marker.is_none() {
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

pub fn parse_header(h: &str) -> Result<(String, String), Error> {
    h.split_once(':')
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty())
        .ok_or_else(|| Error::InvalidInput(format!("header {h:?} must look like 'Name: value'")))
}
