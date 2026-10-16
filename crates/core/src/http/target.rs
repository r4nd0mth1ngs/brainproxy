use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Where a request is sent: scheme, host, and port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Target {
    /// Parses `https://host[:port][/anything]`. A bare `host[:port]` defaults to https.
    pub fn from_url(input: &str) -> Result<Self> {
        let with_scheme = if input.contains("://") { input.to_string() } else { format!("https://{input}") };
        let url =
            url::Url::parse(&with_scheme).map_err(|e| Error::InvalidInput(format!("invalid target {input:?}: {e}")))?;
        let scheme = url.scheme().to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(Error::InvalidInput(format!("unsupported scheme {scheme:?}")));
        }
        let host = url
            .host_str()
            .ok_or_else(|| Error::InvalidInput(format!("target {input:?} has no host")))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = url.port_or_known_default().unwrap_or(if scheme == "https" { 443 } else { 80 });
        Ok(Self { scheme, host, port })
    }

    pub fn is_tls(&self) -> bool {
        self.scheme == "https"
    }

    pub fn default_port(&self) -> bool {
        (self.is_tls() && self.port == 443) || (!self.is_tls() && self.port == 80)
    }

    /// Value for a `Host` header: port is omitted when it's the scheme default.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub fn origin(&self) -> String {
        format!("{}://{}", self.scheme, self.host_header())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_targets() {
        let t = Target::from_url("example.test").unwrap();
        assert_eq!(t.origin(), "https://example.test");
        let t = Target::from_url("http://127.0.0.1:8080/path").unwrap();
        assert_eq!(t.origin(), "http://127.0.0.1:8080");
        let t = Target::from_url("https://[::1]:9443").unwrap();
        assert_eq!((t.host.as_str(), t.host_header()), ("::1", "[::1]:9443".to_string()));
        assert!(Target::from_url("ftp://x").is_err());
    }
}
