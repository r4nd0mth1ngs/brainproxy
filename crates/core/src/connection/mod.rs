//! Connection options: upstream proxies, host name overrides, client TLS
//! certificates, TLS pass-through, and platform authentication (from auth
//! profiles). They live in the project database like the proxy settings, so a
//! running proxy picks up changes within a second; other commands read them when
//! they start.
//!
//! None of them widens the engagement scope. Every target is still resolved and
//! checked by the [`crate::guard::Guard`] (an override replaces DNS, its address is
//! checked, and an internal one must be listed by address), and an upstream proxy is told
//! to connect to the checked address, never the name, so it can't reach an address
//! the guard didn't check. The proxy itself must be on this machine or listed in
//! every scope's `proxies` (see [`crate::guard::Guard::resolve_proxy`]).
//!
//! Secrets are never stored here: proxy and PKCS#12 passwords are read from
//! environment variables when they are used. (The settings live in the `meta`
//! table, which `query` can read; auth profiles, which hold platform passwords,
//! can't be.)

pub mod certs;
#[cfg(test)]
mod e2e;
pub mod platform;
pub mod upstream;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub use certs::ClientIdentity;
pub use platform::{PlatformAuth, PlatformCred, PlatformScheme};
pub use upstream::{ProxyKind, UpstreamProxy};

/// Settings key (`setting.connection` in `meta`).
pub const CONNECTION_KEY: &str = "connection";

/// Connection options as stored. Lists are ordered; for upstream rules and client
/// certificates the first entry whose host pattern matches wins.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ConnectionSettings {
    #[serde(default)]
    pub upstream: Vec<UpstreamRule>,
    #[serde(default)]
    pub hosts: Vec<HostOverride>,
    #[serde(default)]
    pub client_certs: Vec<ClientCert>,
    /// Host patterns whose TLS the proxy tunnels without decrypting.
    #[serde(default)]
    pub passthrough: Vec<String>,
}

/// Which way connections to matching hosts go.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpstreamRule {
    /// Host pattern (see [`HostPattern`]).
    pub host: String,
    /// `http://HOST:PORT` (HTTP CONNECT) or `socks5://HOST:PORT`; none means direct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Environment variable holding the proxy password, read at connect time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_env: Option<String>,
}

/// `/etc/hosts`-style override: connect to `ip` for `host` instead of asking DNS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostOverride {
    pub host: String,
    pub ip: IpAddr,
}

/// A client certificate offered to matching hosts (mutual TLS): a PEM certificate
/// chain and key, or a PKCS#12 file.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ClientCert {
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkcs12: Option<PathBuf>,
    /// Environment variable holding the PKCS#12 password (none: empty password).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_env: Option<String>,
}

/// A host pattern: a name or address where `*` matches any run of characters and
/// `?` one character, case-insensitive, optionally followed by `:PORT`
/// (`[v6]:PORT` for IPv6). `*.example.com` matches subdomains, not `example.com`;
/// `*` matches every host.
#[derive(Debug, Clone, PartialEq)]
pub struct HostPattern {
    raw: String,
    glob: Vec<char>,
    port: Option<u16>,
}

impl HostPattern {
    pub fn parse(raw: &str) -> Result<Self> {
        let s = raw.trim().to_ascii_lowercase();
        let bad =
            || Error::InvalidInput(format!("bad host pattern {raw:?}: use a host, *.domain, or *, optionally :port"));
        if s.is_empty() || s.contains("://") || s.contains('/') || s.contains(char::is_whitespace) {
            return Err(bad());
        }
        let (body, port) = if let Some(rest) = s.strip_prefix('[') {
            let (inner, after) = rest.split_once(']').ok_or_else(bad)?;
            match after.strip_prefix(':') {
                Some(p) => (inner.to_string(), Some(p.parse::<u16>().map_err(|_| bad())?)),
                None if after.is_empty() => (inner.to_string(), None),
                None => return Err(bad()),
            }
        } else if s.matches(':').count() == 1 {
            let (b, p) = s.split_once(':').unwrap();
            (b.to_string(), Some(p.parse::<u16>().map_err(|_| bad())?))
        } else {
            (s.clone(), None)
        };
        let body = body.strip_suffix('.').unwrap_or(&body).to_string();
        if body.is_empty() {
            return Err(bad());
        }
        Ok(Self { raw: raw.trim().to_string(), glob: body.chars().collect(), port })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn matches(&self, host: &str, port: u16) -> bool {
        self.port.is_none_or(|p| p == port) && glob(&self.glob, &norm_host(host).chars().collect::<Vec<_>>())
    }
}

fn glob(pattern: &[char], text: &[char]) -> bool {
    // Iterative wildcard match with backtracking to the last `*`.
    let (mut p, mut t, mut star, mut mark) = (0, 0, None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

/// Hosts compared without brackets, in lowercase, and without one trailing dot.
pub(crate) fn norm_host(host: &str) -> String {
    let h = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    h.strip_suffix('.').map(str::to_string).unwrap_or(h)
}

/// How a connection to a target is made.
#[derive(Debug, Clone)]
pub enum Route {
    Direct,
    Proxy(Arc<UpstreamProxy>),
}

/// Connection options ready to use. Each compile gets a new generation, which is
/// part of the client's pool key, so no pooled connection outlives the settings it
/// was opened with.
#[derive(Debug, Default)]
pub struct Compiled {
    pub generation: u64,
    upstream: Vec<(HostPattern, Route)>,
    hosts: HashMap<String, IpAddr>,
    certs: Vec<(HostPattern, Arc<ClientIdentity>)>,
    passthrough: Vec<HostPattern>,
    platform: Vec<Arc<PlatformCred>>,
}

static GENERATION: AtomicU64 = AtomicU64::new(1);

impl ConnectionSettings {
    /// Checks every entry. Client certificate files are loaded here too, so a bad
    /// path or password is reported when the setting is made.
    pub fn validate(&self) -> Result<()> {
        let compiled = self.compile(Vec::new())?;
        for (pattern, id) in &compiled.certs {
            if let Some(e) = &id.error {
                return Err(Error::InvalidInput(format!("client certificate for {}: {e}", pattern.as_str())));
            }
        }
        Ok(())
    }

    /// Compiles the settings with the platform credentials of the project's auth
    /// profiles. A client certificate that can't be loaded doesn't fail the whole
    /// compile: connections to its hosts fail with the reason instead (never
    /// silently without the certificate).
    pub fn compile(&self, platform: Vec<PlatformCred>) -> Result<Compiled> {
        let mut upstream = Vec::new();
        for r in &self.upstream {
            let route = match &r.proxy {
                None => Route::Direct,
                Some(url) => {
                    Route::Proxy(Arc::new(UpstreamProxy::parse(url, r.username.clone(), r.password_env.clone())?))
                }
            };
            upstream.push((HostPattern::parse(&r.host)?, route));
        }
        let mut hosts = HashMap::new();
        for h in &self.hosts {
            let name = norm_host(&h.host);
            if name.parse::<IpAddr>().is_ok() || name.contains(['*', '?']) || !valid_name(&name) {
                return Err(Error::InvalidInput(format!("bad host override {:?}: give a host name", h.host)));
            }
            hosts.insert(name, h.ip);
        }
        let certs = self
            .client_certs
            .iter()
            .map(|c| Ok((HostPattern::parse(&c.host)?, Arc::new(ClientIdentity::load(c)?))))
            .collect::<Result<Vec<_>>>()?;
        let passthrough = self.passthrough.iter().map(|p| HostPattern::parse(p)).collect::<Result<Vec<_>>>()?;
        Ok(Compiled {
            generation: GENERATION.fetch_add(1, Ordering::Relaxed),
            upstream,
            hosts,
            certs,
            passthrough,
            platform: platform.into_iter().map(Arc::new).collect(),
        })
    }
}

pub(crate) fn valid_name(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

impl Compiled {
    pub fn route(&self, host: &str, port: u16) -> Route {
        self.upstream.iter().find(|(p, _)| p.matches(host, port)).map(|(_, r)| r.clone()).unwrap_or(Route::Direct)
    }

    pub fn host_override(&self, host: &str) -> Option<IpAddr> {
        self.hosts.get(&norm_host(host)).copied()
    }

    pub fn client_cert(&self, host: &str, port: u16) -> Option<(usize, Arc<ClientIdentity>)> {
        self.certs.iter().enumerate().find(|(_, (p, _))| p.matches(host, port)).map(|(i, (_, id))| (i, id.clone()))
    }

    pub fn passthrough(&self, host: &str, port: u16) -> bool {
        self.passthrough.iter().any(|p| p.matches(host, port))
    }

    /// The platform credentials for a host, first match first.
    pub fn platform(&self, host: &str, port: u16) -> Option<Arc<PlatformCred>> {
        self.platform.iter().find(|c| c.matches(host, port)).cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.upstream.is_empty()
            && self.hosts.is_empty()
            && self.certs.is_empty()
            && self.passthrough.is_empty()
            && self.platform.is_empty()
    }
}

/// The options in force, shared by every client of a command through the guard. A
/// running proxy replaces them when the settings change.
#[derive(Default)]
pub struct Live(RwLock<Arc<Compiled>>);

impl Live {
    pub fn get(&self) -> Arc<Compiled> {
        self.0.read().unwrap().clone()
    }

    pub fn set(&self, compiled: Compiled) {
        *self.0.write().unwrap() = Arc::new(compiled);
    }
}

impl Clone for Live {
    fn clone(&self) -> Self {
        Live(RwLock::new(self.get()))
    }
}

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Live(generation {})", self.get().generation)
    }
}

impl crate::store::Store {
    pub fn connection_settings(&self) -> Result<ConnectionSettings> {
        self.setting(CONNECTION_KEY)
    }

    /// The connection options with every auth profile's platform credentials.
    pub fn connection_compiled(&self) -> Result<Compiled> {
        let platform = self
            .auth_list()?
            .into_iter()
            .filter_map(|(p, _)| PlatformCred::from_profile(&p))
            .collect::<Result<Vec<_>>>()?;
        self.connection_settings()?.compile(platform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_patterns() {
        let p = |s: &str| HostPattern::parse(s).unwrap();
        assert!(p("*.corp.test").matches("a.b.corp.test", 443));
        assert!(!p("*.corp.test").matches("corp.test", 443));
        assert!(p("*").matches("anything", 1));
        assert!(p("APP.test").matches("app.test.", 80));
        assert!(p("app?.test").matches("app1.test", 80) && !p("app?.test").matches("app.test", 80));
        assert!(p("app.test:8443").matches("app.test", 8443) && !p("app.test:8443").matches("app.test", 443));
        assert!(p("[::1]:443").matches("::1", 443) && p("::1").matches("[::1]", 80));
        assert!(p("10.0.*").matches("10.0.3.4", 80));
        for bad in ["", "http://x", "a b", "x:99999", "a/b", ":80"] {
            assert!(HostPattern::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn first_matching_rule_wins_and_overrides_are_names() {
        let s = ConnectionSettings {
            upstream: vec![
                UpstreamRule { host: "direct.corp.test".into(), proxy: None, username: None, password_env: None },
                UpstreamRule {
                    host: "*.corp.test".into(),
                    proxy: Some("socks5://127.0.0.1:1080".into()),
                    username: None,
                    password_env: None,
                },
            ],
            hosts: vec![HostOverride { host: "App.Test.".into(), ip: "10.0.0.5".parse().unwrap() }],
            ..Default::default()
        };
        let c = s.compile(vec![]).unwrap();
        assert!(matches!(c.route("direct.corp.test", 443), Route::Direct));
        assert!(matches!(c.route("x.corp.test", 443), Route::Proxy(_)));
        assert!(matches!(c.route("other.test", 443), Route::Direct));
        assert_eq!(c.host_override("app.test"), Some("10.0.0.5".parse().unwrap()));
        let bad = ConnectionSettings {
            hosts: vec![HostOverride { host: "*.test".into(), ip: "10.0.0.5".parse().unwrap() }],
            ..Default::default()
        };
        assert!(bad.validate().is_err());
        assert!(c.generation != s.compile(vec![]).unwrap().generation);
    }
}
