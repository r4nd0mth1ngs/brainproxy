//! Engagement scope guard: the hard boundary for every outbound connection.
//!
//! Two sources, both optional, both enforced when present:
//! - The system scope file (`/etc/brainproxy/scope.json`), written by whoever
//!   provisions the runner. No flag or environment variable can override it while
//!   it exists, so an agent running brainproxy cannot widen it.
//! - The project's engagement scope, set once by `engagement start` and never
//!   modifiable afterwards.
//!
//! A connection is allowed only if every present source allows it. With no source
//! at all, nothing is sent. Hostnames are resolved and checked before connecting,
//! and the connection goes to the checked address, so DNS changes between check
//! and connect don't matter. Link-local addresses (including cloud metadata at
//! 169.254.169.254) are refused unless explicitly included by address.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const SYSTEM_SCOPE_PATH: &str = "/etc/brainproxy/scope.json";
/// Only honoured when the system scope file does not exist (tests, non-root setups).
pub const SYSTEM_SCOPE_ENV: &str = "BRAINPROXY_SYSTEM_SCOPE";
pub const ENGAGEMENT_KEY: &str = "engagement";

/// Scope as written in the system file or stored for an engagement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScopeSpec {
    #[serde(default)]
    pub name: Option<String>,
    /// Allowed targets: `host`, `*.domain`, `IP`, or `CIDR`, each with optional `:port`.
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum Pattern {
    Host(String),
    /// `*.example.com`: subdomains only (not example.com itself).
    Wildcard(String),
    Net(IpAddr, u8),
}

#[derive(Debug, Clone, PartialEq)]
struct Entry {
    pattern: Pattern,
    port: Option<u16>,
}

impl Entry {
    fn parse(raw: &str) -> Result<Self> {
        let s = raw.trim().to_ascii_lowercase();
        let bad = || {
            Error::InvalidInput(format!("bad scope entry {raw:?}: use host, *.domain, IP, or CIDR, optionally :port"))
        };
        if s.is_empty() || s.contains("://") {
            return Err(bad());
        }
        // Split an optional port: "[v6]:443", "host:443", "10.0.0.0/8:443". Bare IPv6 has no port.
        let (body, port) = if let Some(rest) = s.strip_prefix('[') {
            let (inner, after) = rest.split_once(']').ok_or_else(bad)?;
            let port = match after.strip_prefix(':') {
                Some(p) => Some(p.parse::<u16>().map_err(|_| bad())?),
                None if after.is_empty() => None,
                None => return Err(bad()),
            };
            (inner.to_string(), port)
        } else if s.matches(':').count() == 1 {
            let (b, p) = s.split_once(':').unwrap();
            (b.to_string(), Some(p.parse::<u16>().map_err(|_| bad())?))
        } else {
            (s.clone(), None)
        };
        let pattern = if let Some((ip, bits)) = body.split_once('/') {
            let ip: IpAddr = ip.parse().map_err(|_| bad())?;
            let bits: u8 = bits.parse().map_err(|_| bad())?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if bits > max {
                return Err(bad());
            }
            Pattern::Net(ip, bits)
        } else if let Ok(ip) = body.parse::<IpAddr>() {
            Pattern::Net(ip, if ip.is_ipv4() { 32 } else { 128 })
        } else if let Some(domain) = body.strip_prefix("*.") {
            if !valid_host(domain) {
                return Err(bad());
            }
            Pattern::Wildcard(domain.to_string())
        } else {
            if !valid_host(&body) {
                return Err(bad());
            }
            Pattern::Host(body)
        };
        Ok(Self { pattern, port })
    }

    fn port_ok(&self, port: u16) -> bool {
        self.port.is_none_or(|p| p == port)
    }

    fn matches_name(&self, host: &str, port: u16) -> bool {
        self.port_ok(port)
            && match &self.pattern {
                Pattern::Host(h) => host == h,
                Pattern::Wildcard(d) => host.len() > d.len() + 1 && host.ends_with(&format!(".{d}")),
                Pattern::Net(..) => false,
            }
    }

    fn matches_addr(&self, ip: IpAddr, port: u16) -> bool {
        self.port_ok(port) && matches!(self.pattern, Pattern::Net(net, bits) if in_net(ip, net, bits))
    }

    fn names_addr_explicitly(&self, ip: IpAddr) -> bool {
        matches!(self.pattern, Pattern::Net(net, bits) if in_net(ip, net, bits))
    }
}

fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

fn in_net(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits as u32) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits as u32) };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.to_ipv4_mapped().is_some_and(|v4| v4.is_link_local()) || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// One compiled scope.
#[derive(Debug, Clone)]
pub struct Scope {
    pub spec: ScopeSpec,
    pub origin: String,
    include: Vec<Entry>,
    exclude: Vec<Entry>,
}

impl Scope {
    pub fn compile(spec: ScopeSpec, origin: &str) -> Result<Self> {
        if spec.include.is_empty() {
            return Err(Error::InvalidInput(format!("{origin}: scope must include at least one target")));
        }
        let include = spec.include.iter().map(|e| Entry::parse(e)).collect::<Result<Vec<_>>>()?;
        let exclude = spec.exclude.iter().map(|e| Entry::parse(e)).collect::<Result<Vec<_>>>()?;
        Ok(Self { spec, origin: origin.to_string(), include, exclude })
    }

    /// Whether connecting to `host:port`, resolved to `addrs`, is allowed. Returns
    /// the addresses that may be used.
    fn allowed_addrs(&self, host: &str, port: u16, addrs: &[IpAddr]) -> std::result::Result<Vec<IpAddr>, String> {
        let host = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
        let literal = host.parse::<IpAddr>().ok();
        if literal.is_none() && self.exclude.iter().any(|e| e.matches_name(&host, port)) {
            return Err(format!("{host} is excluded by the {}", self.origin));
        }
        let name_ok = literal.is_none() && self.include.iter().any(|e| e.matches_name(&host, port));
        let mut ok = Vec::new();
        for &ip in addrs {
            if self.exclude.iter().any(|e| e.matches_addr(ip, port)) {
                continue;
            }
            let addr_ok = self.include.iter().any(|e| e.matches_addr(ip, port));
            if !(name_ok || addr_ok) {
                continue;
            }
            if is_link_local(ip) && !self.include.iter().any(|e| e.names_addr_explicitly(ip)) {
                continue;
            }
            ok.push(ip);
        }
        if ok.is_empty() {
            return Err(format!("{host}:{port} is outside the {}", self.origin));
        }
        Ok(ok)
    }
}

/// All scopes in force. Every one must allow a connection.
#[derive(Debug, Clone, Default)]
pub struct Guard {
    scopes: Vec<Scope>,
}

impl Guard {
    /// Loads the system scope plus the project's engagement scope.
    pub fn load(engagement: Option<ScopeSpec>) -> Result<Arc<Self>> {
        let mut scopes = Vec::new();
        if let Some(spec) = load_system_scope()? {
            scopes.push(Scope::compile(spec, "system scope")?);
        }
        if let Some(spec) = engagement {
            scopes.push(Scope::compile(spec, "engagement scope")?);
        }
        if scopes.is_empty() {
            return Err(Error::OutOfScope(
                "no engagement scope: run `brainproxy engagement start --target HOST ...` first".into(),
            ));
        }
        Ok(Arc::new(Self { scopes }))
    }

    /// A guard from explicit specs (no system file), for tests and embedding.
    pub fn from_specs(specs: Vec<ScopeSpec>) -> Result<Arc<Self>> {
        let scopes = specs.into_iter().map(|s| Scope::compile(s, "engagement scope")).collect::<Result<Vec<_>>>()?;
        if scopes.is_empty() {
            return Err(Error::OutOfScope("no scope".into()));
        }
        Ok(Arc::new(Self { scopes }))
    }

    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Resolves `host` and returns the socket addresses every scope allows.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let addrs: Vec<IpAddr> = match bare.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => {
                // Refuse names no scope could allow before touching DNS.
                self.precheck_name(bare, port)?;
                tokio::net::lookup_host((bare, port))
                    .await
                    .map_err(|e| Error::Connect(format!("{bare}: {e}")))?
                    .map(|a| a.ip())
                    .collect()
            }
        };
        let mut allowed = addrs.clone();
        for scope in &self.scopes {
            let ok = scope.allowed_addrs(bare, port, &allowed).map_err(Error::OutOfScope)?;
            allowed.retain(|ip| ok.contains(ip));
        }
        if allowed.is_empty() {
            return Err(Error::OutOfScope(format!("{bare}:{port} resolves only to addresses outside the scope")));
        }
        Ok(allowed.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
    }

    /// Quick name-only check (no DNS): false when no scope could ever allow it.
    fn precheck_name(&self, host: &str, port: u16) -> Result<()> {
        let host = host.to_ascii_lowercase();
        for scope in &self.scopes {
            if scope.exclude.iter().any(|e| e.matches_name(&host, port)) {
                return Err(Error::OutOfScope(format!("{host} is excluded by the {}", scope.origin)));
            }
            let has_net = scope.include.iter().any(|e| matches!(e.pattern, Pattern::Net(..)));
            if !has_net && !scope.include.iter().any(|e| e.matches_name(&host, port)) {
                return Err(Error::OutOfScope(format!("{host}:{port} is outside the {}", scope.origin)));
            }
        }
        Ok(())
    }

    /// Cheap check without DNS: false when the target can't possibly be in scope
    /// (true can still be refused at connect time, e.g. for CIDR-only scopes).
    pub fn may_allow(&self, host: &str, port: u16) -> bool {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        match bare.parse::<IpAddr>() {
            Ok(ip) => self.scopes.iter().all(|s| s.allowed_addrs(bare, port, &[ip]).is_ok()),
            Err(_) => self.precheck_name(bare, port).is_ok(),
        }
    }
}

fn system_scope_path() -> Option<PathBuf> {
    let fixed = Path::new(SYSTEM_SCOPE_PATH);
    if fixed.exists() {
        return Some(fixed.to_path_buf());
    }
    std::env::var_os(SYSTEM_SCOPE_ENV).map(PathBuf::from)
}

/// The system scope, if configured. A configured but unreadable or invalid file is
/// an error, never "no scope".
pub fn load_system_scope() -> Result<Option<ScopeSpec>> {
    let Some(path) = system_scope_path() else { return Ok(None) };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| Error::OutOfScope(format!("system scope {} unreadable: {e}", path.display())))?;
    let spec: ScopeSpec = serde_json::from_str(&text)
        .map_err(|e| Error::OutOfScope(format!("system scope {} invalid: {e}", path.display())))?;
    Ok(Some(spec))
}

pub fn system_scope_location() -> Option<PathBuf> {
    system_scope_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(include: &[&str], exclude: &[&str]) -> ScopeSpec {
        ScopeSpec {
            name: None,
            include: include.iter().map(|s| s.to_string()).collect(),
            exclude: exclude.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn ips(s: &[&str]) -> Vec<IpAddr> {
        s.iter().map(|i| i.parse().unwrap()).collect()
    }

    #[test]
    fn parses_entries() {
        for ok in [
            "example.com",
            "*.example.com",
            "10.0.0.5",
            "10.0.0.0/8",
            "example.com:8443",
            "[::1]:443",
            "::1",
            "fd00::/8",
        ] {
            Entry::parse(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in ["", "https://example.com", "10.0.0.0/33", "exa mple.com", "host:99999", "*.", "a..b"] {
            assert!(Entry::parse(bad).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn host_wildcard_port_and_exclude() {
        let s = Scope::compile(spec(&["example.com", "*.api.test:8443"], &["admin.api.test"]), "t").unwrap();
        let any = ips(&["93.184.216.34"]);
        assert!(s.allowed_addrs("EXAMPLE.com", 443, &any).is_ok());
        assert!(s.allowed_addrs("www.example.com", 443, &any).is_err());
        assert!(s.allowed_addrs("v1.api.test", 8443, &any).is_ok());
        assert!(s.allowed_addrs("v1.api.test", 443, &any).is_err());
        assert!(s.allowed_addrs("api.test", 8443, &any).is_err());
        assert!(s.allowed_addrs("admin.api.test", 8443, &any).is_err());
    }

    #[test]
    fn cidr_and_link_local() {
        let s = Scope::compile(spec(&["10.0.0.0/24", "app.test"], &["10.0.0.9"]), "t").unwrap();
        assert!(s.allowed_addrs("10.0.0.5", 80, &ips(&["10.0.0.5"])).is_ok());
        assert!(s.allowed_addrs("10.0.0.9", 80, &ips(&["10.0.0.9"])).is_err());
        assert!(s.allowed_addrs("10.0.1.5", 80, &ips(&["10.0.1.5"])).is_err());
        // An in-scope name that resolves to cloud metadata is still refused.
        assert!(s.allowed_addrs("app.test", 80, &ips(&["169.254.169.254"])).is_err());
        // Only the allowed addresses of a name survive.
        let ok = s.allowed_addrs("other.test", 80, &ips(&["10.0.0.7", "8.8.8.8"])).unwrap();
        assert_eq!(ok, ips(&["10.0.0.7"]));
        // Explicitly scoped link-local is allowed.
        let m = Scope::compile(spec(&["169.254.169.254"], &[]), "t").unwrap();
        assert!(m.allowed_addrs("169.254.169.254", 80, &ips(&["169.254.169.254"])).is_ok());
        // IPv4-mapped IPv6 is treated as IPv4.
        assert!(s.allowed_addrs("::ffff:10.0.0.5", 80, &ips(&["::ffff:10.0.0.5"])).is_ok());
    }

    #[tokio::test]
    async fn guard_intersects_scopes() {
        let g = Guard::from_specs(vec![spec(&["127.0.0.0/8", "localhost"], &[]), spec(&["127.0.0.1"], &[])]).unwrap();
        assert!(g.resolve("127.0.0.1", 80).await.is_ok());
        assert!(matches!(g.resolve("127.0.0.2", 80).await, Err(Error::OutOfScope(_))));
        // CIDR scopes need DNS to decide; either way it must not be allowed.
        assert!(g.resolve("example.org", 80).await.is_err());
        // Host-only scopes refuse other names before any DNS lookup.
        let names = Guard::from_specs(vec![spec(&["app.test"], &[])]).unwrap();
        assert!(matches!(names.resolve("example.org", 80).await, Err(Error::OutOfScope(_))));
        assert!(g.may_allow("127.0.0.1", 80) && !g.may_allow("127.0.0.2", 80));
        assert!(!names.may_allow("example.org", 80) && names.may_allow("app.test", 80));
        assert!(Scope::compile(spec(&[], &[]), "t").is_err());
    }
}

impl crate::store::Store {
    /// The project's engagement scope, if started.
    pub fn engagement(&self) -> Result<Option<ScopeSpec>> {
        match self.meta_get(ENGAGEMENT_KEY)? {
            Some(v) => serde_json::from_str(&v)
                .map(Some)
                .map_err(|e| Error::OutOfScope(format!("stored engagement scope is invalid: {e}"))),
            None => Ok(None),
        }
    }

    /// Sets the engagement scope. Write-once: fails if one is already set.
    pub fn engagement_start(&self, spec: &ScopeSpec) -> Result<()> {
        Scope::compile(spec.clone(), "engagement scope")?;
        let json = serde_json::to_string(spec).map_err(|e| Error::InvalidInput(e.to_string()))?;
        // INSERT (not upsert) so a concurrent or repeated start can't replace it.
        match self
            .conn
            .execute("INSERT INTO meta (key, value) VALUES (?1, ?2)", rusqlite::params![ENGAGEMENT_KEY, json])
        {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => {
                Err(Error::Conflict("this project already has an engagement scope; it cannot be changed".into()))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The guard for this project: system scope plus engagement scope.
    pub fn guard(&self) -> Result<Arc<Guard>> {
        Guard::load(self.engagement()?)
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;

    #[test]
    fn engagement_is_write_once() {
        let s = crate::store::Store::open_in_memory().unwrap();
        assert!(s.engagement().unwrap().is_none());
        let spec = ScopeSpec { name: Some("t".into()), include: vec!["a.test".into()], exclude: vec![] };
        s.engagement_start(&spec).unwrap();
        let wider = ScopeSpec { name: None, include: vec!["*.test".into()], exclude: vec![] };
        assert!(matches!(s.engagement_start(&wider), Err(Error::Conflict(_))));
        assert_eq!(s.engagement().unwrap(), Some(spec));
        // The generic settings writer can't replace it either (different key namespace).
        s.set_setting(ENGAGEMENT_KEY, &wider).unwrap();
        assert_eq!(s.engagement().unwrap().unwrap().include, vec!["a.test".to_string()]);
    }
}
