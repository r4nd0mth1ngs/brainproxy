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
//! and connect don't matter. Internal addresses reached through a name are
//! refused unless the scope includes them by address (see [`Internal`] for the
//! exceptions).
//! Hostnames are compared in one canonical form (see [`norm_host`]).
//!
//! Connection options ([`crate::connection`]) never widen this: a host override
//! takes the place of DNS, its address is checked the same way and, because whoever
//! sets it chooses the address, an internal one must be listed by address; an upstream
//! proxy is only used when it runs on this machine or every scope lists it under
//! `proxies` (see [`Guard::resolve_proxy`]).

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[cfg(not(windows))]
pub const SYSTEM_SCOPE_PATH: &str = "/etc/brainproxy/scope.json";
/// Under %ProgramData%, which is C:\ProgramData unless Windows was installed elsewhere.
#[cfg(windows)]
pub const SYSTEM_SCOPE_PATH: &str = r"C:\ProgramData\brainproxy\scope.json";
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
        // Same canonical form as the hosts it is matched against.
        let body = body.strip_suffix('.').unwrap_or(&body).to_string();
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

/// The canonical form every host is compared in: no brackets, lowercase, and one
/// trailing dot removed (`LOCALHOST.` and `localhost` are the same host).
fn norm_host(host: &str) -> String {
    let h = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    h.strip_suffix('.').map(str::to_string).unwrap_or(h)
}

/// The IPv4 address behind an IPv4-mapped (`::ffff:a.b.c.d`) or NAT64
/// (`64:ff9b::a.b.c.d`) address; otherwise the address itself.
fn unwrap_v4(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) if v6.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0] => {
            let o = v6.octets();
            IpAddr::from([o[12], o[13], o[14], o[15]])
        }
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Internal addresses a name may resolve to, checked per resolved address in
/// [`Scope::allowed_addrs`]. All forms are also matched behind IPv4-mapped
/// (`::ffff:`) and NAT64 (`64:ff9b::/96`) wrapping.
///
/// The rule:
/// - An include entry that names the address by IP or CIDR always allows it (so
///   IP literals and address-scoped lab targets pass).
/// - [`Internal::Sensitive`] (loopback, unspecified / 0.0.0.0/8, link-local, and
///   metadata IPs: 169.254.169.254 via link-local, AWS IPv6 fd00:ec2::254, Alibaba
///   100.100.100.200) is otherwise refused for every name, except loopback for
///   the host `localhost` matched by name (an entry `localhost` means this machine).
/// - [`Internal::Private`] (RFC 1918, IPv6 ULA fc00::/7) is allowed when an exact
///   host entry matches (an internal pentest scoped to `app.corp`), and refused
///   when only a wildcard matches: whoever controls DNS under `*.target.com` could
///   otherwise point a name at the tester's own network.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Internal {
    Sensitive,
    Private,
}

fn internal(ip: IpAddr) -> Option<Internal> {
    if ip == IpAddr::from([0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254]) {
        return Some(Internal::Sensitive);
    }
    let (sensitive, private) = match unwrap_v4(ip) {
        IpAddr::V4(v4) => (
            v4.is_loopback() || v4.is_link_local() || v4.octets()[0] == 0 || v4.octets() == [100, 100, 100, 200],
            v4.is_private(),
        ),
        IpAddr::V6(v6) => (
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80,
            (v6.segments()[0] & 0xfe00) == 0xfc00,
        ),
    };
    if sensitive {
        Some(Internal::Sensitive)
    } else if private {
        Some(Internal::Private)
    } else {
        None
    }
}

/// One compiled scope.
#[derive(Debug, Clone)]
pub struct Scope {
    pub spec: ScopeSpec,
    pub origin: String,
    include: Vec<Entry>,
    exclude: Vec<Entry>,
    /// Upstream proxies (other than ones on this machine) connections may go through.
    proxies: Vec<Entry>,
}

impl Scope {
    pub fn compile(spec: ScopeSpec, origin: &str) -> Result<Self> {
        if spec.include.is_empty() {
            return Err(Error::InvalidInput(format!("{origin}: scope must include at least one target")));
        }
        let include = spec.include.iter().map(|e| Entry::parse(e)).collect::<Result<Vec<_>>>()?;
        let exclude = spec.exclude.iter().map(|e| Entry::parse(e)).collect::<Result<Vec<_>>>()?;
        Ok(Self { spec, origin: origin.to_string(), include, exclude, proxies: vec![] })
    }

    /// Allows these upstream proxies (scope entry syntax: host, IP, or CIDR, with optional :port).
    pub fn with_proxies(mut self, proxies: &[String]) -> Result<Self> {
        self.proxies = proxies.iter().map(|e| Entry::parse(e)).collect::<Result<Vec<_>>>()?;
        Ok(self)
    }

    /// Whether this scope lets connections go through the proxy at `host:port` = `ip`.
    /// A proxy listed by name may not be a link-local or metadata address unless
    /// listed by address too.
    fn allows_proxy(&self, host: &str, port: u16, ip: IpAddr) -> bool {
        self.proxies.iter().any(|e| e.matches_addr(ip, port))
            || (self.proxies.iter().any(|e| e.matches_name(host, port)) && internal(ip) != Some(Internal::Sensitive))
    }

    /// Whether connecting to `host:port`, resolved to `addrs`, is allowed. Returns
    /// the addresses that may be used.
    fn allowed_addrs(&self, host: &str, port: u16, addrs: &[IpAddr]) -> std::result::Result<Vec<IpAddr>, String> {
        let host = norm_host(host);
        let literal = host.parse::<IpAddr>().ok();
        if literal.is_none() && self.exclude.iter().any(|e| e.matches_name(&host, port)) {
            return Err(format!("{host} is excluded by the {}", self.origin));
        }
        let name_ok = literal.is_none() && self.include.iter().any(|e| e.matches_name(&host, port));
        let exact = name_ok
            && self.include.iter().any(|e| matches!(e.pattern, Pattern::Host(_)) && e.matches_name(&host, port));
        let localhost = exact && host == "localhost";
        let mut ok = Vec::new();
        let mut refused = None;
        for &ip in addrs {
            if self.exclude.iter().any(|e| e.matches_addr(ip, port)) {
                continue;
            }
            let addr_ok = self.include.iter().any(|e| e.matches_addr(ip, port));
            if !(name_ok || addr_ok) {
                continue;
            }
            let allowed = match internal(ip) {
                None => true,
                // Naming the address allows it, on the entry's ports only.
                _ if addr_ok => true,
                Some(Internal::Sensitive) => localhost && unwrap_v4(ip).is_loopback(),
                Some(Internal::Private) => exact,
            };
            if !allowed {
                refused.get_or_insert(ip);
                continue;
            }
            ok.push(ip);
        }
        if let (true, Some(ip)) = (ok.is_empty(), refused) {
            return Err(format!(
                "{host} resolves to internal address {ip}; add it (or its CIDR) to the {} to allow it",
                self.origin
            ));
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
    /// Values behind auth placeholders, filled in as requests go out.
    pub vault: crate::auth::Vault,
    /// Connection options (upstream proxies, host overrides, client certificates,
    /// platform credentials) every client of the guard uses.
    pub net: crate::connection::Live,
}

impl Guard {
    /// Loads the system scope plus the project's engagement scope.
    pub fn load(engagement: Option<ScopeSpec>) -> Result<Arc<Self>> {
        Self::load_with_proxies(engagement, &[])
    }

    /// [`Guard::load`], with the upstream proxies the engagement allows.
    pub fn load_with_proxies(engagement: Option<ScopeSpec>, engagement_proxies: &[String]) -> Result<Arc<Self>> {
        let mut scopes = Vec::new();
        if let Some((spec, proxies)) = load_system()? {
            scopes.push(Scope::compile(spec, "system scope")?.with_proxies(&proxies)?);
        }
        if let Some(spec) = engagement {
            scopes.push(Scope::compile(spec, "engagement scope")?.with_proxies(engagement_proxies)?);
        }
        if scopes.is_empty() {
            return Err(Error::OutOfScope(
                "no engagement scope: run `brainproxy engagement start --target HOST ...` first".into(),
            ));
        }
        Ok(Arc::new(Self { scopes, vault: Default::default(), net: Default::default() }))
    }

    /// A guard from explicit specs (no system file), for tests and embedding.
    pub fn from_specs(specs: Vec<ScopeSpec>) -> Result<Arc<Self>> {
        let scopes = specs.into_iter().map(|s| Scope::compile(s, "engagement scope")).collect::<Result<Vec<_>>>()?;
        if scopes.is_empty() {
            return Err(Error::OutOfScope("no scope".into()));
        }
        Ok(Arc::new(Self { scopes, vault: Default::default(), net: Default::default() }))
    }

    /// [`Guard::from_specs`] with allowed upstream proxies for each scope, for tests.
    pub fn from_specs_with_proxies(specs: Vec<(ScopeSpec, Vec<String>)>) -> Result<Arc<Self>> {
        let scopes = specs
            .into_iter()
            .map(|(s, p)| Scope::compile(s, "engagement scope")?.with_proxies(&p))
            .collect::<Result<Vec<_>>>()?;
        if scopes.is_empty() {
            return Err(Error::OutOfScope("no scope".into()));
        }
        Ok(Arc::new(Self { scopes, vault: Default::default(), net: Default::default() }))
    }

    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Resolves `host` and returns the socket addresses every scope allows.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        self.resolve_with(host, port, &self.net.get()).await
    }

    /// [`Guard::resolve`] with the host overrides of this snapshot of the connection options.
    pub async fn resolve_with(
        &self,
        host: &str,
        port: u16,
        net: &crate::connection::Compiled,
    ) -> Result<Vec<SocketAddr>> {
        // Look the name up as given (a trailing dot stops search-domain expansion),
        // but check it in canonical form.
        let lookup = host.trim_start_matches('[').trim_end_matches(']');
        let bare = &norm_host(host);
        let addrs: Vec<IpAddr> = match bare.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => {
                // Refuse names no scope could allow before touching DNS.
                self.precheck_name(bare, port)?;
                let named = self.scopes.iter().all(|sc| sc.include.iter().any(|e| e.matches_name(bare, port)));
                // A host override stands in for DNS, but it's a setting anyone running brainproxy can
                // change, not an answer from the name's owner: an internal address must be listed.
                if let Some(ip) = net.host_override(bare) {
                    self.check_override(bare, port, ip)?;
                    return self.check(bare, port, vec![ip]);
                }
                match tokio::net::lookup_host((lookup, port)).await {
                    Ok(addrs) => addrs.map(|a| a.ip()).collect(),
                    // A name that every scope lists by name is in scope; it just doesn't resolve.
                    Err(e) if named => return Err(Error::Connect(format!("{bare}: {e}"))),
                    // Otherwise only its addresses could make it allowed, and we can't check them.
                    Err(e) => {
                        return Err(Error::OutOfScope(format!(
                            "{bare} could not be resolved to check it against the scope ({e})"
                        )))
                    }
                }
            }
        };
        self.check(bare, port, addrs)
    }

    /// Refuses a host override to an internal address unless every scope lists that
    /// address: no exception for an exact name (private) or `localhost` (loopback).
    fn check_override(&self, bare: &str, port: u16, ip: IpAddr) -> Result<()> {
        if internal(ip).is_none() {
            return Ok(());
        }
        match self.scopes.iter().find(|s| !s.include.iter().any(|e| e.matches_addr(ip, port))) {
            Some(s) => Err(Error::OutOfScope(format!(
                "host override {bare} -> {ip} is an internal address the {} doesn't list; it must list the address \
                 (or its CIDR) for an override to reach it",
                s.origin
            ))),
            None => Ok(()),
        }
    }

    /// The addresses of `bare:port` that every scope allows.
    fn check(&self, bare: &str, port: u16, addrs: Vec<IpAddr>) -> Result<Vec<SocketAddr>> {
        let mut allowed = addrs;
        for scope in &self.scopes {
            let ok = scope.allowed_addrs(bare, port, &allowed).map_err(Error::OutOfScope)?;
            allowed.retain(|ip| ok.contains(ip));
        }
        if allowed.is_empty() {
            return Err(Error::OutOfScope(format!("{bare}:{port} resolves only to addresses outside the scope")));
        }
        Ok(allowed.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
    }

    /// Resolves an upstream proxy and returns the addresses connections may go to:
    /// loopback (a proxy on this machine), or ones every scope lists under `proxies`.
    /// A proxy anywhere else could read what goes through it (TLS isn't verified by
    /// default), so the scopes, not the changeable connection settings, decide.
    ///
    /// Host overrides don't apply: an override of a proxy listed by name would let a
    /// changeable setting choose who reads the traffic.
    pub async fn resolve_proxy(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        self.precheck_proxy(host, port)?;
        let bare = norm_host(host);
        let addrs: Vec<IpAddr> = match bare.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => tokio::net::lookup_host((host.trim_start_matches('[').trim_end_matches(']'), port))
                .await
                .map_err(|e| Error::Connect(format!("upstream proxy {bare}: {e}")))?
                .map(|a| a.ip())
                .collect(),
        };
        let ok: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|&ip| self.proxy_addr_allowed(&bare, port, ip))
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        if ok.is_empty() {
            return Err(proxy_refused(&bare, port));
        }
        Ok(ok)
    }

    /// The check of [`Guard::resolve_proxy`] that needs no DNS: fails when the proxy
    /// can't be allowed whatever its name resolves to. As for targets, such a name
    /// isn't looked up (DNS would carry it out).
    pub fn precheck_proxy(&self, host: &str, port: u16) -> Result<()> {
        let bare = norm_host(host);
        let possible = match bare.parse::<IpAddr>() {
            Ok(ip) => self.proxy_addr_allowed(&bare, port, ip),
            Err(_) => {
                bare == "localhost"
                    || self.scopes.iter().all(|s| {
                        s.proxies.iter().any(|e| e.matches_name(&bare, port) || matches!(e.pattern, Pattern::Net(..)))
                    })
            }
        };
        if possible {
            Ok(())
        } else {
            Err(proxy_refused(&bare, port))
        }
    }

    fn proxy_addr_allowed(&self, bare: &str, port: u16, ip: IpAddr) -> bool {
        unwrap_v4(ip).is_loopback() || self.scopes.iter().all(|s| s.allows_proxy(bare, port, ip))
    }

    /// Quick name-only check (no DNS): false when no scope could ever allow it.
    fn precheck_name(&self, host: &str, port: u16) -> Result<()> {
        let host = norm_host(host);
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
        let bare = &norm_host(host);
        match bare.parse::<IpAddr>() {
            Ok(ip) => self.scopes.iter().all(|s| s.allowed_addrs(bare, port, &[ip]).is_ok()),
            Err(_) => self.precheck_name(bare, port).is_ok(),
        }
    }

    /// Whether `may_allow` is already certain: an address, or a name every scope lists.
    pub fn confirms(&self, host: &str, port: u16) -> bool {
        let bare = &norm_host(host);
        self.may_allow(bare, port)
            && (bare.parse::<IpAddr>().is_ok()
                || self.scopes.iter().all(|s| s.include.iter().any(|e| e.matches_name(bare, port))))
    }
}

fn proxy_refused(bare: &str, port: u16) -> Error {
    Error::OutOfScope(format!(
        "upstream proxy {bare}:{port} is not allowed: use a proxy on this machine (loopback), or list it with \
         `engagement start --proxy HOST:PORT` (and under \"proxies\" in the system scope file, when there is one)"
    ))
}

fn system_scope_path() -> Option<PathBuf> {
    system_scope_at(Path::new(SYSTEM_SCOPE_PATH), std::env::var_os(SYSTEM_SCOPE_ENV))
}

/// The fixed path whenever something may be there: a file we can't stat (a folder we
/// may not enter) or a dangling link is configured, so loading it fails rather than
/// falling back to the environment variable.
fn system_scope_at(fixed: &Path, env: Option<std::ffi::OsString>) -> Option<PathBuf> {
    match fixed.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => env.map(PathBuf::from),
        _ => Some(fixed.to_path_buf()),
    }
}

/// The system scope, if configured. A configured but unreadable or invalid file is
/// an error, never "no scope".
pub fn load_system_scope() -> Result<Option<ScopeSpec>> {
    Ok(load_system()?.map(|(spec, _)| spec))
}

/// Upstream proxies a scope's JSON allows: its optional `"proxies"` list.
#[derive(Deserialize)]
struct ProxyList {
    #[serde(default)]
    proxies: Vec<String>,
}

/// The system scope and the upstream proxies it allows.
pub fn load_system() -> Result<Option<(ScopeSpec, Vec<String>)>> {
    let Some(path) = system_scope_path() else { return Ok(None) };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| Error::OutOfScope(format!("system scope {} unreadable: {e}", path.display())))?;
    let invalid = |e: serde_json::Error| Error::OutOfScope(format!("system scope {} invalid: {e}", path.display()));
    let spec: ScopeSpec = serde_json::from_str(&text).map_err(invalid)?;
    let proxies: ProxyList = serde_json::from_str(&text).map_err(invalid)?;
    Ok(Some((spec, proxies.proxies)))
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
    async fn trailing_dot_and_case_do_not_bypass_name_excludes() {
        // #16: include by CIDR, exclude by name; `localhost.` resolves into the CIDR.
        let g = Guard::from_specs(vec![spec(&["127.0.0.0/8", "10.0.0.0/24"], &["localhost", "admin.corp."])]).unwrap();
        for host in ["localhost", "localhost.", "LOCALHOST.", "[localhost.]"] {
            assert!(matches!(g.resolve(host, 80).await, Err(Error::OutOfScope(_))), "{host}");
            assert!(!g.may_allow(host, 80), "{host}");
        }
        let s = &g.scopes()[0];
        for host in ["admin.corp", "admin.corp.", "Admin.Corp."] {
            assert!(s.allowed_addrs(host, 80, &ips(&["10.0.0.5"])).is_err(), "{host}");
        }
        // Includes are normalised the same way.
        let n = Scope::compile(spec(&["App.Test."], &[]), "t").unwrap();
        assert!(n.allowed_addrs("app.test.", 80, &ips(&["93.184.216.34"])).is_ok());
    }

    #[test]
    fn names_do_not_reach_internal_addresses() {
        // #17: a wildcard name pointed at any internal address is refused...
        let s = Scope::compile(spec(&["*.target.com", "app.corp", "localhost", "10.0.1.0/24"], &[]), "t").unwrap();
        let sensitive = [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "::",
            "fd00:ec2::254",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::7f00:1",
            "::ffff:127.0.0.1",
            "100.100.100.200",
            "169.254.169.254",
            "fe80::1",
        ];
        let private = ["10.1.2.3", "172.16.0.1", "192.168.1.1", "fd12::1", "::ffff:10.1.2.3"];
        for ip in sensitive.iter().chain(&private) {
            let e = s.allowed_addrs("x.target.com", 80, &ips(&[ip])).unwrap_err();
            assert!(e.contains("internal address") && e.contains("to the t to allow it"), "{ip}: {e}");
        }
        assert!(s.allowed_addrs("x.target.com", 80, &ips(&["93.184.216.34"])).is_ok());
        // ...an exact host entry may reach private addresses (internal pentests),
        for ip in private {
            assert!(s.allowed_addrs("app.corp", 80, &ips(&[ip])).is_ok(), "{ip}");
        }
        // but never loopback, link-local or metadata.
        for ip in sensitive {
            assert!(s.allowed_addrs("app.corp", 80, &ips(&[ip])).is_err(), "{ip}");
        }
        // Naming the address (CIDR or IP literal) always allows it.
        assert!(s.allowed_addrs("x.target.com", 80, &ips(&["10.0.1.244"])).is_ok());
        assert!(s.allowed_addrs("10.0.1.244", 80, &ips(&["10.0.1.244"])).is_ok());
        // A `localhost` entry means this machine: loopback, not metadata.
        assert_eq!(s.allowed_addrs("localhost", 80, &ips(&["127.0.0.1", "::1"])).unwrap().len(), 2);
        assert!(s.allowed_addrs("localhost", 80, &ips(&["169.254.169.254"])).is_err());
        // An address named with a port is allowed on that port only, also through a name.
        let s = Scope::compile(spec(&["*.target.com", "10.0.0.5:443"], &[]), "t").unwrap();
        assert!(s.allowed_addrs("x.target.com", 443, &ips(&["10.0.0.5"])).is_ok());
        assert!(s.allowed_addrs("x.target.com", 6379, &ips(&["10.0.0.5"])).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_system_scope_that_cannot_be_checked_is_still_configured() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("bp-sysscope-{}", std::process::id()));
        let locked = dir.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(locked.join("scope.json"), "{}").unwrap();
        let env = Some(std::ffi::OsString::from("/tmp/wide.json"));
        assert_eq!(system_scope_at(&dir.join("none.json"), env.clone()), Some(PathBuf::from("/tmp/wide.json")));
        std::os::unix::fs::symlink(dir.join("gone"), dir.join("dangling.json")).ok();
        assert_eq!(system_scope_at(&dir.join("dangling.json"), env.clone()), Some(dir.join("dangling.json")));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let fixed = locked.join("scope.json");
        let got = system_scope_at(&fixed, env);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        // (root can stat it anyway; either way it isn't the environment variable.)
        assert_eq!(got, Some(fixed));
        let _ = std::fs::remove_dir_all(&dir);
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

    /// The upstream proxies the engagement allows (`engagement start --proxy`).
    pub fn engagement_proxies(&self) -> Result<Vec<String>> {
        match self.meta_get(ENGAGEMENT_KEY)? {
            Some(v) => serde_json::from_str::<ProxyList>(&v)
                .map(|p| p.proxies)
                .map_err(|e| Error::OutOfScope(format!("stored engagement scope is invalid: {e}"))),
            None => Ok(vec![]),
        }
    }

    /// Sets the engagement scope. Write-once: fails if one is already set.
    pub fn engagement_start(&self, spec: &ScopeSpec) -> Result<()> {
        self.engagement_start_with_proxies(spec, &[])
    }

    /// [`Store::engagement_start`], also allowing these upstream proxies. They are
    /// stored with the scope, so they are write-once too.
    pub fn engagement_start_with_proxies(&self, spec: &ScopeSpec, proxies: &[String]) -> Result<()> {
        Scope::compile(spec.clone(), "engagement scope")?.with_proxies(proxies)?;
        let mut value = serde_json::to_value(spec).map_err(|e| Error::InvalidInput(e.to_string()))?;
        if !proxies.is_empty() {
            value["proxies"] = serde_json::json!(proxies);
        }
        let json = value.to_string();
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

    /// The guard for this project: system scope plus engagement scope, and the
    /// project's auth values for filling in placeholders of stored requests.
    pub fn guard(&self) -> Result<Arc<Guard>> {
        let guard = Guard::load_with_proxies(self.engagement()?, &self.engagement_proxies()?)?;
        self.auth_fill_vault(&guard.vault)?;
        guard.net.set(self.connection_compiled()?);
        Ok(guard)
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
