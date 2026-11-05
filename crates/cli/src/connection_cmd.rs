//! Connection options: upstream proxies, host overrides, client certificates, TLS
//! pass-through. Stored in the project; a running proxy picks changes up within a
//! second, other commands when they start.

use std::path::{Path, PathBuf};

use brainproxy_core::connection::{
    ClientCert, ConnectionSettings, HostOverride, HostPattern, Route, UpstreamProxy, UpstreamRule,
};
use brainproxy_core::http::Target;
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::output::Out;

#[derive(Subcommand)]
pub enum ConnectionCmd {
    /// Show every connection option.
    Show,
    /// How a request to TARGET would connect: address and where it came from, proxy,
    /// client certificate, platform auth, pass-through. Resolves DNS; sends nothing.
    Route {
        /// URL or host[:port].
        target: String,
    },
    /// Upstream proxies by host pattern (first match wins; no match: direct).
    #[command(
        subcommand,
        after_help = "Host patterns: app.test, *.corp.test (subdomains), * (everything), optionally :port; * and ? \
        are wildcards. The proxy is asked for the address brainproxy resolved and checked against the scope, never \
        the name, so it can't take a request anywhere the scope doesn't allow (it then sees and logs IP addresses, \
        and plain-HTTP targets go through a CONNECT tunnel too). Only proxies on this machine, or ones listed with \
        `engagement start --proxy` (and under \"proxies\" in the system scope file, when there is one), are used."
    )]
    Upstream(UpstreamCmd),
    /// Host name overrides (like /etc/hosts): connect to IP for HOST without asking DNS.
    #[command(
        subcommand,
        after_help = "The name must be in scope, and an internal address (private, loopback, link-local) must be listed \
        in the scope by address, also for a name listed exactly. Public addresses need no listing. SNI and Host stay \
        the name."
    )]
    Hosts(HostsCmd),
    /// Client TLS certificates for mutual TLS, by host pattern (first match wins).
    #[command(subcommand)]
    Cert(CertCmd),
    /// Hosts whose TLS the proxy tunnels without decrypting (still scope-checked; recorded as a connection).
    #[command(subcommand)]
    Passthrough(PassthroughCmd),
    /// Remove every connection option.
    Clear,
}

#[derive(Subcommand)]
pub enum UpstreamCmd {
    /// Add a rule, or replace the rule with the same host pattern in place.
    Add {
        /// Host pattern the rule applies to.
        #[arg(long)]
        host: String,
        /// Proxy URL: http://HOST:PORT (HTTP CONNECT) or socks5://HOST:PORT.
        #[arg(long, required_unless_present = "direct", conflicts_with = "direct")]
        proxy: Option<String>,
        /// Connect directly (an exception to a broader rule below it).
        #[arg(long)]
        direct: bool,
        /// Proxy username.
        #[arg(long)]
        username: Option<String>,
        /// Environment variable holding the proxy password, read at connect time; never stored.
        #[arg(long, requires = "username")]
        password_env: Option<String>,
        /// Put the rule first instead of last (a new rule only).
        #[arg(long)]
        first: bool,
    },
    /// Remove the rule for this host pattern.
    Remove {
        #[arg(long)]
        host: String,
    },
    /// Remove every upstream rule (all connections direct).
    Clear,
}

#[derive(Subcommand)]
pub enum HostsCmd {
    /// Add or replace an override.
    Add { host: String, ip: std::net::IpAddr },
    /// Remove the override for HOST.
    Remove { host: String },
    /// Remove every override.
    Clear,
}

#[derive(Subcommand)]
pub enum CertCmd {
    /// Add a certificate for a host pattern, or replace the one with the same pattern.
    /// The files are read now (to check them) and whenever settings load.
    Add {
        #[arg(long)]
        host: String,
        /// PEM certificate (chain) file; goes with --key.
        #[arg(long, requires = "key", conflicts_with = "pkcs12")]
        cert: Option<PathBuf>,
        /// PEM private key file (PKCS#8, PKCS#1, or SEC1).
        #[arg(long, requires = "cert")]
        key: Option<PathBuf>,
        /// PKCS#12 (.p12/.pfx) file with the key and certificate.
        #[arg(long, required_unless_present = "cert")]
        pkcs12: Option<PathBuf>,
        /// Environment variable holding the PKCS#12 password; never stored. Without it the password is empty.
        #[arg(long, requires = "pkcs12")]
        password_env: Option<String>,
    },
    /// Remove the certificate for this host pattern.
    Remove {
        #[arg(long)]
        host: String,
    },
    /// Remove every client certificate.
    Clear,
}

#[derive(Subcommand)]
pub enum PassthroughCmd {
    /// Add host patterns. Repeatable.
    Add {
        #[arg(required = true)]
        hosts: Vec<String>,
    },
    /// Remove host patterns.
    Remove {
        #[arg(required = true)]
        hosts: Vec<String>,
    },
    /// Remove every pass-through pattern.
    Clear,
}

pub fn connection(project: &Path, cmd: ConnectionCmd, out: &Out) -> Result<(), Error> {
    let mut store = Store::open(project)?;
    match &cmd {
        ConnectionCmd::Show => {
            let data = view(&store, &store.connection_settings()?)?;
            out.ok(data.clone(), || serde_json::to_string_pretty(&data).unwrap_or_default());
            return Ok(());
        }
        ConnectionCmd::Route { target } => return route(&store, target, out),
        _ => {}
    }
    // The pass-through list decides what the proxy decrypts and records: its changes are logged,
    // whichever command saves it, and saving it unchanged with one of these shows it was seen.
    let passthrough_saved = matches!(cmd, ConnectionCmd::Passthrough(_) | ConnectionCmd::Clear);
    let same = |a: &str, b: &str| a.trim().eq_ignore_ascii_case(b.trim());
    // Edited as saved when the change is logged, so a save by another process in between
    // isn't overwritten, and logged with who changed it (see `update_connection_settings`).
    let s = store.update_connection_settings(passthrough_saved, |s| {
        match cmd {
            ConnectionCmd::Show | ConnectionCmd::Route { .. } => unreachable!("answered above"),
            ConnectionCmd::Upstream(c) => match c {
                UpstreamCmd::Add { host, proxy, direct: _, username, password_env, first } => {
                    HostPattern::parse(&host)?;
                    let rule = UpstreamRule { host, proxy, username, password_env };
                    match s.upstream.iter_mut().find(|r| same(&r.host, &rule.host)) {
                        Some(r) => *r = rule,
                        None if first => s.upstream.insert(0, rule),
                        None => s.upstream.push(rule),
                    }
                }
                UpstreamCmd::Remove { host } => {
                    let before = s.upstream.len();
                    s.upstream.retain(|r| !same(&r.host, &host));
                    if s.upstream.len() == before {
                        return Err(Error::NotFound(format!("upstream rule for {host:?}")));
                    }
                }
                UpstreamCmd::Clear => s.upstream.clear(),
            },
            ConnectionCmd::Hosts(c) => match c {
                HostsCmd::Add { host, ip } => match s.hosts.iter_mut().find(|h| same(&h.host, &host)) {
                    Some(h) => h.ip = ip,
                    None => s.hosts.push(HostOverride { host, ip }),
                },
                HostsCmd::Remove { host } => {
                    let before = s.hosts.len();
                    s.hosts.retain(|h| !same(&h.host, &host));
                    if s.hosts.len() == before {
                        return Err(Error::NotFound(format!("host override for {host:?}")));
                    }
                }
                HostsCmd::Clear => s.hosts.clear(),
            },
            ConnectionCmd::Cert(c) => match c {
                CertCmd::Add { host, cert, key, pkcs12, password_env } => {
                    HostPattern::parse(&host)?;
                    let abs = |p: Option<PathBuf>| p.map(|p| std::path::absolute(&p).unwrap_or(p));
                    let entry = ClientCert { host, cert: abs(cert), key: abs(key), pkcs12: abs(pkcs12), password_env };
                    match s.client_certs.iter_mut().find(|c| same(&c.host, &entry.host)) {
                        Some(c) => *c = entry,
                        None => s.client_certs.push(entry),
                    }
                }
                CertCmd::Remove { host } => {
                    let before = s.client_certs.len();
                    s.client_certs.retain(|c| !same(&c.host, &host));
                    if s.client_certs.len() == before {
                        return Err(Error::NotFound(format!("client certificate for {host:?}")));
                    }
                }
                CertCmd::Clear => s.client_certs.clear(),
            },
            ConnectionCmd::Passthrough(c) => match c {
                PassthroughCmd::Add { hosts } => {
                    for h in hosts {
                        HostPattern::parse(&h)?;
                        if !s.passthrough.iter().any(|p| same(p, &h)) {
                            s.passthrough.push(h);
                        }
                    }
                }
                PassthroughCmd::Remove { hosts } => {
                    for h in &hosts {
                        if !s.passthrough.iter().any(|p| same(p, h)) {
                            return Err(Error::NotFound(format!("pass-through pattern {h:?}")));
                        }
                    }
                    s.passthrough.retain(|p| !hosts.iter().any(|h| same(p, h)));
                }
                PassthroughCmd::Clear => s.passthrough.clear(),
            },
            ConnectionCmd::Clear => *s = ConnectionSettings::default(),
        }
        Ok(())
    })?;
    let data = view(&store, &s)?;
    out.ok(data, || "connection settings saved".into());
    Ok(())
}

/// The settings with warnings about what won't work as configured (an unset
/// password variable, a proxy the scope doesn't allow).
fn view(store: &Store, s: &ConnectionSettings) -> Result<Value, Error> {
    let mut warnings = Vec::new();
    let unset = |var: &Option<String>| var.as_ref().filter(|v| std::env::var_os(v).is_none()).cloned();
    for r in &s.upstream {
        if let Some(v) = unset(&r.password_env) {
            warnings.push(format!("upstream {}: password variable {v} is not set here", r.host));
        }
    }
    for c in &s.client_certs {
        if let Some(v) = unset(&c.password_env) {
            warnings.push(format!("client certificate {}: password variable {v} is not set here", c.host));
        }
    }
    if let Ok(guard) = store.guard() {
        for r in &s.upstream {
            let Some(url) = &r.proxy else { continue };
            let p = UpstreamProxy::parse(url, r.username.clone(), r.password_env.clone())?;
            // No DNS here (this is what `connection show` runs): `connection route` does the full check.
            if let Err(e) = guard.precheck_proxy(&p.host, p.port) {
                warnings.push(format!("upstream {}: {e}", r.host));
            }
        }
    }
    Ok(json!({
        "upstream": s.upstream,
        "hosts": s.hosts,
        "client_certs": s.client_certs,
        "passthrough": s.passthrough,
        "warnings": warnings,
        "note": "Passwords are read from the named environment variables where the command or proxy runs. A running proxy applies changes within a second; other commands when they start.",
    }))
}

fn route(store: &Store, target: &str, out: &Out) -> Result<(), Error> {
    let t = Target::from_url(target)?;
    let guard = store.guard()?;
    let net = guard.net.get();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let addresses = rt.block_on(guard.resolve(&t.host, t.port));
    let proxy = match net.route(&t.host, t.port) {
        Route::Direct => Value::Null,
        Route::Proxy(p) => {
            let allowed = rt.block_on(guard.resolve_proxy(&p.host, p.port));
            json!({
                "url": p.url(),
                "username": p.username,
                "allowed": allowed.is_ok(),
                "reason": allowed.err().map(|e| e.to_string()),
            })
        }
    };
    let cert =
        net.client_cert(&t.host, t.port).map(|(_, id)| json!({"certificates": id.chain.len(), "error": id.error}));
    let platform = net.platform(&t.host, t.port).map(|c| json!({"profile": c.profile, "scheme": c.scheme_name()}));
    let data = json!({
        "target": t.origin(),
        "allowed": addresses.is_ok(),
        "addresses": addresses.as_ref().map(|a| a.iter().map(|a| a.ip().to_string()).collect::<Vec<_>>()).unwrap_or_default(),
        "reason": addresses.as_ref().err().map(|e| e.to_string()),
        "address_from": if net.host_override(&t.host).is_some() { "host override" } else if t.host.parse::<std::net::IpAddr>().is_ok() { "literal" } else { "dns" },
        "proxy": proxy,
        "client_certificate": cert,
        "platform_auth": platform,
        "passthrough": net.passthrough(&t.host, t.port),
    });
    out.ok(data.clone(), || serde_json::to_string_pretty(&data).unwrap_or_default());
    Ok(())
}
