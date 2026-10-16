//! Engagement scope: set once at the start, enforced on every outbound request.

use std::path::Path;

use brainproxy_core::guard::{self, Guard, ScopeSpec};
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::Subcommand;
use serde_json::json;

use crate::output::Out;

#[derive(Subcommand)]
pub enum EngagementCmd {
    /// Fix the targets for this project. Write-once: it can never be changed or
    /// removed afterwards. Every request brainproxy sends must match it.
    #[command(after_help = "Target forms: example.com (exact host), *.example.com (subdomains), 10.0.0.5, \
        10.0.0.0/24, [2001:db8::1], each optionally with :port. Link-local addresses such as cloud metadata \
        (169.254.169.254) are refused unless listed by address.\nA system scope file at /etc/brainproxy/scope.json \
        (same JSON shape as `engagement show`), when present, is enforced as well and cannot be overridden.")]
    Start {
        /// Target that may be contacted. Repeatable; at least one.
        #[arg(long = "target", required = true)]
        targets: Vec<String>,
        /// Target that must never be contacted, even if matched by --target. Repeatable.
        #[arg(long)]
        exclude: Vec<String>,
        /// Label for the engagement.
        #[arg(long)]
        name: Option<String>,
    },
    /// Show the scopes in force.
    Show,
    /// Check whether a host[:port] would be allowed (resolves DNS like a real request).
    Check { target: String },
}

pub fn engagement(project: &Path, cmd: EngagementCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    match cmd {
        EngagementCmd::Start { targets, exclude, name } => {
            let spec = ScopeSpec { name, include: targets, exclude };
            store.engagement_start(&spec)?;
            out.ok(json!({"engagement": spec, "locked": true}), || {
                format!("engagement scope locked: {}", spec.include.join(", "))
            });
        }
        EngagementCmd::Show => {
            let system = guard::load_system_scope()?;
            let engagement = store.engagement()?;
            let data = json!({
                "system": system,
                "system_file": guard::system_scope_location(),
                "engagement": engagement,
                "enforced": system.is_some() || engagement.is_some(),
                "rule": "A request is allowed only if every scope shown allows it. Neither scope can be changed from the CLI once set.",
            });
            out.ok(data.clone(), || serde_json::to_string_pretty(&data).unwrap_or_default());
        }
        EngagementCmd::Check { target } => {
            let t = brainproxy_core::http::Target::from_url(&target)?;
            let port_given =
                target.rsplit(':').next().is_some_and(|p| p.parse::<u16>().is_ok()) && !target.ends_with(']');
            let guard: std::sync::Arc<Guard> = store.guard()?;
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            let ports: Vec<u16> = if port_given || target.contains("://") { vec![t.port] } else { vec![443, 80] };
            let mut results = Vec::new();
            for port in ports {
                let r = rt.block_on(guard.resolve(&t.host, port));
                results.push(match r {
                    Ok(addrs) => json!({"port": port, "allowed": true, "addresses": addrs.iter().map(|a| a.ip().to_string()).collect::<Vec<_>>()}),
                    Err(e) => json!({"port": port, "allowed": false, "reason": e.to_string()}),
                });
            }
            out.ok(json!({"host": t.host, "results": results}), || {
                results
                    .iter()
                    .map(|r| {
                        format!("{}:{} {}", t.host, r["port"], if r["allowed"] == true { "allowed" } else { "refused" })
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
    }
    Ok(())
}
