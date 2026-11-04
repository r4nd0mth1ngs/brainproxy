//! Intercepting proxy: CA, settings (scope, rules, intercept), the log of changes to what it
//! records, and the server.

pub mod ca;
pub mod config;
pub mod h2;
pub mod recording;
pub mod server;

pub use ca::{CaInfo, CertAuthority};
pub use server::{run, ProxyOptions};

/// Key in the project `meta` table holding the running proxy's state.
pub const STATE_KEY: &str = "proxy.state";

/// Written by a running proxy so `proxy status|stop` and other processes can find it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyState {
    pub pid: u32,
    pub listen: String,
    pub started: String,
    pub ca_cert: std::path::PathBuf,
    pub log: Option<std::path::PathBuf>,
    /// The live access-control testing run (`--authz`), a job of kind `authz`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authz_run: Option<i64>,
    /// The `proxy run` arguments it was started with, so it can be started again alike.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}
