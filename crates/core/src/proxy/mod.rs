//! Intercepting proxy: CA, settings (scope, rules, intercept), and the server.

pub mod ca;
pub mod config;
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
}
