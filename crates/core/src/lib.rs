//! brainproxy engine. The CLI, and later the GUI and MCP server, are thin
//! layers over this crate.

pub mod apiimport;
pub mod auth;
pub mod auth_record;
pub mod authz;
pub mod browser_crawl;
pub mod capture;
pub mod checks;
pub mod codec;
pub mod connection;
pub mod crawl;
pub mod data;
pub mod diff;
pub mod error;
pub mod fetch;
pub mod fuzz;
pub mod guard;
pub mod http;
pub mod jobs;
pub mod oob;
pub mod proxy;
pub mod race;
pub mod scan;
pub mod session;
pub mod sign;
pub mod store;
pub mod update;
pub mod wordlists;
pub mod ws;

pub use error::{Error, Result};
