//! brainproxy engine. The CLI, and later the GUI and MCP server, are thin
//! layers over this crate.

pub mod capture;
pub mod codec;
pub mod diff;
pub mod error;
pub mod fuzz;
pub mod http;
pub mod proxy;
pub mod race;
pub mod scan;
pub mod store;

pub use error::{Error, Result};
