//! Braintruder engine. The CLI, and later the GUI and MCP server, are thin
//! layers over this crate.

pub mod codec;
pub mod error;
pub mod http;
pub mod store;

pub use error::{Error, Result};
