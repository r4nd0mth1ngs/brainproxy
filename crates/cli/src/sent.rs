//! How the CLI's own sends are recorded: see `brainproxy_core::sent`.

pub(crate) use brainproxy_core::sent::{SentLog, CANCELLED};
use brainproxy_core::Error;

/// The error a command returns when it was stopped while it waited.
pub(crate) fn cancelled(ids: &[i64]) -> Error {
    let message = if ids.is_empty() {
        "cancelled by user before anything was sent".to_string()
    } else {
        let rows = ids.iter().map(|id| format!("#{id}")).collect::<Vec<_>>().join(", ");
        format!("{CANCELLED} (history {rows})")
    };
    Error::Io(std::io::Error::new(std::io::ErrorKind::Interrupted, message))
}
