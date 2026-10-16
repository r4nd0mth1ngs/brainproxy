use std::time::Duration;

/// Engine errors. Each maps to a stable machine-readable `kind` and process
/// exit code, so callers (and AI agents) can branch on them without parsing text.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("not found: {0}")]
    NotFound(String),
    /// The target is outside the engagement scope (or no scope is set).
    #[error("out of scope: {0}")]
    OutOfScope(String),
    /// The request conflicts with current state (e.g. already running, not pending).
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("connection failed: {0}")]
    Connect(String),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("timed out after {0:?}")]
    Timeout(Duration),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage error: {0}")]
    Store(#[from] rusqlite::Error),
}

impl Error {
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidInput(_) => "invalid_input",
            Error::NotFound(_) => "not_found",
            Error::Conflict(_) => "conflict",
            Error::OutOfScope(_) => "out_of_scope",
            Error::Connect(_) => "connect",
            Error::Tls(_) => "tls",
            Error::Timeout(_) => "timeout",
            Error::Protocol(_) => "protocol",
            Error::Io(_) => "io",
            Error::Store(_) => "store",
        }
    }

    /// Process exit code. 2 is reserved for usage errors from argument parsing.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::InvalidInput(_) | Error::Conflict(_) => 2,
            Error::NotFound(_) => 4,
            Error::OutOfScope(_) => 6,
            Error::Connect(_) | Error::Tls(_) | Error::Timeout(_) | Error::Protocol(_) => 3,
            Error::Io(_) | Error::Store(_) => 1,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
