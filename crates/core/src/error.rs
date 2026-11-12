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
    /// A request rule's script stopped the request: nothing was sent.
    #[error("{0}")]
    Blocked(String),
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
            Error::Blocked(_) => "blocked",
        }
    }

    /// The same error again, for one failure that is the result of several requests.
    pub fn duplicate(&self) -> Error {
        match self {
            Error::InvalidInput(s) => Error::InvalidInput(s.clone()),
            Error::NotFound(s) => Error::NotFound(s.clone()),
            Error::OutOfScope(s) => Error::OutOfScope(s.clone()),
            Error::Conflict(s) => Error::Conflict(s.clone()),
            Error::Connect(s) => Error::Connect(s.clone()),
            Error::Tls(s) => Error::Tls(s.clone()),
            Error::Timeout(d) => Error::Timeout(*d),
            Error::Protocol(s) => Error::Protocol(s.clone()),
            Error::Io(e) => Error::Io(std::io::Error::new(e.kind(), e.to_string())),
            Error::Store(e) => Error::Store(rusqlite::Error::UserFunctionError(e.to_string().into())),
            Error::Blocked(s) => Error::Blocked(s.clone()),
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
            Error::Blocked(_) => 7,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
