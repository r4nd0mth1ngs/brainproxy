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

    /// The error another brainproxy process reported, rebuilt from its envelope's `kind` and
    /// `message` (the `Display` text): the inverse of [`Error::kind`] and `to_string`, so it keeps
    /// its kind and exit code. None for a kind this build doesn't know.
    pub fn from_kind(kind: &str, message: &str) -> Option<Error> {
        let rest = |prefix: &str| message.strip_prefix(prefix).unwrap_or(message).to_string();
        Some(match kind {
            "invalid_input" => Error::InvalidInput(rest("invalid input: ")),
            "not_found" => Error::NotFound(rest("not found: ")),
            "out_of_scope" => Error::OutOfScope(rest("out of scope: ")),
            "conflict" => Error::Conflict(rest("conflict: ")),
            "connect" => Error::Connect(rest("connection failed: ")),
            "tls" => Error::Tls(rest("TLS error: ")),
            "timeout" => Error::Timeout(debug_duration(message.strip_prefix("timed out after ")?)?),
            "protocol" => Error::Protocol(rest("protocol error: ")),
            "io" => Error::Io(std::io::Error::other(rest("I/O error: "))),
            "store" => Error::Store(rusqlite::Error::UserFunctionError(rest("storage error: ").into())),
            "blocked" => Error::Blocked(message.to_string()),
            _ => return None,
        })
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

/// A `Duration` read back from its `Debug` text ("1.5s", "250ms", "12µs", "0ns"), exactly.
fn debug_duration(s: &str) -> Option<Duration> {
    // "ms", "µs" and "ns" end in "s" too, so they go first.
    let (number, unit) = [("ns", 1u128), ("µs", 1_000), ("ms", 1_000_000), ("s", 1_000_000_000)]
        .into_iter()
        .find_map(|(suffix, unit)| s.strip_suffix(suffix).map(|n| (n, unit)))?;
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    let digits = |d: &str| d.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty() || !digits(whole) || !digits(fraction) {
        return None;
    }
    let mut nanos = whole.parse::<u128>().ok()?.checked_mul(unit)?;
    let mut place = unit;
    for d in fraction.bytes() {
        place /= 10;
        nanos = nanos.checked_add(u128::from(d - b'0') * place)?;
    }
    Some(Duration::new(u64::try_from(nanos / 1_000_000_000).ok()?, (nanos % 1_000_000_000) as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_survives_its_kind_and_message() {
        let errors = [
            Error::InvalidInput("bad flag".into()),
            Error::NotFound("auth profile x".into()),
            Error::Conflict("already running".into()),
            Error::OutOfScope("a.test".into()),
            Error::Connect("refused".into()),
            Error::Tls("bad certificate".into()),
            Error::Timeout(Duration::from_secs(1)),
            Error::Timeout(Duration::new(30, 5)),
            Error::Timeout(Duration::from_millis(250)),
            Error::Timeout(Duration::from_micros(12)),
            Error::Timeout(Duration::ZERO),
            Error::Protocol("bad response".into()),
            Error::Io(std::io::Error::other("disk full")),
            Error::Store(rusqlite::Error::UserFunctionError("database is locked".into())),
            Error::Blocked("a request rule's script stopped the request".into()),
        ];
        for e in errors {
            let got = Error::from_kind(e.kind(), &e.to_string()).unwrap();
            assert_eq!((got.kind(), got.to_string(), got.exit_code()), (e.kind(), e.to_string(), e.exit_code()));
        }
        assert!(Error::from_kind("usage", "error: unexpected argument").is_none());
        assert!(Error::from_kind("timeout", "timed out after a while").is_none());
    }
}
