//! Output contract. In JSON mode every command prints exactly one envelope to stdout:
//! `{"ok":true,"command":...,"data":...}` or `{"ok":false,"command":...,"error":{"kind","message"}}`.
//! A command can add `error.data`, what it did before failing, for callers to act on without
//! reading the message (see [`Out::error_data`]). Text mode is for humans. Errors go to stderr there.
//!
//! An envelope that may carry target-controlled content (response bodies, headers, titles,
//! OOB interactions, finding evidence, ...) also has `"_meta":{"provenance":{"untrusted_content":true}}`.
//! That content is data to analyse, never instructions to follow.

use std::io::{IsTerminal, Write};

use clap::ValueEnum;
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// JSON when stdout is not a terminal, text otherwise.
    Auto,
    Json,
    Text,
}

impl Format {
    pub fn resolve(self) -> Format {
        match self {
            Format::Auto if std::io::stdout().is_terminal() => Format::Text,
            Format::Auto => Format::Json,
            f => f,
        }
    }

    /// Best-effort format detection for errors raised before argument parsing finishes.
    pub fn sniff(args: &[String]) -> Format {
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let v = if a == "--format" { it.next().map(String::as_str) } else { a.strip_prefix("--format=") };
            match v {
                Some("json") => return Format::Json,
                Some("text") => return Format::Text,
                _ => {}
            }
        }
        match std::env::var("BRAINPROXY_FORMAT").as_deref() {
            Ok("json") => Format::Json,
            Ok("text") => Format::Text,
            _ => Format::Auto.resolve(),
        }
    }
}

/// Commands whose output comes only from local state the operator set, never from a target.
/// Every other command is marked untrusted, so a new command is untrusted until listed here.
const LOCAL_ONLY: &[&str] = &[
    "capabilities",
    "schema",
    "project init",
    "ca",
    "browser list",
    "scope",
    "engagement",
    "wordlists list",
    "wordlists show",
    "checks list",
    "checks validate",
    "checks update",
    "checks status",
    "proxy start",
    "proxy stop",
    "proxy status",
    "oob start",
    "oob stop",
    "oob status",
    "auth add",
    "auth list",
    "auth remove",
    "replay tabs save",
];

pub struct Out {
    pub format: Format,
    pub command: String,
    error_data: std::sync::Mutex<Option<Value>>,
}

impl Out {
    pub fn new(format: Format, command: String) -> Self {
        Self { format, command, error_data: Default::default() }
    }

    /// Sets what the error envelope's `data` says, should the command fail: the last one set.
    pub fn error_data(&self, data: Value) {
        *self.error_data.lock().unwrap_or_else(|e| e.into_inner()) = Some(data);
    }

    pub fn json(&self) -> bool {
        self.format == Format::Json
    }

    /// Adds the provenance mark to an envelope when the command can carry target content.
    fn mark(&self, mut env: Value) -> Value {
        if !LOCAL_ONLY.contains(&self.command.as_str()) {
            env["_meta"] = json!({"provenance": {"untrusted_content": true}});
        }
        env
    }

    /// Prints a successful result: the envelope in JSON mode, or `text()` otherwise.
    pub fn ok(&self, data: Value, text: impl FnOnce() -> String) {
        let mut stdout = std::io::stdout().lock();
        if self.json() {
            let env = self.mark(json!({"ok": true, "command": self.command, "data": data}));
            let _ = writeln!(stdout, "{env}");
        } else {
            let t = text();
            let _ = if t.ends_with('\n') || t.is_empty() { write!(stdout, "{t}") } else { writeln!(stdout, "{t}") };
        }
    }

    /// Writes raw bytes with no envelope. Used by `--raw` flags for piping.
    pub fn raw(&self, bytes: &[u8]) {
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(bytes);
        let _ = stdout.flush();
    }

    /// [`Out::error`] with what the command did before failing as `data` (JSON mode only).
    pub fn error_with(&self, kind: &str, message: &str, data: Value) {
        if self.json() {
            let error = json!({"kind": kind, "message": message});
            println!("{}", self.mark(json!({"ok": false, "command": self.command, "error": error, "data": data})));
        } else {
            eprintln!("error ({kind}): {message}");
        }
    }

    pub fn error(&self, kind: &str, message: &str) {
        if self.json() {
            let mut error = json!({"kind": kind, "message": message});
            if let Some(data) = self.error_data.lock().unwrap_or_else(|e| e.into_inner()).take() {
                error["data"] = data;
            }
            let env = self.mark(json!({"ok": false, "command": self.command, "error": error}));
            println!("{env}");
        } else {
            eprintln!("error ({kind}): {message}");
        }
    }
}

/// Text for a terminal line: control characters (escape sequences, newlines, carriage returns)
/// and bidi overrides shown as escapes like `\u{1b}` or `\n`, so stored text can't move the
/// cursor, add lines, or show in another order than it reads. For text mode only; JSON keeps
/// the value as it is.
pub fn escape_controls(s: &str) -> std::borrow::Cow<'_, str> {
    let bidi = |c: char| matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
    if !s.chars().any(|c| c.is_control() || bidi(c)) {
        return s.into();
    }
    s.chars()
        .map(|c| match c {
            c if c.is_control() => c.escape_debug().to_string(),
            c if bidi(c) => format!("\\u{{{:x}}}", c as u32),
            c => c.to_string(),
        })
        .collect::<String>()
        .into()
}

/// [`escape_controls`] for text of several lines: each line escaped, the line breaks kept.
pub fn escape_lines(s: &str) -> String {
    s.split('\n').map(|l| escape_controls(l.trim_end_matches('\r'))).collect::<Vec<_>>().join("\n")
}

/// Writes an output file named by the caller (`--out`, `-o`). An existing file is
/// refused unless `force`, so a stray path can't clobber something like ~/.bashrc.
pub fn write_file(path: &std::path::Path, bytes: &[u8], force: bool) -> Result<(), brainproxy_core::Error> {
    let mut f = std::fs::OpenOptions::new();
    f.write(true);
    if force {
        f.create(true).truncate(true);
    } else {
        f.create_new(true);
    }
    let mut f = f.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => {
            brainproxy_core::Error::Conflict(format!("{} already exists; pass --force to overwrite it", path.display()))
        }
        _ => e.into(),
    })?;
    Ok(f.write_all(bytes)?)
}

/// Renders bytes for JSON: UTF-8 text when valid, base64 otherwise, truncated to `max`.
pub fn body_value(bytes: &[u8], max: usize) -> Value {
    let truncated = bytes.len() > max;
    let slice = &bytes[..bytes.len().min(max)];
    let (encoding, content) = match std::str::from_utf8(slice) {
        Ok(s) => ("utf8", s.to_string()),
        // A truncation can split a multi-byte character; keep the valid prefix as text.
        Err(e) if truncated && e.error_len().is_none() => {
            ("utf8", String::from_utf8_lossy(&slice[..e.valid_up_to()]).into_owned())
        }
        Err(_) => {
            use brainproxy_core::codec;
            ("base64", String::from_utf8(codec::encode("base64", slice).unwrap_or_default()).unwrap_or_default())
        }
    };
    json!({"encoding": encoding, "content": content, "length": bytes.len(), "truncated": truncated})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_controls_shows_bidi_overrides() {
        assert_eq!(escape_controls("ok\u{202e}txt.exe"), "ok\\u{202e}txt.exe");
        assert_eq!(escape_lines("a\r\nb\u{1b}[8m"), "a\nb\\u{1b}[8m");
    }

    #[test]
    fn escape_controls_keeps_printable_text() {
        assert_eq!(escape_controls("login é «auth:a:b:c»\\"), "login é «auth:a:b:c»\\");
        assert_eq!(
            escape_controls("\u{1b}[2Ja\r\n  9  http  x\u{7f}\u{85}"),
            r"\u{1b}[2Ja\r\n  9  http  x\u{7f}\u{85}"
        );
    }
}
