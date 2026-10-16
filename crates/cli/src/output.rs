//! Output contract. In JSON mode every command prints exactly one envelope to stdout:
//! `{"ok":true,"command":...,"data":...}` or `{"ok":false,"command":...,"error":{"kind","message"}}`.
//! Text mode is for humans. Errors go to stderr there.

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

pub struct Out {
    pub format: Format,
    pub command: String,
}

impl Out {
    pub fn json(&self) -> bool {
        self.format == Format::Json
    }

    /// Prints a successful result: the envelope in JSON mode, or `text()` otherwise.
    pub fn ok(&self, data: Value, text: impl FnOnce() -> String) {
        let mut stdout = std::io::stdout().lock();
        if self.json() {
            let env = json!({"ok": true, "command": self.command, "data": data});
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

    pub fn error(&self, kind: &str, message: &str) {
        if self.json() {
            let env = json!({"ok": false, "command": self.command, "error": {"kind": kind, "message": message}});
            println!("{env}");
        } else {
            eprintln!("error ({kind}): {message}");
        }
    }
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
