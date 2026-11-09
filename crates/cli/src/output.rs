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
/// refused unless `force`, so a stray path can't clobber something like ~/.bashrc. On Unix
/// a regular file is readable by its owner only (0600), also when `force` overwrites one: an
/// export, report or repro may hold what a target answered, and with `--no-redact` secrets.
/// What isn't a regular file (`/dev/null`, `/dev/stdout` on a pipe) is written as it is.
pub fn write_file(path: &std::path::Path, bytes: &[u8], force: bool) -> Result<(), brainproxy_core::Error> {
    let mut f = std::fs::OpenOptions::new();
    f.write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut f, 0o600);
    // An existing file is opened without truncating it: it is emptied only once it is ours
    // alone (see `make_private`).
    if force {
        f.create(true);
    } else {
        f.create_new(true);
    }
    let mut f = f.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => {
            brainproxy_core::Error::Conflict(format!("{} already exists; pass --force to overwrite it", path.display()))
        }
        _ => e.into(),
    })?;
    if force {
        overwrite(&f, path, make_private)?;
    }
    Ok(f.write_all(bytes)?)
}

/// Empties a regular file opened for overwriting once `private` has made it the owner's
/// only; a file `private` fails on is left as it was. Anything else (a device, a pipe) is
/// left to be written as it is.
fn overwrite(
    f: &std::fs::File,
    path: &std::path::Path,
    private: fn(&std::fs::File) -> std::io::Result<()>,
) -> Result<(), brainproxy_core::Error> {
    if !f.metadata()?.is_file() {
        return Ok(());
    }
    private(f).map_err(|e| {
        brainproxy_core::Error::InvalidInput(format!(
            "{} can't be made readable by its owner only ({e}); it was left as it was: write somewhere else",
            path.display()
        ))
    })?;
    Ok(f.set_len(0)?)
}

/// Sets a file to 0600 (`mode` applies only to a file `open` creates), unless it is already.
fn make_private(f: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if f.metadata()?.permissions().mode() & 0o7777 != 0o600 {
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    let _ = f;
    Ok(())
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

    #[cfg(unix)]
    #[test]
    fn output_files_are_the_owners_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("bp-write-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let new = dir.join("new.json");
        write_file(&new, b"one", false).unwrap();
        assert_eq!(mode(&new), 0o600);
        let old = dir.join("old.json");
        std::fs::write(&old, "a person's").unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(write_file(&old, b"two", false), Err(brainproxy_core::Error::Conflict(_))));
        assert_eq!((std::fs::read_to_string(&old).unwrap().as_str(), mode(&old)), ("a person's", 0o644));
        write_file(&old, b"two", true).unwrap();
        assert_eq!((std::fs::read_to_string(&old).unwrap().as_str(), mode(&old)), ("two", 0o600));
        // Shorter content replaces a longer file whole.
        write_file(&old, b"3", true).unwrap();
        assert_eq!(std::fs::read_to_string(&old).unwrap(), "3");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn force_writes_to_what_is_not_a_regular_file() {
        // No chmod on a device: --output /dev/null --force works for anyone.
        write_file(std::path::Path::new("/dev/null"), b"x", true).unwrap();
        assert!(matches!(
            write_file(std::path::Path::new("/dev/null"), b"x", false),
            Err(brainproxy_core::Error::Conflict(_))
        ));
        // Nor on a pipe (`--output /dev/stdout --force | cat`).
        let (r, w) = std::io::pipe().unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&w);
        write_file(std::path::Path::new(&format!("/dev/fd/{fd}")), b"piped", true).unwrap();
        drop(w);
        let mut got = String::new();
        std::io::Read::read_to_string(&mut { r }, &mut got).unwrap();
        assert_eq!(got, "piped");
    }

    #[test]
    fn a_file_that_cant_be_made_private_is_left_whole() {
        let dir = std::env::temp_dir().join(format!("bp-write-file-chmod-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("someone-elses.json");
        std::fs::write(&path, "theirs").unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let denied = |_: &std::fs::File| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        let e = overwrite(&f, &path, denied).unwrap_err().to_string();
        assert!(e.contains("left as it was"), "{e}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "theirs");
        overwrite(&f, &path, |_| Ok(())).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        let _ = std::fs::remove_dir_all(dir);
    }

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
