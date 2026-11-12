//! Hook scripts: JavaScript a person names to compute what brainproxy otherwise takes as
//! text. Three places call one:
//!
//! - a match-and-replace rule whose replacement is a script (`rules add --script`): its
//!   `replace(match, ctx)` gives what to write in place of each match ([`crate::rules`]);
//! - a fuzz payload processor (`fuzz run --process script:FILE`): its `process(payload, ctx)`
//!   gives the payload to send ([`crate::fuzz`]);
//! - a passive check (`scan script add`): its `check(exchange)` gives findings for a recorded
//!   exchange ([`crate::scan::passive`]);
//! - a request rule (`rules add --location request --script`): its `request(req, ctx)` sees a
//!   request about to be sent and says to send it, send it rewritten, block it, or answer it
//!   itself so nothing is sent ([`crate::rules`]).
//!
//! A script is a file, named where it is used and pinned by the SHA-256 of its text as a
//! signer's script is: a file that changed since it was named doesn't run. It runs in the
//! sandbox every script runs in ([`crate::sandbox`]): a child process with no files, no
//! network and nothing of this process's environment, bounded in time and memory. It is
//! handed data and gives data back; what it is handed is frozen, and what it gives back is
//! checked before anything uses it. Nothing here opens a connection.
//!
//! A hook is called often (for every match, payload or exchange), so its process stays: a
//! few per script, each reading the script once and then answering calls, every call under
//! [`CALL_LIMIT`]. They live as long as something holds the [`Hook`] (a compiled rule set, a
//! processing chain, the passive scanner) and are killed with the last holder. A script
//! stopped at a limit, or that can't be read as a hook, runs no more while it is held:
//! whatever it was to change is left as it is, and the failure is said.
//!
//! [`CALL_LIMIT`]: crate::sandbox::CALL_LIMIT

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{Error, Result};
pub(crate) use crate::sandbox::Failure;
use crate::sandbox::{Worker, OUTPUT_LIMIT};
use crate::scan::{Confidence, Risk};

/// A script file bigger than this isn't read.
pub const MAX_SCRIPT: u64 = 1 << 20;
/// The processes one script may have at once: as many callers run it side by side.
const MAX_WORKERS: usize = 4;
/// What one call may hand a script, as JSON.
const INPUT_LIMIT: usize = OUTPUT_LIMIT as usize;
/// Payloads handed to a processor in one call, and what a set's payloads may come to after it.
const PROCESS_BATCH: usize = 500;
const MAX_PROCESSED: usize = 256 << 20;
/// The findings one exchange may give a check, and the alert types one script may raise in
/// a process's life (each is kept for good, as a declarative check's is).
const MAX_FINDINGS: usize = 50;
const MAX_ALERT_TYPES: usize = 64;

/// Which of a script's functions is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookKind {
    /// `replace(match, ctx)`: a rule's replacement.
    Replace,
    /// `process(payload, ctx)`: a fuzz payload processor.
    Process,
    /// `check(exchange)`: a passive check.
    Check,
    /// `request(req, ctx)`: a request rule, which may block or answer a request.
    Request,
}

impl HookKind {
    /// The function a script of this kind defines.
    pub fn function(self) -> &'static str {
        match self {
            HookKind::Replace => "replace",
            HookKind::Process => "process",
            HookKind::Check => "check",
            HookKind::Request => "request",
        }
    }
}

/// A script file and the hash of the text it was named with.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScriptRef {
    pub file: PathBuf,
    pub sha256: String,
}

/// A script file's text. The error names the file and never quotes it.
fn read_text(file: &Path) -> std::result::Result<String, String> {
    use std::io::Read;
    let from = format!("script file {}", file.display());
    // A file, not a pipe or a device, which could hold the reader up or never end.
    let meta = std::fs::metadata(file).map_err(|_| format!("{from} can't be read"))?;
    if !meta.is_file() {
        return Err(format!("{from} is not a file"));
    }
    // No more than the limit is read, whatever the file says of its size or grows to meanwhile.
    let opened = std::fs::File::open(file).map_err(|_| format!("{from} can't be read"))?;
    let mut bytes = Vec::new();
    opened.take(MAX_SCRIPT + 1).read_to_end(&mut bytes).map_err(|_| format!("{from} can't be read"))?;
    if bytes.len() as u64 > MAX_SCRIPT {
        return Err(format!("{from} is over {} KiB", MAX_SCRIPT >> 10));
    }
    let text = String::from_utf8(bytes).map_err(|_| format!("{from} can't be read as text"))?;
    Ok(text.trim_start_matches('\u{feff}').to_string())
}

impl ScriptRef {
    /// Names `file` as a script: its path made absolute and its hash taken (which must be
    /// `want`, when the caller pins it). Nothing runs, and nothing reads the text as code here:
    /// a script that doesn't parse says so when it is first started ([`Hook::verify`]), in the
    /// sandbox, where a parser that runs away takes a child process with it and nothing else.
    pub fn pin(file: &Path, want: Option<&str>) -> Result<ScriptRef> {
        let file = std::fs::canonicalize(file)
            .map_err(|_| Error::InvalidInput(format!("script file {} can't be read", file.display())))?;
        let text = read_text(&file).map_err(Error::InvalidInput)?;
        let sha256 = crate::fetch::sha256_hex(text.as_bytes());
        if want.is_some_and(|w| !w.eq_ignore_ascii_case(&sha256)) {
            return Err(Error::InvalidInput(format!(
                "script file {} has sha256 {sha256}, not the one given",
                file.display()
            )));
        }
        Ok(ScriptRef { file, sha256 })
    }

    /// The script's text, when it is still the text that was pinned.
    pub fn read(&self) -> std::result::Result<String, String> {
        let text = read_text(&self.file)?;
        if !crate::fetch::sha256_hex(text.as_bytes()).eq_ignore_ascii_case(&self.sha256) {
            return Err(format!(
                "script file {} changed since it was named here; read it and name it again",
                self.file.display()
            ));
        }
        Ok(text)
    }

    /// A short name for messages: the file's.
    pub fn name(&self) -> String {
        self.file.file_name().map_or_else(|| self.file.display().to_string(), |n| n.to_string_lossy().into_owned())
    }
}

/// A script's processes, shared by everything in this process that calls the same script the
/// same way.
struct Host {
    kind: HookKind,
    name: String,
    script: String,
    pool: Mutex<Pool>,
    free: Condvar,
    /// Why it runs no more: stopped at a limit, or it can't be read as a hook.
    stopped: OnceLock<String>,
    /// Failures already said on stderr.
    said: Mutex<HashSet<String>>,
}

#[derive(Default)]
struct Pool {
    idle: Vec<Worker>,
    /// Workers idle, in a call, or starting.
    live: usize,
}

/// Runs `f`, which may wait on a script for as long as its time limit, without holding up the
/// async tasks that share this thread: rules are applied from the proxy's and the engines' tasks.
pub(crate) fn blocking<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

impl Host {
    fn pool(&self) -> MutexGuard<'_, Pool> {
        self.pool.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn earlier(&self) -> Option<Failure> {
        self.stopped.get().map(|why| Failure::Stopped(format!("it was stopped earlier ({why}) and runs no more")))
    }

    /// Notes why the script runs no more, and ends the processes waiting for a call.
    fn stop(&self, why: &str) {
        let _ = self.stopped.set(why.to_string());
        let mut pool = self.pool();
        pool.live -= pool.idle.len();
        pool.idle.clear();
        drop(pool);
        self.free.notify_all();
    }

    /// A worker for one call: an idle one, a new one while there are few, or the next one free.
    fn take(&self) -> std::result::Result<Worker, Failure> {
        let mut pool = self.pool();
        loop {
            if let Some(stopped) = self.earlier() {
                return Err(stopped);
            }
            // One whose process ended while it waited (killed from outside) is no reason to
            // stop the script: another takes its place.
            while let Some(mut worker) = pool.idle.pop() {
                if !worker.gone() {
                    return Ok(worker);
                }
                pool.live -= 1;
            }
            if pool.live < MAX_WORKERS {
                pool.live += 1;
                drop(pool);
                return Worker::start(self.kind.function(), &self.script).inspect_err(|e| {
                    self.pool().live -= 1;
                    self.stop(e.text());
                });
            }
            pool = self.free.wait(pool).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Takes a worker back after a call; `None` for one the call left of no use.
    fn give_back(&self, worker: Option<Worker>) {
        let mut pool = self.pool();
        match worker {
            Some(worker) if !worker.spent() && self.stopped.get().is_none() => pool.idle.push(worker),
            _ => pool.live -= 1,
        }
        drop(pool);
        self.free.notify_one();
    }

    fn call(
        &self,
        cx: &Value,
        items: &[Value],
    ) -> std::result::Result<Vec<std::result::Result<Value, String>>, Failure> {
        self.call_json(cx.to_string(), items.iter().map(Value::to_string).collect(), false)
    }

    /// [`Host::call`], with what the script is handed already written as JSON. With `each`,
    /// every item has the call's time limit to itself.
    fn call_json(
        &self,
        cx: String,
        items: Vec<String>,
        each: bool,
    ) -> std::result::Result<Vec<std::result::Result<Value, String>>, Failure> {
        if let Some(stopped) = self.earlier() {
            return Err(stopped);
        }
        let size = cx.len() + items.iter().map(String::len).sum::<usize>();
        if size > INPUT_LIMIT {
            return Err(Failure::Script(format!(
                "what it would be handed is {} MiB, over the {} MiB a script is given",
                size >> 20,
                INPUT_LIMIT >> 20
            )));
        }
        blocking(|| {
            let mut worker = self.take()?;
            match worker.call(cx, items, each) {
                Ok(out) => {
                    self.give_back(Some(worker));
                    Ok(out)
                }
                Err(e) => {
                    // Its process is in the middle of something: gone with the worker.
                    drop(worker);
                    self.give_back(None);
                    // Stopped at a limit, the script would be stopped there again.
                    if matches!(e, Failure::Stopped(_)) {
                        self.stop(e.text());
                    }
                    Err(e)
                }
            }
        })
    }
}

type Registry = Mutex<HashMap<(HookKind, String), Weak<Host>>>;

/// The scripts in use in this process, by kind and hash: a rule set compiled again (the
/// proxy's, as settings change) finds the processes its script already has, and whether it was
/// stopped. A script nothing holds any more is gone from here, and its processes with it.
fn registry() -> &'static Registry {
    static HOSTS: OnceLock<Registry> = OnceLock::new();
    HOSTS.get_or_init(Default::default)
}

/// A script ready to be called as one kind of hook. Cheap to clone.
#[derive(Clone)]
pub struct Hook(Arc<Host>);

impl std::fmt::Debug for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hook({} {:?})", self.0.kind.function(), self.0.name)
    }
}

impl Hook {
    /// The script `script` names, if its file still holds the text that was pinned. Nothing
    /// runs until the first call.
    pub fn load(kind: HookKind, script: &ScriptRef) -> std::result::Result<Hook, String> {
        Ok(Self::of_text(kind, &script.name(), &script.read()?))
    }

    /// A hook over `text`, called `name` in messages.
    pub fn of_text(kind: HookKind, name: &str, text: &str) -> Hook {
        let key = (kind, crate::fetch::sha256_hex(text.as_bytes()));
        let mut hosts = registry().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(host) = hosts.get(&key).and_then(Weak::upgrade) {
            return Hook(host);
        }
        let host = Arc::new(Host {
            kind,
            name: name.to_string(),
            script: text.to_string(),
            pool: Mutex::default(),
            free: Condvar::new(),
            stopped: OnceLock::new(),
            said: Mutex::default(),
        });
        hosts.retain(|_, known| known.strong_count() > 0);
        hosts.insert(key, Arc::downgrade(&host));
        Hook(host)
    }

    pub fn name(&self) -> &str {
        &self.0.name
    }

    /// Starts the script, to say now what a first call would: that it doesn't parse, throws as
    /// it loads, or defines no function of its kind. This runs the script's top level.
    pub fn verify(&self) -> std::result::Result<(), String> {
        let host = &self.0;
        blocking(|| host.take().map(|worker| host.give_back(Some(worker)))).map_err(|e| e.text().to_string())
    }

    /// Says a failure on stderr, once for each different one: an engine that leaves a message
    /// as it is because its script failed says why, without a line for every message.
    pub fn warn(&self, what: &str, error: &str) {
        let mut said = self.0.said.lock().unwrap_or_else(|e| e.into_inner());
        if said.len() < 20 && said.insert(format!("{what}: {error}")) {
            eprintln!("brainproxy: {what}: script {}: {error}", self.0.name);
        }
    }

    /// Calls `replace` for each of `matches`, all in the message `cx` describes. The
    /// replacement for each, or None where the script says to leave the match as it is. Any
    /// match it fails on fails them all: half a rule's replacements is not what the rule says.
    pub(crate) fn replace(&self, cx: &Value, matches: &[Value]) -> std::result::Result<Vec<Option<Vec<u8>>>, Failure> {
        let mut out = Vec::with_capacity(matches.len());
        for result in self.0.call(cx, matches)? {
            out.push(result.and_then(|v| bytes_back(&v)).map_err(Failure::Script)?);
        }
        Ok(out)
    }

    /// Passes each of `payloads` (payload set `set`, counted from 1) through `process`, in
    /// place. The first payload it fails on stops it, and none is changed.
    pub fn process(&self, set: usize, payloads: &mut [Vec<u8>]) -> Result<()> {
        let bad = |i: usize, e: &str| {
            Error::InvalidInput(format!("script {}: payload {} of set {set}: {e}", self.0.name, i + 1))
        };
        let cx = json!({ "set": set }).to_string();
        let mut done: Vec<Option<Vec<u8>>> = Vec::with_capacity(payloads.len());
        // Each payload is written as JSON once: its length says when a batch is full.
        let mut batch: Vec<String> = Vec::new();
        let (mut size, mut kept) = (0, 0);
        for (i, payload) in payloads.iter().enumerate() {
            let item = with_bytes(json!({ "index": i }), "text", "base64", payload).to_string();
            size += item.len();
            batch.push(item);
            if batch.len() == PROCESS_BATCH || size > INPUT_LIMIT / 4 || i + 1 == payloads.len() {
                let first = i + 1 - batch.len();
                let sent = std::mem::take(&mut batch);
                let results = self.0.call_json(cx.clone(), sent, true).map_err(|e| bad(first, e.text()))?;
                for (k, result) in results.into_iter().enumerate() {
                    let new = result.and_then(|v| bytes_back(&v)).map_err(|e| bad(first + k, &e))?;
                    kept += new.as_ref().map_or(0, Vec::len);
                    if kept > MAX_PROCESSED {
                        let e = format!("the set's payloads come to over {} MiB after it", MAX_PROCESSED >> 20);
                        return Err(bad(first + k, &e));
                    }
                    done.push(new);
                }
                size = 0;
            }
        }
        for (payload, new) in payloads.iter_mut().zip(done) {
            if let Some(new) = new {
                *payload = new;
            }
        }
        Ok(())
    }

    /// Calls `check` on one recorded exchange and reads the findings it gives.
    pub(crate) fn check(&self, exchange: &Value) -> std::result::Result<Vec<ScriptFinding>, Failure> {
        let result = self.0.call(&json!({}), std::slice::from_ref(exchange))?.pop();
        let value = result.unwrap_or_else(|| Err("it gave no result".into())).map_err(Failure::Script)?;
        let list = value["findings"].as_array().ok_or_else(|| Failure::Script("its result couldn't be read".into()))?;
        if list.len() > MAX_FINDINGS {
            return Err(Failure::Script(format!(
                "it gave {} findings for one exchange; at most {MAX_FINDINGS}",
                list.len()
            )));
        }
        list.iter().map(ScriptFinding::read).collect::<std::result::Result<_, _>>().map_err(Failure::Script)
    }

    /// Calls `request` on one request (`req`, as a script reads it) with `cx` (the engine and
    /// host): what it returned, in the shape `hook.js` gives it (`{keep}`, `{request}`,
    /// `{block}` or `{response}`), for [`crate::rules`] to read.
    pub(crate) fn request(&self, cx: &Value, req: &Value) -> std::result::Result<Value, Failure> {
        let result = self.0.call(cx, std::slice::from_ref(req))?.pop();
        result.unwrap_or_else(|| Err("it gave no result".into())).map_err(Failure::Script)
    }
}

/// `o` with `bytes` in it as a script reads them: as text under `text_key`, and when they
/// aren't UTF-8 (so the text has replacement characters) exactly, as base64, under `base64_key`.
pub fn with_bytes(mut o: Value, text_key: &str, base64_key: &str, bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => o[text_key] = json!(text),
        Err(_) => {
            o[text_key] = json!(String::from_utf8_lossy(bytes));
            o[base64_key] = json!(STANDARD.encode(bytes));
        }
    }
    o
}

/// The bytes a `replace` or `process` gave: None for "leave it as it is".
fn bytes_back(v: &Value) -> std::result::Result<Option<Vec<u8>>, String> {
    if let Some(text) = v["text"].as_str() {
        return Ok(Some(text.as_bytes().to_vec()));
    }
    if let Some(b) = v["base64"].as_str() {
        return STANDARD.decode(b.trim()).map(Some).map_err(|_| "the base64 it returned isn't base64".to_string());
    }
    if v["keep"] == true {
        return Ok(None);
    }
    Err("its result couldn't be read".into())
}

/// A finding as a passive check script gives it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScriptFinding {
    /// What tells this script's alert types apart: the script's `id`, or one made of the name.
    pub id: String,
    pub name: String,
    pub risk: Risk,
    pub confidence: Confidence,
    pub param: String,
    pub evidence: String,
    pub info: String,
    pub description: String,
    pub solution: String,
    pub cwe: u32,
}

/// `s` cut to `max` characters.
fn cut(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

impl ScriptFinding {
    fn read(v: &Value) -> std::result::Result<ScriptFinding, String> {
        let known = ["id", "name", "risk", "confidence", "param", "evidence", "info", "description", "solution", "cwe"];
        if let Some(key) = v.as_object().and_then(|o| o.keys().find(|k| !known.contains(&k.as_str()))) {
            return Err(format!("a finding has no {:?}; it has {}", cut(key, 40), known.join(", ")));
        }
        let text = |key: &str, max: usize| -> std::result::Result<String, String> {
            match &v[key] {
                Value::Null => Ok(String::new()),
                Value::String(s) => Ok(cut(s, max)),
                _ => Err(format!("a finding's {key} must be a string")),
            }
        };
        let name = text("name", 200)?;
        if name.trim().is_empty() {
            return Err("a finding needs a name".into());
        }
        let risk = match v["risk"].as_str() {
            None if v["risk"].is_null() => Risk::Info,
            Some(r) => Risk::parse(r).ok_or("a finding's risk is info, low, medium, high or critical")?,
            None => return Err("a finding's risk is info, low, medium, high or critical".into()),
        };
        let confidence = match v["confidence"].as_str() {
            None if v["confidence"].is_null() => Confidence::Medium,
            Some(c) => Confidence::parse(c).ok_or("a finding's confidence is low, medium or high")?,
            None => return Err("a finding's confidence is low, medium or high".into()),
        };
        let cwe = match &v["cwe"] {
            Value::Null => 0,
            n => n.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or("a finding's cwe is a number")?,
        };
        let slug = |s: &str| -> String {
            let s: String =
                s.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect();
            let parts: Vec<&str> = s.split('-').filter(|p| !p.is_empty()).collect();
            cut(&parts.join("-"), 60)
        };
        let id = match text("id", 60)? {
            id if id.is_empty() => slug(&name),
            id => slug(&id),
        };
        Ok(ScriptFinding {
            id,
            name,
            risk,
            confidence,
            param: text("param", 200)?,
            evidence: text("evidence", 4000)?,
            info: text("info", 8000)?,
            description: text("description", 8000)?,
            solution: text("solution", 8000)?,
            cwe,
        })
    }
}

/// How many alert types one script may raise in a process's life.
pub(crate) fn max_alert_types() -> usize {
    MAX_ALERT_TYPES
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sandbox::tests::use_test_runner;

    pub(crate) fn hook(kind: HookKind, text: &str) -> Hook {
        use_test_runner();
        Hook::of_text(kind, "test.js", text)
    }

    /// A script in a file of its own, pinned; the folder is the caller's to remove.
    pub(crate) fn script_file(text: &str) -> (ScriptRef, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "bp-hook-{}-{}",
            std::process::id(),
            crate::fetch::sha256_hex(format!("{text}{:?}", std::thread::current().id()).as_bytes())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("hook.js");
        std::fs::write(&file, text).unwrap();
        (ScriptRef::pin(&file, None).unwrap(), dir)
    }

    #[test]
    fn a_script_is_pinned_and_a_changed_file_doesnt_run() {
        let (script, dir) = script_file("function replace(m) { return m.text; }");
        assert!(script.file.is_absolute() && script.sha256.len() == 64);
        assert!(ScriptRef::pin(&script.file, Some(&script.sha256.to_uppercase())).is_ok());
        assert!(ScriptRef::pin(&script.file, Some(&"0".repeat(64))).unwrap_err().to_string().contains("sha256"));
        assert!(Hook::load(HookKind::Replace, &script).is_ok());
        std::fs::write(&script.file, "function replace(m) { return 'other'; }").unwrap();
        let e = Hook::load(HookKind::Replace, &script).unwrap_err();
        assert!(e.contains("changed since it was named"), "{e}");
        // The error never quotes the file.
        assert!(!e.contains("other"), "{e}");
        // What doesn't parse is pinned like anything else, and says so when it is started.
        std::fs::write(&script.file, "function replace( {").unwrap();
        let broken = ScriptRef::pin(&script.file, None).unwrap();
        use_test_runner();
        assert!(Hook::load(HookKind::Replace, &broken).unwrap().verify().unwrap_err().contains("SyntaxError"));
        // Nor does one nested deeper than a parser's stack: its child process ends, not this one.
        let deep = format!("function replace() {{ return {}1{}; }}", "(".repeat(200_000), ")".repeat(200_000));
        std::fs::write(&script.file, deep).unwrap();
        let deep = ScriptRef::pin(&script.file, None).unwrap();
        assert!(Hook::load(HookKind::Replace, &deep).unwrap().verify().is_err());
        std::fs::remove_file(&script.file).unwrap();
        assert!(Hook::load(HookKind::Replace, &script).unwrap_err().contains("can't be read"));
        assert!(ScriptRef::pin(&script.file, None).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_script_must_be_a_file() {
        assert!(ScriptRef::pin(Path::new("/dev/zero"), None).unwrap_err().to_string().contains("is not a file"));
        let dir = std::env::temp_dir();
        assert!(ScriptRef::pin(&dir, None).unwrap_err().to_string().contains("is not a file"));
    }

    #[test]
    fn a_script_over_the_size_limit_isnt_read() {
        let (script, dir) = script_file("function replace(m) { return m.text; }");
        std::fs::write(&script.file, format!("// {}\n", "x".repeat(MAX_SCRIPT as usize))).unwrap();
        assert!(ScriptRef::pin(&script.file, None).unwrap_err().to_string().contains("is over 1024 KiB"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn replacements_come_back_as_bytes() {
        let h = hook(
            HookKind::Replace,
            "function replace(m, cx) {
                if (m.text === 'keep') return null;
                if (m.base64) return { base64: m.base64 };
                return cx.name + '=' + m.text;
            }",
        );
        h.verify().unwrap();
        let items = [
            with_bytes(json!({}), "text", "base64", b"a"),
            with_bytes(json!({}), "text", "base64", b"keep"),
            with_bytes(json!({}), "text", "base64", &[0xff, 0x00]),
        ];
        let out = h.replace(&json!({"name": "n"}), &items).unwrap();
        assert_eq!(out, [Some(b"n=a".to_vec()), None, Some(vec![0xff, 0x00])]);
        // One match it fails on fails the call, and the next call is served as before.
        let throws =
            hook(HookKind::Replace, "function replace(m) { if (m.text === 'b') throw new Error('no b'); return 'x'; }");
        let items = [json!({"text": "a"}), json!({"text": "b"})];
        assert!(matches!(throws.replace(&json!({}), &items), Err(Failure::Script(e)) if e.contains("no b")));
        assert_eq!(throws.replace(&json!({}), &items[..1]).unwrap(), [Some(b"x".to_vec())]);
        let bad = hook(HookKind::Replace, "function replace(m) { return { base64: '***' }; }");
        assert!(matches!(bad.replace(&json!({}), &items[..1]), Err(Failure::Script(e)) if e.contains("isn't base64")));
    }

    #[test]
    fn a_script_that_cant_be_a_hook_says_so_when_verified_and_runs_no_more() {
        let h = hook(HookKind::Process, "function replace(m) { return m.text; }");
        assert_eq!(h.verify().unwrap_err(), "it defines no process function");
        let mut payloads = vec![b"a".to_vec()];
        let e = h.process(1, &mut payloads).unwrap_err().to_string();
        assert!(e.contains("stopped earlier (it defines no process function)"), "{e}");
        assert_eq!(payloads, [b"a".to_vec()]);
    }

    #[test]
    fn a_hook_stopped_at_the_time_limit_runs_no_more() {
        let h = hook(
            HookKind::Replace,
            "function replace(m) { if (m.text === 'slow') /^(a+)+$/.test('a'.repeat(40) + 'b'); return 'x' + m.text; }",
        );
        assert_eq!(h.replace(&json!({}), &[json!({"text": "a"})]).unwrap(), [Some(b"xa".to_vec())]);
        let r = h.replace(&json!({}), &[json!({"text": "slow"})]);
        assert!(matches!(&r, Err(Failure::Stopped(e)) if e.contains("time limit")), "{r:?}");
        #[cfg(unix)]
        assert!(!crate::sandbox::tests::last_child_alive());
        let started = std::time::Instant::now();
        let r = h.replace(&json!({}), &[json!({"text": "a"})]);
        assert!(matches!(&r, Err(Failure::Stopped(e)) if e.contains("stopped earlier")), "{r:?}");
        assert!(started.elapsed() < std::time::Duration::from_millis(500), "a stopped hook costs nothing more");
        assert!(h.verify().unwrap_err().contains("stopped earlier"));
    }

    #[test]
    fn a_scripts_processes_end_with_the_last_holder_of_its_hook() {
        let text =
            "function replace(m) { if (m.text === 'slow') /^(a+)+$/.test('a'.repeat(40) + 'b'); return 'held'; }";
        let h = hook(HookKind::Replace, text);
        let again = hook(HookKind::Replace, text);
        assert!(Arc::ptr_eq(&h.0, &again.0), "one script, one set of processes");
        assert_eq!(h.replace(&json!({}), &[json!({"text": "a"})]).unwrap(), [Some(b"held".to_vec())]);
        #[cfg(unix)]
        assert!(crate::sandbox::tests::last_child_alive(), "its process waits for the next call");
        drop(again);
        #[cfg(unix)]
        assert!(crate::sandbox::tests::last_child_alive());
        // Stopped, it stays stopped for whoever takes it up while it is held.
        assert!(h.replace(&json!({}), &[json!({"text": "slow"})]).is_err());
        assert!(hook(HookKind::Replace, text).verify().unwrap_err().contains("stopped earlier"));
        drop(h);
        // Held by nobody, it is gone: the next to name it starts afresh, and its process ends with it.
        let fresh = hook(HookKind::Replace, text);
        assert_eq!(fresh.replace(&json!({}), &[json!({"text": "a"})]).unwrap(), [Some(b"held".to_vec())]);
        drop(fresh);
        #[cfg(unix)]
        assert!(!crate::sandbox::tests::last_child_alive(), "no process outlives its script's last holder");
    }

    #[test]
    fn many_callers_share_a_few_processes() {
        let h = hook(
            HookKind::Replace,
            "function replace(m) { return m.text + '!' + cx_of(m); } const cx_of = (m) => m.n;",
        );
        let threads: Vec<_> = (0..12)
            .map(|n| {
                let h = h.clone();
                std::thread::spawn(move || {
                    (0..20)
                        .map(|i| {
                            let item = json!({"text": format!("{n}-{i}"), "n": n});
                            h.replace(&json!({}), &[item]).unwrap().remove(0).unwrap()
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for (n, t) in threads.into_iter().enumerate() {
            let got = t.join().unwrap();
            let want: Vec<Vec<u8>> = (0..20).map(|i| format!("{n}-{i}!{n}").into_bytes()).collect();
            assert_eq!(got, want);
        }
        let pool = h.0.pool();
        assert!(pool.live <= MAX_WORKERS && pool.idle.len() == pool.live, "{} live", pool.live);
    }

    #[test]
    fn payloads_are_processed_in_batches_and_a_bad_one_changes_none() {
        let h = hook(
            HookKind::Process,
            "function process(p, cx) {
                if (p === 'bad') throw new Error('no ' + cx.index);
                if (p === 'same') return null;
                if (cx.base64) return { base64: cx.base64 };
                return cx.set + ':' + p.toUpperCase();
            }",
        );
        let mut payloads: Vec<Vec<u8>> = (0..1203).map(|i| format!("p{i}").into_bytes()).collect();
        payloads[7] = b"same".to_vec();
        payloads[8] = vec![0xfe, 0xff];
        h.process(2, &mut payloads).unwrap();
        assert_eq!(payloads[0], b"2:P0");
        assert_eq!(payloads[7], b"same");
        assert_eq!(payloads[8], [0xfe, 0xff]);
        assert_eq!(payloads[1202], b"2:P1202");
        let mut payloads = vec![b"a".to_vec(), b"bad".to_vec(), b"c".to_vec()];
        let e = h.process(1, &mut payloads).unwrap_err().to_string();
        assert!(e.contains("payload 2 of set 1") && e.contains("no 1"), "{e}");
        assert_eq!(payloads, [b"a".to_vec(), b"bad".to_vec(), b"c".to_vec()]);
    }

    #[test]
    fn findings_are_read_strictly() {
        let h = hook(
            HookKind::Check,
            "function check(x) {
                switch (x.path) {
                    case '/none': return;
                    case '/one': return { name: 'Debug header', risk: 'Low', evidence: x.response.headers[0][1] };
                    case '/two': return [{ name: 'A b/c', id: 'My Id' }, { name: 'B', confidence: 'high', cwe: 200 }];
                    case '/risk': return { name: 'A', risk: 'severe' };
                    case '/noname': return { evidence: 'x' };
                    case '/extra': return { name: 'A', severity: 'high' };
                    case '/string': return 'found';
                    case '/many': return Array.from({ length: 51 }, (_, i) => ({ name: 'N' + i }));
                }
            }",
        );
        let on = |path: &str| h.check(&json!({"path": path, "response": {"headers": [["X-Debug", "1"]]}}));
        assert_eq!(on("/none").unwrap(), []);
        let one = on("/one").unwrap();
        assert_eq!(
            (one[0].id.as_str(), one[0].risk, one[0].confidence, one[0].evidence.as_str()),
            ("debug-header", Risk::Low, Confidence::Medium, "1")
        );
        let two = on("/two").unwrap();
        assert_eq!((two[0].id.as_str(), two[1].id.as_str(), two[1].cwe), ("my-id", "b", 200));
        for (path, why) in [
            ("/risk", "risk is info, low"),
            ("/noname", "needs a name"),
            ("/extra", "has no \"severity\""),
            ("/string", "a string as a finding"),
            ("/many", "51 findings"),
        ] {
            let Err(Failure::Script(e)) = on(path) else { panic!("{path} gave findings") };
            assert!(e.contains(why), "{path}: {e}");
        }
    }

    #[test]
    fn a_call_over_the_input_limit_is_refused_without_stopping_the_script() {
        let h = hook(HookKind::Replace, "function replace(m) { return 'x'; }");
        let big = json!({"text": "a".repeat(INPUT_LIMIT + 1)});
        assert!(matches!(h.replace(&json!({}), &[big]), Err(Failure::Script(e)) if e.contains("over the 16 MiB")));
        assert_eq!(h.replace(&json!({}), &[json!({"text": "a"})]).unwrap(), [Some(b"x".to_vec())]);
    }
}
