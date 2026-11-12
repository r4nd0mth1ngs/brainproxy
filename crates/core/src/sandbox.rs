//! Where the scripts brainproxy runs are run: a signer's Postman pre-request script
//! ([`crate::sign_script`]) and the hook scripts a person names ([`crate::hooks`]).
//!
//! The interpreter is memory safe and has no way out but the few helpers here, which hash,
//! encode and give random bytes: no files, no network, no process, no clock a script can set.
//! A run gets a loop and recursion limit.
//!
//! The interpreter can't be interrupted (a regex that backtracks, a loop of `await`s), so a
//! script runs in a child process, `brainproxy __sign-script`, killed at its time limit. Its
//! memory is bounded on each system its own way: on Linux the child limits its address
//! space, on Windows it runs in a job object with a memory limit, and on macOS (which
//! accepts an address-space limit but doesn't enforce it) the parent watches its memory and
//! kills it over the limit. On Unix it also limits its CPU time. It starts with an empty
//! environment, and gets its script and what the script works on over stdin; all it gives
//! back is JSON on stdout.
//!
//! A signer's script gets a process for each run ([`run_once`]). A hook is called for every
//! match, payload or exchange, so its process stays ([`Worker`]): the script is read once and
//! its function called again and again, each call under a time limit of its own.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{mpsc, OnceLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use boa_engine::object::JsObject;
use boa_engine::{js_string, Context, JsError, JsResult, JsString, JsValue, NativeFunction, Source};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;

const LIB: &str = include_str!("script_lib.js");
const HOOK: &str = include_str!("hook.js");
const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 200;
/// The interpreter recurses on the native stack.
const STACK_BYTES: usize = 16 * 1024 * 1024;
/// How long a signer's run may take, and a hook's process to start.
pub(crate) const TIME_LIMIT: Duration = Duration::from_secs(5);
/// How long one call of a hook's function may take.
pub(crate) const CALL_LIMIT: Duration = Duration::from_secs(2);
/// The child's memory: the interpreter, its stack and the script's data. On Linux it bounds
/// the address space, on Windows the committed memory, on macOS the physical footprint.
pub(crate) const MEMORY_LIMIT: u64 = 1 << 30;
/// How often the parent looks at the child's memory where the system doesn't bound it.
const WATCH_INTERVAL: Duration = if cfg!(target_os = "macos") { Duration::from_millis(10) } else { TIME_LIMIT };
/// A result longer than this is no request's headers, and no replacement or finding either.
pub(crate) const OUTPUT_LIMIT: u64 = 16 * 1024 * 1024;
/// The CPU time of a signer's run, in seconds.
const RUN_CPU: u64 = TIME_LIMIT.as_secs() * 2;
/// The CPU time of a hook's process over its life, in seconds: [`Worker::spent`] says when to
/// start another, well before this.
const WORKER_CPU: u64 = 120;
/// Globals a script has no use for: shared memory and blocking waits.
const REMOVED_GLOBALS: &[&str] = &["SharedArrayBuffer", "Atomics", "Temporal"];

fn text_arg(args: &[JsValue], i: usize, ctx: &mut Context) -> JsResult<String> {
    Ok(args.get(i).cloned().unwrap_or_default().to_string(ctx)?.to_std_string_escaped())
}

fn bytes_arg(args: &[JsValue], i: usize, ctx: &mut Context) -> JsResult<Vec<u8>> {
    hex::decode(text_arg(args, i, ctx)?).map_err(|_| JsError::from_opaque(js_string!("bad bytes").into()))
}

pub(crate) fn js_text(s: &str) -> JsValue {
    JsString::from(s).into()
}

fn digest_of(alg: &str, data: &[u8]) -> JsResult<Vec<u8>> {
    use md5::Md5;
    use sha1::Sha1;
    use sha2::{Sha256, Sha384, Sha512};
    Ok(match alg {
        "md5" => Md5::digest(data).to_vec(),
        "sha1" => Sha1::digest(data).to_vec(),
        "sha256" => Sha256::digest(data).to_vec(),
        "sha384" => Sha384::digest(data).to_vec(),
        "sha512" => Sha512::digest(data).to_vec(),
        _ => return Err(JsError::from_opaque(js_string!("unknown hash").into())),
    })
}

fn native_digest(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let alg = text_arg(args, 0, ctx)?;
    let data = bytes_arg(args, 1, ctx)?;
    Ok(js_text(&hex::encode(digest_of(&alg, &data)?)))
}

fn native_hmac(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let alg = text_arg(args, 0, ctx)?;
    let key = bytes_arg(args, 1, ctx)?;
    let data = bytes_arg(args, 2, ctx)?;
    let mac = match alg.as_str() {
        "sha1" => crate::sign::hmac_digest(crate::sign::HmacAlg::Sha1, &key, &data),
        "sha256" => crate::sign::hmac_digest(crate::sign::HmacAlg::Sha256, &key, &data),
        "sha384" => crate::sign::hmac_digest(crate::sign::HmacAlg::Sha384, &key, &data),
        "sha512" => crate::sign::hmac_digest(crate::sign::HmacAlg::Sha512, &key, &data),
        "md5" => hmac_md5(&key, &data),
        _ => return Err(JsError::from_opaque(js_string!("unknown HMAC hash").into())),
    };
    Ok(js_text(&hex::encode(mac)))
}

pub(crate) fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    use md5::{Digest as _, Md5};
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..16].copy_from_slice(&Md5::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |x: u8| block.iter().map(|b| b ^ x).collect::<Vec<u8>>();
    let inner = Md5::new().chain_update(pad(0x36)).chain_update(data).finalize();
    Md5::new().chain_update(pad(0x5c)).chain_update(inner).finalize().to_vec()
}

fn native_utf8_to_hex(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let s = args.first().cloned().unwrap_or_default().to_string(ctx)?;
    Ok(js_text(&hex::encode(String::from_utf16_lossy(s.as_str().to_vec().as_slice()))))
}

fn native_hex_to_utf8(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    Ok(js_text(&String::from_utf8_lossy(&bytes_arg(args, 0, ctx)?)))
}

fn native_latin1_to_hex(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let s = args.first().cloned().unwrap_or_default().to_string(ctx)?;
    let bytes: Vec<u8> = s.as_str().to_vec().iter().map(|u| *u as u8).collect();
    Ok(js_text(&hex::encode(bytes)))
}

fn native_hex_to_latin1(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let units: Vec<u16> = bytes_arg(args, 0, ctx)?.iter().map(|b| u16::from(*b)).collect();
    Ok(JsString::from(units.as_slice()).into())
}

fn native_hex_to_b64(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    Ok(js_text(&STANDARD.encode(bytes_arg(args, 0, ctx)?)))
}

fn native_b64_to_hex(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let text = text_arg(args, 0, ctx)?;
    let bytes = STANDARD
        .decode(text.trim())
        .or_else(|_| URL_SAFE_NO_PAD.decode(text.trim().trim_end_matches('=')))
        .map_err(|_| JsError::from_opaque(js_string!("bad base64").into()))?;
    Ok(js_text(&hex::encode(bytes)))
}

fn native_random_hex(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let n = args.first().cloned().unwrap_or_default().to_u32(ctx)?.min(4096) as usize;
    let mut b = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| JsError::from_opaque(js_string!("no random bytes").into()))?;
    Ok(js_text(&hex::encode(b)))
}

type Native = fn(&JsValue, &[JsValue], &mut Context) -> JsResult<JsValue>;

const NOT_STARTED: &str = "the script runner failed to start";

/// An interpreter with nothing added, and no way to load a module: left to itself the engine
/// reads `import()`ed files from the working directory.
pub(crate) fn bare_context() -> std::result::Result<Context, String> {
    Context::builder()
        .module_loader(std::rc::Rc::new(boa_engine::module::IdleModuleLoader))
        .build()
        .map_err(|_| NOT_STARTED.to_string())
}

/// An interpreter as every script finds it: its limits set, the globals no script needs gone,
/// and the library (CryptoJS, `Buffer.from`, `btoa`, `require` of a few modules) in place.
/// The byte helpers the library is built on are all that reaches out of it.
pub(crate) fn context() -> std::result::Result<Context, String> {
    let mut ctx = bare_context()?;
    for name in REMOVED_GLOBALS {
        ctx.global_object()
            .delete_property_or_throw(JsString::from(*name), &mut ctx)
            .map_err(|_| NOT_STARTED.to_string())?;
    }
    let limits = ctx.runtime_limits_mut();
    limits.set_loop_iteration_limit(LOOP_LIMIT);
    limits.set_recursion_limit(RECURSION_LIMIT);
    let natives: [(&str, usize, Native); 9] = [
        ("__digest", 2, native_digest),
        ("__hmac", 3, native_hmac),
        ("__utf8ToHex", 1, native_utf8_to_hex),
        ("__hexToUtf8", 1, native_hex_to_utf8),
        ("__latin1ToHex", 1, native_latin1_to_hex),
        ("__hexToLatin1", 1, native_hex_to_latin1),
        ("__hexToB64", 1, native_hex_to_b64),
        ("__b64ToHex", 1, native_b64_to_hex),
        ("__randomHex", 1, native_random_hex),
    ];
    for (name, len, f) in natives {
        ctx.register_global_callable(JsString::from(name), len, NativeFunction::from_fn_ptr(f))
            .map_err(|_| NOT_STARTED.to_string())?;
    }
    ctx.eval(Source::from_bytes(LIB)).map_err(|e| format!("{NOT_STARTED}: {e}"))?;
    Ok(ctx)
}

/// What a script threw, as a short message, with where in the script it was thrown.
pub(crate) fn explain(e: JsError, ctx: &mut Context) -> String {
    explain_at(e, ctx, true)
}

/// [`explain`]; `position` says whether the message ends with a place in the script. A hook's
/// function is called from `hook.js`, and the place given would be there.
fn explain_at(e: JsError, ctx: &mut Context, position: bool) -> String {
    use boa_engine::error::{EngineError, RuntimeLimitError};
    match e.as_engine() {
        Some(EngineError::RuntimeLimit(RuntimeLimitError::LoopIteration)) => {
            return format!("a loop in it ran past the limit of {LOOP_LIMIT} rounds");
        }
        Some(EngineError::RuntimeLimit(_)) => return "it ran past the recursion limit".to_string(),
        Some(_) => return "the interpreter failed".to_string(),
        None => {}
    }
    let text = e.try_native(ctx).map_or_else(
        |_| "it threw a value".to_string(),
        |n| match (position, n.message().trim()) {
            (true, _) => n.to_string(),
            (false, "") => n.kind().to_string(),
            (false, message) => format!("{}: {message}", n.kind()),
        },
    );
    match text.split_once("__unsupported:") {
        Some((_, name)) => {
            format!("it uses {}, which isn't available here", name.chars().take(80).collect::<String>())
        }
        None => text.chars().take(200).collect(),
    }
}

/// Why a run gave no result.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Failure {
    /// The script failed: it threw, or used what isn't here. Another call may fare better.
    Script(String),
    /// The run was stopped at the time or memory limit, or couldn't start: running the
    /// script again would only cost as much again.
    Stopped(String),
}

impl Failure {
    pub(crate) fn text(&self) -> &str {
        match self {
            Failure::Script(e) | Failure::Stopped(e) => e,
        }
    }
}

/// How a script's child process starts.
struct Runner {
    program: PathBuf,
    args: Vec<String>,
    env: Vec<(String, String)>,
}

static RUNNER: OnceLock<Runner> = OnceLock::new();

/// Names the program that runs scripts, with its arguments: the brainproxy command sets
/// itself and `__sign-script`, before anything signs. Without it no script runs.
pub fn set_runner(program: PathBuf, args: &[&str]) {
    set_runner_with_env(program, args, &[]);
}

fn set_runner_with_env(program: PathBuf, args: &[&str], env: &[(&str, &str)]) {
    let _ = RUNNER.set(Runner {
        program,
        args: args.iter().map(|a| a.to_string()).collect(),
        env: env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    });
}

/// What a child is started for: the first line it reads on stdin.
#[derive(Serialize, Deserialize)]
struct Start {
    /// The memory limit, in bytes, for the child to set where it can (Linux).
    memory: u64,
    /// The CPU time it may use, in seconds, where the system limits that (Unix).
    cpu: u64,
    job: Job,
}

#[derive(Serialize, Deserialize)]
pub(crate) enum Job {
    /// One run of a signer's script: the child answers with one [`Reply`] and ends.
    Sign(crate::sign_script::SignJob),
    /// A hook's script: the child answers once it has read the script, then serves [`Call`]s
    /// until its stdin closes.
    Hook { kind: String, script: String },
}

/// One call of a hook: what its function is told about every item, and the items. The child
/// answers with one [`Reply`] for each item, in order, as it gets to them.
#[derive(Serialize, Deserialize)]
struct Call {
    /// JSON, parsed in the script's world.
    cx: String,
    /// JSON, each parsed in the script's world.
    items: Vec<String>,
}

/// The child's answers: each one line of JSON.
#[derive(Default, Serialize, Deserialize)]
struct Reply {
    r: Answer,
}

#[derive(Default, Serialize, Deserialize)]
struct Answer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ok: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// What every answer line starts with: what else is on stdout (a test harness's own lines,
/// in tests) is not one.
const REPLY_PREFIX: &str = "{\"r\":";

fn answer(result: std::result::Result<Value, String>) -> Option<String> {
    let r = match result {
        Ok(v) => Answer { ok: Some(v), error: None },
        Err(e) => Answer { ok: None, error: Some(e) },
    };
    serde_json::to_string(&Reply { r }).ok()
}

/// The child side (`brainproxy __sign-script`): reads what it is started for on stdin, limits
/// itself, and does it on a thread with a large stack (the interpreter recurses on the native
/// stack), writing its answers to stdout. Returns the exit code.
pub fn child_main() -> i32 {
    let mut first = Vec::new();
    if std::io::stdin().lock().read_until(b'\n', &mut first).is_err() {
        return 2;
    }
    let Ok(start) = serde_json::from_slice::<Start>(&first) else { return 2 };
    drop(first);
    limit_resources(start.memory, start.cpu);
    let ran =
        std::thread::Builder::new().name("script".into()).stack_size(STACK_BYTES).spawn(move || match start.job {
            Job::Sign(job) => {
                let result = crate::sign_script::run_here(&job).and_then(|outcome| {
                    serde_json::to_value(outcome).map_err(|_| "its result couldn't be read".to_string())
                });
                // On a line of its own, whatever came before it (the test harness, in tests).
                match answer(result) {
                    Some(line) if say(&format!("\n{line}")) => 0,
                    _ => 3,
                }
            }
            Job::Hook { kind, script } => serve(&kind, &script),
        });
    match ran.map(|t| t.join()) {
        Ok(Ok(code)) => code,
        _ => 3,
    }
}

/// Writes one line to stdout; false when it couldn't.
fn say(line: &str) -> bool {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").and_then(|_| out.flush()).is_ok()
}

/// A hook script's function, ready to be called.
struct Served {
    ctx: Context,
    set_cx: JsObject,
    call: JsObject,
}

impl Served {
    /// Reads `script` and finds the function its kind names (`replace`, `process`, `check` or
    /// `request`).
    fn new(kind: &str, script: &str) -> std::result::Result<Served, String> {
        let mut ctx = context()?;
        let not_started = |_| NOT_STARTED.to_string();
        // Made before the script runs, so nothing the script redefines changes how it is called.
        let wrap = ctx.eval(Source::from_bytes(HOOK)).map_err(not_started)?;
        let wrap = wrap.as_callable().ok_or(NOT_STARTED)?;
        if let Err(e) = ctx.eval(Source::from_bytes(script)) {
            return Err(explain(e, &mut ctx));
        }
        let _ = ctx.run_jobs();
        // A function declared with `function`, or kept in a `const` or `let` at the top.
        let found = ctx
            .eval(Source::from_bytes(&format!("typeof {kind} === 'function' ? {kind} : undefined")))
            .map_err(not_started)?;
        if !found.is_callable() {
            return Err(format!("it defines no {kind} function"));
        }
        let made = wrap.call(&JsValue::undefined(), &[found, js_text(kind)], &mut ctx).map_err(not_started)?;
        let made = made.as_object().ok_or(NOT_STARTED)?;
        let part = |name: &str, ctx: &mut Context| -> std::result::Result<JsObject, String> {
            made.get(JsString::from(name), ctx).ok().and_then(|v| v.as_callable()).ok_or(NOT_STARTED.to_string())
        };
        let (set_cx, call) = (part("cx", &mut ctx)?, part("call", &mut ctx)?);
        Ok(Served { ctx, set_cx, call })
    }

    fn set_cx(&mut self, cx: &str) -> std::result::Result<(), String> {
        self.set_cx
            .call(&JsValue::undefined(), &[js_text(cx)], &mut self.ctx)
            .map(|_| ())
            .map_err(|_| "what it works on couldn't be handed over".to_string())
    }

    fn call(&mut self, item: &str) -> std::result::Result<Value, String> {
        let done = match self.call.call(&JsValue::undefined(), &[js_text(item)], &mut self.ctx) {
            Ok(done) => done,
            Err(e) => return Err(explain_at(e, &mut self.ctx, false)),
        };
        let text = done.as_string().map(|s| s.to_std_string_escaped()).ok_or("its result couldn't be read")?;
        // Read here and written again, so an answer is one line whatever the script made of it.
        serde_json::from_str(&text).map_err(|_| "its result couldn't be read".to_string())
    }
}

/// A hook's child: reads the script, says whether that worked, then answers calls until its
/// stdin closes.
fn serve(kind: &str, script: &str) -> i32 {
    let mut served = match Served::new(kind, script) {
        Ok(served) => served,
        Err(e) => {
            let _ = answer(Err(e)).is_some_and(|line| say(&format!("\n{line}")));
            return 0;
        }
    };
    if !answer(Ok(Value::Null)).is_some_and(|line| say(&format!("\n{line}"))) {
        return 3;
    }
    let mut line = String::new();
    loop {
        line.clear();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) | Err(_) => return 0,
            Ok(_) => {}
        }
        let Ok(call) = serde_json::from_str::<Call>(&line) else { return 2 };
        let ready = served.set_cx(&call.cx);
        for item in &call.items {
            let result = ready.clone().and_then(|()| served.call(item));
            if !answer(result).is_some_and(|line| say(&line)) {
                return 3;
            }
        }
    }
}

/// Bounds the child's address space to `memory` bytes and its CPU time to `cpu` seconds, and
/// turns off core dumps. A limit the system refuses is left as it was: the parent's time limit
/// still holds. macOS accepts the address-space limit without enforcing it, which is why the
/// parent watches the child there.
#[cfg(unix)]
fn limit_resources(memory: u64, cpu: u64) {
    for (resource, soft, hard) in
        [(libc::RLIMIT_AS, memory, memory), (libc::RLIMIT_CPU, cpu, cpu + 1), (libc::RLIMIT_CORE, 0, 0)]
    {
        let limit = libc::rlimit { rlim_cur: soft as libc::rlim_t, rlim_max: hard as libc::rlim_t };
        // SAFETY: setrlimit reads the struct it is given and nothing else.
        unsafe {
            libc::setrlimit(resource, &limit);
        }
    }
}

/// Windows has no setrlimit: the parent puts the child in a [`MemoryJob`] instead.
#[cfg(not(unix))]
fn limit_resources(_memory: u64, _cpu: u64) {}

/// The physical footprint of process `pid`, in bytes: what it holds in memory, compressed
/// or not.
#[cfg(target_os = "macos")]
fn footprint(pid: u32) -> Option<u64> {
    // SAFETY: the struct is plain integers, for which zero is a valid value.
    let mut info: libc::rusage_info_v0 = unsafe { std::mem::zeroed() };
    let buffer = (&mut info as *mut libc::rusage_info_v0).cast::<libc::rusage_info_t>();
    // SAFETY: proc_pid_rusage writes one rusage_info_v0, the flavor asked for, into `info`.
    let r = unsafe { libc::proc_pid_rusage(pid as libc::c_int, libc::RUSAGE_INFO_V0, buffer) };
    (r == 0).then_some(info.ri_phys_footprint)
}

/// Whether the child is over the memory limit, where the parent has to look for itself.
#[cfg(target_os = "macos")]
fn over_memory(child: &Child, memory: u64) -> bool {
    footprint(child.id()).is_some_and(|used| used > memory)
}

#[cfg(not(target_os = "macos"))]
fn over_memory(_child: &Child, _memory: u64) -> bool {
    false
}

/// A Windows job object holding the child: a process in it can't commit more than its
/// memory limit, and closing the job (when this is dropped) kills whatever is still in it.
#[cfg(windows)]
struct MemoryJob(windows_sys::Win32::Foundation::HANDLE);

// SAFETY: a job handle may be used and closed from any thread.
#[cfg(windows)]
unsafe impl Send for MemoryJob {}

#[cfg(windows)]
impl MemoryJob {
    fn hold(child: &Child, memory: u64) -> Option<MemoryJob> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        };
        // SAFETY: both arguments may be null: no security attributes, no name.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return None;
        }
        let job = MemoryJob(handle);
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        info.ProcessMemoryLimit = usize::try_from(memory).unwrap_or(usize::MAX);
        // SAFETY: `info` is the struct this information class names, with its size; the
        // child's handle stays open while `child` lives.
        let held = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) != 0
                && AssignProcessToJobObject(job.0, child.as_raw_handle()) != 0
        };
        held.then_some(job)
    }
}

#[cfg(windows)]
impl Drop for MemoryJob {
    fn drop(&mut self) {
        // SAFETY: the handle is the job's, and closed only here.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
thread_local! {
    /// The process of this thread's last run.
    pub(crate) static LAST_CHILD: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// A script's child process, with its memory bounded. Killed when this is dropped, so nothing
/// of a script outlives whoever ran it.
struct Proc {
    child: Child,
    memory: u64,
    #[cfg(windows)]
    _job: MemoryJob,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts the child: nothing of this process's environment, and only its pipes. It runs
/// nothing until it has read what it is started for.
fn spawn(memory: u64) -> std::result::Result<(Proc, ChildStdin, ChildStdout), String> {
    let runner = RUNNER.get().ok_or("scripts run only from the brainproxy command")?;
    let mut cmd = Command::new(&runner.program);
    cmd.args(&runner.args)
        .env_clear()
        .envs(runner.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        cmd.env("SystemRoot", root);
    }
    let mut child = cmd.spawn().map_err(|_| "the script couldn't start")?;
    #[cfg(test)]
    LAST_CHILD.set(child.id());
    let pipes = (child.stdin.take(), child.stdout.take());
    // Before the child has its job: it runs nothing until it has read it all.
    #[cfg(windows)]
    let job = MemoryJob::hold(&child, memory);
    #[cfg(windows)]
    let Some(job) = job
    else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("the script's memory couldn't be limited".into());
    };
    let proc = Proc {
        child,
        memory,
        #[cfg(windows)]
        _job: job,
    };
    match pipes {
        (Some(stdin), Some(stdout)) => Ok((proc, stdin, stdout)),
        _ => Err("the script couldn't start".into()),
    }
}

fn start_line(job: Job, memory: u64, cpu: u64) -> std::result::Result<Vec<u8>, String> {
    let mut line = serde_json::to_vec(&Start { memory, cpu, job }).map_err(|_| "the script couldn't be handed over")?;
    line.push(b'\n');
    Ok(line)
}

/// How a wait for the child ended.
enum Waited<T> {
    Answered(T),
    /// The child's stdout closed.
    Ended,
    OverTime,
    OverMemory,
}

/// Waits up to `limit` for what the child's reader sends, looking at the child's memory
/// meanwhile where the system doesn't bound it.
fn wait<T>(recv: &mpsc::Receiver<T>, proc: &Proc, limit: Duration) -> Waited<T> {
    let deadline = Instant::now() + limit;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match recv.recv_timeout(left.min(WATCH_INTERVAL)) {
            Ok(out) => return Waited::Answered(out),
            Err(mpsc::RecvTimeoutError::Disconnected) => return Waited::Ended,
            Err(mpsc::RecvTimeoutError::Timeout) if left <= WATCH_INTERVAL => return Waited::OverTime,
            Err(mpsc::RecvTimeoutError::Timeout) if over_memory(&proc.child, proc.memory) => return Waited::OverMemory,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

fn over_time(limit: Duration) -> String {
    format!("it ran past the time limit of {} s", limit.as_secs())
}

fn over_memory_text(memory: u64) -> String {
    format!("it went past the memory limit of {} MiB", memory >> 20)
}

/// What a call returned is over [`OUTPUT_LIMIT`]: this call's failure, not the script's for good.
fn over_size() -> Failure {
    Failure::Script(format!("what it returned is over {} MiB", OUTPUT_LIMIT >> 20))
}

const NO_RESULT: &str = "it ended without a result: out of memory, or the interpreter failed";

/// A script's own message as it may be shown: short, with control characters and text-direction
/// overrides written out. A script can throw whatever it read in a response, and the message
/// goes to a terminal.
pub(crate) fn shown(error: &str) -> String {
    shown_cut(error, 300)
}

/// [`shown`], at most `max` characters.
pub(crate) fn shown_cut(error: &str, max: usize) -> String {
    let bidi = |c: char| matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
    let mut out = String::new();
    for c in error.chars().take(max) {
        match c {
            c if c.is_control() => out.extend(c.escape_debug()),
            c if bidi(c) => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The answer on `line`, if it is one.
fn read_answer(line: &str) -> Option<std::result::Result<Value, String>> {
    let reply = serde_json::from_str::<Reply>(line.trim()).ok()?.r;
    match (reply.ok, reply.error) {
        (_, Some(e)) => Some(Err(shown(&e))),
        (Some(v), None) => Some(Ok(v)),
        (None, None) => Some(Ok(Value::Null)),
    }
}

/// Runs `job` in a child process of its own, killed if it passes the time or memory limit, so
/// nothing of it outlives the call. The script's own failure is `Failure::Script`.
pub(crate) fn run_once(job: Job, memory: u64) -> std::result::Result<Value, Failure> {
    let stopped = |e: &str| Failure::Stopped(e.to_string());
    let input = start_line(job, memory, RUN_CPU).map_err(|e| stopped(&e))?;
    let (mut proc, mut stdin, stdout) = spawn(memory).map_err(|e| stopped(&e))?;
    let (send, recv) = mpsc::channel();
    // Ends when the child does: killing it closes both pipes.
    let io = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
        drop(stdin);
        let mut out = Vec::new();
        let _ = stdout.take(OUTPUT_LIMIT).read_to_end(&mut out);
        let _ = send.send(out);
    });
    let waited = wait(&recv, &proc, TIME_LIMIT);
    // Also when it answered: a child that wrote too much may still be waiting to write.
    let _ = proc.child.kill();
    let status = proc.child.wait();
    let _ = io.join();
    let out = match waited {
        Waited::Answered(out) => out,
        Waited::Ended => Vec::new(),
        Waited::OverTime => return Err(stopped(&over_time(TIME_LIMIT))),
        Waited::OverMemory => return Err(stopped(&over_memory_text(memory))),
    };
    let text = String::from_utf8_lossy(&out);
    let reply = text.lines().rev().find(|l| !l.trim().is_empty()).and_then(read_answer);
    match (reply, status) {
        (Some(Ok(outcome)), Ok(s)) if s.success() => Ok(outcome),
        (Some(Err(e)), Ok(s)) if s.success() => Err(Failure::Script(e)),
        _ => Err(stopped(NO_RESULT)),
    }
}

/// A line of a child's stdout.
#[derive(Debug, PartialEq)]
enum Line {
    Read(String),
    /// Longer than the limit, or cut off as the child ended: no answer either way.
    TooLong,
    End,
}

/// The next line of `from`, if it is at most `limit` bytes.
fn next_line(from: &mut impl BufRead, limit: u64) -> Line {
    let mut line = Vec::new();
    match from.take(limit + 1).read_until(b'\n', &mut line) {
        Ok(0) | Err(_) => Line::End,
        Ok(_) if line.last() != Some(&b'\n') => Line::TooLong,
        Ok(_) => Line::Read(String::from_utf8_lossy(&line).into_owned()),
    }
}

/// A hook script's process: the script read, its function waiting to be called. One call at a
/// time; whoever holds it kills it by dropping it.
pub(crate) struct Worker {
    proc: Proc,
    /// Lines for the child's stdin, written by a thread of their own so a child that doesn't
    /// read can't hold the caller.
    to_child: mpsc::Sender<Vec<u8>>,
    /// The child's answers; None for a line longer than [`OUTPUT_LIMIT`].
    answers: mpsc::Receiver<Option<String>>,
    /// How long its calls have taken in all.
    spent: Duration,
}

/// The time a worker's calls may take in all before another is started in its place: its CPU
/// time is limited over its whole life ([`WORKER_CPU`]), and it never gives memory back.
const WORKER_LIFE: Duration = Duration::from_secs(30);

impl Worker {
    /// Starts a process for `script`, whose function is the one `kind` names. Fails when the
    /// script can't be read as one: it doesn't parse, throws as it loads, or has no such function.
    pub(crate) fn start(kind: &str, script: &str) -> std::result::Result<Worker, Failure> {
        let stopped = |e: String| Failure::Stopped(e);
        let job = Job::Hook { kind: kind.to_string(), script: script.to_string() };
        let first = start_line(job, MEMORY_LIMIT, WORKER_CPU).map_err(stopped)?;
        let (proc, mut stdin, stdout) = spawn(MEMORY_LIMIT).map_err(stopped)?;
        let (to_child, lines) = mpsc::channel::<Vec<u8>>();
        // Both threads end when the child does: killing it closes its pipes.
        std::thread::spawn(move || {
            for line in lines {
                if stdin.write_all(&line).and_then(|_| stdin.flush()).is_err() {
                    break;
                }
            }
        });
        // Bounded: a child that answers faster than it is read waits to write.
        let (send, answers) = mpsc::sync_channel(64);
        std::thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                match next_line(&mut stdout, OUTPUT_LIMIT) {
                    Line::End => break,
                    Line::TooLong => {
                        let _ = send.send(None);
                        break;
                    }
                    Line::Read(line) => {
                        if line.starts_with(REPLY_PREFIX) && send.send(Some(line)).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let _ = to_child.send(first);
        let mut worker = Worker { proc, to_child, answers, spent: Duration::ZERO };
        match worker.answer(TIME_LIMIT, TIME_LIMIT)?.0 {
            Ok(_) => Ok(worker),
            // Reading it again would fail the same way.
            Err(e) => Err(Failure::Stopped(e)),
        }
    }

    /// The child's next answer and its size, waited for at most `wait`, or why there is none
    /// (after which the worker is of no use). `limit` is the time limit that `wait` is what is
    /// left of, for the message.
    fn answer(
        &mut self,
        wait_for: Duration,
        limit: Duration,
    ) -> std::result::Result<(std::result::Result<Value, String>, usize), Failure> {
        let started = Instant::now();
        let waited = wait(&self.answers, &self.proc, wait_for);
        self.spent += started.elapsed();
        let stopped = |e: String| Err(Failure::Stopped(e));
        match waited {
            Waited::Answered(Some(line)) => {
                read_answer(&line).map(|answer| (answer, line.len())).ok_or(Failure::Stopped(NO_RESULT.into()))
            }
            // This call's alone: the next may return less. The worker is of no use all the same.
            Waited::Answered(None) => Err(over_size()),
            Waited::Ended => stopped(NO_RESULT.into()),
            Waited::OverTime => stopped(over_time(limit)),
            Waited::OverMemory => stopped(over_memory_text(self.proc.memory)),
        }
    }

    /// Calls the script's function once for each of `items` (JSON), all told `cx` (JSON).
    /// Each item's result is what the function returned, in the shape `hook.js` gives it, or
    /// what it threw. The call has [`CALL_LIMIT`] for all its items, or with `each` for every
    /// one of them (payloads, which are unrelated to one another), and its answers come to at
    /// most [`OUTPUT_LIMIT`] in all: what the parent keeps of a call is bounded whatever the
    /// script returns. A failure of the whole call leaves the worker of no use: drop it.
    pub(crate) fn call(
        &mut self,
        cx: String,
        items: Vec<String>,
        each: bool,
    ) -> std::result::Result<Vec<std::result::Result<Value, String>>, Failure> {
        self.call_within(cx, items, each, OUTPUT_LIMIT)
    }

    /// [`Worker::call`], with `most` bytes for the call's answers in all.
    fn call_within(
        &mut self,
        cx: String,
        items: Vec<String>,
        each: bool,
        most: u64,
    ) -> std::result::Result<Vec<std::result::Result<Value, String>>, Failure> {
        let stopped = |e: &str| Failure::Stopped(e.to_string());
        let count = items.len();
        let mut line =
            serde_json::to_vec(&Call { cx, items }).map_err(|_| stopped("what it works on couldn't be handed over"))?;
        line.push(b'\n');
        self.to_child.send(line).map_err(|_| stopped(NO_RESULT))?;
        let deadline = Instant::now() + CALL_LIMIT;
        let mut out = Vec::with_capacity(count.min(1024));
        let mut size = 0;
        for _ in 0..count {
            let wait_for = if each { CALL_LIMIT } else { deadline.saturating_duration_since(Instant::now()) };
            let (answer, len) = self.answer(wait_for, CALL_LIMIT)?;
            size += len;
            if size as u64 > most {
                return Err(over_size());
            }
            out.push(answer);
        }
        Ok(out)
    }

    /// Whether its calls have taken so long in all that another should take its place.
    pub(crate) fn spent(&self) -> bool {
        self.spent > WORKER_LIFE
    }

    /// Whether its process has ended while it waited for a call (killed from outside, say).
    pub(crate) fn gone(&mut self) -> bool {
        !matches!(self.proc.child.try_wait(), Ok(None))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Runs scripts in this test binary started again on [`script_child`], which then acts as
    /// `brainproxy __sign-script`.
    pub(crate) fn use_test_runner() {
        let exe = std::env::current_exe().unwrap();
        let args = ["--exact", "sandbox::tests::script_child", "--nocapture", "--test-threads=1"];
        set_runner_with_env(exe, &args, &[("BRAINPROXY_TEST_SCRIPT_CHILD", "1")]);
    }

    #[test]
    fn script_child() {
        if std::env::var_os("BRAINPROXY_TEST_SCRIPT_CHILD").is_some() {
            std::process::exit(child_main());
        }
    }

    /// Whether the process of this thread's last run is still there.
    #[cfg(unix)]
    pub(crate) fn last_child_alive() -> bool {
        let pid = LAST_CHILD.get() as libc::pid_t;
        // SAFETY: signal 0 only asks whether the process exists.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    fn worker(kind: &str, script: &str) -> std::result::Result<Worker, Failure> {
        use_test_runner();
        Worker::start(kind, script)
    }

    fn one(worker: &mut Worker, item: &str) -> std::result::Result<Value, String> {
        worker.call("{}".into(), vec![item.to_string()], false).unwrap().remove(0)
    }

    #[test]
    fn a_worker_answers_call_after_call_and_keeps_its_script() {
        let mut w =
            worker("replace", "let n = 0; function replace(m, cx) { n += 1; return m.text + n + cx.host; }").unwrap();
        let cx = r#"{"host":"h.test"}"#;
        let items = [r#"{"text":"a"}"#.to_string(), r#"{"text":"b"}"#.to_string()];
        let out = w.call(cx.into(), items.to_vec(), false).unwrap();
        assert_eq!(out, [Ok(serde_json::json!({"text": "a1h.test"})), Ok(serde_json::json!({"text": "b2h.test"}))]);
        assert_eq!(one(&mut w, r#"{"text":"c"}"#), Ok(serde_json::json!({"text": "c3undefined"})));
    }

    #[test]
    fn a_script_that_cant_be_read_as_a_hook_never_starts() {
        for (script, why) in [
            ("function replace( {", "SyntaxError"),
            ("throw new Error('at the top')", "at the top"),
            ("function other() {}", "it defines no replace function"),
            ("const replace = 5;", "it defines no replace function"),
        ] {
            let Err(Failure::Stopped(e)) = worker("replace", script) else { panic!("{script} started") };
            assert!(e.contains(why), "{script}: {e}");
        }
        // A function kept in a const is one.
        worker("replace", "const replace = (m) => m.text;").unwrap();
    }

    #[test]
    fn a_call_that_throws_or_returns_the_wrong_thing_fails_alone() {
        let mut w = worker(
            "replace",
            "function replace(m) {
                if (m.text === 'throw') throw new Error('no ' + m.text);
                if (m.text === 'number') return 5;
                if (m.text === 'nothing') return;
                if (m.text === 'promise') return Promise.resolve('x');
                if (m.text === 'null') return null;
                if (m.text === 'bytes') return { base64: 'AP8=' };
                if (m.text === 'cycle') { const o = { base64: 'AA==' }; o.self = o; return o; }
                return m.text.toUpperCase();
            }",
        )
        .unwrap();
        let mut run = |text: &str| one(&mut w, &serde_json::json!({ "text": text }).to_string());
        assert!(run("throw").unwrap_err().contains("no throw"));
        assert!(run("number").unwrap_err().contains("it returned a number"));
        assert!(run("nothing").unwrap_err().contains("it returned nothing"));
        assert!(run("promise").unwrap_err().contains("promise"));
        assert_eq!(run("null"), Ok(serde_json::json!({"keep": true})));
        assert_eq!(run("bytes"), Ok(serde_json::json!({"base64": "AP8="})));
        assert_eq!(run("cycle"), Ok(serde_json::json!({"base64": "AA=="})));
        assert_eq!(run("fine"), Ok(serde_json::json!({"text": "FINE"})));
    }

    #[test]
    fn what_a_hook_is_given_cant_be_changed() {
        let mut w = worker(
            "replace",
            "'use strict'; function replace(m, cx) {
                try { cx.request.headers[0][1] = 'x'; return 'changed'; } catch (e) {}
                try { m.text = 'x'; return 'changed'; } catch (e) {}
                return cx.request.headers[0][1];
            }",
        )
        .unwrap();
        let cx = r#"{"request":{"headers":[["Host","h.test"]]}}"#;
        let out = w.call(cx.into(), vec![r#"{"text":"a"}"#.to_string()], false).unwrap();
        assert_eq!(out, [Ok(serde_json::json!({"text": "h.test"}))]);
    }

    /// A script can't redefine its way out of how its result is read: the answer is one line
    /// of JSON whatever it does to the globals.
    #[test]
    fn redefined_globals_dont_forge_an_answer() {
        let mut w = worker(
            "replace",
            r#"JSON.stringify = () => '{"text":"forged"}}\n{"r":{"ok":{"text":"second"}}';
               JSON.parse = () => ({ text: 'lie' });
               Object.freeze = (o) => o;
               function replace(m) { return m.text; }"#,
        )
        .unwrap();
        let items = [r#"{"text":"a"}"#.to_string(), r#"{"text":"b"}"#.to_string()];
        let out = w.call("{}".into(), items.to_vec(), false).unwrap();
        assert_eq!(out, [Ok(serde_json::json!({"text": "a"})), Ok(serde_json::json!({"text": "b"}))]);
    }

    /// Calls `item` on a hook that never returns for it, and checks the call is stopped at the
    /// call's time limit and the process is gone.
    fn stopped_in_time(script: &str) {
        let mut w = worker("replace", script).unwrap();
        assert_eq!(one(&mut w, r#"{"text":"fine"}"#), Ok(serde_json::json!({"text": "fine"})));
        let started = Instant::now();
        let r = w.call("{}".into(), vec![r#"{"text":"loop"}"#.to_string()], false);
        let took = started.elapsed();
        assert!(matches!(&r, Err(Failure::Stopped(e)) if e.contains("time limit")), "{script}: {r:?}");
        assert!(took >= CALL_LIMIT && took < CALL_LIMIT + Duration::from_secs(3), "{script}: {took:?}");
        drop(w);
        #[cfg(unix)]
        assert!(!last_child_alive(), "{script}: its process is still there");
    }

    #[test]
    fn a_hook_that_never_returns_is_stopped_with_its_process() {
        stopped_in_time(
            "function replace(m) { if (m.text === 'loop') /^(a+)+$/.test('a'.repeat(40) + 'b'); return m.text; }",
        );
    }

    #[test]
    fn a_hook_that_loops_is_stopped_by_the_loop_limit_or_the_clock() {
        let mut w = worker("replace", "function replace(m) { while (true) {} }").unwrap();
        match w.call("{}".into(), vec![r#"{"text":"a"}"#.to_string()], false) {
            // The interpreter's loop limit, when it gets there within the time limit.
            Ok(out) => assert!(out[0].as_ref().unwrap_err().contains("a loop in it ran past the limit"), "{out:?}"),
            Err(Failure::Stopped(e)) => assert!(e.contains("time limit"), "{e}"),
            Err(e) => panic!("{e:?}"),
        }
    }

    #[test]
    fn a_hook_has_no_way_out() {
        let mut w = worker(
            "replace",
            "function replace(m) {
                const names = ['fetch', 'XMLHttpRequest', 'WebSocket', 'process', 'Deno', 'Bun', 'require',
                               'importScripts', 'SharedArrayBuffer', 'Atomics', 'postMessage', 'navigator',
                               'localStorage', 'pm', 'postman', '__input'];
                if (m.text === 'globals') return names.filter((n) => typeof globalThis[n] !== 'undefined').join();
                if (m.text === 'fs') return String(require('fs'));
                if (m.text === 'net') return String(require('net'));
                if (m.text === 'child') return String(require('child_process'));
                if (m.text === 'import') return String(import('fs'));
                return String(eval(m.text));
            }",
        )
        .unwrap();
        let mut run = |text: &str| one(&mut w, &serde_json::json!({ "text": text }).to_string());
        // `require` is the library's: it gives a few hashing modules and refuses the rest.
        assert_eq!(run("globals"), Ok(serde_json::json!({"text": "require"})));
        for module in ["fs", "net", "child"] {
            let e = run(module).unwrap_err();
            assert!(e.contains("isn't available here"), "{module}: {e}");
        }
        for script in ["fetch('http://x.test')", "new XMLHttpRequest()", "process.exit(1)", "new WebSocket('ws://x')"] {
            assert!(run(script).is_err(), "{script}");
        }
        // And the worker is still there: none of that ended its process.
        assert_eq!(run("1 + 1"), Ok(serde_json::json!({"text": "2"})));
    }

    #[test]
    fn an_answer_over_the_limit_is_no_answer() {
        let mut out = std::io::Cursor::new(b"short\nexactly10\nthis one is too long\nnext\n".to_vec());
        assert_eq!(next_line(&mut out, 10), Line::Read("short\n".into()));
        assert_eq!(next_line(&mut out, 10), Line::Read("exactly10\n".into()));
        assert_eq!(next_line(&mut out, 10), Line::TooLong);
        let mut cut_off = std::io::Cursor::new(b"{\"r\":{\"ok\"".to_vec());
        assert_eq!(next_line(&mut cut_off, 100), Line::TooLong);
        assert_eq!(next_line(&mut cut_off, 100), Line::End);
        // A real one: the script's process is stopped, by the size or (a debug build takes its
        // time over 16 MiB) by the clock.
        let mut w = worker(
            "replace",
            "function replace(m) { let s = 'x'.repeat(1 << 20); while (s.length < (1 << 24) + 10) s += s; return s; }",
        )
        .unwrap();
        let r = w.call("{}".into(), vec![r#"{"text":"a"}"#.to_string()], false);
        let e = r.as_ref().err().map(Failure::text).unwrap_or_default();
        assert!(e.contains("is over 16 MiB") || e.contains("time limit"), "{r:?}");
    }

    /// A module file beside the tests, for a script to try to load; removed when dropped.
    pub(crate) struct ModuleFile(pub String);

    impl ModuleFile {
        pub(crate) fn new(tag: &str) -> ModuleFile {
            let name = format!("bp-import-{tag}-{}.mjs", std::process::id());
            std::fs::write(&name, "export const secret = 'S3CRET-FROM-A-FILE';").unwrap();
            ModuleFile(name)
        }
    }

    impl Drop for ModuleFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn a_hook_cant_load_a_file_as_a_module() {
        // The file is there, where the engine's own loader would look: the working directory.
        let file = ModuleFile::new("hook");
        let script = format!(
            "let got = 'pending';
             import('./{0}').then((m) => {{ got = 'read ' + m.secret; }}, (e) => {{ got = 'refused: ' + e.message; }});
             function replace(m) {{
                 if (m.text === 'again') import('./{0}').then((m) => {{ got = 'read ' + m.secret; }});
                 return got;
             }}",
            file.0
        );
        let mut w = worker("replace", &script).unwrap();
        let run = |w: &mut Worker, text: &str| one(w, &serde_json::json!({ "text": text }).to_string()).unwrap();
        let refused = serde_json::json!({"text": "refused: module resolution is disabled for this context"});
        assert_eq!(run(&mut w, "a"), refused);
        run(&mut w, "again");
        assert_eq!(run(&mut w, "a"), refused);
        // A static import isn't a script's to write at all.
        let script = format!("import {{ secret }} from './{}'; function replace() {{ return secret; }}", file.0);
        assert!(matches!(worker("replace", &script), Err(Failure::Stopped(_))));
    }

    #[test]
    fn what_a_script_throws_is_shown_without_its_control_characters() {
        let mut w = worker(
            "replace",
            "function replace(m) { throw new Error('a\\u001b[2Jb\\r\\nc\\u202ed' + 'x'.repeat(500)); }",
        )
        .unwrap();
        let e = one(&mut w, r#"{"text":"a"}"#).unwrap_err();
        assert!(e.starts_with("Error: a\\u{1b}[2Jb\\r\\nc\\u{202e}dxxx"), "{e}");
        assert!(e.chars().count() <= 300 && !e.chars().any(char::is_control), "{e}");
        assert_eq!(shown("plain é text"), "plain é text");
    }

    #[test]
    fn a_worker_whose_process_ended_says_so() {
        let mut w = worker("replace", "function replace(m) { return m.text; }").unwrap();
        assert!(!w.gone());
        let _ = w.proc.child.kill();
        let _ = w.proc.child.wait();
        assert!(w.gone());
    }

    #[test]
    fn a_call_has_one_time_limit_and_one_size_limit_for_all_its_items() {
        let script = "function replace(m) {
            if (m.text === 'slow') { const end = Date.now() + 300; while (Date.now() < end) {} return 'x'; }
            return 'x'.repeat(10000);
        }";
        let items = |text: &str, n: usize| vec![serde_json::json!({ "text": text }).to_string(); n];
        // Each answer takes a moment: twenty of them are one call, with one time limit.
        let mut w = worker("replace", script).unwrap();
        let started = Instant::now();
        let r = w.call("{}".into(), items("slow", 20), false);
        assert!(matches!(&r, Err(Failure::Stopped(e)) if e.contains("time limit")), "{r:?}");
        assert!(started.elapsed() < CALL_LIMIT + Duration::from_secs(3), "{:?}", started.elapsed());
        // Payloads have the limit each.
        let mut w = worker("replace", script).unwrap();
        assert_eq!(w.call("{}".into(), items("slow", 9), true).unwrap().len(), 9);
        // Each answer is small, and twenty of them are over what the call may return in all.
        assert_eq!(w.call_within("{}".into(), items("big", 9), true, 100_000).unwrap().len(), 9);
        let r = w.call_within("{}".into(), items("big", 20), true, 100_000);
        assert!(matches!(&r, Err(Failure::Script(e)) if e.contains("is over 16 MiB")), "{:?}", r.map(|a| a.len()));
    }
}
