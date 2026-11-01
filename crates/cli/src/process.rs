//! Background processes (proxy, OOB listener, jobs, browsers): detaching, telling a live
//! process from a later one reusing its pid, and stopping one cleanly.
//!
//! A stop is requested through the project database (`request_stop`), which the process
//! polls (`shutdown`); on Unix it also gets SIGTERM. Windows has no SIGTERM, so the
//! database flag is how it learns to flush and exit there.
//!
//! A project on a shared volume can be opened from another container, where the saved pid
//! means nothing: it isn't visible, or is some other process. A listener therefore records
//! its PID namespace and holds a lock file while it runs ([`RunLock`]). From another
//! namespace the lock says whether it still runs, and the database flag is the only way to
//! stop it. A job or fuzz run does the same with a lock file of its own ([`work_lock`]).

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{ErrorKind, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use brainproxy_core::store::Store;
use brainproxy_core::Error;

/// Starts `cmd` detached from this process: its own process group (no signals or Ctrl-C
/// from our terminal) and, on Windows, no console window.
pub(crate) fn detach(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
        use windows_sys::Win32::System::Console::{
            GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
        // A child inherits every inheritable handle we hold, including our own stdout pipe:
        // whoever reads our output (the app, a script) would then wait until the child exits.
        // The child's stdio is given explicitly, as inheritable copies, so it still gets those.
        for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            unsafe {
                let h = GetStdHandle(id);
                if !h.is_null() {
                    SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
                }
            }
        }
    }
}

/// Asks the process recorded as `pid` under `key` to stop; see [`shutdown`].
pub(crate) fn request_stop(store: &Store, key: &str, pid: u32) -> Result<(), Error> {
    store.meta_set(key, Some(&pid.to_string()))
}

/// Resolves on Ctrl-C, SIGTERM (Unix), or once `request_stop(store, key, our pid)` was called.
/// Clears a stale request for our pid first.
pub(crate) async fn shutdown(store: &Store, key: &str) {
    let me = std::process::id().to_string();
    let _ = store.meta_set(key, None);
    let flagged = async {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if store.meta_get(key).ok().flatten().as_deref() == Some(me.as_str()) {
                let _ = store.meta_set(key, None);
                return;
            }
        }
    };
    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut t) => {
                t.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term => {}
        _ = flagged => {}
    }
}

/// Whether `pid` is a live process we may stop.
pub(crate) fn alive(pid: u32) -> bool {
    sys::alive(pid)
}

/// When `pid` started, as an opaque number: tells a process from a later one reusing its pid.
pub(crate) fn start_time(pid: u32) -> Option<u64> {
    sys::start_time(pid)
}

/// Whether the process recorded as `pid`, started at `start`, still runs: `Some(false)`
/// when it is gone or the pid now belongs to another process, `None` when the pid is
/// alive but there is no start time to compare (state from an older version). Pid 1 always
/// exists, so without a start time it says nothing, and older versions never ran as it.
pub(crate) fn still_running(pid: u32, start: Option<u64>) -> Option<bool> {
    if !alive(pid) || (pid == 1 && start.is_none()) {
        return Some(false);
    }
    start.map(|s| start_time(pid) == Some(s))
}

/// This process's PID namespace; pids only mean something inside one. `None` where there
/// are no such namespaces to tell apart, or `/proc` isn't there to ask.
pub(crate) fn pid_namespace() -> Option<String> {
    sys::pid_namespace()
}

/// Whether a pid saved along with `pid_ns` belongs to another PID namespace, such as another
/// container on the same volume. State without one has a pid to go by, as it always had.
pub(crate) fn elsewhere(pid_ns: Option<&str>) -> bool {
    pid_ns.is_some_and(|ns| pid_namespace().as_deref() != Some(ns))
}

/// A saved pid for people to read, since one from another namespace can't be looked up here.
pub(crate) fn pid_text(pid: u32, pid_ns: Option<&str>) -> String {
    if elsewhere(pid_ns) {
        format!("pid {pid} in another container or PID namespace")
    } else {
        format!("pid {pid}")
    }
}

/// What is known about a saved listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Liveness {
    Running,
    /// Certainly gone, so its state can be cleared.
    Gone,
    /// In another namespace, with a lock that can't be read. Its state stays, and only
    /// `stop --forget` clears it.
    Unverified,
}

/// A listener in another namespace is judged by its lock, any other by its pid.
pub(crate) fn liveness(store: &Store, what: &str, pid: u32, start: Option<u64>, pid_ns: Option<&str>) -> Liveness {
    if elsewhere(pid_ns) {
        match lock_held(store, what) {
            Some(true) => Liveness::Running,
            Some(false) => Liveness::Gone,
            None => Liveness::Unverified,
        }
    } else if still_running(pid, start) == Some(false) {
        Liveness::Gone
    } else {
        Liveness::Running
    }
}

fn label(what: &str) -> &str {
    if what == "oob" {
        "OOB listener"
    } else {
        what
    }
}

/// Why a saved listener can't be verified, and the way out.
pub(crate) fn unverified_text(what: &str, pid: u32) -> String {
    format!(
        "can't verify the {} recorded as pid {pid} in another container or PID namespace: its lock file isn't \
         readable here. If it is no longer running, `brainproxy {what} stop --forget` clears the record",
        label(what)
    )
}

/// A listener's hold on `<project>-<what>.lock`, for as long as it runs. The kernel releases
/// it the moment the process dies, however that happens, and it works across PID namespaces.
///
/// Never open this file again from the process holding the lock: on NFS `flock` becomes a
/// per-process POSIX lock, which closing any descriptor for the file releases.
pub(crate) struct RunLock(#[allow(dead_code)] File);

impl RunLock {
    /// Takes the lock, or fails if another listener holds it. `None` where it can't be taken
    /// (no namespaces to tell apart, a filesystem without locks): a listener then records no
    /// namespace, and is judged by its pid.
    pub(crate) fn acquire(store: &Store, what: &str) -> Result<Option<Self>, Error> {
        let Some(path) = lock_path(store, what).filter(|_| pid_namespace().is_some()) else { return Ok(None) };
        // `flock` needs no write access, so a lock file left by another user will do.
        let opened = OpenOptions::new().create(true).truncate(false).write(true).open(&path);
        let Ok(file) = opened.or_else(|_| File::open(&path)) else { return Ok(None) };
        // Store::open's umask makes it owner-only, but it holds no data and listeners and
        // probes can run as different users (`docker run --user`), which must all be able to
        // open it. Failing is fine: then it isn't ours, and its owner has set this already.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o644));
        }
        // A probe holds it for an instant, so being refused once proves nothing.
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Some(Self(file))),
                Err(TryLockError::WouldBlock) if Instant::now() >= deadline => {
                    return Err(Error::Conflict(format!(
                        "another {} is already running for this project",
                        label(what)
                    )));
                }
                Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(20)),
                Err(TryLockError::Error(_)) => return Ok(None),
            }
        }
    }
}

fn lock_path(store: &Store, what: &str) -> Option<PathBuf> {
    let mut path = store.path()?.as_os_str().to_owned();
    path.push(format!("-{what}.lock"));
    Some(path.into())
}

/// Whether a listener holds its lock: `None` when that can't be found out. A shared lock, so
/// that probes don't get in each other's way.
fn lock_held(store: &Store, what: &str) -> Option<bool> {
    let file = match File::open(lock_path(store, what)?) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    };
    match file.try_lock_shared() {
        Ok(()) => Some(false),
        Err(TryLockError::WouldBlock) => Some(true),
        Err(TryLockError::Error(_)) => None,
    }
}

/// Takes `<project>-<name>.lock` for a job or fuzz run, before its pid is recorded, and writes
/// the PID namespace into it. `None` where it can't be taken, which leaves its pid to go by.
/// Already held, it is a `--background` child's own, handed over through [`work_lock_stdin`]:
/// nothing else takes a lock with this name. The child then keeps it where nothing it starts
/// can inherit it, and gets /dev/null on stdin.
pub(crate) fn work_lock(store: &Store, name: &str) -> Option<File> {
    let ns = pid_namespace()?;
    let path = lock_path(store, name)?;
    let mut file = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&path).ok()?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return sys::take_stdin_if_same(&file),
        Err(TryLockError::Error(_)) => {
            let _ = std::fs::remove_file(&path);
            return None;
        }
    }
    // Readable by a container running as another user: the umask would leave it to its owner.
    sys::readable_by_all(&file);
    if file.set_len(0).and_then(|()| file.write_all(ns.as_bytes())).is_err() {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    Some(file)
}

/// Stdin for a `--background` child: its lock instead of /dev/null. A lock belongs to the open
/// file, so the child holds it from its first instruction and the parent can exit, leaving no
/// moment when a child that is starting looks dead. Until the child moves it (see
/// [`work_lock`]) it reads as empty, like /dev/null: the file's position is past what was
/// written.
pub(crate) fn work_lock_stdin(store: &Store, name: &str) -> Stdio {
    work_lock(store, name).map_or_else(Stdio::null, Stdio::from)
}

/// The namespace a job or fuzz run recorded in its lock file. None without one (state from an
/// older version, or no locks here), which leaves its pid to go by.
fn work_namespace(store: &Store, name: &str) -> std::io::Result<Option<String>> {
    let Some(path) = lock_path(store, name) else { return Ok(None) };
    match std::fs::read_to_string(path) {
        Ok(ns) => Ok(Some(ns).filter(|ns| !ns.is_empty())),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether the process of a job or fuzz run is certainly gone. With a lock file the lock
/// decides, in any namespace: a pid can be reused, and so can a namespace's number. Without
/// one, or if the lock can't be read here, the pid does, as far as it means anything here;
/// if it doesn't, the work counts as running. A job's final state is written before it exits,
/// so once it is gone that state can be trusted: read it after this.
pub(crate) fn work_gone(store: &Store, name: &str, pid: u32) -> bool {
    let Ok(ns) = work_namespace(store, name) else { return false };
    let held = ns.as_ref().and_then(|_| lock_held(store, name));
    match held {
        Some(held) => !held,
        None => !elsewhere(ns.as_deref()) && !alive(pid),
    }
}

/// Whether a job or fuzz run runs in another container or PID namespace.
pub(crate) fn work_elsewhere(store: &Store, name: &str) -> bool {
    elsewhere(work_namespace(store, name).ok().flatten().as_deref())
}

/// The pid of a job or fuzz run, for people to read.
pub(crate) fn work_pid_text(store: &Store, name: &str, pid: u32) -> String {
    pid_text(pid, work_namespace(store, name).ok().flatten().as_deref())
}

/// Removes the lock file of a job or fuzz run that has finished. Nothing looks at it any more.
pub(crate) fn forget_work_lock(store: &Store, name: &str) {
    if let Some(path) = lock_path(store, name) {
        let _ = std::fs::remove_file(path);
    }
}

/// Waits for a listener in another namespace to act on the caller's `request_stop`: its lock
/// is released, or if that can't be read, it has cleared its record under `state_key`. Its
/// pid means something else here, so it is never signalled.
pub(crate) fn await_exit_elsewhere(
    store: &Store,
    what: &str,
    state_key: &str,
    pid: u32,
    wait: Duration,
) -> Result<(), Error> {
    let deadline = Instant::now() + wait;
    loop {
        let held = lock_held(store, what);
        if held == Some(false) || store.meta_get(state_key)?.is_none() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::Conflict(match held {
                Some(_) => format!(
                    "the {} (pid {pid} in another container or PID namespace) is still running after being asked to \
                     stop, and can't be signalled from here; stop it where it runs",
                    label(what)
                ),
                None => unverified_text(what, pid),
            }));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Stops the process recorded as (`pid`, `start`), after the caller's `request_stop`: on
/// Unix SIGTERM too, then a forced kill after 5 s. Returns whether the kill was needed. A
/// process that can't be verified is never killed, and neither is pid 1, which is never
/// signalled at all and has only the database flag to go by.
pub(crate) fn terminate(pid: u32, start: Option<u64>, what: &str, wait: Duration) -> Result<bool, Error> {
    let gone = || still_running(pid, start) == Some(false);
    if gone() {
        return Ok(false);
    }
    sys::ask_to_exit(pid);
    let deadline = Instant::now() + wait;
    while !gone() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if gone() {
        return Ok(false);
    }
    if pid == 1 {
        return Err(Error::Conflict(format!(
            "the {what} is still running after being asked to stop. It is pid 1, which brainproxy never signals; \
             stop its container instead"
        )));
    }
    if start.is_none() {
        return Err(Error::Conflict(format!(
            "pid {pid} is still running after being asked to stop. Its {what} state comes from an older brainproxy \
             without a process start time, so it can't be verified as the {what}; not sending SIGKILL. Check pid \
             {pid} yourself and stop it if it is the {what}"
        )));
    }
    sys::kill(pid);
    Ok(true)
}

#[cfg(unix)]
mod sys {
    /// `pid` as a pid_t to look at: 0 and anything that turns negative (`kill(0|-1|-n)` hits
    /// a process group or every process) are refused.
    pub(super) fn pid_t(pid: u32) -> Option<libc::pid_t> {
        libc::pid_t::try_from(pid).ok().filter(|&p| p > 0)
    }

    /// `pid` as a pid_t that is safe to signal: not 1 either. A `proxy run` that is a
    /// container's main command is pid 1 and can be looked at, but init never gets a signal.
    pub(super) fn signal_target(pid: u32) -> Option<libc::pid_t> {
        pid_t(pid).filter(|&p| p > 1)
    }

    /// Signal 0 checks without delivering anything; EPERM means another user's process,
    /// which is not ours.
    pub fn alive(pid: u32) -> bool {
        pid_t(pid).is_some_and(|p| unsafe { libc::kill(p, 0) } == 0)
    }

    pub fn ask_to_exit(pid: u32) {
        if let Some(p) = signal_target(pid) {
            unsafe { libc::kill(p, libc::SIGTERM) };
        }
    }

    pub fn kill(pid: u32) {
        if let Some(p) = signal_target(pid) {
            unsafe { libc::kill(p, libc::SIGKILL) };
        }
    }

    /// Moves `lock` off stdin if that is where it is: to a descriptor no child inherits
    /// (`try_clone_to_owned` sets close-on-exec), with /dev/null on stdin instead.
    pub fn take_stdin_if_same(lock: &std::fs::File) -> Option<std::fs::File> {
        use std::os::fd::{AsFd, AsRawFd};
        use std::os::unix::fs::MetadataExt;
        let held = std::fs::File::from(std::io::stdin().as_fd().try_clone_to_owned().ok()?);
        let (a, b) = (held.metadata().ok()?, lock.metadata().ok()?);
        if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
            return None;
        }
        let null = std::fs::File::open("/dev/null").ok()?;
        (unsafe { libc::dup2(null.as_raw_fd(), libc::STDIN_FILENO) } == libc::STDIN_FILENO).then_some(held)
    }

    pub fn readable_by_all(file: &std::fs::File) {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o644));
    }

    #[cfg(target_os = "linux")]
    pub fn pid_namespace() -> Option<String> {
        std::fs::read_link("/proc/self/ns/pid").ok()?.into_os_string().into_string().ok()
    }

    #[cfg(not(target_os = "linux"))]
    pub fn pid_namespace() -> Option<String> {
        None
    }

    #[cfg(target_os = "macos")]
    pub fn start_time(pid: u32) -> Option<u64> {
        let p = pid_t(pid)?;
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let ptr = (&mut info as *mut libc::proc_bsdinfo).cast();
        let n = unsafe { libc::proc_pidinfo(p, libc::PROC_PIDTBSDINFO, 0, ptr, size) };
        (n == size).then(|| info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
    }

    #[cfg(target_os = "linux")]
    pub fn start_time(pid: u32) -> Option<u64> {
        // Field 22 (clock ticks since boot); the fields after `(comm)` start at 3.
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid_t(pid)?)).ok()?;
        stat.rsplit_once(')')?.1.split_whitespace().nth(19)?.parse().ok()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub fn start_time(_: u32) -> Option<u64> {
        None
    }
}

#[cfg(windows)]
mod sys {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessTimes, OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_TERMINATE,
    };

    const STILL_ACTIVE: u32 = 259;

    /// An open process handle, closed on drop. Pids 0 (idle) and 4 (System) are refused.
    struct Process(HANDLE);

    impl Process {
        fn open(pid: u32, access: u32) -> Option<Self> {
            if pid <= 4 {
                return None;
            }
            let h = unsafe { OpenProcess(access, 0, pid) };
            (!h.is_null()).then_some(Self(h))
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    pub fn alive(pid: u32) -> bool {
        let Some(p) = Process::open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else { return false };
        let mut code = 0u32;
        (unsafe { GetExitCodeProcess(p.0, &mut code) } != 0) && code == STILL_ACTIVE
    }

    pub fn pid_namespace() -> Option<String> {
        None
    }

    /// There are no namespaces here, so no locks are taken to hand over.
    pub fn take_stdin_if_same(_: &std::fs::File) -> Option<std::fs::File> {
        None
    }

    pub fn readable_by_all(_: &std::fs::File) {}

    /// Nothing to send: the caller's `request_stop` flag is how a Windows process is asked.
    pub fn ask_to_exit(_: u32) {}

    pub fn kill(pid: u32) {
        if let Some(p) = Process::open(pid, PROCESS_TERMINATE) {
            unsafe { TerminateProcess(p.0, 1) };
        }
    }

    pub fn start_time(pid: u32) -> Option<u64> {
        let p = Process::open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        let ok = unsafe { GetProcessTimes(p.0, &mut created, &mut exited, &mut kernel, &mut user) };
        (ok != 0).then(|| (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_identity() {
        for bad in [0, u32::MAX, i32::MAX as u32 + 1] {
            assert!(!alive(bad) && start_time(bad).is_none(), "{bad}");
        }
        let me = std::process::id();
        let start = start_time(me);
        assert!(start.is_some() && start == start_time(me));
        assert_eq!(still_running(me, start), Some(true));
        assert_eq!(still_running(me, start.map(|s| s + 1)), Some(false));
        assert_eq!(still_running(me, None), None);
    }

    #[cfg(unix)]
    #[test]
    fn pid_1_can_be_looked_at_but_not_signalled() {
        assert_eq!(sys::pid_t(1), Some(1));
        assert_eq!(sys::signal_target(1), None);
        for bad in [0, u32::MAX, i32::MAX as u32 + 1] {
            assert_eq!(sys::pid_t(bad), None, "{bad}");
            assert_eq!(sys::signal_target(bad), None, "{bad}");
        }
        assert_eq!(sys::signal_target(2), Some(2));
    }

    #[test]
    fn another_namespace_is_told_from_this_one() {
        assert!(elsewhere(Some("pid:[1]")));
        assert!(!elsewhere(None));
        assert_eq!(pid_text(7, None), "pid 7");
        assert!(pid_text(7, Some("pid:[1]")).contains("another container"));
        if let Some(here) = pid_namespace() {
            assert!(!elsewhere(Some(&here)));
            assert_eq!(pid_text(7, Some(&here)), "pid 7");
        }
    }

    /// A project in a fresh folder.
    fn store(name: &str) -> (std::path::PathBuf, Store) {
        let dir = std::env::temp_dir().join(format!("bp-process-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("p.bpdb")).unwrap();
        (dir, store)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_lock_tells_whether_a_listener_elsewhere_runs() {
        let (dir, store) = store("lock");
        let other = Some("pid:[1]");
        // No listener has ever run here: there is no lock, and nothing holds it.
        assert_eq!(lock_held(&store, "proxy"), Some(false));
        assert_eq!(liveness(&store, "proxy", 1, Some(1), other), Liveness::Gone);

        let lock = RunLock::acquire(&store, "proxy").unwrap().expect("lock");
        assert_eq!(lock_held(&store, "proxy"), Some(true));
        // Neither a pid that isn't there nor an unknown start time says anything elsewhere.
        assert_eq!(liveness(&store, "proxy", i32::MAX as u32, None, other), Liveness::Running);
        assert!(matches!(RunLock::acquire(&store, "proxy"), Err(Error::Conflict(_))));
        // Each listener has its own.
        assert_eq!(lock_held(&store, "oob"), Some(false));
        store.meta_set("state", Some("{}")).unwrap();
        let err = await_exit_elsewhere(&store, "proxy", "state", 1, Duration::from_millis(100)).unwrap_err();
        assert!(err.to_string().contains("still running"), "{err}");

        drop(lock);
        assert_eq!(lock_held(&store, "proxy"), Some(false));
        assert_eq!(liveness(&store, "proxy", 1, Some(1), other), Liveness::Gone);
        await_exit_elsewhere(&store, "proxy", "state", 1, Duration::from_millis(100)).unwrap();
        assert!(RunLock::acquire(&store, "proxy").unwrap().is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Being unable to read the lock says nothing, and other users can read a lock it made.
    /// Permissions don't bind root, so that part only runs for other users.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_lock_file_that_cannot_be_read_says_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, store) = store("unreadable");
        let path = lock_path(&store, "proxy").unwrap();
        let chmod = |mode| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();

        let lock = RunLock::acquire(&store, "proxy").unwrap().expect("lock");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o644);
        drop(lock);

        // It can be taken without write access, as with a file left by another user.
        chmod(0o444);
        let lock = RunLock::acquire(&store, "proxy").unwrap().expect("a read-only lock file will do");
        assert_eq!(lock_held(&store, "proxy"), Some(true));
        drop(lock);

        chmod(0o000);
        if File::open(&path).is_err() {
            store.meta_set("state", Some("{}")).unwrap();
            assert_eq!(lock_held(&store, "proxy"), None);
            assert_eq!(liveness(&store, "proxy", 1, Some(1), Some("pid:[1]")), Liveness::Unverified);
            let err = await_exit_elsewhere(&store, "proxy", "state", 1, Duration::from_millis(100)).unwrap_err();
            assert!(err.to_string().contains("stop --forget"), "{err}");
            // A listener that answers clears its record, whatever the lock says.
            store.meta_set("state", None).unwrap();
            await_exit_elsewhere(&store, "proxy", "state", 1, Duration::from_millis(100)).unwrap();
        }
        chmod(0o644);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_project_without_a_file_has_no_lock() {
        let store = Store::open_in_memory().unwrap();
        assert!(RunLock::acquire(&store, "proxy").unwrap().is_none());
        assert_eq!(lock_held(&store, "proxy"), None);
        assert!(work_lock(&store, "job-1").is_none());
        assert!(work_gone(&store, "job-1", 0));
        assert!(!work_gone(&store, "job-1", std::process::id()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_lock_tells_whether_work_elsewhere_runs() {
        let (dir, store) = store("work");
        let (name, dead, me) = ("job-1", i32::MAX as u32, std::process::id());
        // No lock file (an older version, or no locks there): the pid decides.
        assert!(work_gone(&store, name, dead));
        assert!(!work_gone(&store, name, me));

        // With a lock file the lock decides, whatever the pid looks like.
        let held = work_lock(&store, name).expect("lock");
        assert_eq!(work_namespace(&store, name).unwrap(), pid_namespace());
        assert!(!work_gone(&store, name, dead));
        assert!(!work_elsewhere(&store, name));
        assert_eq!(work_pid_text(&store, name, 7), "pid 7");
        // Held by something other than our stdin: not ours to take.
        assert!(work_lock(&store, name).is_none());
        let path = lock_path(&store, name).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o644);
        }

        // The same goes elsewhere.
        std::fs::write(&path, "pid:[1]").unwrap();
        assert!(!work_gone(&store, name, dead));
        assert!(work_elsewhere(&store, name));
        assert!(work_pid_text(&store, name, 7).contains("another container"));
        drop(held);
        assert!(work_gone(&store, name, me));

        // A free lock in "our" namespace: its number was reused, or the pid was. Gone.
        std::fs::write(&path, pid_namespace().unwrap()).unwrap();
        assert!(work_gone(&store, name, me));

        // A lock file left behind by a crash is taken over.
        assert!(work_lock(&store, name).is_some());
        assert_eq!(work_namespace(&store, name).unwrap(), pid_namespace());
        forget_work_lock(&store, name);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Here the pid decides, as it does for state from an older version.
    #[test]
    fn this_namespace_goes_by_the_pid() {
        let (dir, store) = store("pid");
        let me = std::process::id();
        let start = start_time(me);
        for ns in [None, pid_namespace()] {
            assert_eq!(liveness(&store, "proxy", me, start, ns.as_deref()), Liveness::Running);
            assert_eq!(liveness(&store, "proxy", me, start.map(|s| s + 1), ns.as_deref()), Liveness::Gone);
            assert_eq!(liveness(&store, "proxy", 0, start, ns.as_deref()), Liveness::Gone);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
