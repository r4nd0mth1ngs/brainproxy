//! Temporary engagements, a desktop-app feature: a project kept in a RAM-backed folder where the
//! OS has one (Linux tmpfs), deleted when the user discards it. Only this process creates or
//! deletes them. The CLI never does: a project started from the CLI or by an agent stays as
//! proof of the work until a person removes it.
//!
//! Layout: `<root>/<id>/temp.bpdb`, `<root>/<id>/temp.json` (marker: when it was made, by which
//! pid) and `<root>/<id>/owner.lock`, locked by the app for as long as it has the project. The
//! OS releases the lock when the app exits or crashes, so a folder whose lock can be taken is
//! a leftover; the app asks what to do with it, never deleting one by itself. Everything the
//! project keeps next to its file (logs, browser profiles) is inside the folder.

use std::fs::{DirBuilder, File};
use std::hash::{BuildHasher, RandomState};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

/// The project file's name inside its folder.
pub const FILE_NAME: &str = "temp.bpdb";
const MARKER: &str = "temp.json";
const LOCK: &str = "owner.lock";
/// Folders being deleted are renamed to this prefix first, so a half-finished delete is never
/// mistaken for a live project and is finished later.
const DELETING: &str = ".delete-";

/// Where temp projects go and whether that is RAM rather than disk.
pub struct Location {
    pub root: PathBuf,
    pub ram_backed: bool,
}

/// `$BRAINPROXY_TEMP_DIR`, else on Linux whichever of `$XDG_RUNTIME_DIR` and `/dev/shm` (both
/// tmpfs) has more room, else the OS temp folder, which is on disk. The brainproxy folder
/// inside it is per user.
pub fn location() -> Location {
    let base =
        std::env::var_os("BRAINPROXY_TEMP_DIR").map(PathBuf::from).or_else(ram_base).unwrap_or_else(std::env::temp_dir);
    let ram_backed = is_ram_backed(&base);
    Location { root: base.join(folder_name()), ram_backed }
}

/// The runtime dir is often capped at 10% of RAM and /dev/shm at 50%, and captured traffic and
/// browser profiles grow, so the one with more free space wins. A read-only mount is skipped.
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_cast)] // statfs field types differ between libc targets.
fn ram_base() -> Option<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    runtime
        .into_iter()
        .chain([PathBuf::from("/dev/shm")])
        .filter(|d| d.is_dir() && is_ram_backed(d) && writable(d))
        .max_by_key(|d| statfs(d).map_or(0, |st| st.f_bavail as u64 * st.f_bsize as u64))
}

#[cfg(not(target_os = "linux"))]
fn ram_base() -> Option<PathBuf> {
    None
}

#[cfg(target_os = "linux")]
fn c_path(path: &Path) -> Option<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes()).ok()
}

#[cfg(target_os = "linux")]
fn statfs(dir: &Path) -> Option<libc::statfs> {
    let c = c_path(dir)?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0).then_some(st)
}

#[cfg(target_os = "linux")]
fn writable(dir: &Path) -> bool {
    c_path(dir).is_some_and(|c| unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) } == 0)
}

/// tmpfs or ramfs: file contents live in memory (and swap), never on a disk filesystem.
/// f_type is i32, i64 or u32 depending on the target; the magics are 32-bit values.
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_cast)]
fn is_ram_backed(dir: &Path) -> bool {
    const TMPFS_MAGIC: u32 = 0x0102_1994;
    const RAMFS_MAGIC: u32 = 0x8584_58f6;
    statfs(dir).is_some_and(|st| matches!(st.f_type as u32, TMPFS_MAGIC | RAMFS_MAGIC))
}

#[cfg(not(target_os = "linux"))]
fn is_ram_backed(_: &Path) -> bool {
    false
}

/// Per user, since /dev/shm and /tmp are shared. Named after the CLI (`brainproxy-temp-<uid>`,
/// `brainproxy-dev-temp-<uid>` for a dev package), so a dev app never offers, or migrates, a
/// release's leftovers.
#[cfg(unix)]
fn folder_name() -> String {
    format!("{}-temp-{}", crate::CLI_NAME, unsafe { libc::getuid() })
}

/// The Windows temp folder is already per user.
#[cfg(not(unix))]
fn folder_name() -> String {
    format!("{}-temp", crate::CLI_NAME)
}

/// The folder holding `project`, resolved ("." for a bare file name).
fn folder_of(project: &Path) -> Option<PathBuf> {
    let dir = project.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::canonicalize(dir).ok()
}

/// Whether the temp project at `project` is in RAM rather than on disk.
pub fn ram_backed(project: &Path) -> bool {
    folder_of(project).is_some_and(|d| is_ram_backed(&d))
}

/// Creates the root owner-only, refusing one that someone else made (or a symlink planted
/// there), since /dev/shm and /tmp are writable by everyone.
fn ensure_root(root: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(root)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot create folder {}: {e}", root.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(root)?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::getuid() } || meta.mode() & 0o077 != 0 {
            return Err(io::Error::other(format!(
                "{} must be a folder owned by you with no access for others; remove it or set BRAINPROXY_TEMP_DIR",
                root.display()
            )));
        }
    }
    Ok(())
}

/// 128 random bits as hex: RandomState is seeded from the OS's randomness per instance.
fn random_id() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let a = RandomState::new().hash_one((std::process::id(), nanos));
    let b = RandomState::new().hash_one((nanos, std::process::id()));
    format!("{a:016x}{b:016x}")
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Makes a new temp project folder, writes its marker and locks it for this process. Returns
/// the project file's path (created by the CLI's `project init`) and the lock, which must be
/// kept for as long as the app has the project.
pub fn create() -> io::Result<(PathBuf, File)> {
    let root = location().root;
    ensure_root(&root)?;
    let dir = root.join(random_id());
    let mut builder = DirBuilder::new();
    // Not recursive: the root exists, and the project's folder must be a new one.
    builder.recursive(false);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(&dir)?;
    let marker = json!({"created": now(), "pid": std::process::id()});
    std::fs::write(dir.join(MARKER), marker.to_string())?;
    let lock = File::create(dir.join(LOCK))?;
    lock.try_lock().map_err(io::Error::other)?;
    Ok((dir.join(FILE_NAME), lock))
}

/// The marker of `project` if it is a temp project: named `temp.bpdb`, with a marker beside it,
/// in a folder directly inside this user's brainproxy temp folder. Anything else is never
/// deleted.
pub fn marker(project: &Path) -> Option<Value> {
    if project.file_name()? != FILE_NAME {
        return None;
    }
    let dir = folder_of(project)?;
    if dir.parent()?.file_name()? != folder_name().as_str() || dir.file_name()?.to_str()?.starts_with('.') {
        return None;
    }
    serde_json::from_slice(&std::fs::read(dir.join(MARKER)).ok()?).ok()
}

/// Temp projects no running app has: their lock could be taken, and is returned held, so no
/// other app instance offers them at the same time. Each comes with its marker.
pub fn leftovers() -> Vec<(PathBuf, Value, File)> {
    finish_deletes();
    let Ok(entries) = std::fs::read_dir(location().root) else { return Vec::new() };
    entries
        .flatten()
        .map(|e| e.path().join(FILE_NAME))
        .filter_map(|p| {
            let marker = marker(&p)?;
            // A folder without a lock file was being created, or isn't ours: leave it.
            let lock = File::options().write(true).open(p.parent()?.join(LOCK)).ok()?;
            lock.try_lock().ok()?;
            Some((p, marker, lock))
        })
        .collect()
}

/// Whether `path` (which need not exist yet) is inside a temp project's folder, and so would be
/// deleted with it.
pub fn is_inside(path: &Path) -> bool {
    let Ok(abs) = std::path::absolute(path) else { return false };
    let Some(existing) = abs.ancestors().find_map(|a| std::fs::canonicalize(a).ok()) else { return false };
    existing.ancestors().any(|d| marker(&d.join(FILE_NAME)).is_some())
}

/// Deletes a temp project's folder and everything in it. The caller has stopped everything
/// using it and dropped its lock (Windows can't rename a folder with an open file). Refuses
/// anything that isn't a temp project.
pub fn remove(project: &Path) -> io::Result<()> {
    if marker(project).is_none() {
        return Err(io::Error::other(format!("{} is not a temporary project", project.display())));
    }
    let dir = folder_of(project).ok_or_else(|| io::Error::other("the project's folder is gone"))?;
    let name = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let claimed = dir.with_file_name(format!("{DELETING}{name}"));
    std::fs::rename(&dir, &claimed)?;
    match std::fs::remove_dir_all(&claimed) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Finishes deletes that were interrupted: those folders were already chosen for deletion.
fn finish_deletes() {
    let Ok(entries) = std::fs::read_dir(location().root) else { return };
    for e in entries.flatten() {
        if e.file_name().to_string_lossy().starts_with(DELETING) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test touching the env var, so tests running in parallel don't race on it.
    #[test]
    fn create_find_and_remove() {
        let base = std::env::temp_dir().join(format!("bp-gui-temp-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::env::set_var("BRAINPROXY_TEMP_DIR", &base);

        let (p, lock) = create().unwrap();
        assert_eq!(p.file_name().unwrap(), FILE_NAME);
        assert!(p.parent().unwrap().starts_with(&base));
        assert_eq!(marker(&p).unwrap()["pid"], std::process::id());
        // Held by us: not a leftover.
        assert!(leftovers().is_empty());
        drop(lock);
        // Released (as when the app exits or crashes): offered, and held while offered.
        let found = leftovers();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, p);
        assert!(leftovers().is_empty());

        // Only the real layout counts: a look-alike elsewhere isn't a temp project.
        let fake = base.join("elsewhere");
        std::fs::create_dir_all(&fake).unwrap();
        std::fs::write(fake.join(MARKER), b"{}").unwrap();
        assert!(marker(&fake.join(FILE_NAME)).is_none());
        assert!(remove(&fake.join(FILE_NAME)).is_err());
        assert!(fake.exists());

        // Anything saved inside it would be deleted with it.
        assert!(is_inside(&p.parent().unwrap().join("kept/acme.bpdb")));
        assert!(!is_inside(&base.join("kept/acme.bpdb")));

        // Found by its layout even when the temp location now resolves elsewhere.
        std::env::set_var("BRAINPROXY_TEMP_DIR", base.join("other"));
        assert!(marker(&p).is_some());
        std::env::set_var("BRAINPROXY_TEMP_DIR", &base);

        drop(found);
        std::fs::write(&p, b"data").unwrap();
        remove(&p).unwrap();
        assert!(!p.parent().unwrap().exists());

        // An interrupted delete is finished later.
        let left = location().root.join(format!("{DELETING}abc"));
        std::fs::create_dir_all(&left).unwrap();
        finish_deletes();
        assert!(!left.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(location().root).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0);
        }
        std::env::remove_var("BRAINPROXY_TEMP_DIR");
        let _ = std::fs::remove_dir_all(&base);
    }
}
