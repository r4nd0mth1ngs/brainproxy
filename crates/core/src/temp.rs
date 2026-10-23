//! Temporary projects: a project for one engagement that is never meant to be kept. It is an
//! ordinary project file (the CLI, proxy and jobs are separate processes sharing it), but it
//! lives in a RAM-backed folder where the OS has one (Linux tmpfs) and is wiped when its owner
//! (the desktop app or `mcp serve`) closes it, or by a later sweep if the owner died.
//!
//! Layout: `<root>/<id>/temp.bpdb` plus `<root>/<id>/temp.json` (the marker: who owns it).
//! Everything the project keeps next to its file (logs, browser profiles) lands in that folder
//! too, so removing the folder removes all of it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The project file's name inside its temp folder.
pub const FILE_NAME: &str = "temp.bpdb";
const MARKER: &str = "temp.json";
/// Folders being wiped are renamed to this prefix first, so a half-finished wipe is never
/// mistaken for a live project and a later sweep can finish it.
const DISCARDING: &str = ".discard-";

/// The process a temp project belongs to: it is wiped once this process is gone.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Owner {
    pub pid: u32,
    /// Process start time (see the CLI's `process::start_time`), so a later process reusing
    /// the pid isn't taken for the owner.
    pub start_time: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Marker {
    pub owner: Option<Owner>,
    /// Unix seconds.
    pub created: u64,
}

/// Where temp projects go and whether that is RAM rather than disk.
#[derive(Clone, Debug, Serialize)]
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
    let root = base.join(folder_name());
    let ram_backed = is_ram_backed(&base);
    Location { root, ram_backed }
}

/// The runtime dir is often capped at 10% of RAM and /dev/shm at 50%, and captured traffic and
/// browser profiles grow, so the one with more free space wins. A read-only mount (a sandbox, a
/// locked-down runtime dir) is skipped.
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

/// Whether the temp project at `project` is in RAM rather than on disk.
pub fn ram_backed(project: &Path) -> bool {
    folder_of(project).is_some_and(|d| is_ram_backed(&d))
}

/// Per user, since /dev/shm and /tmp are shared.
#[cfg(unix)]
fn folder_name() -> String {
    format!("brainproxy-temp-{}", unsafe { libc::getuid() })
}

/// The Windows temp folder is already per user.
#[cfg(not(unix))]
fn folder_name() -> String {
    "brainproxy-temp".into()
}

/// Creates the root owner-only, refusing one that someone else made (or a symlink planted
/// there), since /dev/shm and /tmp are writable by everyone.
fn ensure_root(root: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(root).map_err(|e| io_error(format!("cannot create folder {}: {e}", root.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(root)?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::getuid() } || meta.mode() & 0o077 != 0 {
            return Err(Error::Conflict(format!(
                "{} must be a folder owned by you with no access for others; remove it or set BRAINPROXY_TEMP_DIR",
                root.display()
            )));
        }
    }
    Ok(())
}

fn io_error(message: String) -> Error {
    Error::Io(std::io::Error::other(message))
}

/// Makes a new, empty temp project folder and returns the project file's path (not created
/// yet: the first `Store::open` creates it).
pub fn create(owner: Option<Owner>) -> Result<PathBuf> {
    let root = location().root;
    ensure_root(&root)?;
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
    let dir = root.join(hex::encode(bytes));
    let mut builder = std::fs::DirBuilder::new();
    // Not recursive: the root exists, and the project's folder must be a new one.
    builder.recursive(false);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(&dir)?;
    let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let marker = Marker { owner, created };
    std::fs::write(dir.join(MARKER), serde_json::to_vec(&marker).unwrap_or_default())?;
    Ok(dir.join(FILE_NAME))
}

/// The folder holding `project`, resolved ("." for a bare file name).
fn folder_of(project: &Path) -> Option<PathBuf> {
    let dir = project.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::canonicalize(dir).ok()
}

/// The marker of `project` if it is a temp project: named `temp.bpdb`, with a marker beside
/// it, in a folder directly inside this user's brainproxy temp folder. The layout identifies
/// it, not today's temp location (which depends on the environment). Anything else is never
/// wiped.
pub fn marker(project: &Path) -> Option<Marker> {
    if project.file_name()? != FILE_NAME {
        return None;
    }
    let dir = folder_of(project)?;
    if dir.parent()?.file_name()? != folder_name().as_str() || dir.file_name()?.to_str()?.starts_with('.') {
        return None;
    }
    serde_json::from_slice(&std::fs::read(dir.join(MARKER)).ok()?).ok()
}

/// Whether `path` (which need not exist yet) is inside a temp project's folder, and so would be
/// wiped with it.
pub fn is_inside(path: &Path) -> bool {
    let Ok(abs) = std::path::absolute(path) else { return false };
    let Some(existing) = abs.ancestors().find_map(|a| std::fs::canonicalize(a).ok()) else { return false };
    existing.ancestors().any(|d| marker(&d.join(FILE_NAME)).is_some())
}

/// Every temp project under the root, with its marker.
pub fn list() -> Vec<(PathBuf, Marker)> {
    let Ok(entries) = std::fs::read_dir(location().root) else { return Vec::new() };
    entries.flatten().map(|e| e.path().join(FILE_NAME)).filter_map(|p| marker(&p).map(|m| (p, m))).collect()
}

/// Removes a temp project's folder and everything in it. The caller stops whatever still
/// uses it first. Refuses anything that isn't a temp project.
pub fn remove(project: &Path) -> Result<()> {
    if marker(project).is_none() {
        return Err(Error::InvalidInput(format!("{} is not a temporary project", project.display())));
    }
    let dir = folder_of(project).ok_or_else(|| Error::NotFound(format!("folder of {}", project.display())))?;
    let name = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let claimed = dir.with_file_name(format!("{DISCARDING}{name}"));
    std::fs::rename(&dir, &claimed)?;
    // A sweep finishing leftovers may be removing the same folder at the same time.
    match std::fs::remove_dir_all(&claimed) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// Finishes wipes that were interrupted (folders left with the discarding prefix).
pub fn remove_leftovers() {
    let Ok(entries) = std::fs::read_dir(location().root) else { return };
    for e in entries.flatten() {
        if e.file_name().to_string_lossy().starts_with(DISCARDING) {
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
        let base = std::env::temp_dir().join(format!("bp-temp-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::env::set_var("BRAINPROXY_TEMP_DIR", &base);

        let owner = Owner { pid: 4242, start_time: Some(7) };
        let p = create(Some(owner)).unwrap();
        assert_eq!(p.file_name().unwrap(), FILE_NAME);
        assert!(p.parent().unwrap().starts_with(&base));
        assert_eq!(marker(&p).unwrap().owner, Some(owner));
        assert_eq!(list().len(), 1);

        // Only the real layout counts: a project elsewhere with a look-alike marker doesn't.
        let fake = base.join("elsewhere");
        std::fs::create_dir_all(&fake).unwrap();
        std::fs::write(fake.join(MARKER), b"{\"owner\":null,\"created\":0}").unwrap();
        assert!(marker(&fake.join(FILE_NAME)).is_none());
        assert!(remove(&fake.join(FILE_NAME)).is_err());
        assert!(fake.exists());

        // Anything saved inside it would be wiped with it.
        assert!(is_inside(&p.parent().unwrap().join("kept/acme.bpdb")));
        assert!(!is_inside(&base.join("kept/acme.bpdb")));

        // Found by its layout even when the temp location now resolves elsewhere.
        std::env::set_var("BRAINPROXY_TEMP_DIR", base.join("other"));
        assert!(marker(&p).is_some());
        std::env::set_var("BRAINPROXY_TEMP_DIR", &base);

        std::fs::write(&p, b"data").unwrap();
        remove(&p).unwrap();
        assert!(!p.parent().unwrap().exists());
        assert!(list().is_empty());

        // An interrupted wipe is finished later.
        let left = location().root.join(format!("{DISCARDING}abc"));
        std::fs::create_dir_all(&left).unwrap();
        remove_leftovers();
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
