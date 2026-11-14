//! Deleting a project, a desktop-app feature: the project file and what the CLI keeps beside it.
//! Like temporary engagements, nothing reachable from the CLI or MCP can do this, so a project
//! started from the CLI or by an agent stays until a person deletes it here.
//!
//! Beside `<dir>/<name>.bpdb` the CLI keeps:
//! - SQLite's `<name>.bpdb-wal`, `-shm` and `-journal` (core `store.rs`);
//! - lock files `<name>.bpdb-<what>.lock`: `proxy`, `oob`, `proxy-restart`, `job-<id>`, ...
//!   (cli `process.rs`);
//! - browser profiles in `<name>.bpdb.browsers/` (cli `browser_cmd.rs`);
//! - default logs `<name>.proxy.log`, `<name>.oob.log`, `<name>.record.log`, `<name>.job-<id>.log`
//!   and `<name>.fuzz-<id>.log`, and a fuzz run's staged request `<name>.fuzz-<id>.req` (cli
//!   `proxy_cmd.rs`, `oob_cmd.rs`, `auth_cmd.rs`, `jobs_cmd.rs`, `fuzz_cmd.rs`; cli `mcp.rs`'s
//!   `project_own_file` keeps the same list).
//!
//! The logs are named after the file's stem alone, so another project with that stem and a
//! different extension (`acme.db`, which the CLI allows) would share them: they are kept then.
//! Only `.browsers` is ever a folder, so a folder with any other of these names isn't the
//! CLI's and is kept, as is anything holding an SQLite database: another project, whatever its
//! name. Logs written elsewhere with `--log`, reports, exports and saved copies are the user's
//! own files and are kept.

use std::io;
use std::path::{Path, PathBuf};

/// The first 16 bytes of every SQLite database file.
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// What `check` found at the path.
#[derive(Debug, PartialEq)]
pub enum Found {
    /// A project file this may delete.
    Project(Checked),
    /// Nothing there: deleted already, or moved.
    Missing,
}

/// A project file `check` passed: its path through its folder's real path, and which file it
/// is, so `remove` deletes that file or nothing, even if the path changed meanwhile (the file
/// replaced, or a folder on the way swapped for a link while what ran for it was stopped).
#[derive(Debug, PartialEq)]
pub struct Checked {
    asked: PathBuf,
    path: PathBuf,
    id: Option<Identity>,
}

/// Which file a path holds: device and inode on unix, creation time elsewhere (std has no
/// stable file id on Windows). `None` where neither can be had.
#[derive(Debug, PartialEq)]
struct Identity(u64, u128);

fn identity(meta: &std::fs::Metadata) -> Option<Identity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(Identity(meta.dev(), meta.ino().into()))
    }
    #[cfg(not(unix))]
    {
        let created = meta.created().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?;
        Some(Identity(0, created.as_nanos()))
    }
}

/// Whether `path` is a regular file (not a link) holding an SQLite database.
fn is_database(path: &Path) -> io::Result<bool> {
    let mut head = [0u8; 16];
    let mut file = std::fs::File::open(path)?;
    let mut read = 0;
    while read < head.len() {
        match io::Read::read(&mut file, &mut head[read..])? {
            0 => break,
            n => read += n,
        }
    }
    Ok(read == head.len() && &head == SQLITE_HEADER)
}

/// Whether `project` is a project file this may delete: a full path to a regular `.bpdb` file
/// (not a link, whose target could be anything) holding an SQLite database. Anything else is
/// refused, so a wrong path never deletes some other file.
pub fn check(project: &Path) -> io::Result<Found> {
    let Some(path) = file_at(project)? else { return Ok(Found::Missing) };
    let meta = std::fs::symlink_metadata(&path)?;
    Ok(Found::Project(Checked { asked: project.to_path_buf(), path, id: identity(&meta) }))
}

/// `project` through its folder's real path, once it passes `check`'s tests; `None` if nothing
/// is there.
fn file_at(project: &Path) -> io::Result<Option<PathBuf>> {
    if !project.is_absolute() {
        return Err(io::Error::other(format!("{} is not a full path", project.display())));
    }
    // Any case: the Open dialog's filter ignores case on Windows and macOS.
    if project.extension().is_none_or(|e| !e.eq_ignore_ascii_case("bpdb"))
        || project.file_stem().is_none_or(|s| s.is_empty())
    {
        return Err(io::Error::other(format!("{} is not a .bpdb project file", project.display())));
    }
    let meta = match std::fs::symlink_metadata(project) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() {
        return Err(io::Error::other(format!("{} is a link; delete the file it points to instead", project.display())));
    }
    if !meta.is_file() {
        return Err(io::Error::other(format!("{} is not a file", project.display())));
    }
    if !is_database(project)? {
        return Err(io::Error::other(format!("{} is not a brainproxy project", project.display())));
    }
    let bad = || io::Error::other(format!("{} is not a project file path", project.display()));
    let dir = std::fs::canonicalize(project.parent().ok_or_else(bad)?)?;
    Ok(Some(dir.join(project.file_name().ok_or_else(bad)?)))
}

/// Which of the files the CLI keeps for the project `<stem>.bpdb` (`name`) a file in its folder is.
#[derive(Debug, PartialEq)]
enum Sidecar {
    /// Named after the whole file name: only this project's.
    Own,
    /// A default log or staged request, named after the stem alone.
    Stem,
}

fn sidecar(entry: &str, name: &str, stem: &str) -> Option<Sidecar> {
    let word = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let numbered = |s: &str, kind: &str| {
        s.strip_prefix(kind).is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
    };
    if let Some(rest) = entry.strip_prefix(name) {
        if matches!(rest, "-wal" | "-shm" | "-journal" | ".browsers")
            || rest.strip_prefix('-').and_then(|r| r.strip_suffix(".lock")).is_some_and(word)
        {
            return Some(Sidecar::Own);
        }
    }
    // `Path::with_extension`: these swap `.bpdb` for their own extension.
    let rest = entry.strip_prefix(stem)?.strip_prefix('.')?;
    let log = rest.strip_suffix(".log").is_some_and(|log| {
        matches!(log, "proxy" | "oob" | "record") || numbered(log, "job-") || numbered(log, "fuzz-")
    });
    let staged = rest.strip_suffix(".req").is_some_and(|req| numbered(req, "fuzz-"));
    (log || staged).then_some(Sidecar::Stem)
}

/// Whether another project with this stem is in `dir` (`acme.db` beside `acme.bpdb`), which
/// would share the stem's logs. Case is ignored: on Windows and macOS `ACME.db` shares them too.
fn stem_shared(dir: &Path, name: &str, stem: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else { return true };
    entries.flatten().any(|e| {
        let path = e.path();
        e.file_name().to_str().is_some_and(|f| f != name)
            && path.file_stem().and_then(|s| s.to_str()).is_some_and(|s| s.eq_ignore_ascii_case(stem))
            && e.file_type().is_ok_and(|t| t.is_file())
            && is_database(&path).unwrap_or(false)
    })
}

/// What `remove` deleted, and what it couldn't, with why.
#[derive(Debug, Default)]
pub struct Removed {
    pub removed: Vec<PathBuf>,
    pub left: Vec<(PathBuf, String)>,
}

/// Deletes the project file `check` passed, then what the CLI keeps beside it. The caller has
/// stopped everything running for it. The file is checked again first, and must still be the
/// same one at the same real place: otherwise nothing is deleted. The project file goes first:
/// if that fails nothing is touched, while deleting its `-wal` first and then failing would
/// leave it missing the writes that hadn't reached the file yet. Once it is gone the rest is
/// only leftovers, so a failure there is reported in `left` rather than stopping the others.
/// Links are deleted, never followed.
pub fn remove(checked: &Checked) -> io::Result<Removed> {
    let changed = || {
        io::Error::other(format!(
            "{} changed while what ran for it was being stopped, so nothing was deleted",
            checked.asked.display()
        ))
    };
    let now = file_at(&checked.asked)?.ok_or_else(changed)?;
    let meta = std::fs::symlink_metadata(&now)?;
    if now != checked.path || identity(&meta) != checked.id {
        return Err(changed());
    }
    let project = checked.path.as_path();
    let bad = || io::Error::other(format!("{} is not a project file path", project.display()));
    let name = project.file_name().and_then(|n| n.to_str()).ok_or_else(bad)?;
    let stem = project.file_stem().and_then(|n| n.to_str()).ok_or_else(bad)?;
    let dir = project.parent().ok_or_else(bad)?;
    std::fs::remove_file(project)?;
    let mut done = Removed { removed: vec![project.to_path_buf()], left: Vec::new() };
    let logs_too = !stem_shared(dir, name, stem);
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            done.left.push((dir.to_path_buf(), format!("its folder couldn't be read for the files beside it: {e}")));
            return Ok(done);
        }
    };
    for entry in entries.flatten() {
        let Some(file) = entry.file_name().to_str().map(str::to_owned) else { continue };
        match sidecar(&file, name, stem) {
            Some(Sidecar::Own) => {}
            Some(Sidecar::Stem) if logs_too => {}
            _ => continue,
        }
        let path = entry.path();
        // DirEntry::file_type doesn't follow links: a linked folder is removed as a link.
        let gone = match entry.file_type() {
            Ok(t) if t.is_dir() => {
                if !file.ends_with(".browsers") {
                    continue;
                }
                std::fs::remove_dir_all(&path)
            }
            // Another project, named like one of these, is kept.
            Ok(t) if t.is_file() => match is_database(&path) {
                Ok(true) => continue,
                Ok(false) => std::fs::remove_file(&path),
                Err(e) => Err(e),
            },
            Ok(_) => std::fs::remove_file(&path),
            Err(e) => Err(e),
        };
        match gone {
            Ok(()) => done.removed.push(path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => done.left.push((path, e.to_string())),
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bp-gui-delete-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn checked(project: &Path) -> Checked {
        match check(project).unwrap() {
            Found::Project(c) => c,
            Found::Missing => panic!("{} is missing", project.display()),
        }
    }

    fn database(path: &Path) {
        let mut bytes = SQLITE_HEADER.to_vec();
        bytes.resize(4096, 0);
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn sidecars_are_told_from_other_files() {
        let (name, stem) = ("acme.bpdb", "acme");
        for yes in [
            "acme.bpdb-wal",
            "acme.bpdb-shm",
            "acme.bpdb-journal",
            "acme.bpdb.browsers",
            "acme.bpdb-proxy.lock",
            "acme.bpdb-proxy-restart-guard.lock",
            "acme.bpdb-job-12.lock",
            "acme.proxy.log",
            "acme.oob.log",
            "acme.record.log",
            "acme.job-3.log",
            "acme.fuzz-40.log",
            "acme.fuzz-40.req",
        ] {
            assert!(sidecar(yes, name, stem).is_some(), "{yes}");
        }
        for no in [
            "acme.bpdb",
            "acme.bpdb-wal.bak",
            "acme.bpdb-.lock",
            "acme.bpdb-Proxy.lock",
            "acme.bpdb.browsers2",
            "acme.log",
            "acme.job-.log",
            "acme.job-1a.log",
            "acme.report.log",
            "acme.record.req",
            "acme.v2.record.log",
            "acme.job-3.req",
            "acme.fuzz-.req",
            "acme.html",
            // Another project's: acme.v2.bpdb, acme.job-1.bpdb.
            "acme.v2.proxy.log",
            "acme.v2.bpdb-wal",
            "acme.job-1.proxy.log",
            "acmecorp.proxy.log",
        ] {
            assert!(sidecar(no, name, stem).is_none(), "{no}");
        }
    }

    #[test]
    fn only_a_project_file_passes_the_check() {
        let dir = folder("check");
        let project = dir.join("acme.bpdb");
        assert_eq!(check(&project).unwrap(), Found::Missing);
        database(&project);
        assert!(matches!(check(&project).unwrap(), Found::Project(_)));
        assert!(check(Path::new("acme.bpdb")).is_err(), "relative");

        let text = dir.join("notes.bpdb");
        std::fs::write(&text, b"not a database at all").unwrap();
        assert!(check(&text).is_err());
        let short = dir.join("short.bpdb");
        std::fs::write(&short, b"SQLite").unwrap();
        assert!(check(&short).is_err());
        let other = dir.join("acme.sqlite");
        database(&other);
        assert!(check(&other).is_err(), "not .bpdb");
        let upper = dir.join("Upper.BPDB");
        database(&upper);
        assert!(matches!(check(&upper).unwrap(), Found::Project(_)));
        assert!(check(&dir.join(".bpdb")).is_err(), "no name");
        let folder = dir.join("folder.bpdb");
        std::fs::create_dir(&folder).unwrap();
        assert!(check(&folder).is_err());
        #[cfg(unix)]
        {
            let link = dir.join("link.bpdb");
            std::os::unix::fs::symlink(&project, &link).unwrap();
            assert!(check(&link).is_err());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn removes_the_project_and_its_files_and_nothing_else() {
        let dir = folder("remove");
        let project = dir.join("acme.bpdb");
        database(&project);
        for f in [
            "acme.bpdb-wal",
            "acme.bpdb-shm",
            "acme.bpdb-proxy.lock",
            "acme.proxy.log",
            "acme.record.log",
            "acme.job-2.log",
        ] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        std::fs::create_dir_all(dir.join("acme.bpdb.browsers/chrome/Default")).unwrap();
        std::fs::write(dir.join("acme.bpdb.browsers/chrome/Default/Cookies"), b"x").unwrap();
        let kept = ["acme.v2.bpdb", "acme.v2.bpdb-wal", "acme-report.html", "notes.txt"];
        for f in kept {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        // A linked folder of browser profiles: the link goes, never what it points to.
        #[cfg(unix)]
        let outside = {
            let outside = folder("remove-outside");
            std::fs::write(outside.join("keep"), b"x").unwrap();
            std::fs::remove_dir_all(dir.join("acme.bpdb.browsers")).unwrap();
            std::os::unix::fs::symlink(&outside, dir.join("acme.bpdb.browsers")).unwrap();
            outside
        };

        let done = remove(&checked(&project)).unwrap();
        assert!(done.left.is_empty(), "{:?}", done.left);
        assert_eq!(done.removed.len(), 8, "{:?}", done.removed);
        let mut left: Vec<String> =
            std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        left.sort();
        let mut expected: Vec<String> = kept.iter().map(|s| s.to_string()).collect();
        expected.sort();
        assert_eq!(left, expected);
        #[cfg(unix)]
        {
            assert!(outside.join("keep").exists());
            let _ = std::fs::remove_dir_all(&outside);
        }

        // Gone already: nothing is touched.
        database(&project);
        let c = checked(&project);
        std::fs::remove_file(&project).unwrap();
        assert!(remove(&c).is_err());
        assert!(dir.join("acme.v2.bpdb-wal").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn logs_another_project_shares_are_kept() {
        let dir = folder("shared");
        let project = dir.join("acme.bpdb");
        database(&project);
        // acme.db, a project made with the CLI, logs to the same acme.proxy.log.
        database(&dir.join("acme.db"));
        for f in ["acme.bpdb-wal", "acme.proxy.log", "acme.job-1.log"] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        let done = remove(&checked(&project)).unwrap();
        assert_eq!(done.removed.len(), 2, "{:?}", done.removed);
        assert!(dir.join("acme.proxy.log").exists() && dir.join("acme.job-1.log").exists());
        assert!(!dir.join("acme.bpdb-wal").exists());

        // Something else with that stem (a report) doesn't share them.
        database(&project);
        std::fs::remove_file(dir.join("acme.db")).unwrap();
        std::fs::write(dir.join("acme.html"), b"<html>").unwrap();
        remove(&checked(&project)).unwrap();
        assert!(!dir.join("acme.proxy.log").exists() && !dir.join("acme.job-1.log").exists());
        assert!(dir.join("acme.html").exists());

        // Case is ignored: ACME.db shares them on Windows and macOS.
        database(&project);
        database(&dir.join("ACME.db"));
        std::fs::write(dir.join("acme.oob.log"), b"x").unwrap();
        remove(&checked(&project)).unwrap();
        assert!(dir.join("acme.oob.log").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_what_the_cli_makes_is_removed() {
        let dir = folder("only");
        let project = dir.join("acme.bpdb");
        database(&project);
        // A project named like a log or lock, and folders named like them: not the CLI's.
        database(&dir.join("acme.proxy.log"));
        database(&dir.join("acme.bpdb-oob.lock"));
        std::fs::create_dir_all(dir.join("acme.job-999.log")).unwrap();
        std::fs::write(dir.join("acme.job-999.log/precious.txt"), b"x").unwrap();
        std::fs::create_dir_all(dir.join("acme.bpdb-wal")).unwrap();
        // A fuzz run's staged request, left by a launch that failed.
        std::fs::write(dir.join("acme.fuzz-3.req"), b"GET / HTTP/1.1\r\nAuthorization: x\r\n\r\n").unwrap();

        let done = remove(&checked(&project)).unwrap();
        assert!(done.left.is_empty(), "{:?}", done.left);
        assert!(!dir.join("acme.fuzz-3.req").exists());
        assert!(dir.join("acme.proxy.log").exists() && dir.join("acme.bpdb-oob.lock").exists());
        assert!(dir.join("acme.job-999.log/precious.txt").exists() && dir.join("acme.bpdb-wal").is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_that_changed_since_the_check_deletes_nothing() {
        let dir = folder("changed");
        let project = dir.join("acme.bpdb");
        database(&project);
        std::fs::write(dir.join("acme.bpdb-wal"), b"x").unwrap();
        let c = checked(&project);
        // Replaced while what ran for it was stopped (made first, so it can't reuse the inode).
        database(&dir.join("new.tmp"));
        std::fs::rename(dir.join("new.tmp"), &project).unwrap();
        let err = remove(&c).unwrap_err();
        assert!(err.to_string().contains("changed"), "{err}");
        assert!(project.exists() && dir.join("acme.bpdb-wal").exists());

        // A folder on the way swapped for a link to another one.
        #[cfg(unix)]
        {
            let real = dir.join("eng");
            let other = dir.join("other");
            std::fs::create_dir_all(&real).unwrap();
            std::fs::create_dir_all(&other).unwrap();
            database(&real.join("acme.bpdb"));
            let c = checked(&real.join("acme.bpdb"));
            std::fs::rename(&real, dir.join("eng-moved")).unwrap();
            database(&other.join("acme.bpdb"));
            std::os::unix::fs::symlink(&other, &real).unwrap();
            assert!(remove(&c).is_err());
            assert!(other.join("acme.bpdb").exists());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
