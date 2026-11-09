//! Private request files for one CLI call, held until it exits (including cancellation).
use std::io::Write;
use std::path::PathBuf;

pub struct RaceFiles(Option<PathBuf>);

impl RaceFiles {
    pub fn stage(args: &mut [String], files: Vec<Vec<u8>>) -> std::io::Result<Self> {
        let mut held = Self(None);
        if files.is_empty() {
            return Ok(held);
        }
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        for attempt in 0..100 {
            let dir = std::env::temp_dir().join(format!("brainproxy-race-{}-{stamp}-{attempt}", std::process::id()));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&dir) {
                Ok(()) => {
                    held.0 = Some(dir);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        let dir = held.0.as_ref().ok_or_else(|| std::io::Error::other("cannot allocate race request directory"))?;
        for (i, bytes) in files.iter().enumerate() {
            let marker = format!("--also=@request:{i}");
            let arg = args
                .iter_mut()
                .find(|arg| **arg == marker)
                .ok_or_else(|| std::io::Error::other("missing race request argument"))?;
            let path = dir.join(format!("{i}.http"));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(&path)?.write_all(bytes)?;
            *arg = format!("--also={}", path.display());
        }
        Ok(held)
    }
}

impl Drop for RaceFiles {
    fn drop(&mut self) {
        if let Some(dir) = &self.0 {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Prefix of the per-call staging directories (`<prefix><pid>-<stamp>-<attempt>`).
const DIR_PREFIX: &str = "brainproxy-race-";

/// Removes staging directories a previous run left behind. The `RaceFiles` guard deletes its own
/// directory when the CLI call ends, but a hard app exit (a quit while a cancelled call is still
/// finishing) can skip the Drop and leave one on disk. Called once at startup; an active call's
/// directory is seconds old, so an age cutoff keeps a second running instance's files safe.
pub fn sweep_orphans() {
    sweep_dir(&std::env::temp_dir(), std::time::Duration::from_secs(3600));
}

fn sweep_dir(root: &std::path::Path, cutoff: std::time::Duration) {
    let Ok(entries) = std::fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(DIR_PREFIX) {
            continue;
        }
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .map(|t| t.elapsed().map(|age| age > cutoff).unwrap_or(false))
            .unwrap_or(false);
        if old && entry.path().is_dir() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_private_and_removed_on_drop() {
        let mut args = vec!["send".into(), "--also=@request:0".into(), "-".into()];
        let bytes = vec![0, 255, b'\r', b'\n'];
        let held = RaceFiles::stage(&mut args, vec![bytes.clone()]).unwrap();
        let dir = held.0.clone().unwrap();
        assert_eq!(std::fs::read(args[1].strip_prefix("--also=").unwrap()).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(std::fs::metadata(dir.join("0.http")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        drop(held);
        assert!(!dir.exists());
    }

    #[test]
    fn a_partial_staging_failure_removes_files_already_written() {
        let mut args = vec!["--also=@request:0".into()];
        assert!(RaceFiles::stage(&mut args, vec![b"first".to_vec(), b"second".to_vec()]).is_err());
        let path = PathBuf::from(args[0].strip_prefix("--also=").unwrap());
        assert!(!path.parent().unwrap().exists());
    }

    #[test]
    fn only_explicit_markers_are_replaced() {
        let mut args = vec!["--also=person.http".into()];
        assert!(RaceFiles::stage(&mut args, vec![b"raw".to_vec()]).is_err());
        assert_eq!(args[0], "--also=person.http");
    }

    #[test]
    fn sweep_removes_stale_dirs_and_keeps_fresh_and_foreign() {
        let root = std::env::temp_dir().join(format!("{DIR_PREFIX}sweep-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let ours = root.join(format!("{DIR_PREFIX}1-2-3"));
        let other = root.join("keep-me");
        std::fs::create_dir(&ours).unwrap();
        std::fs::write(ours.join("0.http"), b"raw").unwrap();
        std::fs::create_dir(&other).unwrap();
        // A zero cutoff treats every entry as stale; only the prefixed directory is removed.
        sweep_dir(&root, std::time::Duration::ZERO);
        assert!(!ours.exists());
        assert!(other.exists());
        // A long cutoff spares a staging directory that is only seconds old (another instance's).
        let fresh = root.join(format!("{DIR_PREFIX}9-9-9"));
        std::fs::create_dir(&fresh).unwrap();
        sweep_dir(&root, std::time::Duration::from_secs(3600));
        assert!(fresh.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
