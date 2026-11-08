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
}
