//! Downloads for rule data and check templates (`scan data update`, `checks update`).
//!
//! Only GitHub, only over verified TLS, and only through the guarded client: the
//! scope for these downloads is exactly the GitHub hosts below, and the system scope
//! (`/etc/brainproxy/scope.json`) still applies on top, so a locked-down runner
//! refuses them (the provisioner then imports with `--from DIR`). Target scopes are
//! never involved. Refs are resolved to a commit first, so every file of one update
//! comes from the same pinned commit, which the manifests record.

use std::io::Read;
use std::time::Duration;

use crate::capture::decode_body;
use crate::error::{Error, Result};
use crate::guard::{Guard, ScopeSpec};
use crate::http::request::split_head_body;
use crate::http::{parse_response_head, Client, RawRequest, SendOptions};

pub const GITHUB_HOSTS: [&str; 3] = ["api.github.com:443", "raw.githubusercontent.com:443", "codeload.github.com:443"];

/// Largest download accepted (a nuclei-templates tarball is ~10 MiB).
pub const MAX_DOWNLOAD: usize = 128 << 20;

pub struct GitHub {
    client: Client,
}

impl GitHub {
    pub fn new() -> Result<Self> {
        let spec = ScopeSpec {
            name: Some("GitHub downloads".into()),
            include: GITHUB_HOSTS.iter().map(|h| h.to_string()).collect(),
            exclude: vec![],
        };
        let guard = Guard::load(Some(spec))?;
        Ok(Self {
            client: Client::new(SendOptions {
                timeout: Duration::from_secs(300),
                verify_tls: true,
                sni: None,
                guard: Some(guard),
                http2: false,
            }),
        })
    }

    /// GETs `url`; anything but 200 is an error. Returns the decoded body.
    pub async fn get(&self, url: &str, accept: &str) -> Result<Vec<u8>> {
        let headers = [("Accept".to_string(), accept.to_string())];
        let (req, target) = RawRequest::build("GET", url, &headers, b"")?;
        let ex = self.client.send(&req, &target).await?;
        let head = parse_response_head(&ex.response)?;
        if head.status != 200 {
            let kind = if head.status == 404 || head.status == 422 { Error::NotFound } else { Error::Protocol };
            return Err(kind(format!("{url}: HTTP {}", head.status)));
        }
        let body = decode_body(&head.headers, split_head_body(&ex.response).1);
        if body.len() > MAX_DOWNLOAD {
            return Err(Error::InvalidInput(format!("{url}: larger than {} MiB", MAX_DOWNLOAD >> 20)));
        }
        Ok(body)
    }

    /// Resolves a branch, tag, or commit of `repo` ("owner/name") to a commit sha.
    pub async fn resolve(&self, repo: &str, reference: &str) -> Result<String> {
        check_repo_ref(repo, reference)?;
        let url = format!("https://api.github.com/repos/{repo}/commits/{reference}");
        let sha = String::from_utf8_lossy(&self.get(&url, "application/vnd.github.sha").await?).trim().to_string();
        if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Protocol(format!("unexpected commit id from GitHub: {sha:.60}")));
        }
        Ok(sha)
    }

    pub async fn raw_file(&self, repo: &str, commit: &str, path: &str) -> Result<Vec<u8>> {
        check_repo_ref(repo, commit)?;
        self.get(&format!("https://raw.githubusercontent.com/{repo}/{commit}/{path}"), "*/*").await
    }

    /// The gzipped tarball of `repo` at `commit`.
    pub async fn tarball(&self, repo: &str, commit: &str) -> Result<Vec<u8>> {
        check_repo_ref(repo, commit)?;
        self.get(&format!("https://codeload.github.com/{repo}/tar.gz/{commit}"), "*/*").await
    }
}

/// Keeps user-supplied repo names and refs from changing the URL's meaning.
fn check_repo_ref(repo: &str, reference: &str) -> Result<()> {
    let ok = |s: &str, slash: bool| {
        !s.is_empty()
            && !s.contains("..")
            && !s.starts_with(['/', '.', '-'])
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b) || (slash && b == b'/'))
    };
    if !ok(repo, true) || repo.matches('/').count() != 1 {
        return Err(Error::InvalidInput(format!("bad repository {repo:?}: use owner/name")));
    }
    if !ok(reference, true) {
        return Err(Error::InvalidInput(format!("bad ref {reference:?}")));
    }
    Ok(())
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

/// Largest single file read out of a tarball; bigger entries are skipped.
pub const MAX_TAR_ENTRY: u64 = 4 << 20;
/// Bound on the decompressed tarball (gzip bombs).
const MAX_TAR_TOTAL: u64 = 2 << 30;

/// Calls `f(path, contents)` for each regular file in a gzipped tar (ustar, pax
/// and GNU long names) of at most `MAX_TAR_ENTRY` bytes.
pub fn tar_gz_files(gz: &[u8], mut f: impl FnMut(&str, &[u8]) -> Result<()>) -> Result<()> {
    let mut r = flate2::read::GzDecoder::new(gz).take(MAX_TAR_TOTAL);
    let mut long_name: Option<String> = None;
    let bad = |m: &str| Error::InvalidInput(format!("bad tar archive: {m}"));
    loop {
        let mut h = [0u8; 512];
        if let Err(e) = r.read_exact(&mut h) {
            return if e.kind() == std::io::ErrorKind::UnexpectedEof { Ok(()) } else { Err(e.into()) };
        }
        if h.iter().all(|&b| b == 0) {
            return Ok(());
        }
        let field = |a: usize, b: usize| {
            let s = &h[a..b];
            String::from_utf8_lossy(&s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]).into_owned()
        };
        let size = u64::from_str_radix(field(124, 136).trim(), 8).map_err(|_| bad("size"))?;
        let kind = h[156];
        let mut name = field(0, 100);
        if &h[257..262] == b"ustar" {
            let prefix = field(345, 500);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        let padded = size.div_ceil(512) * 512;
        let wanted = matches!(kind, b'0' | 0 | b'x' | b'L') && size <= MAX_TAR_ENTRY;
        let mut data = Vec::new();
        if wanted {
            r.by_ref().take(size).read_to_end(&mut data)?;
            if data.len() as u64 != size {
                return Err(bad("truncated entry"));
            }
            std::io::copy(&mut r.by_ref().take(padded - size), &mut std::io::sink())?;
        } else {
            std::io::copy(&mut r.by_ref().take(padded), &mut std::io::sink())?;
        }
        match kind {
            b'x' if wanted => {
                // Pax records: "<len> key=value\n".
                for rec in String::from_utf8_lossy(&data).lines() {
                    if let Some(path) = rec.split_once(' ').and_then(|(_, kv)| kv.strip_prefix("path=")) {
                        long_name = Some(path.to_string());
                    }
                }
            }
            b'L' if wanted => long_name = Some(String::from_utf8_lossy(&data).trim_end_matches('\0').to_string()),
            b'0' | 0 => {
                let path = long_name.take().unwrap_or(name);
                if wanted {
                    f(&path, &data)?;
                }
            }
            _ => long_name = None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal ustar.gz builder for tests.
    pub fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (name, data) in files {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..107].copy_from_slice(b"0000644");
            h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
            h[156] = b'0';
            h[257..263].copy_from_slice(b"ustar\0");
            h[148..156].copy_from_slice(b"        ");
            let sum: u32 = h.iter().map(|&b| b as u32).sum();
            h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
            tar.extend_from_slice(&h);
            tar.extend_from_slice(data);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }
        tar.extend_from_slice(&[0; 1024]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn reads_tar_entries() {
        let gz = tar_gz(&[("repo-abc/http/a.yaml", b"id: a\n"), ("repo-abc/README.md", &[b'x'; 700])]);
        let mut got = Vec::new();
        tar_gz_files(&gz, |p, d| {
            got.push((p.to_string(), d.len()));
            Ok(())
        })
        .unwrap();
        assert_eq!(got, vec![("repo-abc/http/a.yaml".to_string(), 6), ("repo-abc/README.md".to_string(), 700)]);
    }

    #[test]
    fn rejects_url_changing_refs() {
        assert!(check_repo_ref("zaproxy/zap-extensions", "main").is_ok());
        assert!(check_repo_ref("zaproxy/zap-extensions", "v1.2/x").is_ok());
        for (repo, r) in
            [("a/b", "../x"), ("a/b", "x?y"), ("a/b/c", "main"), ("a", "main"), ("a/b", "x#y"), ("a/b", "")]
        {
            assert!(check_repo_ref(repo, r).is_err(), "{repo} {r}");
        }
    }
}
