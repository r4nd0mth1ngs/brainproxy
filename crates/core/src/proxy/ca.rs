//! The interception CA. One CA per brainproxy home directory; leaf certificates
//! are minted on demand per host and cached in memory. All leaves share one key
//! pair, which makes minting a certificate a single signature.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};

use crate::error::{Error, Result};

const CA_CERT: &str = "ca.pem";
const CA_KEY: &str = "ca.key";
const CACHE_LIMIT: usize = 4096;

pub struct CertAuthority {
    dir: PathBuf,
    ca_pem: String,
    ca_der: CertificateDer<'static>,
    /// DER SubjectPublicKeyInfo of the CA key.
    spki: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
    leaf_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CaInfo {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub created: bool,
}

impl CertAuthority {
    /// Loads the CA from `dir`, creating it if missing.
    pub fn load_or_create(dir: &Path) -> Result<(Self, CaInfo)> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert_path = dir.join(CA_CERT);
        let key_path = dir.join(CA_KEY);
        // Held while the pair is created and read, so a process starting at the same time
        // never reads a half-written file, or a cert and a key from two different creations.
        let _lock = lock(dir);
        let created = !cert_path.exists() || !key_path.exists();
        if created {
            Self::write_new(dir)?;
        }
        warn_if_loose(&key_path);
        let ca_pem = std::fs::read_to_string(&cert_path)?;
        let key = KeyPair::from_pem(&std::fs::read_to_string(&key_path)?).map_err(ca_err)?;
        let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, key).map_err(ca_err)?;
        let ca_der = rustls_pemfile_cert(&ca_pem)?;
        let ca = Self {
            dir: dir.to_path_buf(),
            ca_pem,
            ca_der,
            spki,
            issuer,
            leaf_key: KeyPair::generate().map_err(ca_err)?,
            cache: Mutex::new(HashMap::new()),
        };
        Ok((ca, CaInfo { cert_path, key_path, created }))
    }

    /// Writes a fresh CA to `dir`, replacing any existing one.
    pub fn generate(dir: &Path) -> Result<()> {
        let _lock = lock(dir);
        Self::write_new(dir)
    }

    /// [`CertAuthority::generate`], for a caller holding the lock.
    fn write_new(dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let key = KeyPair::generate().map_err(ca_err)?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "brainproxy CA");
        dn.push(DnType::OrganizationName, "brainproxy");
        params.distinguished_name = dn;
        // pathlen:0: the CA signs leaves only, never another CA.
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages =
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(2);
        params.not_after = now + Duration::days(3650);
        let cert = params.self_signed(&key).map_err(ca_err)?;

        let key_path = dir.join(CA_KEY);
        write_private(&key_path, key.serialize_pem().as_bytes())?;
        std::fs::write(dir.join(CA_CERT), cert.pem())?;
        Ok(())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn cert_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn cert_der(&self) -> &[u8] {
        self.ca_der.as_ref()
    }

    /// base64(SHA-256(SubjectPublicKeyInfo)) of the CA key: the form Chromium's
    /// --ignore-certificate-errors-spki-list takes. Every proxied chain includes the CA.
    pub fn spki_sha256_base64(&self) -> String {
        use base64::Engine;
        use sha2::Digest;
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&self.spki))
    }

    /// TLS server config presenting a certificate for `host`.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let host = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
        if let Some(cfg) = self.cache.lock().unwrap().get(&host) {
            return Ok(cfg.clone());
        }
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host.as_str());
        params.distinguished_name = dn;
        params.subject_alt_names = vec![match host.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.clone().try_into().map_err(ca_err)?),
        }];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(2);
        params.not_after = now + Duration::days(365);
        params.serial_number = Some(rand_serial().into());
        let leaf = params.signed_by(&self.leaf_key, &self.issuer).map_err(ca_err)?;

        let chain = vec![leaf.der().clone(), self.ca_der.clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|e| Error::Tls(e.to_string()))?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);

        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= CACHE_LIMIT {
            cache.clear();
        }
        cache.insert(host, cfg.clone());
        Ok(cfg)
    }
}

fn rustls_pemfile_cert(pem: &str) -> Result<CertificateDer<'static>> {
    let block = pem::parse(pem).map_err(|e| Error::InvalidInput(format!("CA certificate: {e}")))?;
    Ok(CertificateDer::from(block.into_contents()))
}

fn rand_serial() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let mut v = nanos.to_be_bytes().to_vec();
    v[0] &= 0x7f; // Keep the serial positive.
    v
}

/// An exclusive lock on `<dir>/.lock` for creating or reading the CA, released when dropped.
/// Best effort: without it (a read-only directory holding an existing CA, a filesystem with
/// no locks) the CA still loads, as it did before there was a lock.
fn lock(dir: &Path) -> Option<std::fs::File> {
    std::fs::create_dir_all(dir).ok()?;
    let file = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join(".lock")).ok()?;
    file.lock().ok()?;
    Some(file)
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(path)?;
    // `mode` only applies when the file is created; tighten an existing one too
    // (before writing, so the new key is never readable by others).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(data)?;
    Ok(())
}

/// Warns on stderr when the CA key is readable or writable by group or others.
fn warn_if_loose(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "brainproxy: warning: CA key {} has mode {mode:o}; anyone who can read it can intercept any host. Run `chmod 600` on it.",
                    path.display()
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn ca_err(e: impl std::fmt::Display) -> Error {
    Error::Tls(format!("certificate authority: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_reloads_and_mints() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("bp-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (ca, info) = CertAuthority::load_or_create(&dir).unwrap();
        assert!(info.created);
        let first_pem = ca.cert_pem().to_string();
        ca.server_config("example.test").unwrap();
        ca.server_config("127.0.0.1").unwrap();

        let (ca2, info2) = CertAuthority::load_or_create(&dir).unwrap();
        assert!(!info2.created);
        assert_eq!(ca2.cert_pem(), first_pem);
        let a = ca2.server_config("Example.test").unwrap();
        let b = ca2.server_config("example.test").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }

    /// Processes starting at once on a new home all get the same, whole CA.
    #[test]
    fn concurrent_first_loads_share_one_ca() {
        let dir = std::env::temp_dir().join(format!("bp-ca-race-{}", std::process::id()));
        for _ in 0..5 {
            let _ = std::fs::remove_dir_all(&dir);
            let barrier = std::sync::Barrier::new(8);
            let pems: Vec<String> = std::thread::scope(|s| {
                let loads: Vec<_> = (0..8)
                    .map(|_| {
                        s.spawn(|| {
                            barrier.wait();
                            CertAuthority::load_or_create(&dir).unwrap().0.cert_pem().to_string()
                        })
                    })
                    .collect();
                loads.into_iter().map(|l| l.join().unwrap()).collect()
            });
            assert!(pems.iter().all(|p| *p == pems[0]));
            assert_eq!(std::fs::read_to_string(dir.join(CA_CERT)).unwrap(), pems[0]);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn regenerate_tightens_key_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("bp-ca-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        CertAuthority::generate(&dir).unwrap();
        let key = dir.join(CA_KEY);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        // `ca init --force` over a loose key must leave it 0600.
        CertAuthority::generate(&dir).unwrap();
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
        CertAuthority::load_or_create(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
