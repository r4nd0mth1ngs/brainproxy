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
        let created = !cert_path.exists() || !key_path.exists();
        if created {
            Self::generate(dir)?;
        }
        let ca_pem = std::fs::read_to_string(&cert_path)?;
        let key = KeyPair::from_pem(&std::fs::read_to_string(&key_path)?).map_err(ca_err)?;
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, key).map_err(ca_err)?;
        let ca_der = rustls_pemfile_cert(&ca_pem)?;
        let ca = Self {
            dir: dir.to_path_buf(),
            ca_pem,
            ca_der,
            issuer,
            leaf_key: KeyPair::generate().map_err(ca_err)?,
            cache: Mutex::new(HashMap::new()),
        };
        Ok((ca, CaInfo { cert_path, key_path, created }))
    }

    /// Writes a fresh CA to `dir`, replacing any existing one.
    pub fn generate(dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let key = KeyPair::generate().map_err(ca_err)?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "brainproxy CA");
        dn.push(DnType::OrganizationName, "brainproxy");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
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

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    opts.open(path)?.write_all(data)?;
    Ok(())
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
}
