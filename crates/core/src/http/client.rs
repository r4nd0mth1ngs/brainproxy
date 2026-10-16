//! A raw HTTP/1.x client: writes the request bytes as-is and reads one response.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::error::{Error, Result};
use crate::guard::Guard;
use crate::http::request::RawRequest;
use crate::http::target::Target;
use crate::http::wire::WireReader;

#[derive(Debug, Clone)]
pub struct SendOptions {
    pub timeout: Duration,
    /// Verify the server's TLS certificate. Off by default, as in most
    /// intercepting proxies: test targets often use self-signed certificates.
    pub verify_tls: bool,
    /// Override the TLS SNI name (defaults to the target host).
    pub sni: Option<String>,
    /// Scope every connection must pass. Without one, nothing is sent.
    pub guard: Option<Arc<Guard>>,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self { timeout: Duration::from_secs(30), verify_tls: false, sni: None, guard: None }
    }
}

/// A completed round trip.
#[derive(Debug, Clone, Serialize)]
pub struct Exchange {
    pub target: Target,
    #[serde(skip)]
    pub request: Vec<u8>,
    #[serde(skip)]
    pub response: Vec<u8>,
    pub duration_ms: u64,
}

#[derive(Clone)]
pub struct Client {
    tls: TlsConnector,
    opts: SendOptions,
}

impl Client {
    pub fn new(opts: SendOptions) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = if opts.verify_tls {
            let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
        } else {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth()
        };
        let mut config = config;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self { tls: TlsConnector::from(Arc::new(config)), opts }
    }

    pub async fn send(&self, req: &RawRequest, target: &Target) -> Result<Exchange> {
        let method = req.head().map(|h| h.method).unwrap_or_else(|_| "GET".into());
        let started = Instant::now();
        let response = tokio::time::timeout(self.opts.timeout, self.round_trip(req.as_bytes(), target, &method))
            .await
            .map_err(|_| Error::Timeout(self.opts.timeout))??;
        Ok(Exchange {
            target: target.clone(),
            request: req.as_bytes().to_vec(),
            response,
            duration_ms: started.elapsed().as_millis() as u64,
        })
    }

    async fn round_trip(&self, bytes: &[u8], target: &Target, method: &str) -> Result<Vec<u8>> {
        let mut stream = self.connect(target).await?;
        stream.write_all(bytes).await?;
        stream.flush().await?;
        WireReader::new().read_response(&mut stream, method).await
    }

    /// Opens a connection to the target, wrapped in TLS for https. The target
    /// must pass the scope guard; the connection goes to an address the guard
    /// checked.
    pub async fn connect(&self, target: &Target) -> Result<Stream> {
        let guard = self.opts.guard.as_ref().ok_or_else(|| {
            Error::OutOfScope("no engagement scope: run `brainproxy engagement start --target HOST ...` first".into())
        })?;
        let addrs = guard.resolve(&target.host, target.port).await?;
        let tcp = TcpStream::connect(&addrs[..])
            .await
            .map_err(|e| Error::Connect(format!("{}:{}: {e}", target.host, target.port)))?;
        tcp.set_nodelay(true).ok();
        if !target.is_tls() {
            return Ok(Box::new(tcp));
        }
        let name = self.opts.sni.as_deref().unwrap_or(&target.host);
        let server_name = ServerName::try_from(name.to_string())
            .map_err(|e| Error::InvalidInput(format!("bad TLS server name {name:?}: {e}")))?;
        let tls = self.tls.connect(server_name, tcp).await.map_err(|e| Error::Tls(e.to_string()))?;
        Ok(Box::new(tls))
    }
}

/// Any bidirectional byte stream (plain TCP or TLS).
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type Stream = Box<dyn AsyncStream>;

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}
