//! The connection a client speaks over: plain TCP, then TLS, then TLS again after
//! StartTLS.
//!
//! Mirrors `server::Stream`, for a different reason: the server only ever *accepts* TLS,
//! while a client starts plain, may upgrade in the middle of a connection, and has to hold
//! a certificate policy. Keeping the upgrade in one place is what makes `-Z` one call
//! rather than a second copy of the protocol loop.

use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Whether the server's certificate is checked, and against what.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Trust {
    /// The public roots compiled into the binary. What a client gets without asking.
    #[default]
    WebPki,
    /// A private certificate authority, or one self-signed certificate: the directory's own.
    File(std::path::PathBuf),
    /// Accept any certificate. `LDAPTLS_REQCERT=never` under another name, and just as
    /// dangerous: without this flag the connection is encrypted and unauthenticated, which
    /// protects against reading the traffic and not against the wrong server answering.
    Insecure,
}

impl Trust {
    /// The client configuration this policy resolves to.
    pub fn config(&self) -> Result<Arc<ClientConfig>, crate::client::Error> {
        let provider = Arc::new(rustls_rustcrypto::provider());

        let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|err| crate::client::Error::Tls(err.to_string()))?;

        let config = match self {
            Trust::Insecure => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
                .with_no_client_auth(),
            other => builder
                .with_root_certificates(other.roots()?)
                .with_no_client_auth(),
        };

        Ok(Arc::new(config))
    }

    /// The roots this policy trusts.
    fn roots(&self) -> Result<RootCertStore, crate::client::Error> {
        let mut roots = RootCertStore::empty();

        match self {
            Trust::WebPki => {
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
            Trust::File(path) => {
                for certificate in read_certificates(path)? {
                    roots.add(certificate).map_err(|err| {
                        crate::client::Error::Tls(format!(
                            "certificate in '{}' cannot be trusted: {err}",
                            path.display()
                        ))
                    })?;
                }
            }
            Trust::Insecure => {}
        }

        if roots.is_empty() {
            return Err(crate::client::Error::Tls(format!(
                "no certificate authority to verify the server against: {}",
                match self {
                    Trust::WebPki => "the built-in roots are empty".to_string(),
                    Trust::File(path) => format!("'{}' holds no certificate", path.display()),
                    Trust::Insecure => "the insecure policy needs no roots".to_string(),
                }
            )));
        }

        Ok(roots)
    }
}

/// Every PEM certificate in the file, in order.
fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, crate::client::Error> {
    let data = std::fs::read(path).map_err(|err| {
        crate::client::Error::Tls(format!("cannot read '{}': {err}", path.display()))
    })?;

    let mut reader = data.as_slice();
    let certificates: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|err| {
            crate::client::Error::Tls(format!(
                "'{}' is not a PEM certificate: {err}",
                path.display()
            ))
        })?;

    if certificates.is_empty() {
        return Err(crate::client::Error::Tls(format!(
            "'{}' holds no PEM certificate",
            path.display()
        )));
    }

    Ok(certificates)
}

/// Accepts any certificate. Only reachable through `Trust::Insecure`.
///
/// The signature checks still run against the negotiated key, so the handshake is a real
/// one; what is missing is the question of whether the name in the certificate is the name
/// that was asked for. Written out rather than delegating because rustls has no
/// "trust nothing, verify nothing" shortcut, and a shortcut for this would be worse.
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A client connection: plain until it is upgraded.
pub enum Transport {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl Transport {
    /// Opens the connection the URL describes.
    pub async fn open(
        host: &str,
        port: u16,
        tls: bool,
        trust: &Trust,
        timeout: std::time::Duration,
    ) -> Result<Self, crate::client::Error> {
        let connect = TcpStream::connect((host, port));

        let stream = match tokio::time::timeout(timeout, connect).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                return Err(crate::client::Error::Connect {
                    host: host.to_string(),
                    port,
                    detail: err.to_string(),
                });
            }
            Err(_) => {
                return Err(crate::client::Error::Connect {
                    host: host.to_string(),
                    port,
                    detail: format!("no answer within {timeout:?}"),
                });
            }
        };

        // Nagle off: LDAP is request/response, so a delayed small write is a delayed answer.
        let _ = stream.set_nodelay(true);

        let transport = Transport::Plain(stream);
        if tls {
            return transport.upgrade(host, trust).await;
        }
        Ok(transport)
    }

    /// Runs TLS on top of the plaintext connection.
    ///
    /// Also the StartTLS path: the upgrade is the same operation from the transport's point
    /// of view, and the only thing that differs is who asked for it.
    pub(crate) async fn upgrade(
        self,
        host: &str,
        trust: &Trust,
    ) -> Result<Self, crate::client::Error> {
        let config = trust.config()?;
        let name = ServerName::try_from(host.to_string()).map_err(|err| {
            crate::client::Error::Tls(format!("'{host}' is not a server name: {err}"))
        })?;

        let connector = TlsConnector::from(config);
        let stream = connector
            .connect(name, self.into_plain()?)
            .await
            .map_err(|err| {
                crate::client::Error::Tls(format!("handshake with {host} failed: {err}"))
            })?;

        Ok(Transport::Tls(Box::new(stream)))
    }

    /// The plaintext stream, for an upgrade that needs to wrap it.
    fn into_plain(self) -> Result<TcpStream, crate::client::Error> {
        match self {
            Transport::Plain(stream) => Ok(stream),
            // StartTLS is only legal on a plaintext connection, so a transport that is
            // already encrypted here means the caller asked for the wrong thing.
            Transport::Tls(_) => Err(crate::client::Error::Tls(
                "the connection is already encrypted; StartTLS is only valid on a plaintext one"
                    .to_string(),
            )),
        }
    }
}

impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Transport::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Transport::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Transport::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Transport::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Transport::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}
