//! TLS: LDAPS and StartTLS, on rustls with the pure-Rust crypto provider.
//!
//! The provider is `rustls-rustcrypto` rather than the default `ring`/`aws-lc-rs`,
//! so the whole chain stays free of C: rustls itself is Rust, and the primitives
//! come from RustCrypto. The cost is that the provider is young, so it is pinned
//! exactly and covered by a handshake test against a certificate generated in the
//! test.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use thiserror::Error;
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("error reading '{path}': {source}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("no certificate found in '{0}'")]
    NoCertificate(String),
    #[error("no private key found in '{0}'")]
    NoPrivateKey(String),
    #[error("error reading private key from '{path}': {reason}")]
    PrivateKey { path: String, reason: String },
    #[error("error building the TLS configuration: {0}")]
    Config(String),
}

/// Builds the TLS acceptor from a PEM certificate chain and private key.
///
/// The certificate file may hold the leaf and the intermediates; the key file may
/// be PKCS#8, PKCS#1 or SEC1, because that is what `openssl req` and `certbot`
/// produce respectively.
pub fn acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor, TlsError> {
    let config = server_config(cert_path, key_path)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// The RFC 5929 `tls-server-end-point` channel binding for the configured certificate.
///
/// This is what ties a Kerberos ticket to *this* TLS session: a ticket captured from one session
/// cannot be replayed into another, because the binding the client computed is over the certificate
/// of the session it was captured on. It is computed here rather than per bind because it is a
/// property of the certificate, which changes only when the server restarts with a new one.
///
/// `None` means "no binding is defined for this certificate": RFC 5929 §4 names the hash of the
/// certificate's signature algorithm, and there is none for Ed25519. Reporting `None` is honest -
/// a binding invented for such a certificate would be one no client computes.
pub fn channel_binding(cert_path: &Path) -> Result<Option<krb5::ChannelBindings>, TlsError> {
    let certs = load_certs(cert_path)?;
    let Some(leaf) = certs.first() else {
        return Ok(None);
    };
    Ok(krb5::ChannelBindings::tls_server_end_point(leaf.as_ref()))
}

fn server_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig, TlsError> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
        .with_safe_default_protocol_versions()
        .map_err(|err| TlsError::Config(err.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| TlsError::Config(err.to_string()))
}

fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, TlsError> {
    let data = std::fs::read(path).map_err(|source| TlsError::Read {
        path: path.display().to_string(),
        source,
    })?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut data.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|source| TlsError::Read {
            path: path.display().to_string(),
            source,
        })?;

    if certs.is_empty() {
        return Err(TlsError::NoCertificate(path.display().to_string()));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>, TlsError> {
    let data = std::fs::read(path).map_err(|source| TlsError::Read {
        path: path.display().to_string(),
        source,
    })?;

    rustls_pemfile::private_key(&mut data.as_slice())
        .map_err(|source| TlsError::PrivateKey {
            path: path.display().to_string(),
            reason: source.to_string(),
        })?
        .ok_or_else(|| TlsError::NoPrivateKey(path.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_pem(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(body.as_bytes()).expect("write");
        path
    }

    #[test]
    fn missing_certificate_file_names_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = write_pem(dir.path(), "key.pem", "not a key");

        let err = acceptor(&dir.path().join("absent.pem"), &key)
            .err()
            .expect("must fail");

        assert_eq!(
            err.to_string(),
            format!(
                "error reading '{}': No such file or directory (os error 2)",
                dir.path().join("absent.pem").display()
            )
        );
    }

    #[test]
    fn file_without_certificate_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert = write_pem(
            dir.path(),
            "cert.pem",
            "-----BEGIN FOO-----\nAAAA\n-----END FOO-----\n",
        );
        let key = write_pem(
            dir.path(),
            "key.pem",
            "-----BEGIN BAR-----\nAAAA\n-----END BAR-----\n",
        );

        let err = acceptor(&cert, &key).err().expect("must fail");

        assert_eq!(
            err.to_string(),
            format!("no certificate found in '{}'", cert.display())
        );
    }

    #[test]
    fn the_channel_binding_is_computed_from_the_certificate_that_is_presented() {
        // RFC 5929 §4: `tls-server-end-point:` and the hash of the certificate's DER, with the hash
        // taken from its signature algorithm. The test pins both halves: the label, and that the
        // hash is over the same bytes the client sees on the wire - so it compares against
        // `rustls_pemfile`'s own DER rather than against a hash this code computed twice.
        let dir = tempfile::tempdir().expect("tempdir");
        let generated =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
        let cert = write_pem(dir.path(), "cert.pem", &generated.cert.pem());

        let binding = channel_binding(&cert)
            .expect("readable")
            .expect("a binding for this certificate");

        use sha2::Digest as _;
        let der = generated.cert.der();
        let expected = sha2::Sha256::digest(der.as_ref()).to_vec();
        let mut want = b"tls-server-end-point:".to_vec();
        want.extend_from_slice(&expected);
        assert_eq!(binding.application_data, want[..]);
    }

    #[test]
    fn a_certificate_that_cannot_be_read_has_no_binding() {
        // Not an error that stops a bind: the acceptor fails on the same file with a better message,
        // and a binding computed from half a file is worse than none.
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("absent.pem");
        assert!(channel_binding(&missing).is_err());
    }

    #[test]
    fn certificate_without_key_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let generated =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
        let cert = write_pem(dir.path(), "cert.pem", &generated.cert.pem());
        let key = write_pem(
            dir.path(),
            "key.pem",
            "-----BEGIN BAR-----\nAAAA\n-----END BAR-----\n",
        );

        let err = acceptor(&cert, &key).err().expect("must fail");

        assert_eq!(
            err.to_string(),
            format!("no private key found in '{}'", key.display())
        );
    }

    #[test]
    fn self_signed_certificate_and_pkcs8_key_build_an_acceptor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let generated =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
        let cert = write_pem(dir.path(), "cert.pem", &generated.cert.pem());
        let key = write_pem(
            dir.path(),
            "key.pem",
            &generated.signing_key.serialize_pem(),
        );

        acceptor(&cert, &key).expect("acceptor");
    }

    #[tokio::test]
    async fn handshake_completes_against_a_self_signed_certificate() {
        use tokio_rustls::TlsConnector;

        let dir = tempfile::tempdir().expect("tempdir");
        let generated =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
        let cert = write_pem(dir.path(), "cert.pem", &generated.cert.pem());
        let key = write_pem(
            dir.path(),
            "key.pem",
            &generated.signing_key.serialize_pem(),
        );
        let acceptor = acceptor(&cert, &key).expect("acceptor");

        // Client side: trust exactly this certificate.
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                generated.cert.der().to_vec(),
            ))
            .expect("trust anchor");
        let client_config =
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut stream = acceptor.accept(server_io).await.expect("server handshake");
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buffer = [0u8; 5];
            stream.read_exact(&mut buffer).await.expect("read");
            stream.write_all(&buffer).await.expect("write");
        });

        let domain = rustls::pki_types::ServerName::try_from("localhost").expect("name");
        let mut stream = connector
            .connect(domain, client_io)
            .await
            .expect("client handshake");
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        stream.write_all(b"hello").await.expect("write");
        let mut answer = [0u8; 5];
        stream.read_exact(&mut answer).await.expect("read");

        assert_eq!(&answer, b"hello");
        server_task.await.expect("server task");
    }
}
