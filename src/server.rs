//! The server: accepts connections and drives one LDAP session per connection.
//!
//! The loop is deliberately thin: read a framed message, hand it to
//! [`crate::ldap::handle`], write what comes back. Everything testable lives
//! behind that boundary, so this file only has to get the things right that a
//! socket adds — reading exactly one message, writing replies in order, upgrading
//! the stream for StartTLS, and closing the connection when the protocol says so.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::directory::Directory;
use crate::ldap::session::Session;
use crate::ldap::{Action, codec};
use crate::security::Security;

/// What one connection did, for logging and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hangup {
    /// The client sent unbind.
    Unbind,
    /// The client closed the connection.
    PeerClosed,
    /// A message could not be framed or decoded.
    Malformed,
    /// The client asked for StartTLS and the handshake did not complete.
    TlsHandshakeFailed,
}

/// A connection stream: plain, or encrypted after a StartTLS upgrade.
///
/// Both variants are `Unpin`, so polling dispatches on the variant and no
/// pin-projection machinery is needed.
pub enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl Unpin for Stream {}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Stream::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Stream::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Stream::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Stream::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl Stream {
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Stream::Tls(_))
    }
}

/// Serves one connection until the client leaves.
///
/// `acceptor` enables StartTLS on a plain connection; without it the extended
/// operation is refused with `unavailable`. A connection that arrives already
/// encrypted (LDAPS) comes in as [`Stream::Tls`] and cannot be upgraded again.
pub async fn serve_connection(
    mut stream: Stream,
    acceptor: Option<TlsAcceptor>,
    directory: Arc<Directory>,
    security: Arc<Security>,
) -> Result<Hangup, codec::CodecError> {
    let mut session = Session::new();
    session.set_encrypted(stream.is_encrypted());

    loop {
        let bytes = match codec::read_message(&mut stream).await {
            Ok(bytes) => bytes,
            Err(codec::CodecError::Frame(codec::FrameError::Truncated)) => {
                return Ok(Hangup::PeerClosed);
            }
            Err(codec::CodecError::Read(err))
                if err.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                return Ok(Hangup::PeerClosed);
            }
            Err(err) => return Err(err),
        };

        let message = match codec::decode(&bytes) {
            Ok(message) => message,
            // A message that cannot be decoded is a protocol error, not a reason to
            // keep reading: the frame boundary is no longer trustworthy.
            Err(_) => return Ok(Hangup::Malformed),
        };

        match crate::ldap::handle(&mut session, &directory, &security, message) {
            Action::Reply(messages) => {
                for message in messages {
                    codec::write_message(&mut stream, &message).await?;
                }
            }
            Action::Silent => {}
            Action::StartTls(message_id) => {
                if acceptor.is_none() {
                    codec::write_message(
                        &mut stream,
                        &crate::ldap::responses::extended_response(
                            message_id,
                            rasn_ldap::ResultCode::Unavailable,
                            "StartTLS is not configured on this server",
                            None,
                        ),
                    )
                    .await?;
                    continue;
                }

                codec::write_message(
                    &mut stream,
                    &crate::ldap::responses::extended_response(
                        message_id,
                        rasn_ldap::ResultCode::Success,
                        "",
                        Some(crate::ldap::starttls::STARTTLS_OID),
                    ),
                )
                .await?;

                let Stream::Plain(tcp) = stream else {
                    // Already encrypted: answered above, session unchanged.
                    continue;
                };
                let Some(acceptor) = acceptor.clone() else {
                    return Ok(Hangup::TlsHandshakeFailed);
                };

                stream = match acceptor.accept(tcp).await {
                    Ok(tls) => Stream::Tls(Box::new(tls)),
                    Err(_) => return Ok(Hangup::TlsHandshakeFailed),
                };
                session.set_encrypted(true);
                // RFC 4511 §4.14.1: the security layer is new, so the previous
                // bind no longer applies to it.
                session.reset();
            }
            Action::Close => {
                return Ok(Hangup::Unbind);
            }
        }
    }
}

/// Accepts connections until `shutdown` resolves.
///
/// Every connection gets its own task; a failing task is logged rather than taking
/// the listener down, because one broken client must not stop the server
/// (gorestldap crashed the whole process on a client disconnect).
pub async fn serve(
    listener: TcpListener,
    acceptor: Option<TlsAcceptor>,
    ldaps: bool,
    directory: Arc<Directory>,
    security: Arc<Security>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), std::io::Error> {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        // A failed accept (reset while accepting, out of file
                        // descriptors) must not kill the listener.
                        eprintln!("error accepting connection: {err}");
                        continue;
                    }
                };
                let _ = tcp.set_nodelay(true);

                let directory = Arc::clone(&directory);
                let security = Arc::clone(&security);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let stream = match (&acceptor, ldaps) {
                        (Some(acceptor), true) => match acceptor.accept(tcp).await {
                            Ok(tls) => Stream::Tls(Box::new(tls)),
                            Err(err) => {
                                eprintln!("client {peer}: TLS handshake failed: {err}");
                                return;
                            }
                        },
                        _ => Stream::Plain(tcp),
                    };

                    match serve_connection(stream, acceptor, directory, security).await {
                        Ok(Hangup::PeerClosed) | Ok(Hangup::Unbind) => {}
                        Ok(Hangup::Malformed) => {
                            eprintln!("client {peer} sent a malformed message, connection closed");
                        }
                        Ok(Hangup::TlsHandshakeFailed) => {
                            eprintln!("client {peer}: StartTLS handshake failed");
                        }
                        Err(err) => eprintln!("client {peer}: {err}"),
                    }
                });
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Group, User};
    use crate::password::{StoreScheme, hash as hash_password};
    use rasn_ldap::{
        AuthenticationChoice, BindRequest, LdapDn, LdapMessage, ProtocolOp, ResultCode,
        UnbindRequest,
    };
    use tokio::io::AsyncWriteExt;

    const BASE: &str = "dc=example,dc=com";
    const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";

    fn directory() -> Arc<Directory> {
        Arc::new(Directory::new(
            BASE,
            "users",
            "groups",
            vec![User {
                ldap_admin: true,
                object_class: vec!["top".to_string(), "inetOrgPerson".to_string()],
                cn: "admin".to_string(),
                uid: Some("admin".to_string()),
                user_password: Some(
                    hash_password("admin-secret", StoreScheme::Argon2id).expect("hash"),
                ),
                ..User::default()
            }],
            vec![Group {
                object_class: vec!["top".to_string(), "posixGroup".to_string()],
                cn: "group_a".to_string(),
                ..Group::default()
            }],
        ))
    }

    fn default_security() -> Arc<Security> {
        Arc::new(Security::default())
    }

    fn bind_message(message_id: u32, password: &[u8]) -> LdapMessage {
        LdapMessage::new(
            message_id,
            ProtocolOp::BindRequest(BindRequest::new(
                3,
                LdapDn::from(ADMIN_DN),
                AuthenticationChoice::Simple(rasn::types::OctetString::from_slice(password)),
            )),
        )
    }

    fn unbind_message(message_id: u32) -> LdapMessage {
        LdapMessage::new(message_id, ProtocolOp::UnbindRequest(UnbindRequest))
    }

    fn starttls_message(message_id: u32) -> LdapMessage {
        LdapMessage::new(
            message_id,
            ProtocolOp::ExtendedReq(rasn_ldap::ExtendedRequest {
                request_name: rasn::types::OctetString::from(
                    crate::ldap::starttls::STARTTLS_OID.as_bytes(),
                ),
                request_value: None,
            }),
        )
    }

    struct Running {
        client: Option<TcpStream>,
        addr: std::net::SocketAddr,
        task: tokio::task::JoinHandle<()>,
    }

    impl Running {
        fn client(&mut self) -> &mut TcpStream {
            self.client.as_mut().expect("client stream is still owned")
        }

        /// Hands the socket over to a TLS connector.
        fn take_client(&mut self) -> TcpStream {
            self.client.take().expect("client stream is still owned")
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn start(acceptor: Option<TlsAcceptor>, ldaps: bool, security: Arc<Security>) -> Running {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let _ = serve(listener, acceptor, ldaps, directory(), security, rx).await;
        });
        let client = TcpStream::connect(addr).await.expect("connect");
        Running {
            client: Some(client),
            addr,
            task,
        }
    }

    async fn write<W: AsyncWrite + Unpin>(client: &mut W, message: &LdapMessage) {
        let bytes = codec::encode(message).expect("encode");
        client.write_all(&bytes).await.expect("write");
    }

    async fn read<R: AsyncRead + Unpin>(client: &mut R) -> LdapMessage {
        let bytes = codec::read_message(client).await.expect("read");
        codec::decode(&bytes).expect("decode")
    }

    fn result_code(message: &LdapMessage) -> ResultCode {
        match &message.protocol_op {
            ProtocolOp::BindResponse(response) => response.result_code,
            ProtocolOp::SearchResDone(done) => done.0.result_code,
            ProtocolOp::ExtendedResp(response) => response.result_code,
            other => panic!("unexpected response: {other:?}"),
        }
    }

    fn test_acceptor() -> (TlsAcceptor, rustls::pki_types::CertificateDer<'static>) {
        let generated =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, generated.cert.pem()).expect("cert");
        std::fs::write(&key_path, generated.signing_key.serialize_pem()).expect("key");
        let acceptor = crate::tls::acceptor(&cert_path, &key_path).expect("acceptor");
        (
            acceptor,
            rustls::pki_types::CertificateDer::from(generated.cert.der().to_vec()),
        )
    }

    fn client_config(anchor: rustls::pki_types::CertificateDer<'static>) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(anchor).expect("trust anchor");
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    #[tokio::test]
    async fn a_bind_over_plain_tcp_is_answered() {
        let mut running = start(None, false, default_security()).await;

        write(running.client(), &bind_message(1, b"admin-secret")).await;
        let response = read(running.client()).await;

        assert_eq!(response.message_id, 1);
        assert_eq!(result_code(&response), ResultCode::Success);
    }

    #[tokio::test]
    async fn two_requests_in_one_connection_are_answered_in_order() {
        let mut running = start(None, false, default_security()).await;

        write(running.client(), &bind_message(1, b"admin-secret")).await;
        write(running.client(), &bind_message(2, b"wrong")).await;

        assert_eq!(
            result_code(&read(running.client()).await),
            ResultCode::Success
        );
        let second = read(running.client()).await;
        assert_eq!(second.message_id, 2);
        assert_eq!(result_code(&second), ResultCode::InvalidCredentials);
    }

    #[tokio::test]
    async fn unbind_does_not_stop_the_listener() {
        let mut first = start(None, false, default_security()).await;
        write(first.client(), &unbind_message(1)).await;

        let mut next = TcpStream::connect(first.addr).await.expect("connect");
        write(&mut next, &bind_message(3, b"admin-secret")).await;

        assert_eq!(result_code(&read(&mut next).await), ResultCode::Success);
    }

    #[tokio::test]
    async fn a_disconnecting_client_is_not_an_error() {
        let mut running = start(None, false, default_security()).await;
        drop(running.take_client());

        // The listener keeps serving: a new client works.
        let mut next = TcpStream::connect(running.addr).await.expect("connect");
        write(&mut next, &bind_message(4, b"admin-secret")).await;
        assert_eq!(result_code(&read(&mut next).await), ResultCode::Success);
    }

    #[tokio::test]
    async fn undecodable_message_closes_only_that_connection() {
        let running = start(None, false, default_security()).await;
        {
            let mut broken = TcpStream::connect(running.addr).await.expect("connect");
            // A well-framed SEQUENCE that is not an LDAP message.
            broken
                .write_all(&[0x30, 0x03, 0x02, 0x01, 0x01])
                .await
                .expect("write");
        }

        let mut next = TcpStream::connect(running.addr).await.expect("connect");
        write(&mut next, &bind_message(5, b"admin-secret")).await;
        assert_eq!(result_code(&read(&mut next).await), ResultCode::Success);
    }

    #[tokio::test]
    async fn search_over_the_socket_returns_entries_and_done() {
        use rasn_ldap::{SearchRequest, SearchRequestDerefAliases, SearchRequestScope};

        let mut running = start(None, false, default_security()).await;
        write(running.client(), &bind_message(1, b"admin-secret")).await;
        let _ = read(running.client()).await;

        let search = LdapMessage::new(
            2,
            ProtocolOp::SearchRequest(SearchRequest::new(
                LdapDn::from(BASE),
                SearchRequestScope::WholeSubtree,
                SearchRequestDerefAliases::NeverDerefAliases,
                0,
                0,
                false,
                rasn_ldap::Filter::Present(rasn_ldap::AttributeDescription::from("objectClass")),
                vec![],
            )),
        );
        write(running.client(), &search).await;

        let mut entries = 0;
        loop {
            let message = read(running.client()).await;
            match &message.protocol_op {
                ProtocolOp::SearchResEntry(_) => entries += 1,
                ProtocolOp::SearchResDone(done) => {
                    assert_eq!(done.0.result_code, ResultCode::Success);
                    break;
                }
                other => panic!("unexpected response: {other:?}"),
            }
        }

        assert_eq!(entries, 5, "domain, two ous, one user and one group");
    }

    #[tokio::test]
    async fn ldaps_listener_answers_a_bind_over_tls() {
        let (acceptor, anchor) = test_acceptor();
        let mut running = start(Some(acceptor), true, default_security()).await;

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config(anchor)));
        let domain = rustls::pki_types::ServerName::try_from("localhost").expect("name");
        let mut tls = connector
            .connect(domain, running.take_client())
            .await
            .expect("handshake");

        write(&mut tls, &bind_message(1, b"admin-secret")).await;
        assert_eq!(result_code(&read(&mut tls).await), ResultCode::Success);
    }

    #[tokio::test]
    async fn starttls_upgrades_the_connection_and_answers_a_bind() {
        let (acceptor, anchor) = test_acceptor();
        let mut running = start(Some(acceptor), false, default_security()).await;

        write(running.client(), &starttls_message(1)).await;
        let response = read(running.client()).await;
        assert_eq!(result_code(&response), ResultCode::Success);
        assert_eq!(
            response.message_id, 1,
            "the StartTLS answer must carry the request's message id"
        );

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config(anchor)));
        let domain = rustls::pki_types::ServerName::try_from("localhost").expect("name");
        let mut tls = connector
            .connect(domain, running.take_client())
            .await
            .expect("handshake");

        write(&mut tls, &bind_message(2, b"admin-secret")).await;
        assert_eq!(result_code(&read(&mut tls).await), ResultCode::Success);
    }

    #[tokio::test]
    async fn starttls_is_refused_without_a_certificate() {
        let mut running = start(None, false, default_security()).await;

        write(running.client(), &starttls_message(1)).await;

        assert_eq!(
            result_code(&read(running.client()).await),
            ResultCode::Unavailable
        );
    }

    #[tokio::test]
    async fn plaintext_bind_is_refused_when_encryption_is_required() {
        let security = Arc::new(Security {
            allow_plaintext_simple_bind: false,
            ..Security::default()
        });
        let mut running = start(None, false, security).await;

        write(running.client(), &bind_message(1, b"admin-secret")).await;

        assert_eq!(
            result_code(&read(running.client()).await),
            ResultCode::StrongerAuthRequired
        );
    }

    #[tokio::test]
    async fn starttls_then_bind_is_allowed_when_plaintext_is_refused() {
        let (acceptor, anchor) = test_acceptor();
        let security = Arc::new(Security {
            allow_plaintext_simple_bind: false,
            ..Security::default()
        });
        let mut running = start(Some(acceptor), false, security).await;

        write(running.client(), &starttls_message(1)).await;
        assert_eq!(
            result_code(&read(running.client()).await),
            ResultCode::Success
        );

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config(anchor)));
        let domain = rustls::pki_types::ServerName::try_from("localhost").expect("name");
        let mut tls = connector
            .connect(domain, running.take_client())
            .await
            .expect("handshake");

        write(&mut tls, &bind_message(2, b"admin-secret")).await;
        assert_eq!(result_code(&read(&mut tls).await), ResultCode::Success);
    }
}
