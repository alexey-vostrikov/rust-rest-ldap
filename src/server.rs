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

use crate::ldap::session::Session;
use crate::ldap::{Action, codec};
use crate::metrics::{Metrics, Operation};
use crate::reload::Source;
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
    /// The server is stopping: the connection was closed between operations.
    Shutdown,
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

/// Writes the journal line for a write.
fn journal_note(
    journal: &crate::metrics::Journal,
    note: &crate::metrics::Note,
    peer: &str,
    result: rasn_ldap::ResultCode,
) {
    if !journal.is_on() {
        return;
    }

    // The journal keeps the number, because whoever reads the file has the RFC and not this
    // code. `ResultCode` is a C-like enum, so the number is its discriminant.
    let change = note.change(peer, result as u8);

    if let Err(err) = journal.record(&change) {
        // A journal that cannot be written is reported and not raised: a full disk must not
        // take the directory down for a reason unrelated to the directory.
        eprintln!(
            "{}",
            crate::i18n::t("error.journal", &[("detail", &err.to_string())])
        );
    }
}

/// The metric label for a protocol operation.
fn operation_of(operation: &rasn_ldap::ProtocolOp) -> Option<Operation> {
    use rasn_ldap::ProtocolOp;

    match operation {
        ProtocolOp::BindRequest(_) => Some(Operation::Bind),
        ProtocolOp::SearchRequest(_) => Some(Operation::Search),
        ProtocolOp::CompareRequest(_) => Some(Operation::Compare),
        ProtocolOp::ModifyRequest(_) => Some(Operation::Modify),
        ProtocolOp::AddRequest(_) => Some(Operation::Add),
        ProtocolOp::DelRequest(_) => Some(Operation::Delete),
        ProtocolOp::ModDnRequest(_) => Some(Operation::ModifyDn),
        ProtocolOp::ExtendedReq(_) => Some(Operation::Extended),
        ProtocolOp::AbandonRequest(_) => Some(Operation::Abandon),
        ProtocolOp::UnbindRequest(_) => Some(Operation::Unbind),
        // A response arriving at the server is a protocol violation, not an operation.
        _ => None,
    }
}

/// True when a response carries a success code.
fn succeeded(response: &rasn_ldap::ProtocolOp) -> bool {
    use rasn_ldap::{ProtocolOp, ResultCode};

    let code = match response {
        ProtocolOp::BindResponse(response) => response.result_code,
        ProtocolOp::SearchResDone(done) => done.0.result_code,
        ProtocolOp::CompareResponse(response) => response.0.result_code,
        ProtocolOp::ModifyResponse(response) => response.0.result_code,
        ProtocolOp::AddResponse(response) => response.0.result_code,
        ProtocolOp::DelResponse(response) => response.0.result_code,
        ProtocolOp::ModDnResponse(response) => response.0.result_code,
        ProtocolOp::ExtendedResp(response) => response.result_code,
        // An entry or a reference is part of a search whose done carries the verdict.
        _ => return true,
    };

    matches!(
        code,
        ResultCode::Success | ResultCode::CompareTrue | ResultCode::CompareFalse
    )
}

/// Serves one connection until the client leaves.
///
/// `acceptor` enables StartTLS on a plain connection; without it the extended
/// operation is refused with `unavailable`. A connection that arrives already
/// encrypted (LDAPS) comes in as [`Stream::Tls`] and cannot be upgraded again.
pub async fn serve_connection(
    stream: Stream,
    acceptor: Option<TlsAcceptor>,
    source: Arc<Source>,
    security: Arc<Security>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<Hangup, codec::CodecError> {
    serve_connection_as(
        stream,
        acceptor,
        source,
        security,
        shutdown,
        Observers::default(),
        String::new(),
    )
    .await
}

/// The same, with the shared observers and the peer address for the journal.
pub async fn serve_connection_as(
    mut stream: Stream,
    acceptor: Option<TlsAcceptor>,
    source: Arc<Source>,
    security: Arc<Security>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    observers: Observers,
    peer: String,
) -> Result<Hangup, codec::CodecError> {
    let mut session = Session::new();
    session.set_encrypted(stream.is_encrypted());

    loop {
        // The stop signal is only watched while waiting for the NEXT message: an
        // operation already being answered is finished before the connection is
        // closed, which is what "graceful" has to mean for a client mid-search.
        let bytes = match tokio::select! {
            read = codec::read_message(&mut stream) => read,
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
                    return Ok(Hangup::Shutdown);
                }
                continue;
            }
        } {
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

        // One snapshot per message: a reload or another client's write is visible
        // immediately, while a single operation still sees one consistent directory.
        let directory = source.directory().await;

        let operation = operation_of(&message.protocol_op);
        let started = std::time::Instant::now();

        match crate::ldap::handle(&mut session, &directory, &security, message) {
            Action::Reply(messages) => {
                let returned = messages
                    .iter()
                    .filter(|message| {
                        matches!(
                            message.protocol_op,
                            rasn_ldap::ProtocolOp::SearchResEntry(_)
                        )
                    })
                    .count();

                // The result of the LAST message is the answer: a search ends with a done,
                // and a failure anywhere else is a single response.
                if let (Some(last), Some(operation)) = (messages.last(), operation) {
                    observers
                        .metrics
                        .record(operation, succeeded(&last.protocol_op));
                }
                if operation == Some(Operation::Search) {
                    observers.metrics.record_search(started.elapsed(), returned);
                }

                for message in messages {
                    codec::write_message(&mut stream, &message).await?;
                }
            }
            Action::Persist(action) => {
                let crate::ldap::PersistAction {
                    changes,
                    success,
                    message_id,
                    failure,
                    journal,
                } = *action;
                // The reply follows the write, so `success` is never sent for a change
                // that did not reach the store.
                let outcome = source.apply(&changes).await;
                let code = if outcome.is_ok() {
                    rasn_ldap::ResultCode::Success
                } else {
                    rasn_ldap::ResultCode::UnwillingToPerform
                };

                // Recorded either way: "who tried" is a different question from "who
                // succeeded", and a journal that only holds successes cannot answer why a
                // change did not happen.
                if let Some(note) = &journal {
                    journal_note(&observers.journal, note, &peer, code);
                }

                if outcome.is_ok() {
                    observers.metrics.write_stored();
                }

                match outcome {
                    Ok(_) => codec::write_message(&mut stream, &success).await?,
                    Err(err) => {
                        eprintln!(
                            "{}",
                            crate::i18n::t("error.write", &[("detail", &err.to_string())])
                        );
                        let response = failure.message(
                            message_id,
                            rasn_ldap::ResultCode::UnwillingToPerform,
                            &format!("error updating backend data: {err}"),
                        );
                        codec::write_message(&mut stream, &response).await?;
                    }
                }
            }
            Action::PersistAfterReply { messages, changes } => {
                for message in &messages {
                    codec::write_message(&mut stream, message).await?;
                }
                // The reply is already out and it is correct; a failure here is an
                // operational problem to log, not an error to report to this client.
                if let Err(err) = source.apply(&changes).await {
                    eprintln!(
                        "{}",
                        crate::i18n::t("error.hash_upgrade", &[("detail", &err.to_string())])
                    );
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
    source: Arc<Source>,
    security: Arc<Security>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    grace: std::time::Duration,
) -> Result<(), std::io::Error> {
    // No observers: the tests and any caller that only wants the protocol.
    serve_with(
        listener,
        Listener {
            acceptor,
            ldaps,
            grace,
        },
        source,
        security,
        shutdown,
        Observers::default(),
    )
    .await
}

/// What the server reports to: counters and the change journal.
///
/// One value rather than two parameters, because every caller that wants one wants both,
/// and a growing parameter list to the accept loop is the kind of change that makes a
/// function unreviewable.
#[derive(Clone)]
pub struct Observers {
    pub metrics: Arc<Metrics>,
    pub journal: Arc<crate::metrics::Journal>,
}

impl Default for Observers {
    fn default() -> Self {
        Self {
            metrics: Metrics::new(),
            journal: Arc::new(crate::metrics::Journal::off()),
        }
    }
}

/// What the listener is configured with, apart from the directory it serves.
///
/// Bundled because the accept loop already took eight arguments and the next knob would have
/// made nine: a signature nobody can read is where parameters start getting swapped by
/// mistake.
pub struct Listener {
    pub acceptor: Option<TlsAcceptor>,
    /// The listener speaks TLS from the first byte (LDAPS).
    pub ldaps: bool,
    /// How long a client gets to finish the operation it is in the middle of.
    pub grace: std::time::Duration,
}

pub async fn serve_with(
    listener: TcpListener,
    settings: Listener,
    source: Arc<Source>,
    security: Arc<Security>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    observers: Observers,
) -> Result<(), std::io::Error> {
    let Listener {
        acceptor,
        ldaps,
        grace,
    } = settings;
    // Every connection task holds one clone of this sender; the receiver reports
    // "all gone" once the last one finishes, which is the condition to wait for
    // after the listener closes.
    let (finished_tx, mut finished_rx) = tokio::sync::mpsc::channel::<()>(1);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        // A failed accept (reset while accepting, out of file
                        // descriptors) must not kill the listener.
                        eprintln!(
                        "{}",
                        crate::i18n::t("error.accept", &[("detail", &err.to_string())])
                    );
                        continue;
                    }
                };
                let _ = tcp.set_nodelay(true);

                let source = Arc::clone(&source);
                let security = Arc::clone(&security);
                let observers = observers.clone();
                let acceptor = acceptor.clone();
                let stop = shutdown.clone();
                let finished = finished_tx.clone();
                tokio::spawn(async move {
                    let stream = match (&acceptor, ldaps) {
                        (Some(acceptor), true) => match acceptor.accept(tcp).await {
                            Ok(tls) => Stream::Tls(Box::new(tls)),
                            Err(err) => {
                                eprintln!(
                                    "{}",
                                    crate::i18n::t(
                                        "error.tls_handshake",
                                        &[("peer", &peer.to_string()), ("detail", &err.to_string())]
                                    )
                                );
                                return;
                            }
                        },
                        _ => Stream::Plain(tcp),
                    };

                    observers.metrics.connection_opened();
                    let outcome = serve_connection_as(
                        stream,
                        acceptor,
                        Arc::clone(&source),
                        Arc::clone(&security),
                        stop,
                        observers.clone(),
                        peer.to_string(),
                    )
                    .await;
                    observers.metrics.connection_closed();

                    match outcome {
                        Ok(Hangup::PeerClosed) | Ok(Hangup::Unbind) | Ok(Hangup::Shutdown) => {}
                        Ok(Hangup::Malformed) => {
                            eprintln!(
                                "{}",
                                crate::i18n::t("error.malformed", &[("peer", &peer.to_string())])
                            );
                        }
                        Ok(Hangup::TlsHandshakeFailed) => {
                            eprintln!(
                                "{}",
                                crate::i18n::t(
                                    "error.starttls_handshake",
                                    &[("peer", &peer.to_string())]
                                )
                            );
                        }
                        Err(err) => eprintln!(
                            "{}",
                            crate::i18n::t(
                                "error.client",
                                &[("peer", &peer.to_string()), ("detail", &err.to_string())]
                            )
                        ),
                    }
                    drop(finished);
                });
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    // The listener no longer accepts. Open connections are told to finish their
    // current operation and close; waiting is bounded so a stuck client cannot
    // hold the process.
    drop(finished_tx);
    let drained = async { while finished_rx.recv().await.is_some() {} };
    if tokio::time::timeout(grace, drained).await.is_err() {
        eprintln!(
            "{}",
            crate::i18n::t(
                "error.shutdown_timeout",
                &[("grace", &format!("{grace:?}"))]
            )
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn_ldap::{
        AuthenticationChoice, BindRequest, LdapDn, LdapMessage, ProtocolOp, ResultCode,
        UnbindRequest,
    };
    use tokio::io::AsyncWriteExt;

    const BASE: &str = "dc=example,dc=com";
    const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";

    async fn test_source() -> Arc<Source> {
        let dir = tempfile::tempdir().expect("tempdir");
        let users = dir.path().join("users.json");
        let groups = dir.path().join("groups.json");
        let password =
            crate::password::hash("admin-secret", crate::password::StoreScheme::Argon2id)
                .expect("hash");
        std::fs::write(
            &users,
            serde_json::json!([{
                "ldapAdmin": true,
                "objectClass": ["top", "person", "inetOrgPerson"],
                "cn": "admin",
                "sn": "Admin",
                "uid": "admin",
                "userPassword": password,
            }])
            .to_string(),
        )
        .expect("users");
        std::fs::write(
            &groups,
            r#"[{"objectClass":["top","posixGroup"],"cn":"group_a","gidNumber":2000}]"#,
        )
        .expect("groups");
        let backend_config = serde_json::json!({
            "users_path": users,
            "groups_path": groups,
        });
        let backend =
            crate::backend::Backend::from_config("file", Some(&backend_config)).expect("backend");
        let config = test_config();
        let (source, _) = Source::load(&config, backend).await.expect("load");
        source
    }

    fn test_config() -> crate::config::Config {
        crate::config::Config {
            backend: "file".to_string(),
            base_dn: BASE.to_string(),
            listen_addr: "127.0.0.1:0".to_string(),
            update_interval: std::time::Duration::from_secs(300),
            log_path: None,
            debug: false,
            log_timestamp: false,
            log_caller: false,
            backends: Default::default(),
            respect_control_criticality: true,
            users_ou_name: "users".to_string(),
            groups_ou_name: "groups".to_string(),
            use_tls: false,
            server_cert: None,
            server_key: None,
            http_listen_addr: None,
            callback_auth_token: None,
            passwords: Default::default(),
            schema: crate::schema::Schema::core(),
            schema_mode: crate::schema::Mode::Strict,
            schema_files: Vec::new(),
            indexes: crate::index::IndexConfig::default(),
            acl: Default::default(),
            allow_unencrypted_bind: true,
            dangerous_settings: Vec::new(),
            integrity: crate::integrity::IntegrityConfig::default(),
            observability: crate::config::ObservabilityConfig::default(),
            bootstrap: None,
            locale: (crate::i18n::Locale::english(), crate::i18n::Source::Default),
            locale_file: None,
            document: None,
        }
    }

    /// Security for the socket tests.
    ///
    /// They speak LDAP over a plain TCP socket on purpose - a TLS handshake is a
    /// different test - so the unencrypted bind has to be on, exactly as a lab server
    /// would have it in its configuration.
    fn default_security() -> Arc<Security> {
        Arc::new(Security {
            allow_unencrypted_bind: true,
            ..Security::default()
        })
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
        task: Option<tokio::task::JoinHandle<()>>,
        shutdown: tokio::sync::watch::Sender<bool>,
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

    impl Running {
        /// Waits for the listener task to return, giving up after a timeout.
        async fn join(&mut self) -> bool {
            let Some(task) = self.task.take() else {
                return true;
            };
            tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .map(|joined| joined.is_ok())
                .unwrap_or(false)
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }

    async fn start(acceptor: Option<TlsAcceptor>, ldaps: bool, security: Arc<Security>) -> Running {
        start_with_grace(acceptor, ldaps, security, std::time::Duration::from_secs(5)).await
    }

    async fn start_with_grace(
        acceptor: Option<TlsAcceptor>,
        ldaps: bool,
        security: Arc<Security>,
        grace: std::time::Duration,
    ) -> Running {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (shutdown, rx) = tokio::sync::watch::channel(false);
        let source = test_source().await;
        let task = tokio::spawn(async move {
            let _ = serve(listener, acceptor, ldaps, source, security, rx, grace).await;
        });
        let client = TcpStream::connect(addr).await.expect("connect");
        Running {
            client: Some(client),
            addr,
            task: Some(task),
            shutdown,
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
            allow_unencrypted_bind: false,
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
    async fn shutdown_closes_an_idle_connection_between_operations() {
        let mut running = start(None, false, default_security()).await;
        write(running.client(), &bind_message(1, b"admin-secret")).await;
        let _ = read(running.client()).await;

        running.shutdown.send(true).expect("shutdown");

        // The connection is closed cleanly: a read returns EOF, not a reset.
        let mut buffer = [0u8; 16];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::io::AsyncReadExt::read(running.client(), &mut buffer),
        )
        .await
        .expect("connection closes without hanging")
        .expect("read does not fail");
        assert_eq!(read, 0, "server must half-close the stream");
    }

    #[tokio::test]
    async fn shutdown_stops_accepting_new_connections() {
        let mut running = start(None, false, default_security()).await;
        let addr = running.addr;
        running.shutdown.send(true).expect("shutdown");

        // The task ends; the listener socket is closed with it.
        assert!(
            running.join().await,
            "serve must return after the stop signal"
        );

        let result = TcpStream::connect(addr).await;
        if let Ok(mut stream) = result {
            // Accepting may have raced with the close; either the connection is
            // refused or it is closed immediately without an answer.
            let mut buffer = [0u8; 16];
            let read = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::io::AsyncReadExt::read(&mut stream, &mut buffer),
            )
            .await
            .expect("closed connection must not hang");
            assert!(
                matches!(read, Ok(0) | Err(_)),
                "unexpected read result: {read:?}"
            );
        }
    }

    #[tokio::test]
    async fn shutdown_waits_for_a_connection_to_finish_and_times_out_when_it_does_not() {
        let mut running = start_with_grace(
            None,
            false,
            default_security(),
            std::time::Duration::from_millis(100),
        )
        .await;

        // The client stays connected and does nothing: the grace period expires.
        running.shutdown.send(true).expect("shutdown");

        assert!(
            running.join().await,
            "serve must return once the grace period expires"
        );
    }

    #[tokio::test]
    async fn starttls_then_bind_is_allowed_when_plaintext_is_refused() {
        let (acceptor, anchor) = test_acceptor();
        let security = Arc::new(Security {
            allow_unencrypted_bind: false,
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
