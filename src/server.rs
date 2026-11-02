//! The server: accepts connections and drives one LDAP session per connection.
//!
//! The loop is deliberately thin: read a framed message, hand it to
//! [`crate::ldap::handle`], write what comes back. Everything testable lives
//! behind that boundary, so this file only has to get the three things right that
//! a socket adds — reading exactly one message, writing replies in order, and
//! closing the connection when the protocol says so.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

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
    /// The client sent something a client must not send.
    ProtocolViolation,
    /// A message could not be framed or decoded.
    Malformed,
}

/// Serves one connection until the client leaves.
///
/// `directory` is the immutable snapshot shared with the reloader, `security` the
/// policy bundle; both are swapped as a whole, so a connection always sees one
/// consistent version for the length of one request.
pub async fn serve_connection<IO>(
    mut io: IO,
    directory: Arc<Directory>,
    security: Arc<Security>,
) -> Result<Hangup, codec::CodecError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = Session::new();

    loop {
        let bytes = match codec::read_message(&mut io).await {
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
            Err(err) => {
                // A message that cannot be decoded is a protocol error, not a
                // reason to keep reading garbage.
                let _ = err;
                return Ok(Hangup::Malformed);
            }
        };

        match crate::ldap::handle(&mut session, &directory, &security, message) {
            Action::Reply(messages) => {
                for message in messages {
                    codec::write_message(&mut io, &message).await?;
                }
            }
            Action::Silent => {}
            Action::Close => {
                return Ok(Hangup::Unbind);
            }
        }
    }
}

/// Accepts connections until `shutdown` resolves.
///
/// Every connection gets its own task; a task that fails is logged in the returned
/// count rather than taking the listener down, because one broken client must not
/// stop the server (gorestldap crashed the whole process on a client disconnect).
pub async fn serve(
    listener: TcpListener,
    directory: Arc<Directory>,
    security: Arc<Security>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), std::io::Error> {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        // A failed accept (connection reset while accepting, out of
                        // file descriptors) must not kill the listener.
                        eprintln!("error accepting connection: {err}");
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);

                let directory = Arc::clone(&directory);
                let security = Arc::clone(&security);
                tokio::spawn(async move {
                    match serve_connection(stream, directory, security).await {
                        Ok(Hangup::PeerClosed) | Ok(Hangup::Unbind) => {}
                        Ok(Hangup::ProtocolViolation) | Ok(Hangup::Malformed) => {
                            eprintln!("client {peer} sent a malformed message, connection closed");
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

    fn security() -> Arc<Security> {
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

    /// Returns a duplex pair where the server side is already being served.
    fn spawn_session() -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<Result<Hangup, codec::CodecError>>,
    ) {
        let (client, server) = tokio::io::duplex(8192);
        let handle = tokio::spawn(serve_connection(server, directory(), security()));
        (client, handle)
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
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_bind_over_the_socket_is_answered() {
        let (mut client, server) = spawn_session();

        write(&mut client, &bind_message(1, b"admin-secret")).await;
        let response = read(&mut client).await;

        assert_eq!(response.message_id, 1);
        assert_eq!(result_code(&response), ResultCode::Success);
        drop(client);
        assert_eq!(
            server.await.expect("join").expect("session"),
            Hangup::PeerClosed
        );
    }

    #[tokio::test]
    async fn two_requests_in_one_connection_are_answered_in_order() {
        let (mut client, server) = spawn_session();

        write(&mut client, &bind_message(1, b"admin-secret")).await;
        write(&mut client, &bind_message(2, b"wrong")).await;

        assert_eq!(result_code(&read(&mut client).await), ResultCode::Success);
        let second = read(&mut client).await;
        assert_eq!(second.message_id, 2);
        assert_eq!(result_code(&second), ResultCode::InvalidCredentials);
        drop(client);
        let _ = server.await;
    }

    #[tokio::test]
    async fn unbind_closes_the_connection() {
        let (mut client, server) = spawn_session();

        write(&mut client, &bind_message(1, b"admin-secret")).await;
        let _ = read(&mut client).await;
        write(&mut client, &unbind_message(2)).await;

        assert_eq!(
            server.await.expect("join").expect("session"),
            Hangup::Unbind
        );
    }

    #[tokio::test]
    async fn client_disconnect_is_not_an_error() {
        let (client, server) = spawn_session();
        drop(client);

        assert_eq!(
            server.await.expect("join").expect("session"),
            Hangup::PeerClosed
        );
    }

    #[tokio::test]
    async fn undecodable_message_ends_the_session_instead_of_looping() {
        let (mut client, server) = spawn_session();
        // A well-framed SEQUENCE that is not an LDAP message.
        client
            .write_all(&[0x30, 0x03, 0x02, 0x01, 0x01])
            .await
            .expect("write");

        assert_eq!(
            server.await.expect("join").expect("session"),
            Hangup::Malformed
        );
    }

    #[tokio::test]
    async fn search_over_the_socket_returns_entries_and_done() {
        use rasn_ldap::{SearchRequest, SearchRequestDerefAliases, SearchRequestScope};

        let (mut client, server) = spawn_session();
        write(&mut client, &bind_message(1, b"admin-secret")).await;
        let _ = read(&mut client).await;

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
        write(&mut client, &search).await;

        let mut entries = 0;
        loop {
            let message = read(&mut client).await;
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
        drop(client);
        let _ = server.await;
    }

    #[tokio::test]
    async fn listener_serves_a_real_tcp_client_and_stops_on_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = tokio::sync::watch::channel(false);

        let server = tokio::spawn(serve(listener, directory(), security(), rx));

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        write(&mut stream, &bind_message(1, b"admin-secret")).await;
        assert_eq!(result_code(&read(&mut stream).await), ResultCode::Success);

        tx.send(true).expect("shutdown");
        server.await.expect("join").expect("server");
    }

    #[tokio::test]
    async fn a_broken_client_does_not_stop_the_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(serve(listener, directory(), security(), rx));

        // First client sends garbage and disappears.
        {
            let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            stream
                .write_all(&[0x30, 0x03, 0x02, 0x01, 0x01])
                .await
                .expect("write");
        }

        // Second client must still be served.
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        write(&mut stream, &bind_message(7, b"admin-secret")).await;
        let response = read(&mut stream).await;

        assert_eq!(response.message_id, 7);
        assert_eq!(result_code(&response), ResultCode::Success);
        server.abort();
    }
}
