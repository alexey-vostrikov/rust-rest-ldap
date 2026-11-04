//! The client: an LDAP session the utilities of this crate are built on.
//!
//! The server and the client live in one crate on purpose. A protocol implemented only on
//! the server side is a protocol nobody has walked from the other end: the utilities in
//! `src/bin` are the first outside caller, and the tests that run them against this server
//! are what proves the two agree.
//!
//! The shape here follows one rule: **responses are matched by message id, never by order.**
//! RFC 4511 lets a server answer the requests of one connection in any order, and a client
//! that reads "the next message" gets another request's answer — which in a directory means
//! showing one user another user's data. Requests therefore register their id, and an
//! answer that arrives early is kept until its own request asks for it.

use std::collections::HashMap;
use std::time::Duration;

use rasn_ldap::{
    AuthenticationChoice, BindRequest, ExtendedRequest, LdapMessage, MessageId, ProtocolOp,
    ResultCode,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

mod transport;

pub use transport::{Transport, Trust};

use crate::ldap::codec;

/// How much the client is willing to hold in memory for one response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest message the client will read, header included.
    ///
    /// A server that sends more is not sending an LDIF dump: it is either broken or hostile,
    /// and either way the client should stop rather than allocate. Enforced on the frame
    /// header, so the body is never read.
    pub max_message: usize,
    /// Largest search result the client will collect, in entries. `None` means no limit.
    ///
    /// Separate from `max_message` because a search result is a stream of small messages:
    /// ten million entries pass any per-message limit and still exhaust the memory of the
    /// machine.
    pub max_entries: Option<usize>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message: 8 * 1024 * 1024,
            max_entries: None,
        }
    }
}

/// How the session behaves, as opposed to what it asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// How long one response may take before the client gives up.
    ///
    /// A directory that has stopped answering and a directory that is thinking hard look
    /// identical from here, and waiting forever turns a broken server into a hung script.
    pub timeout: Duration,
    /// How long opening the socket may take.
    pub connect_timeout: Duration,
    pub limits: Limits,
    pub trust: Trust,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            limits: Limits::default(),
            trust: Trust::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "cannot connect to {host}:{port}: {detail}; an LDAP URL looks like ldap://host:389 \
         or ldaps://host:636"
    )]
    Connect {
        host: String,
        port: u16,
        detail: String,
    },
    #[error("the URL '{0}' is not understood; expected ldap://host[:port] or ldaps://host[:port]")]
    Url(String),
    #[error("the connection is closed")]
    Closed,
    #[error("no answer from the server within {waited:?}")]
    Timeout { waited: Duration },
    #[error("TLS: {0}")]
    Tls(String),
    #[error("error talking to the server: {0}")]
    Io(String),
    #[error("the server sent something that is not an LDAP message: {0}")]
    Protocol(String),
    #[error("the server sent a {size}-byte message, over the {limit}-byte limit")]
    TooLarge { size: usize, limit: usize },
    #[error("the search returned more than {limit} entries and the client stopped reading")]
    TooManyEntries { limit: usize },
    #[error("{message}")]
    Server { code: ResultCode, message: String },
    #[error("the server answered a {expected} with a {got}")]
    Unexpected {
        expected: &'static str,
        got: &'static str,
    },
}

impl From<codec::CodecError> for Error {
    fn from(err: codec::CodecError) -> Self {
        Error::Protocol(err.to_string())
    }
}

/// One session. Cheap to share: the methods take `&self`, so two tasks can have requests in
/// flight over the same connection.
pub struct Client {
    inner: std::sync::Arc<Inner>,
}

impl std::fmt::Debug for Client {
    /// The host and nothing else: a client holds a socket and a lock, neither of which
    /// prints anything a reader wants, and `Debug` is what `expect` needs to report a
    /// failure.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("host", &self.inner.host)
            .finish_non_exhaustive()
    }
}

struct Inner {
    reader: tokio::sync::Mutex<Option<ReadHalf<Transport>>>,
    writer: tokio::sync::Mutex<Option<WriteHalf<Transport>>>,
    /// Message ids and the answers that arrived before their request asked for them.
    bookkeeping: tokio::sync::Mutex<Bookkeeping>,
    host: String,
    options: Options,
}

struct Bookkeeping {
    next_id: MessageId,
    early: HashMap<MessageId, Vec<LdapMessage>>,
}

impl Bookkeeping {
    fn next_id(&mut self) -> MessageId {
        let id = self.next_id;
        // Ids are positive and non-zero; wrapping keeps a long-lived session from running
        // out, and the wrap cannot collide because old answers are long gone by then.
        self.next_id = if id == MessageId::MAX { 1 } else { id + 1 };
        id
    }
}

impl Client {
    /// Opens a connection. `ldaps://` runs TLS from the first byte.
    pub async fn connect(url: &str, options: Options) -> Result<Self, Error> {
        let target = Target::parse(url)?;
        let transport = Transport::open(
            &target.host,
            target.port,
            target.tls,
            &options.trust,
            options.connect_timeout,
        )
        .await?;

        let (reader, writer) = tokio::io::split(transport);

        Ok(Self {
            inner: std::sync::Arc::new(Inner {
                reader: tokio::sync::Mutex::new(Some(reader)),
                writer: tokio::sync::Mutex::new(Some(writer)),
                bookkeeping: tokio::sync::Mutex::new(Bookkeeping {
                    next_id: 1,
                    early: HashMap::new(),
                }),
                host: target.host,
                options,
            }),
        })
    }

    /// The host this session is connected to, as the URL spelled it.
    pub fn host(&self) -> &str {
        &self.inner.host
    }

    /// Simple bind. An empty DN is an anonymous bind, which is a legitimate request and not
    /// an error: plenty of directories serve a rootDSE that way.
    pub async fn bind(&self, dn: &str, password: &str) -> Result<(), Error> {
        let request = BindRequest::new(
            3,
            rasn_ldap::LdapDn::from(dn),
            AuthenticationChoice::Simple(rasn::types::OctetString::from(password.as_bytes())),
        );

        let responses = self
            .exchange(ProtocolOp::BindRequest(request), "bind response")
            .await?;

        result_of(&responses, "bind response").map(|_| ())
    }

    /// Runs a search and collects the answers until the server says it is done.
    ///
    /// A connection that closes before the final `searchResDone` is an error, not a short
    /// result: half a list presented as a whole one is the failure mode that makes a script
    /// act on data it never saw.
    pub async fn search(
        &self,
        request: rasn_ldap::SearchRequest,
    ) -> Result<(Vec<LdapMessage>, Outcome), Error> {
        let responses = self
            .exchange(ProtocolOp::SearchRequest(request), "search result done")
            .await?;

        let result = result_of(&responses, "search result done")?;
        Ok((responses, result))
    }

    /// Sends a request and returns every message of its answer.
    pub async fn request(
        &self,
        op: ProtocolOp,
        expected: &'static str,
    ) -> Result<Vec<LdapMessage>, Error> {
        self.exchange(op, expected).await
    }

    /// The same, with controls attached to the request.
    ///
    /// Controls are per request, not per connection: a paged search and an ordinary one can
    /// share a connection, and the page size of one must not touch the other.
    pub async fn request_with(
        &self,
        op: ProtocolOp,
        controls: Vec<rasn_ldap::Control>,
        expected: &'static str,
    ) -> Result<Vec<LdapMessage>, Error> {
        let id = self.inner.bookkeeping.lock().await.next_id();

        let mut message = LdapMessage::new(id, op);
        if !controls.is_empty() {
            message.controls = Some(controls.into_iter().collect());
        }

        let bytes = codec::encode(&message)?;
        self.send(&bytes).await?;
        self.collect(id, expected).await
    }

    /// A search with controls, which is how a paged or sorted search is asked for.
    pub async fn search_with(
        &self,
        request: rasn_ldap::SearchRequest,
        controls: Vec<rasn_ldap::Control>,
    ) -> Result<(Vec<LdapMessage>, Outcome), Error> {
        let responses = self
            .request_with(
                ProtocolOp::SearchRequest(request),
                controls,
                "search result done",
            )
            .await?;

        let result = result_of(&responses, "search result done")?;
        Ok((responses, result))
    }

    /// Upgrades the connection with StartTLS (RFC 4511 §4.14).
    pub async fn starttls(&self) -> Result<(), Error> {
        let request = ExtendedRequest {
            request_name: rasn_ldap::LdapOid::from(crate::ldap::starttls::STARTTLS_OID.as_bytes()),
            request_value: None,
        };

        let responses = self
            .exchange(ProtocolOp::ExtendedReq(request), "extended response")
            .await?;
        result_of(&responses, "extended response")?;

        // Both halves at once: the upgrade replaces the stream the two of them share, so no
        // other request may be reading or writing while it happens.
        let mut reader = self.inner.reader.lock().await;
        let mut writer = self.inner.writer.lock().await;

        let (read_half, write_half) = match (reader.take(), writer.take()) {
            (Some(reader), Some(writer)) => (reader, writer),
            // One half without the other means the connection is being closed elsewhere.
            _ => return Err(Error::Closed),
        };

        let transport = read_half.unsplit(write_half);
        let upgraded = match transport
            .upgrade(&self.inner.host, &self.inner.options.trust)
            .await
        {
            Ok(upgraded) => upgraded,
            Err(err) => {
                // The connection is unusable either way: the upgrade consumed the socket,
                // and half of it is not a stream. Reporting Closed later is honest.
                return Err(err);
            }
        };

        let (reader_half, writer_half) = tokio::io::split(upgraded);
        *reader = Some(reader_half);
        *writer = Some(writer_half);

        Ok(())
    }

    /// Sends the unbind and closes the connection.
    ///
    /// Unbind has no response (RFC 4511 §4.3), so there is nothing to wait for and nothing
    /// that can report a failure: the request is best effort by design.
    pub async fn unbind(&self) -> Result<(), Error> {
        let id = self.inner.bookkeeping.lock().await.next_id();
        let message = LdapMessage::new(id, ProtocolOp::UnbindRequest(rasn_ldap::UnbindRequest));
        let bytes = codec::encode(&message)?;

        let mut writer = self.inner.writer.lock().await;
        let half = writer.take();

        if let Some(half) = half {
            let mut half = half;
            let _ = half.write_all(&bytes).await;
            let _ = half.shutdown().await;
        }

        // The reader half is dropped too: a closed connection that still holds a task
        // reading from it keeps the descriptor open.
        let _ = self.inner.reader.lock().await.take();

        Ok(())
    }

    /// Sends one request and collects its answer.
    async fn exchange(
        &self,
        op: ProtocolOp,
        expected: &'static str,
    ) -> Result<Vec<LdapMessage>, Error> {
        let id = self.inner.bookkeeping.lock().await.next_id();
        let bytes = codec::encode(&LdapMessage::new(id, op))?;
        self.send(&bytes).await?;
        self.collect(id, expected).await
    }

    /// Starts a `refreshAndPersist` search and reads until the refresh stage ends.
    ///
    /// The answer to a persistent search never carries a `searchResDone`: RFC 4533 §1.3.2 closes
    /// the refresh with a `syncInfo` message and then keeps the connection open. A client that
    /// waits for the usual final message waits for ever - which is what happened before this
    /// existed, and is why it does.
    ///
    /// Returns the messages of the refresh stage and the message id, which `next_change` uses to
    /// tell this search's notifications from another's.
    pub async fn search_persist(
        &self,
        request: rasn_ldap::SearchRequest,
        controls: Vec<rasn_ldap::Control>,
    ) -> Result<(Vec<LdapMessage>, MessageId), Error> {
        let id = self.inner.bookkeeping.lock().await.next_id();
        let mut message = LdapMessage::new(id, ProtocolOp::SearchRequest(request));
        if !controls.is_empty() {
            message.controls = Some(controls);
        }
        self.send(&codec::encode(&message)?).await?;

        let mut reader = self.inner.reader.lock().await;
        let mut answer = Vec::new();

        loop {
            let half = reader.as_mut().ok_or(Error::Closed)?;
            // No read deadline: a refresh on a directory of any size takes as long as it takes,
            // and the caller stops it through its own shutdown, not through a per-frame timer.
            let bytes = self.read_frame_with(half, None).await?;
            let message = codec::decode(&bytes)?;

            if message.message_id != id {
                continue;
            }

            let finished = matches!(message.protocol_op, ProtocolOp::SearchResDone(_))
                || matches!(message.protocol_op, ProtocolOp::IntermediateResponse(_));
            answer.push(message);

            if finished {
                return Ok((answer, id));
            }
        }
    }

    /// Reads one pushed message for a persistent search.
    ///
    /// `None` when the connection closed. The caller matches on the message id it was given by
    /// `search_persist`, because a connection may carry more than one persistent search.
    pub async fn next_change(&self) -> Result<Option<LdapMessage>, Error> {
        let mut reader = self.inner.reader.lock().await;
        let half = reader.as_mut().ok_or(Error::Closed)?;

        match self.read_frame_with(half, None).await {
            Ok(bytes) => Ok(Some(codec::decode(&bytes)?)),
            Err(Error::Io(_)) | Err(Error::Closed) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Writes one framed message.
    async fn send(&self, bytes: &[u8]) -> Result<(), Error> {
        let mut writer = self.inner.writer.lock().await;
        let half = writer.as_mut().ok_or(Error::Closed)?;

        half.write_all(bytes)
            .await
            .map_err(|err| Error::Io(err.to_string()))?;
        half.flush().await.map_err(|err| Error::Io(err.to_string()))
    }

    /// Reads messages until the one that finishes the answer to `id`.
    async fn collect(
        &self,
        id: MessageId,
        expected: &'static str,
    ) -> Result<Vec<LdapMessage>, Error> {
        // Only one reader at a time: the socket has one stream, and two tasks reading it
        // would each get half a message.
        let mut reader = self.inner.reader.lock().await;

        // An answer that arrived while another request was reading is already here.
        if let Some(answer) = self.inner.bookkeeping.lock().await.early.remove(&id) {
            return Ok(answer);
        }

        let mut answer = Vec::new();

        loop {
            let half = reader.as_mut().ok_or(Error::Closed)?;
            let bytes = self.read_frame(half).await?;
            let message = codec::decode(&bytes)?;

            if message.message_id == id {
                let finished = is_final(&message.protocol_op);
                answer.push(message);

                if finished {
                    return Ok(answer);
                }

                // Checked per entry rather than after the fact: a search that returns ten
                // million entries passes every per-message limit and still fills the memory
                // of the machine, and finding out at the end means finding out too late.
                if let Some(limit) = self.inner.options.limits.max_entries
                    && answer
                        .iter()
                        .filter(|message| {
                            matches!(message.protocol_op, ProtocolOp::SearchResEntry(_))
                        })
                        .count()
                        > limit
                {
                    return Err(Error::TooManyEntries { limit });
                }
                // A message of the right id that is neither part of a search result nor a
                // final response means the server is not answering what was asked. Reading
                // on would wait for a `{expected}` that is never coming.
                if !is_partial(answer_last(&answer)) {
                    return Err(Error::Unexpected {
                        expected,
                        got: name_of(&answer_last(&answer).protocol_op),
                    });
                }
                continue;
            }

            // Somebody else's answer (or an unsolicited notification, which carries id 0).
            // Kept, not dropped: its request is waiting for exactly this.
            self.inner
                .bookkeeping
                .lock()
                .await
                .early
                .entry(message.message_id)
                .or_default()
                .push(message);
        }
    }

    /// Reads one framed message, refusing an oversized one on its header.
    async fn read_frame(&self, reader: &mut ReadHalf<Transport>) -> Result<Vec<u8>, Error> {
        self.read_frame_with(reader, Some(self.inner.options.timeout))
            .await
    }

    /// Reads one frame, waiting at most `patience` for it - or not at all when `None`.
    ///
    /// A persistent search is idle by nature: nothing happens on it between changes, and that is
    /// the point. Applying the ordinary read deadline there makes an idle connection look broken,
    /// which is exactly what a live run showed - a peer reconnecting every thirty seconds and
    /// retransmitting a refresh nobody had asked for.
    async fn read_frame_with(
        &self,
        reader: &mut ReadHalf<Transport>,
        patience: Option<Duration>,
    ) -> Result<Vec<u8>, Error> {
        let limit = self.inner.options.limits.max_message;
        let mut buffer = Vec::with_capacity(256);

        loop {
            // Enough bytes to decide the length? The header is at most ten octets, so this
            // loop runs a couple of times and never reads the body of a message that is
            // about to be refused.
            if buffer.len() >= 2 {
                match codec::parse_header(&buffer) {
                    Ok(frame) => {
                        if frame.total_len() > limit {
                            return Err(Error::TooLarge {
                                size: frame.total_len(),
                                limit,
                            });
                        }

                        buffer.resize(frame.total_len(), 0);
                        let filled = frame.header_len.min(buffer.len());
                        reader
                            .read_exact(&mut buffer[filled..])
                            .await
                            .map_err(|err| match err.kind() {
                                std::io::ErrorKind::UnexpectedEof => Error::Closed,
                                _ => Error::Io(err.to_string()),
                            })?;
                        return Ok(buffer);
                    }
                    // The header needs more octets than we have; read another.
                    Err(codec::FrameError::Truncated) => {}
                    Err(err) => return Err(Error::Protocol(err.to_string())),
                }
            }

            // One octet at a time for the header: at most ten bytes on a healthy
            // connection, and it means a partial header never consumes the body.
            let mut byte = [0u8; 1];

            let outcome = match patience {
                Some(limit) => {
                    match tokio::time::timeout(limit, reader.read_exact(&mut byte)).await {
                        Ok(result) => result.map(Some),
                        Err(_) => Ok(None),
                    }
                }
                None => reader.read_exact(&mut byte).await.map(Some),
            };

            match outcome {
                Ok(Some(_)) => buffer.push(byte[0]),
                Ok(None) => {
                    return Err(Error::Timeout {
                        waited: patience.unwrap_or_default(),
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(Error::Closed);
                }
                Err(err) => return Err(Error::Io(err.to_string())),
            }
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Channels and halves are dropped with the struct; nothing to send here because an
        // unbind needs an await, which a destructor cannot have. `unbind` is the explicit
        // path, and a server sees a closed socket either way.
    }
}

/// How an operation ended, as the server reported it.
///
/// Own type rather than `rasn_ldap::LdapResult` because the crate is `#[non_exhaustive]`
/// and half its responses repeat the result fields instead of wrapping them — a caller
/// should not have to know which of the two shapes it is holding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub code: ResultCode,
    /// The server's own words: the only place a refusal explains itself.
    pub diagnostic: String,
}

/// The result in an answer, refused when it is not a success.
fn result_of(messages: &[LdapMessage], expected: &'static str) -> Result<Outcome, Error> {
    let (code, diagnostic) = match messages.last().map(|message| &message.protocol_op) {
        Some(ProtocolOp::BindResponse(response)) => {
            (response.result_code, &response.diagnostic_message)
        }
        Some(ProtocolOp::SearchResDone(response)) => {
            (response.0.result_code, &response.0.diagnostic_message)
        }
        Some(ProtocolOp::ExtendedResp(response)) => {
            (response.result_code, &response.diagnostic_message)
        }
        Some(ProtocolOp::ModifyResponse(response)) => {
            (response.0.result_code, &response.0.diagnostic_message)
        }
        Some(ProtocolOp::AddResponse(response)) => {
            (response.0.result_code, &response.0.diagnostic_message)
        }
        Some(ProtocolOp::DelResponse(response)) => {
            (response.0.result_code, &response.0.diagnostic_message)
        }
        Some(ProtocolOp::ModDnResponse(response)) => {
            (response.0.result_code, &response.0.diagnostic_message)
        }
        Some(ProtocolOp::CompareResponse(response)) => {
            (response.0.result_code, &response.0.diagnostic_message)
        }
        Some(other) => {
            return Err(Error::Unexpected {
                expected,
                got: name_of(other),
            });
        }
        None => return Err(Error::Closed),
    };

    let diagnostic = String::from_utf8_lossy(diagnostic.as_ref()).to_string();

    if code == ResultCode::Success
        || code == ResultCode::CompareTrue
        || code == ResultCode::CompareFalse
    {
        // `compareTrue` and `compareFalse` are answers, not refusals: a comparison that
        // came out false is a successful operation.
        return Ok(Outcome { code, diagnostic });
    }

    Err(Error::Server {
        code,
        message: diagnostic,
    })
}

/// The last message of an answer, which is the one being judged.
fn answer_last(answer: &[LdapMessage]) -> &LdapMessage {
    answer.last().expect("an answer that was just pushed to")
}

/// The entry a search result message carries.
///
/// The protocol hands back a list of attribute descriptions and octet strings; everything
/// above this layer wants an `Entry`. Converting here keeps the utilities from each writing
/// their own version of the same six lines.
pub fn entry_of(message: &LdapMessage) -> Option<crate::model::Entry> {
    let ProtocolOp::SearchResEntry(entry) = &message.protocol_op else {
        return None;
    };

    let mut attributes = crate::model::Attributes::new();

    for attribute in entry.attributes.iter() {
        let values: Vec<String> = attribute
            .vals
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_ref()).to_string())
            .collect();

        if values.is_empty() {
            continue;
        }

        attributes = attributes.push(crate::model::Attribute::new(
            attribute.r#type.as_str(),
            values,
        ));
    }

    Some(crate::model::Entry::new(
        entry.object_name.as_str(),
        attributes,
    ))
}

/// The controls an answer carried, if any.
pub fn controls_of(message: &LdapMessage) -> Vec<rasn_ldap::Control> {
    message
        .controls
        .as_ref()
        .map(|controls| controls.to_vec())
        .unwrap_or_default()
}

/// Whether this message is a part of an answer rather than the end of it.
fn is_partial(message: &LdapMessage) -> bool {
    matches!(
        message.protocol_op,
        ProtocolOp::SearchResEntry(_)
            | ProtocolOp::SearchResRef(_)
            | ProtocolOp::IntermediateResponse(_)
    )
}

/// Whether this response ends the answer to its request.
fn is_final(op: &ProtocolOp) -> bool {
    !matches!(
        op,
        ProtocolOp::SearchResEntry(_)
            | ProtocolOp::SearchResRef(_)
            | ProtocolOp::IntermediateResponse(_)
    )
}

fn name_of(op: &ProtocolOp) -> &'static str {
    match op {
        ProtocolOp::BindResponse(_) => "bind response",
        ProtocolOp::SearchResEntry(_) => "search result entry",
        ProtocolOp::SearchResDone(_) => "search result done",
        ProtocolOp::SearchResRef(_) => "search result reference",
        ProtocolOp::ExtendedResp(_) => "extended response",
        ProtocolOp::ModifyResponse(_) => "modify response",
        ProtocolOp::AddResponse(_) => "add response",
        ProtocolOp::DelResponse(_) => "delete response",
        ProtocolOp::ModDnResponse(_) => "modify dn response",
        ProtocolOp::CompareResponse(_) => "compare response",
        ProtocolOp::IntermediateResponse(_) => "intermediate response",
        _ => "request",
    }
}

/// What a URL says about where to connect.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    host: String,
    port: u16,
    tls: bool,
}

impl Target {
    fn parse(url: &str) -> Result<Self, Error> {
        let (tls, rest) = if let Some(rest) = url.strip_prefix("ldaps://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("ldap://") {
            (false, rest)
        } else {
            return Err(Error::Url(url.to_string()));
        };

        // A path or a query after the authority belongs to a URL we do not use: an LDAP URL
        // can carry a base and a filter, and silently ignoring them would run a different
        // search than the one that was written.
        let rest = rest.split('/').next().unwrap_or(rest);
        if rest.is_empty() {
            return Err(Error::Url(url.to_string()));
        }

        let (host, port) = split_authority(rest).ok_or_else(|| Error::Url(url.to_string()))?;

        if host.is_empty() {
            return Err(Error::Url(url.to_string()));
        }

        Ok(Self {
            host,
            port: port.unwrap_or(if tls { 636 } else { 389 }),
            tls,
        })
    }
}

/// Splits `host[:port]`, keeping an IPv6 literal intact.
///
/// The brackets are not decoration: `::1` contains colons, so splitting at the last one
/// would turn `[::1]` into the host `[:` and the port `1]`. Inside a bracket the colons
/// belong to the address; only what follows `]` can be a port.
fn split_authority(rest: &str) -> Option<(String, Option<u16>)> {
    if let Some(closing) = rest.strip_prefix('[') {
        let (address, after) = closing.split_once(']')?;
        if address.is_empty() {
            return None;
        }

        let port = match after {
            "" => None,
            after => Some(after.strip_prefix(':')?.parse::<u16>().ok()?),
        };

        return Some((address.to_string(), port));
    }

    match rest.rsplit_once(':') {
        Some((host, port)) => Some((host.to_string(), Some(port.parse::<u16>().ok()?))),
        None => Some((rest.to_string(), None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_port_follows_the_scheme() {
        assert_eq!(Target::parse("ldap://host").expect("ldap").port, 389);
        assert_eq!(Target::parse("ldaps://host").expect("ldaps").port, 636);
    }

    #[test]
    fn an_explicit_port_wins_over_the_scheme() {
        let target = Target::parse("ldaps://host:1389").expect("url");
        assert_eq!(target.port, 1389);
        assert!(target.tls);
    }

    #[test]
    fn an_ipv6_literal_keeps_its_address_and_loses_its_brackets() {
        // `::1:389` would split at the last colon and give host "::1"; `[::1]` is the
        // spelling that cannot be confused with a port.
        let target = Target::parse("ldap://[::1]:1389").expect("url");
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 1389);

        let target = Target::parse("ldap://[::1]").expect("url");
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 389);
    }

    #[test]
    fn a_scheme_that_is_not_ldap_is_refused() {
        for url in ["http://host", "host:389", "ldap:/host", ""] {
            let err = Target::parse(url).expect_err("must refuse");
            assert!(matches!(err, Error::Url(_)), "{url} gave {err}");
        }
    }

    #[test]
    fn a_port_that_is_not_a_number_is_refused() {
        let err = Target::parse("ldap://host:ldap").expect_err("must refuse");
        assert!(matches!(err, Error::Url(_)), "{err}");
    }

    #[test]
    fn a_path_after_the_authority_is_ignored_explicitly() {
        // The URL may carry a base and a filter; this client takes them as arguments
        // instead, so the authority is all it reads.
        let target = Target::parse("ldap://host:389/dc=example,dc=com??sub").expect("url");
        assert_eq!(target.host, "host");
        assert_eq!(target.port, 389);
    }

    #[test]
    fn the_limits_default_is_a_size_a_directory_can_actually_read() {
        // An LDIF block for one entry is kilobytes; eight megabytes is a generous ceiling
        // for one message and a hard stop long before the machine runs out.
        assert_eq!(Limits::default().max_message, 8 * 1024 * 1024);
        assert_eq!(Limits::default().max_entries, None);
    }
}
