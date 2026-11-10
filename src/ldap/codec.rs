//! BER framing for LDAP messages.
//!
//! An LDAP message is a BER `SEQUENCE`, so a stream carries a sequence of
//! tag/length/content blocks. `rasn` decodes one value from a complete byte
//! slice, therefore the framing (how many bytes belong to the next message) is
//! done here, and only then the bytes are handed to `rasn`.
//!
//! gorestldap took framing from its `ldapserver` library; doing it explicitly
//! keeps the read loop under our control and testable without a socket.

use rasn_ldap::LdapMessage;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Tag of a BER `SEQUENCE`, the only top-level tag an LDAP message uses.
const SEQUENCE_TAG: u8 = 0x30;
/// Lengths above this are refused instead of being allocated.
pub const MAX_FRAME_LEN: usize = 1 << 20;
/// Long-form lengths longer than this are refused (RFC 4511 has no use for them).
const MAX_LENGTH_OCTETS: u8 = 4;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("message is not a BER sequence (tag 0x{0:02x})")]
    NotSequence(u8),
    #[error("indefinite BER length is not allowed in LDAP")]
    IndefiniteLength,
    #[error("BER length uses {0} octets, more than {MAX_LENGTH_OCTETS} allowed")]
    LengthTooLong(u8),
    #[error("message length {0} exceeds limit {MAX_FRAME_LEN}")]
    TooLong(usize),
    #[error("stream ended inside a message")]
    Truncated,
    #[error(
        "the client is sending SASL-wrapped data (RFC 4121 wrap, token id 0x0504): this server \
         negotiates the \"none\" security layer only, so it cannot unwrap anything. A libsasl \
         client asks for none with `-O maxssf=0`; Samba's `net ads join` cannot - libnet_connect_ads \
         asks for ADS_SASL_SEAL in the source, whatever `client ldap sasl wrapping` says"
    )]
    SaslWrapped,
}

#[derive(Debug, Error)]
pub enum CodecError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("error reading from client: {0}")]
    Read(std::io::Error),
    #[error("error writing to client: {0}")]
    Write(std::io::Error),
    /// The SASL security layer refused a message: it could not seal ours, could not open theirs,
    /// or theirs arrived out of order.
    ///
    /// A separate variant rather than a `Frame` one because the frame was well formed: what failed
    /// is the key, the sequence number or the peer's good faith, and the operator has to see which.
    #[error("SASL security layer: {0}")]
    Wrap(String),
    #[error("error decoding LDAP message: {0}")]
    Decode(String),
    #[error("error encoding LDAP message: {0}")]
    Encode(String),
}

/// Where the message header ends and how long the whole message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSize {
    /// Tag and length octets.
    pub header_len: usize,
    /// Length of the content octets.
    pub content_len: usize,
}

impl FrameSize {
    pub fn total_len(&self) -> usize {
        self.header_len + self.content_len
    }
}

/// Parses the tag and length octets at the start of `header`.
///
/// `header` must hold at least two bytes; callers loop until the parse either
/// succeeds or reports how many bytes are still missing.
pub fn parse_header(header: &[u8]) -> Result<FrameSize, FrameError> {
    let tag = *header.first().ok_or(FrameError::Truncated)?;
    if tag != SEQUENCE_TAG {
        return Err(FrameError::NotSequence(tag));
    }
    let first_length_byte = *header.get(1).ok_or(FrameError::Truncated)?;

    if first_length_byte == 0x80 {
        return Err(FrameError::IndefiniteLength);
    }

    if first_length_byte < 0x80 {
        let content_len = first_length_byte as usize;
        let frame = FrameSize {
            header_len: 2,
            content_len,
        };
        check_limit(frame)?;
        return Ok(frame);
    }

    let octets = first_length_byte & 0x7f;
    if octets > MAX_LENGTH_OCTETS {
        return Err(FrameError::LengthTooLong(octets));
    }
    let octets = octets as usize;
    let length_bytes = header.get(2..2 + octets).ok_or(FrameError::Truncated)?;
    let content_len = length_bytes
        .iter()
        .fold(0usize, |acc, byte| (acc << 8) | *byte as usize);

    let frame = FrameSize {
        header_len: 2 + octets,
        content_len,
    };
    check_limit(frame)?;
    Ok(frame)
}

fn check_limit(frame: FrameSize) -> Result<(), FrameError> {
    if frame.total_len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLong(frame.total_len()));
    }
    Ok(())
}

/// Reads one complete LDAP message (framing bytes included).
pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, CodecError> {
    let mut head = [0u8; 2];
    read_exact_or_eof(reader, &mut head).await?;

    if head[0] != SEQUENCE_TAG {
        // Not LDAP as this server speaks it - but one shape is worth naming rather than closing on
        // silence. A SASL security layer puts a four-octet big-endian length in front of an
        // RFC 4121 token, so the first message of a wrapped session starts with `00 00 00 NN 05 04`
        // and reads here as tag 0x00. Samba's `net ads join` does exactly this whatever its
        // configuration says, and the client then waits for an answer that never comes, reporting
        // a timeout much later and about something else entirely.
        if head[0] == 0x00 {
            let mut probe = [0u8; 4];
            if reader.read_exact(&mut probe).await.is_ok() && probe[2] == 0x05 && probe[3] == 0x04 {
                return Err(CodecError::Frame(FrameError::SaslWrapped));
            }
        }
        return Err(CodecError::Frame(FrameError::NotSequence(head[0])));
    }

    let mut message = Vec::with_capacity(2 + head[1] as usize);
    message.extend_from_slice(&head);

    // Long-form length: the octets are read before the header can be parsed.
    if head[1] & 0x80 != 0 {
        if head[1] == 0x80 {
            return Err(CodecError::Frame(FrameError::IndefiniteLength));
        }
        let octets = head[1] & 0x7f;
        if octets > MAX_LENGTH_OCTETS {
            return Err(CodecError::Frame(FrameError::LengthTooLong(octets)));
        }
        let mut length_bytes = vec![0u8; octets as usize];
        reader
            .read_exact(&mut length_bytes)
            .await
            .map_err(|_| CodecError::Frame(FrameError::Truncated))?;
        message.extend_from_slice(&length_bytes);
    }

    let frame = parse_header(&message).map_err(CodecError::Frame)?;

    let mut content = vec![0u8; frame.content_len];
    reader
        .read_exact(&mut content)
        .await
        .map_err(|_| CodecError::Frame(FrameError::Truncated))?;
    message.extend_from_slice(&content);

    Ok(message)
}

async fn read_exact_or_eof<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<(), CodecError> {
    match reader.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(CodecError::Frame(FrameError::Truncated))
        }
        Err(err) => Err(CodecError::Read(err)),
    }
}

/// Decodes a framed message.
pub fn decode(bytes: &[u8]) -> Result<LdapMessage, CodecError> {
    rasn::ber::decode(bytes).map_err(|err| CodecError::Decode(err.to_string()))
}

/// Reads one LDAP message, sealed or plain, as the session's security layer requires.
///
/// RFC 4422 §3.2: in a layer that protects, each buffer starts with a four-octet big-endian length.
/// So the decision cannot be made from the first byte - a sealed frame's first four octets are a
/// length, and 0x30 is a length of 48 - and it comes from the session instead.
pub async fn read_message_with<R: AsyncRead + Unpin>(
    reader: &mut R,
    wrap: Option<&mut super::sasl_bind::Wrap>,
) -> Result<Vec<u8>, CodecError> {
    let Some(wrap) = wrap.filter(|wrap| wrap.is_active()) else {
        return read_message(reader).await;
    };

    let mut head = [0u8; 4];
    read_exact_or_eof(reader, &mut head).await?;
    let len = u32::from_be_bytes(head) as usize;
    // Zero is not a message and a buffer past the frame limit is not one either; both are refused
    // before the allocation, because the length is the peer's.
    if len == 0 || len > MAX_FRAME_LEN {
        return Err(CodecError::Frame(FrameError::TooLong(len)));
    }
    let mut token = vec![0u8; len];
    reader
        .read_exact(&mut token)
        .await
        .map_err(|_| CodecError::Frame(FrameError::Truncated))?;

    wrap.open(&token).map_err(CodecError::Wrap)
}

/// Writes one LDAP message, sealing it when the session's layer is in force.
///
/// The response that announces a layer is the one exception, and it is not a special case here: the
/// layer is installed as pending and [`super::sasl_bind::Wrap::activate`] runs when such a response
/// is written. A client starts sealing only after it has read that answer, and a server that sealed
/// it would be sending ciphertext to a peer still reading BER.
pub async fn write_message_with<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &LdapMessage,
    wrap: Option<&mut super::sasl_bind::Wrap>,
) -> Result<(), CodecError> {
    let bytes = encode(message)?;

    match wrap {
        Some(wrap) if wrap.is_active() => {
            let sealed = wrap.seal(&bytes).map_err(CodecError::Wrap)?;
            writer.write_all(&sealed).await.map_err(CodecError::Write)
        }
        Some(wrap) => {
            wrap.activate();
            writer.write_all(&bytes).await.map_err(CodecError::Write)
        }
        None => writer.write_all(&bytes).await.map_err(CodecError::Write),
    }
}

/// Encodes a message for the wire.
pub fn encode(message: &LdapMessage) -> Result<Vec<u8>, CodecError> {
    rasn::ber::encode(message).map_err(|err| CodecError::Encode(err.to_string()))
}

/// Writes one message.
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &LdapMessage,
) -> Result<(), CodecError> {
    let bytes = encode(message)?;
    writer.write_all(&bytes).await.map_err(CodecError::Write)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BindRequest: messageID 1, version 3, name "admin", simple "secret".
    const BIND_REQUEST: &[u8] = &[
        0x30, 0x17, 0x02, 0x01, 0x01, 0x60, 0x12, 0x02, 0x01, 0x03, 0x04, 0x05, b'a', b'd', b'm',
        b'i', b'n', 0x80, 0x06, b's', b'e', b'c', b'r', b'e', b't',
    ];

    #[test]
    fn short_form_length_is_parsed() {
        assert_eq!(
            parse_header(&[0x30, 0x17]),
            Ok(FrameSize {
                header_len: 2,
                content_len: 23
            })
        );
    }

    #[test]
    fn one_octet_long_form_length_is_parsed() {
        assert_eq!(
            parse_header(&[0x30, 0x81, 0x80]),
            Ok(FrameSize {
                header_len: 3,
                content_len: 128
            })
        );
    }

    #[test]
    fn multi_octet_long_form_length_is_parsed() {
        assert_eq!(
            parse_header(&[0x30, 0x82, 0x01, 0x00]),
            Ok(FrameSize {
                header_len: 4,
                content_len: 256
            })
        );
    }

    #[test]
    fn not_a_sequence_is_rejected() {
        assert_eq!(
            parse_header(&[0x31, 0x00]),
            Err(FrameError::NotSequence(0x31))
        );
        assert_eq!(
            parse_header(&[0x02, 0x01, 0x01]),
            Err(FrameError::NotSequence(0x02))
        );
    }

    #[test]
    fn indefinite_length_is_rejected() {
        assert_eq!(
            parse_header(&[0x30, 0x80]),
            Err(FrameError::IndefiniteLength)
        );
    }

    #[test]
    fn too_many_length_octets_are_rejected() {
        assert_eq!(
            parse_header(&[0x30, 0x85, 1, 2, 3, 4, 5]),
            Err(FrameError::LengthTooLong(5))
        );
    }

    #[test]
    fn message_over_the_limit_is_rejected() {
        assert_eq!(
            parse_header(&[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]),
            Err(FrameError::TooLong(2_147_483_653))
        );
    }

    #[test]
    fn incomplete_header_is_reported_as_truncated() {
        assert_eq!(parse_header(&[]), Err(FrameError::Truncated));
        assert_eq!(parse_header(&[0x30]), Err(FrameError::Truncated));
        assert_eq!(
            parse_header(&[0x30, 0x82, 0x01]),
            Err(FrameError::Truncated)
        );
    }

    #[test]
    fn decodes_a_bind_request() {
        let message = decode(BIND_REQUEST).expect("decode");

        assert_eq!(message.message_id, 1);
        match &message.protocol_op {
            rasn_ldap::ProtocolOp::BindRequest(request) => {
                assert_eq!(request.version, 3);
                assert_eq!(request.name.0, "admin");
                match &request.authentication {
                    rasn_ldap::AuthenticationChoice::Simple(password) => {
                        assert_eq!(password.as_ref(), b"secret");
                    }
                    other => panic!("unexpected authentication: {other:?}"),
                }
            }
            other => panic!("unexpected operation: {other:?}"),
        }
    }

    #[test]
    fn decode_of_garbage_reports_a_decode_error() {
        let err = decode(&[0x30, 0x03, 0x02, 0x01, 0x01]).expect_err("must fail");

        assert!(
            matches!(err, CodecError::Decode(_)),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn reads_exactly_one_message_from_the_stream() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(BIND_REQUEST).await.expect("write");
        client.write_all(BIND_REQUEST).await.expect("write");

        let first = read_message(&mut server).await.expect("first message");
        let second = read_message(&mut server).await.expect("second message");

        assert_eq!(first, BIND_REQUEST);
        assert_eq!(second, BIND_REQUEST);
    }

    #[tokio::test]
    async fn reads_a_message_with_long_form_length() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let content = vec![0u8; 200];
        let mut message = vec![0x30, 0x81, 200];
        message.extend_from_slice(&content);
        client.write_all(&message).await.expect("write");

        let read = read_message(&mut server).await.expect("message");

        assert_eq!(read, message);
    }

    #[tokio::test]
    async fn truncated_message_is_reported() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&BIND_REQUEST[..10]).await.expect("write");
        drop(client);

        let err = read_message(&mut server).await.expect_err("must fail");

        assert!(
            matches!(err, CodecError::Frame(FrameError::Truncated)),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn empty_stream_is_reported_as_truncated() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);

        let err = read_message(&mut server).await.expect_err("must fail");

        assert!(
            matches!(err, CodecError::Frame(FrameError::Truncated)),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn sasl_wrapped_data_is_named_and_not_just_closed_on_tag_zero() {
        // The octets Samba sends after a sealed GSS-SPNEGO bind: a four-octet length, then the
        // RFC 4121 wrap token id `05 04`. Read as LDAP it is "tag 0x00", and the client waits for
        // an answer that never comes - which is how a missing security layer looks like a timeout.
        let wrapped = [
            0x00, 0x00, 0x00, 0xb7, 0x05, 0x04, 0x02, 0xff, 0x00, 0x00, 0x00, 0x1c,
        ];
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&wrapped).await.expect("write");

        let err = read_message(&mut server).await.expect_err("not LDAP");

        assert!(
            matches!(err, CodecError::Frame(FrameError::SaslWrapped)),
            "unexpected error: {err:?}"
        );
        // The message names what the operator has to do, rather than the octet it tripped on.
        assert!(err.to_string().contains("maxssf=0"), "{err}");
    }

    #[tokio::test]
    async fn a_zero_tag_that_is_not_a_wrap_token_stays_a_framing_error() {
        // The probe must not turn every malformed stream into a claim about SASL: only an RFC 4121
        // Wrap token at the offset the layer puts it is named.
        let other = [0x00, 0x00, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04];
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&other).await.expect("write");

        let err = read_message(&mut server).await.expect_err("must fail");

        assert!(
            matches!(err, CodecError::Frame(FrameError::NotSequence(0))),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn written_message_can_be_read_back_and_decode_equals_the_original() {
        let original = decode(BIND_REQUEST).expect("decode");
        let (mut client, mut server) = tokio::io::duplex(1024);

        write_message(&mut client, &original).await.expect("write");
        let bytes = read_message(&mut server).await.expect("read");

        assert_eq!(decode(&bytes).expect("decode"), original);
    }
}
