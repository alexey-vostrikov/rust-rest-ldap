//! The server's first SPNEGO token: a `NegTokenInit` that names the mechanisms, built by hand.
//!
//! # Why the server speaks first
//!
//! SPNEGO (RFC 4178 §3.1) has the initiator speak first, and that is what every client that carries
//! a ticket straight away does - `ldapsearch -Y GSSAPI`, a browser, our own acceptor's usual input.
//! Samba's `ads_sasl_bind` does not: it sends an LDAP SASL bind naming `GSS-SPNEGO` with **no**
//! token and waits for the server to say which mechanisms it has (`source3/libads/sasl.c`, then
//! `gensec_spnego`'s `SPNEGO_SERVER_START`). A domain controller answers exactly that, so a server
//! that only accepts a client-first token never gets as far as reading one: the bind is refused
//! before the client sends anything.
//!
//! # What the bytes are
//!
//! The GSS-API framing of a SPNEGO offer (RFC 4178 §4.2.1), with both Kerberos OIDs and no token:
//!
//! ```text
//! 60 26                                     [APPLICATION 0] InitialContextToken
//!    06 06 2b 06 01 05 05 02                id-spnego, 1.3.6.1.5.5.2
//!    a0 1c                                  [0] negTokenInit
//!       30 1a                              SEQUENCE
//!          a0 18                            [0] mechTypes
//!             30 16                          SEQUENCE OF MechType
//!                06 09 2a 86 48 86 f7 12 01 02 02      krb5, 1.2.840.113554.1.2.2
//!                06 09 2a 86 48 82 f7 12 01 02 02      MS krb5, 1.2.840.48018.1.2.2
//! ```
//!
//! Both OIDs because Windows lists its own misspelling first and MIT treats the two as one thing
//! (see `krb5::spnego`); offering only the standard one works with MIT and is a needless argument
//! with a Windows client.
//!
//! No `mechToken` and no `mechListMIC`: this server has nothing to say before the client's ticket,
//! and a MIC over a mechanism list nobody has negotiated yet would be a value to fake. Samba's own
//! server puts the string `not_defined_in_RFC4178@please_ignore` in that field, which its client
//! reads as "the server has no opinion"; an absent field reads the same way everywhere.
//!
//! # Why not the crate
//!
//! `krb5::spnego` speaks both halves of a client-first negotiation, and neither of them is this
//! message: its acceptor starts by parsing a `NegTokenInit`, and a client that was polite enough to
//! send one is a client Samba's problem never reaches us with. The encoder there is private, so the
//! bytes are written here, once, against the diagram above.

/// Kerberos 5, DER: `1.2.840.113554.1.2.2`.
const KRB5: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];

/// Microsoft's Kerberos 5, DER: `1.2.840.48018.1.2.2` - the same mechanism under an OID it got
/// wrong, which Windows offers first.
const MS_KRB5: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
];

/// The SPNEGO mechanism OID under GSS-API framing, `1.3.6.1.5.5.2`.
const SPNEGO: [u8; 8] = [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

const SEQUENCE: u8 = 0x30;

/// A length in DER's short or long form (X.690 §8.1.3).
fn length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|&&byte| byte == 0).count();
    let mut out = vec![0x80 | (bytes.len() - skip) as u8];
    out.extend_from_slice(&bytes[skip..]);
    out
}

/// One tag-length-value.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    out.extend_from_slice(&length(content.len()));
    out.extend_from_slice(content);
    out
}

/// `[n]` context-specific, constructed - the `a0`/`a1` that opens every SPNEGO field.
fn context(n: u8) -> u8 {
    0xa0 | n
}

/// The `NegTokenInit` this server answers an empty `GSS-SPNEGO` bind with.
pub fn offer() -> Vec<u8> {
    let mut mech_types = KRB5.to_vec();
    mech_types.extend_from_slice(&MS_KRB5);
    let mech_list = tlv(SEQUENCE, &mech_types);
    // `[0] mechTypes` inside the NegTokenInit SEQUENCE. No reqFlags ([1]), no mechToken ([2]), no
    // mechListMIC ([3]) - see the module note.
    let init = tlv(SEQUENCE, &tlv(context(0), &mech_list));

    let mut body = SPNEGO.to_vec();
    body.extend_from_slice(&tlv(context(0), &init));
    tlv(0x60, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_offer_is_the_bytes_the_diagram_names() {
        // Written out rather than recomputed: a test that rebuilds the encoder with the encoder
        // proves the encoder agrees with itself. These are the octets a reader of RFC 4178 §4.2.1
        // can check by hand, and the ones a capture of this server shows on the wire.
        let expected: Vec<u8> = vec![
            0x60, 0x26, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x1c, 0x30, 0x1a,
            0xa0, 0x18, 0x30, 0x16, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02,
            0x02, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
        ];
        assert_eq!(offer(), expected);
    }

    #[test]
    fn the_offer_names_kerberos_and_nothing_else() {
        // NTLMSSP is the one other mechanism a Samba client will reach for, and offering it would
        // promise a conversation this server refuses two rounds later with a message about a
        // token. Its OID must not appear here: `1.3.6.1.4.1.311.2.2.10`.
        let ntlm = [
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
        ];
        let offer = offer();
        assert!(
            !offer.windows(ntlm.len()).any(|window| window == ntlm),
            "the offer names NTLM"
        );
    }

    #[test]
    fn a_long_length_keeps_the_der_form() {
        // The offer is 40 octets today and does not use the long form; the encoder is shared, and a
        // length of 200 encoded as one octet would be a parser's problem in a later token rather
        // than here.
        assert_eq!(length(39), vec![39]);
        assert_eq!(length(200), vec![0x81, 200]);
        assert_eq!(length(300), vec![0x82, 0x01, 0x2c]);
    }
}
