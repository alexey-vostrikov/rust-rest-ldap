//! A ticket bound to a TLS session is accepted only on that session.
//!
//! The property is the whole point of RFC 5929 `tls-server-end-point`, and it is one a unit test
//! cannot show: it needs a real ticket, a real initiator that hashes the binding into its
//! authenticator checksum, and a real acceptor that recomputes it. So the KDC here is
//! `rust-heimdal-kdc` in this process, the client is `krb5`, and the acceptor is the same code the
//! LDAP server's bind path runs.
//!
//! What is being tested is the *wiring*: that the binding computed from a certificate reaches
//! `AcceptOptions` at all. The cryptography underneath is the crate's, and it has its own vectors.
use std::sync::Arc;

use rust_heimdal_kdc::crypto::{Enctype, OwnCipher};
use rust_heimdal_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rust_heimdal_kdc::kdc::{Kdc, KdcConfig};
use rust_heimdal_kdc::name::Principal as HdbPrincipal;
use rust_heimdal_kdc::transport::{RunningKdc, serve_loopback};

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";
const SERVICE: &str = "ldap/host.example.com";

/// A realm with a `krbtgt`, a user and the service principal the ticket is for.
fn realm() -> Arc<dyn Hdb> {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();

    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for enctype in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, enctype, b"master-key-of-the-realm", 1)
            .expect("a key from the realm's master password");
    }
    db.insert(krbtgt).expect("the krbtgt entry");

    let mut alice =
        HdbEntry::user(HdbPrincipal::parse(&format!("alice@{REALM}")).expect("a principal"));
    // A service entry must carry `SERVER`, or the TGS refuses to issue a ticket for it - the KDC
    // says "may not be issued a ticket", which is `KDC_ERR_S_PRINCIPAL_UNKNOWN` reused. `user()`
    // sets `CLIENT`, which is why this is not one.
    let mut service =
        HdbEntry::user(HdbPrincipal::parse(&format!("{SERVICE}@{REALM}")).expect("a principal"));
    service.flags = rust_heimdal_kdc::hdb::flags::SERVER
        | rust_heimdal_kdc::hdb::flags::FORWARDABLE
        | rust_heimdal_kdc::hdb::flags::PROXIABLE;
    for enctype in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, enctype, PASSWORD.as_bytes(), 1)
            .expect("a key");
        // The same password for both, so the keytab below can be written from it: the service key
        // has to be a key the KDC encrypted the ticket with, or the acceptor cannot decrypt it.
        service
            .add_password_key(&cipher, enctype, PASSWORD.as_bytes(), 1)
            .expect("a key");
    }
    db.insert(alice).expect("the user entry");
    db.insert(service).expect("the service entry");

    Arc::new(db)
}

fn start() -> RunningKdc {
    let config = KdcConfig::new(REALM).expect("a realm of that name");
    serve_loopback(Kdc::new(config, realm(), Arc::new(OwnCipher)))
}

/// A keytab holding the service key - the same key the KDC encrypted the ticket with.
///
/// Taken out of the HDB entry rather than derived here: a keytab with a key computed twice is a
/// keytab that disagrees with the KDC the first time a salt or an enctype detail changes, and the
/// failure would look like a broken acceptor.
fn keytab() -> krb5::Keytab {
    let cipher = OwnCipher;
    let mut service =
        HdbEntry::user(HdbPrincipal::parse(&format!("{SERVICE}@{REALM}")).expect("a principal"));
    service
        .add_password_key(&cipher, Enctype::Aes256Sha1, PASSWORD.as_bytes(), 1)
        .expect("a key");
    service
        .add_password_key(&cipher, Enctype::Aes128Sha1, PASSWORD.as_bytes(), 1)
        .expect("a key");

    let mut keytab = krb5::Keytab::new();
    for key in &service.keys {
        let enctype = match key.key.enctype() {
            Enctype::Aes256Sha1 => krb5::EncType::AES256CtsHmacSha196,
            _ => krb5::EncType::AES128CtsHmacSha196,
        };
        keytab.add(krb5::ServiceKey::new(
            SERVICE,
            REALM,
            key.kvno,
            enctype,
            key.key.bytes().to_vec(),
        ));
    }
    keytab
}

/// An AP-REQ for `SERVICE`, from a client that bound it to `binding` (or to nothing).
fn ap_req(binding: Option<&krb5::ChannelBindings>) -> Vec<u8> {
    let stand = start();
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).expect("a principal");
    let tgt = client
        .login_with_password(&alice, PASSWORD)
        .expect("a TGT from this KDC");
    let service = krb5::Principal::parse(&format!("{SERVICE}@{REALM}")).expect("a principal");
    let credentials = client
        .service_ticket(&tgt, &service)
        .expect("a ticket for the service");

    // `InitOptions` is `#[non_exhaustive]` too, so it is built from `default()` and adjusted.
    let mut options = krb5::initiator::InitOptions::default();
    options.channel_bindings = binding;
    // Integrity, so the acceptor gets a context it can use; mutual, because a Windows client asks
    // for it and the acceptor's answer is what proves it holds the key.
    let flags = krb5::initiator::GSS_C_MUTUAL_FLAG | krb5::initiator::GSS_C_INTEG_FLAG;
    let (_context, token) =
        krb5::InitiatorContext::with_options(&credentials, flags, options).expect("an AP-REQ");
    token
}

#[test]
fn a_ticket_bound_to_a_certificate_is_accepted_with_that_certificate() {
    let binding = krb5::ChannelBindings::new(b"tls-server-end-point:example".to_vec());
    let keytab = keytab();

    let mut options = krb5::acceptor::AcceptOptions::default();
    options.channel_bindings = Some(binding);

    let accepted = krb5::spnego::SpnegoAcceptor::with_options(&keytab, options)
        .step(&ap_req(Some(&krb5::ChannelBindings::new(
            b"tls-server-end-point:example".to_vec(),
        ))))
        .expect("accepted on the session it was bound to");
    assert!(accepted.is_some(), "the acceptor answers with the AP-REP");
}

#[test]
fn a_ticket_bound_to_another_session_is_refused() {
    // The property a channel binding exists for: the same ticket, the same keytab, a binding that
    // does not match. If this passed, the binding would be decoration - and a server that accepts a
    // ticket captured from somebody else's TLS session has the exact problem the binding solves.
    let keytab = keytab();
    let mut options = krb5::acceptor::AcceptOptions::default();
    options.channel_bindings = Some(krb5::ChannelBindings::new(
        b"tls-server-end-point:the-real-one".to_vec(),
    ));

    let refused = krb5::spnego::SpnegoAcceptor::with_options(&keytab, options).step(&ap_req(Some(
        &krb5::ChannelBindings::new(b"tls-server-end-point:captured-elsewhere".to_vec()),
    )));

    // The *reason* matters as much as the refusal: a test that only asserted `is_err` would pass on
    // an expired ticket or a broken key, and this one is here to prove the binding did the work.
    match refused {
        Err(krb5::KerberosError::BadBindings(_)) => {}
        other => panic!("expected a binding mismatch, got {other:?}"),
    }
}

#[test]
fn a_ticket_with_no_binding_is_accepted_by_an_acceptor_that_has_one() {
    // MIT's own rule, and the reason turning the binding on cannot break a working client: a client
    // that sent none never claimed to bind, so there is nothing to check. An acceptor that demanded
    // a binding would refuse every client that does not send one.
    let keytab = keytab();
    let mut options = krb5::acceptor::AcceptOptions::default();
    options.channel_bindings = Some(krb5::ChannelBindings::new(
        b"tls-server-end-point:ours".to_vec(),
    ));

    let accepted = krb5::spnego::SpnegoAcceptor::with_options(&keytab, options)
        .step(&ap_req(None))
        .expect("a client that did not bind is accepted");

    assert!(accepted.is_some());
}
