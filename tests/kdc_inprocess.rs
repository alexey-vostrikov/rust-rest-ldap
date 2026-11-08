//! The in-process KDC, used the way a directory server would use it.
//!
//! `rust-heimdal-kdc` is a library, not a daemon: sockets, clocks and storage are the caller's. That
//! is what makes it usable here at all - a test that needed a running `krb5kdc` and a keytab on the
//! host would be a test that skips on every machine that has neither.
//!
//! The client is `krb5`, which is also what the LDAP server's accept path is built on. That is
//! deliberate and it is the only arrangement worth testing: two implementations from different
//! authors, one issuing a ticket and the other accepting it. A KDC that only agrees with itself
//! agrees with nothing.
use std::sync::Arc;

use rust_heimdal_kdc::crypto::{Enctype, OwnCipher};
use rust_heimdal_kdc::hdb::{HdbEntry, MemoryHdb};
use rust_heimdal_kdc::kdc::KdcConfig;
use rust_heimdal_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";
const PASSWORD: &str = "correct horse battery staple";

/// A realm with `krbtgt/REALM` and one user, both keyed with `PASSWORD`.
fn realm() -> Arc<dyn rust_heimdal_kdc::hdb::Hdb> {
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
        HdbEntry::user(Principal::parse(&format!("alice@{REALM}")).expect("a well-formed principal"));
    for enctype in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        alice
            .add_password_key(&cipher, enctype, PASSWORD.as_bytes(), 1)
            .expect("a key from the user's password");
    }
    db.insert(alice).expect("the user entry");

    Arc::new(db)
}

/// The KDC on a loopback port, answering until the test ends.
fn start() -> rust_heimdal_kdc::transport::RunningKdc {
    let config = KdcConfig::new(REALM).expect("a realm of that name");
    let kdc = rust_heimdal_kdc::kdc::Kdc::new(config, realm(), Arc::new(OwnCipher));
    rust_heimdal_kdc::transport::serve_loopback(kdc)
}

#[test]
fn a_client_logs_in_against_the_in_process_kdc() {
    // The whole point of the dependency: this test issues a ticket with one implementation and
    // accepts it with another, in one process, with no daemon and no keytab file on the host.
    let stand = start();
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).expect("a well-formed principal");

    let credentials = client
        .login_with_password(&alice, PASSWORD)
        .expect("kinit against this KDC");

    assert_eq!(
        credentials.server.to_string(),
        format!("krbtgt/{REALM}@{REALM}"),
        "a TGT is a ticket for krbtgt, which is what makes it one"
    );
    assert_eq!(credentials.client.to_string(), format!("alice@{REALM}"));
}

#[test]
fn a_wrong_password_gets_no_ticket() {
    // The negative case, because an acceptor that refuses nothing passes any positive test: a KDC
    // that issued a ticket for the wrong password would make every assertion above meaningless.
    let stand = start();
    let client = krb5::KdcClient::new(REALM, [stand.addr().as_str()]);
    let alice = krb5::Principal::parse(&format!("alice@{REALM}")).expect("a well-formed principal");

    assert!(
        client
            .login_with_password(&alice, "not the password")
            .is_err(),
        "a ticket was issued for the wrong password"
    );
}
