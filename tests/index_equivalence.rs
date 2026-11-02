//! The indexed path must answer exactly like the full scan.
//!
//! Every filter here is run twice against the same data: once with indexes built and
//! once without. The two DN lists must be identical, in the same order. This is the
//! test that makes an index safe to ship: an index may only decide what to *skip
//! checking*, never what to return.

use rasn::types::OctetString;
use rasn_ldap::{
    AttributeDescription, AttributeValueAssertion, Filter, LdapMessage, ProtocolOp, SearchRequest,
    SearchRequestDerefAliases, SearchRequestScope,
};
use rust_rest_ldap::directory::Directory;
use rust_rest_ldap::index::IndexConfig;
use rust_rest_ldap::ldap::search::handle_search;
use rust_rest_ldap::ldap::session::Session;
use rust_rest_ldap::model::{Attribute, Attributes, Entry};
use rust_rest_ldap::security::Security;

const BASE: &str = "dc=example,dc=com";

/// A directory big enough that a wrong candidate set shows up as missing entries.
fn entries(count: usize) -> Vec<Entry> {
    let mut entries = Vec::new();

    for index in 0..count {
        let name = format!("user{index:03}");
        let mut attributes = Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec![
                    "top".to_string(),
                    "person".to_string(),
                    "inetOrgPerson".to_string(),
                ],
            ))
            .push(Attribute::single("cn", &name))
            .push(Attribute::single("sn", &format!("Surname{index:03}")))
            .push(Attribute::single("uid", &name))
            // Numbers of *different width* on purpose. A fixed-width column orders the same
            // way as text, so an index that keyed numbers as strings would pass every test
            // written against it; `13` sorts before `9` as text and after it as a number.
            .push(Attribute::single("uidNumber", &format!("{}", index * 37)));

        // Only every third entry has mail, so `presence` and `equality` disagree.
        if index % 3 == 0 {
            attributes = attributes.push(Attribute::single("mail", &format!("{name}@example.com")));
        }
        if index % 5 == 0 {
            attributes = attributes.push(
                Attribute::new("userPassword", vec![format!("{{SSHA}}{index}")]).case_sensitive(),
            );
        }
        if index % 7 == 0 {
            attributes = attributes.push(Attribute::single("telephoneNumber", "+7 495 000-00-00"));
        }

        entries.push(Entry::new(format!("cn={name},ou=users,{BASE}"), attributes));
    }

    for index in 0..count / 10 {
        let name = format!("group{index:02}");
        let mut attributes = Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "posixGroup".to_string()],
            ))
            .push(Attribute::single("cn", &name))
            .push(Attribute::single("gidNumber", &format!("{}", 2000 + index)));

        if index % 2 == 0 {
            attributes = attributes.push(Attribute::new(
                "memberUid",
                vec![format!("user{index:03}"), "user001".to_string()],
            ));
        }

        entries.push(Entry::new(
            format!("cn={name},ou=groups,{BASE}"),
            attributes,
        ));
    }

    entries
}

fn directory(indexed: bool) -> Directory {
    let directory = Directory::from_entries(BASE, "users", "groups", entries(300));
    if !indexed {
        return directory;
    }

    let config = IndexConfig {
        default: vec!["pres".to_string()],
        attributes: [
            ("cn", vec!["eq", "pres", "sub", "ord"]),
            ("objectClass", vec!["eq", "pres"]),
            ("mail", vec!["eq", "pres", "sub"]),
            ("uid", vec!["eq", "sub"]),
            ("userPassword", vec!["eq"]),
            ("gidNumber", vec!["eq", "ord"]),
            ("sn", vec!["eq", "sub", "ord"]),
            ("uidNumber", vec!["eq", "ord"]),
        ]
        .into_iter()
        .map(|(attribute, kinds)| {
            (
                attribute.to_string(),
                kinds.into_iter().map(str::to_string).collect(),
            )
        })
        .collect(),
    };

    directory.with_indexes(&config).expect("indexes")
}

fn present(name: &str) -> Filter {
    Filter::Present(AttributeDescription::from(name))
}

fn equality(name: &str, value: &str) -> Filter {
    Filter::EqualityMatch(AttributeValueAssertion::new(
        AttributeDescription::from(name),
        OctetString::from(value.as_bytes()),
    ))
}

fn substring(name: &str, part: &str) -> Filter {
    Filter::Substrings(rasn_ldap::SubstringFilter::new(
        AttributeDescription::from(name),
        vec![rasn_ldap::SubstringChoice::Initial(OctetString::from(
            part.as_bytes(),
        ))],
    ))
}

/// `(name=*part*)`, the interior form.
fn substring_any(name: &str, part: &str) -> Filter {
    Filter::Substrings(rasn_ldap::SubstringFilter::new(
        AttributeDescription::from(name),
        vec![rasn_ldap::SubstringChoice::Any(OctetString::from(
            part.as_bytes(),
        ))],
    ))
}

/// `(name=*part)`, the final form.
fn substring_final(name: &str, part: &str) -> Filter {
    Filter::Substrings(rasn_ldap::SubstringFilter::new(
        AttributeDescription::from(name),
        vec![rasn_ldap::SubstringChoice::Final(OctetString::from(
            part.as_bytes(),
        ))],
    ))
}

fn less(name: &str, value: &str) -> Filter {
    Filter::LessOrEqual(AttributeValueAssertion::new(
        AttributeDescription::from(name),
        OctetString::from(value.as_bytes()),
    ))
}

fn greater(name: &str, value: &str) -> Filter {
    Filter::GreaterOrEqual(AttributeValueAssertion::new(
        AttributeDescription::from(name),
        OctetString::from(value.as_bytes()),
    ))
}

fn search(directory: &Directory, filter: Filter) -> Vec<String> {
    let request = SearchRequest::new(
        rasn_ldap::LdapDn::from(BASE),
        SearchRequestScope::WholeSubtree,
        SearchRequestDerefAliases::NeverDerefAliases,
        0,
        0,
        false,
        filter,
        vec![rasn_ldap::LdapString::from("dn")],
    );

    let mut session = Session::new();
    session.set_identity(rust_rest_ldap::ldap::session::Identity::new(
        "cn=admin,ou=users,dc=example,dc=com",
        true,
    ));

    let messages: Vec<LdapMessage> =
        handle_search(&session, directory, 1, &request, None, &Security::default());

    messages
        .iter()
        .filter_map(|message| match &message.protocol_op {
            ProtocolOp::SearchResEntry(entry) => Some(entry.object_name.0.clone()),
            _ => None,
        })
        .collect()
}

/// Runs `filter` against the indexed and the plain directory and compares the answers.
///
/// Also asserts the filter matched something: a test where both sides return nothing
/// would pass while proving nothing.
fn assert_same(filter: &Filter, label: &str) {
    let plain = search(&directory(false), filter.clone());
    let indexed = search(&directory(true), filter.clone());

    assert_eq!(
        indexed, plain,
        "{label}: the indexed answer must match the scan exactly"
    );
    assert!(
        !plain.is_empty(),
        "{label}: the filter must match something"
    );
}

/// Compares the answers without requiring a match, for filters that answer with an error
/// or with nothing on purpose.
fn assert_same_answer(filter: &Filter, label: &str) {
    assert_eq!(
        search(&directory(true), filter.clone()),
        search(&directory(false), filter.clone()),
        "{label}: the indexed answer must match the scan exactly"
    );
}

#[test]
fn presence_filters_agree() {
    assert_same(&present("mail"), "(mail=*)");
    assert_same(&present("userPassword"), "(userPassword=*)");
    assert_same(&present("telephoneNumber"), "(telephoneNumber=*)");
    assert_same(&present("memberUid"), "(memberUid=*)");
    assert_same(&present("objectClass"), "(objectClass=*)");
}

#[test]
fn equality_filters_agree() {
    assert_same(&equality("cn", "user007"), "(cn=user007)");
    assert_same(&equality("uid", "user042"), "(uid=user042)");
    assert_same(
        &equality("mail", "user021@example.com"),
        "(mail=user021@example.com)",
    );
    assert_same(&equality("sn", "Surname123"), "(sn=Surname123)");
    assert_same(
        &equality("objectClass", "posixGroup"),
        "(objectClass=posixGroup)",
    );
    assert_same(&equality("gidNumber", "2003"), "(gidNumber=2003)");
}

#[test]
fn equality_on_a_case_sensitive_attribute_agrees() {
    assert_same(
        &equality("userPassword", "{SSHA}35"),
        "(userPassword={SSHA}35)",
    );
    // Wrong case matches neither path: the filter is exact and the index is exact.
    let plain = search(&directory(false), equality("userPassword", "{ssha}35"));
    let indexed = search(&directory(true), equality("userPassword", "{ssha}35"));
    assert_eq!(indexed, plain);
    assert!(plain.is_empty(), "a case-sensitive match must not fold");
}

#[test]
fn case_folded_equality_agrees() {
    assert_same(&equality("cn", "USER007"), "(cn=USER007)");
    assert_same(
        &equality("objectClass", "POSIXGROUP"),
        "(objectClass=POSIXGROUP)",
    );
}

#[test]
fn conjunctions_agree() {
    assert_same(
        &Filter::And(rasn::types::SetOf::from_vec(vec![
            present("mail"),
            equality("cn", "user009"),
        ])),
        "(&(mail=*)(cn=user009))",
    );
    assert_same(
        &Filter::And(rasn::types::SetOf::from_vec(vec![
            equality("objectClass", "inetOrgPerson"),
            present("telephoneNumber"),
            present("mail"),
        ])),
        "(&(objectClass=inetOrgPerson)(telephoneNumber=*)(mail=*))",
    );
}

#[test]
fn disjunctions_agree() {
    assert_same(
        &Filter::Or(rasn::types::SetOf::from_vec(vec![
            equality("cn", "user001"),
            equality("cn", "user002"),
        ])),
        "(|(cn=user001)(cn=user002))",
    );
    assert_same(
        &Filter::Or(rasn::types::SetOf::from_vec(vec![
            present("memberUid"),
            equality("objectClass", "organizationalUnit"),
        ])),
        "(|(memberUid=*)(objectClass=organizationalUnit))",
    );
}

#[test]
fn negations_agree() {
    assert_same(
        &Filter::Not(Box::new(equality("cn", "user001"))),
        "(!(cn=user001))",
    );
    assert_same(&Filter::Not(Box::new(present("mail"))), "(!(mail=*))");
}

#[test]
fn substring_filters_agree() {
    // The trigram index narrows all three shapes, and the answer must still be the scan's:
    // an index may only add candidates, and the filter decides.
    assert_same(&substring("cn", "user1"), "(cn=user1*)");
    assert_same(&substring("cn", "user"), "(cn=user*)");
    assert_same(&substring_any("cn", "ser01"), "(cn=*ser01*)");
    assert_same(&substring_any("cn", "er1"), "(cn=*er1*)");
    assert_same(&substring_final("cn", "07"), "(cn=*07)");
    assert_same(
        &substring_final("mail", "@example.com"),
        "(mail=*@example.com)",
    );
    assert_same(&substring_any("sn", "name12"), "(sn=*name12*)");
    assert_same(&substring_any("uid", "user04"), "(uid=*user04*)");
}

#[test]
fn substring_filters_that_cannot_be_indexed_agree_too() {
    // Two characters make no trigram: the index stands aside and the scan answers.
    assert_same(&substring("cn", "us"), "(cn=us*)");
    assert_same(&substring_any("cn", "7"), "(cn=*7*)");
    // A pattern nobody can match: both paths must be empty, and the test says so.
    let plain = search(&directory(false), substring_any("cn", "zzzz"));
    let indexed = search(&directory(true), substring_any("cn", "zzzz"));
    assert_eq!(indexed, plain);
    assert!(plain.is_empty());
}

#[test]
fn ordering_filters_agree() {
    assert_same(&greater("gidNumber", "2005"), "(gidNumber>=2005)");
    assert_same(&less("gidNumber", "2005"), "(gidNumber<=2005)");
    assert_same(&greater("gidNumber", "2000"), "(gidNumber>=2000)");
    // Variable-width numbers: `(uidNumber>=100)` has to include 3700 and 1110 and exclude 74,
    // which is exactly where a text ordering would answer differently.
    assert_same(&greater("uidNumber", "100"), "(uidNumber>=100)");
    assert_same(&less("uidNumber", "100"), "(uidNumber<=100)");
    assert_same(&less("gidNumber", "2999"), "(gidNumber<=2999)");
    // Text ordering, folded: `user010` is below `user020` as text as well as as a number,
    // which is why the fixture uses a fixed width.
    assert_same(&greater("cn", "user010"), "(cn>=user010)");
    assert_same(&less("sn", "Surname100"), "(sn<=Surname100)");
}

#[test]
fn an_ordering_filter_with_no_match_agrees() {
    let plain = search(&directory(false), greater("gidNumber", "99999"));
    let indexed = search(&directory(true), greater("gidNumber", "99999"));

    assert_eq!(indexed, plain);
    assert!(plain.is_empty());
}

#[test]
fn filters_the_index_cannot_use_still_agree() {
    // Approximate matching and extensible matching have no index and no evaluation: the
    // answer is the scan's, unchanged. Substrings and ordering used to be listed here and
    // moved out when they gained both an index and a comparison of their own.
    assert_same_answer(
        &Filter::ApproxMatch(AttributeValueAssertion::new(
            AttributeDescription::from("cn"),
            OctetString::from("user007".as_bytes()),
        )),
        "(cn~=user007)",
    );
    assert_same(
        &Filter::And(rasn::types::SetOf::from_vec(vec![
            substring("cn", "user1"),
            present("mail"),
        ])),
        "(&(cn=user1*)(mail=*))",
    );
    assert_same(
        &Filter::Or(rasn::types::SetOf::from_vec(vec![
            substring("cn", "user29"),
            equality("cn", "user001"),
        ])),
        "(|(cn=user29*)(cn=user001))",
    );
}

#[test]
fn substring_and_ordering_filters_combined_agree() {
    // Users carry `mail` and groups carry `gidNumber`: an intersection of the two on one
    // entry is empty, so the pair below combines an interior substring with a range that can
    // both apply to a user - `mail` present, `cn` containing "user1".
    assert_same(
        &Filter::And(rasn::types::SetOf::from_vec(vec![
            substring_any("cn", "user1"),
            present("mail"),
        ])),
        "(&(cn=*user1*)(mail=*))",
    );
    assert_same(
        &Filter::Or(rasn::types::SetOf::from_vec(vec![
            substring_final("cn", "00"),
            less("gidNumber", "2002"),
        ])),
        "(|(cn=*00)(gidNumber<=2002))",
    );
}

#[test]
fn a_value_nobody_has_agrees() {
    let plain = search(&directory(false), equality("cn", "user999"));
    let indexed = search(&directory(true), equality("cn", "user999"));

    assert_eq!(indexed, plain);
    assert!(plain.is_empty());
}

#[test]
fn nested_filters_agree() {
    assert_same(
        &Filter::And(rasn::types::SetOf::from_vec(vec![
            equality("objectClass", "inetOrgPerson"),
            Filter::Or(rasn::types::SetOf::from_vec(vec![
                present("mail"),
                Filter::Not(Box::new(present("telephoneNumber"))),
            ])),
        ])),
        "(&(objectClass=inetOrgPerson)(|(mail=*)(!(telephoneNumber=*))))",
    );
    assert_same(
        &Filter::Not(Box::new(Filter::And(rasn::types::SetOf::from_vec(vec![
            present("mail"),
            equality("sn", "Surname015"),
        ])))),
        "(!(&(mail=*)(sn=Surname015)))",
    );
}

#[test]
fn the_index_actually_narrows() {
    let directory = directory(true);

    let candidates = directory
        .candidates(&rust_rest_ldap::index::Query::Equality {
            attribute: "cn".into(),
            value: "user007".to_string(),
        })
        .expect("cn is indexed");

    assert_eq!(
        candidates.len(),
        1,
        "an equality on an indexed attribute should leave one candidate, not {}",
        candidates.len()
    );
}

#[test]
fn the_substring_index_actually_narrows() {
    // Without this the step could be "correct" by never being used: an index that always
    // answers with everything agrees with the scan perfectly and buys nothing.
    let directory = directory(true);

    let narrow = directory
        .candidates(&rust_rest_ldap::index::Query::Substring {
            attribute: "cn".into(),
            initial: None,
            any: vec!["user007".to_string()],
            final_part: None,
        })
        .expect("cn has a substring index");

    assert_eq!(
        narrow.len(),
        1,
        "one value holds the trigram '007', so one candidate is expected, not {}",
        narrow.len()
    );

    // "ser2" is in "user200".."user299" only: fewer than everything, more than one. A
    // trigram shared by every value - "use", for instance - would narrow nothing at all,
    // which is a property of the data rather than of the index.
    let broad = directory
        .candidates(&rust_rest_ldap::index::Query::Substring {
            attribute: "cn".into(),
            initial: None,
            any: vec!["ser2".to_string()],
            final_part: None,
        })
        .expect("cn has a substring index");

    assert_eq!(
        broad.len(),
        100,
        "user200..user299 is a hundred entries, not {}",
        broad.len()
    );
}

#[test]
fn the_ordered_index_actually_narrows() {
    let directory = directory(true);

    let candidates = directory
        .candidates(&rust_rest_ldap::index::Query::Range {
            attribute: "gidNumber".into(),
            bound: rust_rest_ldap::index::RangeBound::AtLeast,
            value: "2990".to_string(),
        })
        .expect("gidNumber has an ordered index");

    assert!(
        candidates.len() < 30,
        "`>= 2990` should leave the top of the range, not {} entries",
        candidates.len()
    );
}

#[test]
fn without_indexes_there_are_no_candidates() {
    let directory = directory(false);

    assert!(
        directory
            .candidates(&rust_rest_ldap::index::Query::Equality {
                attribute: "cn".into(),
                value: "user007".to_string(),
            })
            .is_none(),
        "a directory built without indexes must not narrow anything"
    );
}
