//! Search operation: rootDSE, entry selection, filters, limits and paging.
//!
//! Two deliberate differences from gorestldap, both visible in its issue list and
//! in the `gorestldap` skill notes:
//!
//! 1. The client size limit is applied AFTER the filter, so `ldapsearch -z 1`
//!    on a single match returns that match instead of `sizeLimitExceeded`.
//! 2. Paging is stateless: the cookie is the offset of the next entry, so a page
//!    request carries everything needed to continue it and a reconnect, a
//!    different page size or a reloaded directory cannot desynchronize the
//!    cursor (gorestldap kept four booleans and an index per connection).

use rasn_ldap::{Controls, LdapMessage, MessageId, ResultCode, SearchRequest};

use super::filter;
use super::paged::{self, PAGED_RESULTS_OID, Page};
use super::responses::{self, search_done_with_controls, search_result_entry};
use super::session::Session;
use super::sort;
use crate::directory::Directory;
use crate::model::{Attribute, Attributes};
use crate::security::Security;

/// Values of the root DSE that the server publishes.
const ROOT_DSE_OBJECT_CLASS: [&str; 2] = ["top", "LDAProotDSE"];

/// Handles a search request.
///
/// `controls` come from the message envelope; `respect_critical` decides whether
/// an unsupported critical control aborts the search or is ignored.
pub fn handle_search(
    session: &Session,
    directory: &Directory,
    message_id: MessageId,
    request: &SearchRequest,
    controls: Option<&Controls>,
    security: &Security,
) -> Vec<LdapMessage> {
    let base_object = request.base_object.0.to_string();

    // Root DSE is served before any access check: clients need it to discover the
    // naming contexts before they can bind.
    if base_object.is_empty() {
        return search_root_dse(message_id, request, directory.base_dn());
    }

    // The subschema subentry does not live under the naming context; a client addresses
    // it by its own name (RFC 4512 §4.2).
    if super::schema_entry::is_schema_dn(&base_object) {
        return super::schema_entry::search(message_id, request, &security.schema, &base_object);
    }

    let mut page = Page::default();
    let mut has_paged_control = false;
    let mut sort_request: Option<sort::SortRequest> = None;
    let mut sort_critical = false;
    let mut virtual_list: Option<sort::VirtualList> = None;
    for control in controls.into_iter().flatten() {
        if control.control_type.as_ref() == PAGED_RESULTS_OID.as_bytes() {
            has_paged_control = true;
            match control
                .control_value
                .as_ref()
                .map(|value| paged::decode(value.as_ref()))
            {
                Some(Ok(decoded)) => page = decoded,
                Some(Err(err)) => {
                    return vec![responses::search_done(
                        message_id,
                        ResultCode::ProtocolError,
                        &format!("error decoding paged results control: {err}"),
                    )];
                }
                None => {
                    return vec![responses::search_done(
                        message_id,
                        ResultCode::ProtocolError,
                        "paged results control carries no value",
                    )];
                }
            }
        } else if control.control_type.as_ref() == sort::SORT_OID.as_bytes() {
            sort_critical = control.criticality;
            match control.control_value.as_ref() {
                Some(value) => match sort::decode_sort(value.as_ref()) {
                    Ok(request) => sort_request = Some(request),
                    Err(err) => {
                        // A sort the server cannot read must not become "unsorted but
                        // successful": the client asked for an order.
                        return vec![responses::search_done(
                            message_id,
                            ResultCode::ProtocolError,
                            &format!("error decoding the sort control: {err}"),
                        )];
                    }
                },
                None => {
                    return vec![responses::search_done(
                        message_id,
                        ResultCode::ProtocolError,
                        "the sort control carries no value",
                    )];
                }
            }
        } else if control.control_type.as_ref() == sort::VLV_OID.as_bytes() {
            match control.control_value.as_ref() {
                Some(value) => match sort::decode_vlv(value.as_ref()) {
                    Ok(list) => virtual_list = Some(list),
                    Err(err) => {
                        return vec![responses::search_done(
                            message_id,
                            ResultCode::ProtocolError,
                            &format!("error decoding the VLV control: {err}"),
                        )];
                    }
                },
                None => {
                    return vec![responses::search_done(
                        message_id,
                        ResultCode::ProtocolError,
                        "the VLV control carries no value",
                    )];
                }
            }
        } else if control.criticality && security.respect_control_criticality {
            return vec![responses::search_done(
                message_id,
                ResultCode::UnavailableCriticalExtension,
                &format!(
                    "unsupported critical control '{}'",
                    String::from_utf8_lossy(control.control_type.as_ref())
                ),
            )];
        }
    }

    // Access is decided by the rules, per entry and per attribute.
    let requester = session.requester();
    if !security
        .acl
        .rights(&requester, directory, &base_object, None)
        .search
    {
        return vec![responses::search_done(
            message_id,
            ResultCode::NoSuchObject,
            "insufficient access",
        )];
    }

    let scope = scope_of(request);
    let selection: Vec<String> = request
        .attributes
        .iter()
        .map(|attribute| attribute.0.clone())
        .collect();

    // The index only narrows: every candidate is still checked by the filter below,
    // so a wrong index costs speed, never correctness.
    let candidates = directory.candidates(&filter::to_query(&request.filter));

    let mut matched: Vec<(String, Attributes)> = Vec::new();
    for (position, entry) in directory.entries_with_ids(&base_object, scope) {
        if candidates
            .as_ref()
            .is_some_and(|candidates| !candidates.contains(position as u32))
        {
            continue;
        }
        let entry_dn = entry.dn().to_string();
        if !security
            .acl
            .rights(&requester, directory, &entry_dn, None)
            .read
        {
            continue;
        }
        match filter::matches(entry.attributes(), &entry_dn, &request.filter) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(err) => {
                return vec![responses::search_done(
                    message_id,
                    ResultCode::UnwillingToPerform,
                    &err.to_string(),
                )];
            }
        }
        matched.push((entry_dn, entry.attributes().clone()));
    }

    // Sort before limits and paging: a client that asks for a sorted page means "the
    // first twenty of the sorted list", not "the first twenty, sorted".
    let mut sort_response: Option<sort::SortResponse> = None;
    if let Some(request) = &sort_request {
        match sort::check_rules(request) {
            Ok(()) => {
                matched.sort_by(|(left_dn, left), (right_dn, right)| {
                    sort::compare_attributes(left_dn, left, right_dn, right, &request.keys)
                });
                sort_response = Some(sort::SortResponse::ok());
            }
            Err(err) => {
                // A critical sort that cannot be honoured must refuse the search: the
                // client said it cannot work with an unsorted answer, and returning one
                // with a note in a control is exactly the silent wrong order it guarded
                // against. A non-critical sort reports the failure and returns the
                // entries as they came.
                if sort_critical && security.respect_control_criticality {
                    return vec![responses::search_done(
                        message_id,
                        ResultCode::InappropriateMatching,
                        &format!("cannot apply the sort control: {err}"),
                    )];
                }

                sort_response = Some(sort::SortResponse::failed(
                    sort::SortResult::InappropriateMatching,
                    request.keys.first().map(|key| key.attribute.as_str()),
                ));
            }
        }
    }

    // VLV narrows the sorted list to a window; without a sort it has no meaning, which is
    // why RFC 2891 pairs them and this server refuses the combination it cannot answer.
    let mut vlv_response: Option<sort::VirtualListResponse> = None;
    let mut window: Option<(usize, usize)> = None;
    if let Some(list) = &virtual_list {
        if sort_request.is_none() {
            return vec![responses::search_done(
                message_id,
                ResultCode::UnwillingToPerform,
                "the virtual list view control requires the sort control",
            )];
        }

        let content_count = matched.len() as u32;
        window = Some(list.window(matched.len()));
        vlv_response = Some(sort::VirtualListResponse {
            target_position: list.target_position(matched.len()),
            content_count,
            result: sort::SortResult::Success,
            context: Vec::new(),
        });
    }

    // Client size limit: applied to the entries that matched, per RFC 4511.
    let size_limit = request.size_limit as usize;
    let size_limit_exceeded = size_limit > 0 && matched.len() > size_limit;
    if size_limit_exceeded {
        matched.truncate(size_limit);
    }

    // Paging: the cookie is the offset of the first entry of this page.
    let offset = if has_paged_control {
        match parse_cookie(&page.cookie) {
            Ok(offset) => offset,
            Err(offset_err) => {
                return vec![responses::search_done(
                    message_id,
                    ResultCode::UnwillingToPerform,
                    &offset_err,
                )];
            }
        }
    } else {
        0
    };
    if offset >= matched.len() && offset > 0 {
        return vec![responses::search_done(
            message_id,
            ResultCode::UnwillingToPerform,
            &format!("paged results cookie points past the end ({offset})"),
        )];
    }

    // A VLV window replaces the page boundaries: the client asked for a range of the
    // sorted list, not for the next page of one. Paged results and VLV together would be
    // two answers to the same question, so the window wins and the cookie is not used.
    let (page_start, page_end) = match window {
        Some((from, to)) => (from, to),
        None => {
            let page_size = if has_paged_control && page.is_requested() {
                page.size as usize
            } else {
                matched.len()
            };
            (offset, (offset + page_size).min(matched.len()))
        }
    };

    let mut messages: Vec<LdapMessage> = matched[page_start..page_end]
        .iter()
        .map(|(dn, attributes)| {
            let visible: Vec<Attribute> = attributes
                .select(dn, &selection)
                .into_iter()
                .filter(|attribute| {
                    security
                        .acl
                        .rights(&requester, directory, dn, Some(&*attribute.name))
                        .read
                })
                .collect();
            let selected = if request.types_only {
                visible.into_iter().map(without_values).collect()
            } else {
                visible
            };
            search_result_entry(message_id, dn, &selected)
        })
        .collect();

    let mut controls_out: Controls = Vec::new();

    // A sorted search without the sort response leaves the client guessing whether the
    // order it sees is the order it asked for.
    if let Some(response) = sort_response
        .as_ref()
        .filter(|_| sort_request.is_some() || sort_critical)
    {
        controls_out.push(responses::control(
            sort::SORT_RESPONSE_OID,
            false,
            Some(&response.encode()),
        ));
    }
    if let Some(response) = &vlv_response {
        controls_out.push(responses::control(
            sort::VLV_RESPONSE_OID,
            false,
            Some(&response.encode()),
        ));
    }
    if has_paged_control && window.is_none() {
        let cookie = if page_end < matched.len() {
            page_end.to_string().into_bytes()
        } else {
            Vec::new()
        };
        controls_out.push(responses::paged_results_control(&Page::new(0, cookie)));
    }

    let code = if size_limit_exceeded {
        ResultCode::SizeLimitExceeded
    } else {
        ResultCode::Success
    };
    messages.push(search_done_with_controls(
        message_id,
        code,
        "",
        controls_out,
    ));

    messages
}

fn without_values(attribute: crate::model::Attribute) -> crate::model::Attribute {
    crate::model::Attribute {
        values: Vec::new().into_boxed_slice(),
        ..attribute
    }
}

fn parse_cookie(cookie: &[u8]) -> Result<usize, String> {
    if cookie.is_empty() {
        return Ok(0);
    }
    std::str::from_utf8(cookie)
        .ok()
        .and_then(|text| text.parse::<usize>().ok())
        .ok_or_else(|| {
            format!(
                "paged results cookie '{}' is not a position",
                String::from_utf8_lossy(cookie)
            )
        })
}

pub fn scope_of(request: &SearchRequest) -> crate::directory::Scope {
    use crate::directory::Scope;
    use rasn_ldap::SearchRequestScope;

    match request.scope {
        SearchRequestScope::BaseObject => Scope::Base,
        SearchRequestScope::SingleLevel => Scope::OneLevel,
        _ => Scope::Subtree,
    }
}

fn search_root_dse(
    message_id: MessageId,
    request: &SearchRequest,
    base_dn: &str,
) -> Vec<LdapMessage> {
    if scope_of(request) != crate::directory::Scope::Base {
        return vec![responses::search_done(message_id, ResultCode::Success, "")];
    }

    let attributes = Attributes::new()
        .push(crate::model::Attribute::new(
            crate::model::ATTR_OBJECT_CLASS,
            ROOT_DSE_OBJECT_CLASS
                .iter()
                .map(|value| value.to_string())
                .collect(),
        ))
        .push(crate::model::Attribute::single(
            "vendorVersion",
            env!("CARGO_PKG_VERSION"),
        ))
        .push(crate::model::Attribute::single("supportedLDAPVersion", "3"))
        .push(crate::model::Attribute::single(
            "supportedControl",
            PAGED_RESULTS_OID,
        ))
        .push(crate::model::Attribute::single("namingContexts", base_dn))
        // Where a client goes to read the schema; RFC 4512 requires the root DSE to
        // name it, otherwise the entry is unreachable by discovery.
        .push(crate::model::Attribute::single(
            "subschemaSubentry",
            super::schema_entry::PRIMARY_DN,
        ));

    let selection: Vec<String> = request
        .attributes
        .iter()
        .map(|attribute| attribute.0.clone())
        .collect();

    vec![
        search_result_entry(message_id, "", &attributes.select("", &selection)),
        responses::search_done(message_id, ResultCode::Success, ""),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::Scope;
    use crate::ldap::paged;
    use crate::ldap::session::Identity;
    use crate::model::{Group, User};
    use rasn_ldap::{
        AttributeDescription, AttributeValueAssertion, Control, Filter, LdapDn, LdapOid,
        ProtocolOp, SearchRequestDerefAliases, SearchRequestScope,
    };

    const BASE: &str = "dc=example,dc=com";
    const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
    const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";

    fn directory() -> Directory {
        let admin = User {
            ldap_admin: true,
            object_class: vec!["top".to_string(), "inetOrgPerson".to_string()],
            cn: "admin".to_string(),
            uid: Some("admin".to_string()),
            mail: Some("admin@example.com".to_string()),
            user_password: Some("{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=".to_string()),
            ..User::default()
        };
        let alice = User {
            object_class: vec!["top".to_string(), "inetOrgPerson".to_string()],
            cn: "alice".to_string(),
            uid: Some("alice".to_string()),
            mail: Some("alice@example.com".to_string()),
            user_password: Some("{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=".to_string()),
            ..User::default()
        };
        let group = Group {
            object_class: vec!["top".to_string(), "posixGroup".to_string()],
            cn: "group_a".to_string(),
            member_uid: vec!["alice".to_string()],
            ..Group::default()
        };
        Directory::new(BASE, "users", "groups", vec![admin, alice], vec![group])
    }

    fn admin_session() -> Session {
        let mut session = Session::new();
        session.set_identity(Identity::new(ADMIN_DN, true));
        session
    }

    fn user_session() -> Session {
        let mut session = Session::new();
        session.set_identity(Identity::new(ALICE_DN, false));
        session
    }

    fn present(name: &str) -> Filter {
        Filter::Present(AttributeDescription::from(name))
    }

    fn equality(name: &str, value: &str) -> Filter {
        Filter::EqualityMatch(AttributeValueAssertion::new(
            AttributeDescription::from(name),
            rasn::types::OctetString::from(value.as_bytes()),
        ))
    }

    fn request(
        base: &str,
        scope: SearchRequestScope,
        filter: Filter,
        size_limit: u32,
        attributes: &[&str],
    ) -> SearchRequest {
        SearchRequest::new(
            LdapDn::from(base),
            scope,
            SearchRequestDerefAliases::NeverDerefAliases,
            size_limit,
            0,
            false,
            filter,
            attributes
                .iter()
                .map(|name| rasn_ldap::LdapString::from(*name))
                .collect(),
        )
    }

    fn security() -> Security {
        Security::default()
    }

    fn search(
        session: &Session,
        request: &SearchRequest,
        controls: Option<&Controls>,
    ) -> Vec<LdapMessage> {
        handle_search(session, &directory(), 1, request, controls, &security())
    }

    fn dns(messages: &[LdapMessage]) -> Vec<String> {
        messages
            .iter()
            .filter_map(|message| match &message.protocol_op {
                ProtocolOp::SearchResEntry(entry) => Some(entry.object_name.0.clone()),
                _ => None,
            })
            .collect()
    }

    fn result_code(messages: &[LdapMessage]) -> ResultCode {
        match &messages.last().expect("at least one message").protocol_op {
            ProtocolOp::SearchResDone(done) => done.0.result_code,
            other => panic!("last message must be searchResDone, got {other:?}"),
        }
    }

    fn diagnostic(messages: &[LdapMessage]) -> String {
        match &messages.last().expect("at least one message").protocol_op {
            ProtocolOp::SearchResDone(done) => done.0.diagnostic_message.0.clone(),
            other => panic!("unexpected last message: {other:?}"),
        }
    }

    fn attribute_names(messages: &[LdapMessage]) -> Vec<String> {
        match &messages[0].protocol_op {
            ProtocolOp::SearchResEntry(entry) => entry
                .attributes
                .iter()
                .map(|attribute| attribute.r#type.0.clone())
                .collect(),
            other => panic!("unexpected first message: {other:?}"),
        }
    }

    #[test]
    fn root_dse_publishes_naming_context_and_supported_control_constantly() {
        let session = admin_session();
        let request = request(
            "",
            SearchRequestScope::BaseObject,
            present("objectClass"),
            0,
            &[],
        );

        let messages = search(&session, &request, None);

        assert_eq!(messages.len(), 2);
        assert_eq!(dns(&messages), vec![""]);
        assert_eq!(
            attribute_names(&messages),
            vec![
                "objectClass",
                "vendorVersion",
                "supportedLDAPVersion",
                "supportedControl",
                "namingContexts",
                // RFC 4512 requires the root DSE to name the subschema subentry, or a
                // client cannot discover that this server publishes a schema at all.
                "subschemaSubentry",
            ]
        );
        assert_eq!(result_code(&messages), ResultCode::Success);
    }

    #[test]
    fn root_dse_is_readable_before_bind() {
        let session = Session::new();
        let request = request(
            "",
            SearchRequestScope::BaseObject,
            present("objectClass"),
            0,
            &[],
        );

        let messages = search(&session, &request, None);

        assert_eq!(result_code(&messages), ResultCode::Success);
        assert_eq!(dns(&messages), vec![""]);
    }

    #[test]
    fn root_dse_with_subtree_scope_returns_no_entries() {
        let session = admin_session();
        let request = request(
            "",
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let messages = search(&session, &request, None);

        assert!(dns(&messages).is_empty());
        assert_eq!(result_code(&messages), ResultCode::Success);
    }

    #[test]
    fn admin_subtree_search_returns_every_entry() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let messages = search(&session, &request, None);

        assert_eq!(
            dns(&messages),
            vec![
                BASE,
                "ou=users,dc=example,dc=com",
                "ou=groups,dc=example,dc=com",
                ADMIN_DN,
                ALICE_DN,
                "cn=group_a,ou=groups,dc=example,dc=com",
            ]
        );
        assert_eq!(result_code(&messages), ResultCode::Success);
    }

    #[test]
    fn one_level_scope_of_users_ou_returns_users_only() {
        let session = admin_session();
        let request = request(
            "ou=users,dc=example,dc=com",
            SearchRequestScope::SingleLevel,
            present("objectClass"),
            0,
            &[],
        );

        assert_eq!(
            dns(&search(&session, &request, None)),
            vec![ADMIN_DN, ALICE_DN]
        );
    }

    #[test]
    fn filter_narrows_the_result() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            equality("cn", "alice"),
            0,
            &[],
        );

        assert_eq!(dns(&search(&session, &request, None)), vec![ALICE_DN]);
    }

    #[test]
    fn size_limit_applies_after_the_filter() {
        // gorestldap answered sizeLimitExceeded here, because it compared the
        // limit before evaluating the filter.
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            equality("cn", "alice"),
            1,
            &[],
        );

        let messages = search(&session, &request, None);

        assert_eq!(dns(&messages), vec![ALICE_DN]);
        assert_eq!(result_code(&messages), ResultCode::Success);
    }

    #[test]
    fn size_limit_truncates_a_real_overflow_and_reports_it() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            2,
            &[],
        );

        let messages = search(&session, &request, None);

        assert_eq!(dns(&messages).len(), 2);
        assert_eq!(result_code(&messages), ResultCode::SizeLimitExceeded);
    }

    #[test]
    fn unsupported_filter_is_reported_not_silently_empty() {
        let session = admin_session();
        let filter = Filter::GreaterOrEqual(AttributeValueAssertion::new(
            AttributeDescription::from("cn"),
            rasn::types::OctetString::from(b"a".as_slice()),
        ));
        let request = request(BASE, SearchRequestScope::WholeSubtree, filter, 0, &[]);

        let messages = search(&session, &request, None);

        assert!(dns(&messages).is_empty());
        assert_eq!(result_code(&messages), ResultCode::UnwillingToPerform);
        assert_eq!(
            diagnostic(&messages),
            "unsupported filter type 'greaterOrEqual'"
        );
    }

    #[test]
    fn attribute_selection_is_respected() {
        let session = admin_session();
        let request = request(
            ALICE_DN,
            SearchRequestScope::BaseObject,
            present("objectClass"),
            0,
            &["mail"],
        );

        let messages = search(&session, &request, None);

        assert_eq!(attribute_names(&messages), vec!["mail"]);
    }

    #[test]
    fn types_only_returns_descriptions_without_values() {
        let session = admin_session();
        let mut request = request(
            ALICE_DN,
            SearchRequestScope::BaseObject,
            present("objectClass"),
            0,
            &["mail"],
        );
        request.types_only = true;

        let messages = search(&session, &request, None);

        match &messages[0].protocol_op {
            ProtocolOp::SearchResEntry(entry) => {
                assert_eq!(entry.attributes[0].r#type.0, "mail");
                assert!(
                    entry.attributes[0].vals.is_empty(),
                    "typesOnly must drop values"
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn regular_user_may_search_only_own_entry() {
        let session = user_session();
        let own = request(
            ALICE_DN,
            SearchRequestScope::BaseObject,
            present("objectClass"),
            0,
            &[],
        );
        let other = request(
            ADMIN_DN,
            SearchRequestScope::BaseObject,
            present("objectClass"),
            0,
            &[],
        );
        let subtree = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        assert_eq!(dns(&search(&session, &own, None)), vec![ALICE_DN]);
        assert_eq!(
            result_code(&search(&session, &other, None)),
            ResultCode::NoSuchObject
        );
        assert_eq!(
            result_code(&search(&session, &subtree, None)),
            ResultCode::NoSuchObject
        );
    }

    #[test]
    fn anonymous_session_cannot_search_the_directory() {
        let session = Session::new();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let messages = search(&session, &request, None);

        assert!(dns(&messages).is_empty());
        assert_eq!(result_code(&messages), ResultCode::NoSuchObject);
        assert_eq!(diagnostic(&messages), "insufficient access");
    }

    fn paged_control(size: u32, cookie: &[u8]) -> Controls {
        vec![Control::new(
            LdapOid::from(PAGED_RESULTS_OID.as_bytes()),
            true,
            Some(rasn::types::OctetString::from(paged::encode(
                &paged::Page::new(size, cookie),
            ))),
        )]
    }

    fn returned_cookie(messages: &[LdapMessage]) -> Vec<u8> {
        let controls = messages
            .last()
            .expect("done")
            .controls
            .as_ref()
            .expect("paged control in response");
        let value = controls[0].control_value.as_ref().expect("control value");
        paged::decode(value.as_ref()).expect("decode").cookie
    }

    #[test]
    fn paging_returns_the_first_page_with_a_continuation_cookie() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );
        let controls = paged_control(2, b"");

        let messages = search(&session, &request, Some(&controls));

        assert_eq!(dns(&messages), vec![BASE, "ou=users,dc=example,dc=com"]);
        assert_eq!(returned_cookie(&messages), b"2".to_vec());
        assert_eq!(result_code(&messages), ResultCode::Success);
    }

    #[test]
    fn paging_continues_from_the_cookie_and_finishes_with_empty_cookie() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let first = search(&session, &request, Some(&paged_control(4, b"")));
        let cookie = returned_cookie(&first);
        let second = search(&session, &request, Some(&paged_control(4, &cookie)));

        assert_eq!(
            dns(&second),
            vec![ALICE_DN, "cn=group_a,ou=groups,dc=example,dc=com"]
        );
        assert!(
            returned_cookie(&second).is_empty(),
            "the last page must carry an empty cookie"
        );
    }

    #[test]
    fn paging_is_stateless_so_any_page_size_may_follow() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let first = search(&session, &request, Some(&paged_control(1, b"")));
        let second = search(
            &session,
            &request,
            Some(&paged_control(3, &returned_cookie(&first))),
        );

        assert_eq!(dns(&first), vec![BASE]);
        assert_eq!(
            dns(&second),
            vec![
                "ou=users,dc=example,dc=com",
                "ou=groups,dc=example,dc=com",
                ADMIN_DN
            ]
        );
    }

    #[test]
    fn cookie_that_is_not_a_position_is_rejected() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let messages = search(&session, &request, Some(&paged_control(2, b"nonsense")));

        assert!(dns(&messages).is_empty());
        assert_eq!(result_code(&messages), ResultCode::UnwillingToPerform);
        assert_eq!(
            diagnostic(&messages),
            "paged results cookie 'nonsense' is not a position"
        );
    }

    #[test]
    fn cookie_pointing_past_the_end_is_rejected() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let messages = search(&session, &request, Some(&paged_control(2, b"99")));

        assert!(dns(&messages).is_empty());
        assert_eq!(result_code(&messages), ResultCode::UnwillingToPerform);
        assert_eq!(
            diagnostic(&messages),
            "paged results cookie points past the end (99)"
        );
    }

    #[test]
    fn broken_paged_control_value_is_a_protocol_error() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );
        let controls = vec![Control::new(
            LdapOid::from(PAGED_RESULTS_OID.as_bytes()),
            true,
            Some(rasn::types::OctetString::from_static(&[0x30, 0x01])),
        )];

        let messages = search(&session, &request, Some(&controls));

        assert_eq!(result_code(&messages), ResultCode::ProtocolError);
        assert!(
            diagnostic(&messages).starts_with("error decoding paged results control: "),
            "unexpected: {}",
            diagnostic(&messages)
        );
    }

    #[test]
    fn control_without_value_is_a_protocol_error() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );
        let controls = vec![Control::new(
            LdapOid::from(PAGED_RESULTS_OID.as_bytes()),
            true,
            None,
        )];

        let messages = search(&session, &request, Some(&controls));

        assert_eq!(result_code(&messages), ResultCode::ProtocolError);
        assert_eq!(
            diagnostic(&messages),
            "paged results control carries no value"
        );
    }

    #[test]
    fn unsupported_critical_control_aborts_when_respected() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );
        let controls = vec![Control::new(
            LdapOid::from(b"1.2.3.4.5".as_slice()),
            true,
            None,
        )];

        let messages = handle_search(
            &session,
            &directory(),
            1,
            &request,
            Some(&controls),
            &security(),
        );

        assert_eq!(
            result_code(&messages),
            ResultCode::UnavailableCriticalExtension
        );
        assert_eq!(
            diagnostic(&messages),
            "unsupported critical control '1.2.3.4.5'"
        );
    }

    #[test]
    fn unsupported_critical_control_is_ignored_when_not_respected() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );
        let controls = vec![Control::new(
            LdapOid::from(b"1.2.3.4.5".as_slice()),
            true,
            None,
        )];

        let security = Security {
            respect_control_criticality: false,
            ..Security::default()
        };
        let messages = handle_search(
            &session,
            &directory(),
            1,
            &request,
            Some(&controls),
            &security,
        );

        assert_eq!(result_code(&messages), ResultCode::Success);
        assert_eq!(dns(&messages).len(), 6);
    }

    #[test]
    fn non_critical_unknown_control_is_ignored() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );
        let controls = vec![Control::new(
            LdapOid::from(b"1.2.3.4.5".as_slice()),
            false,
            None,
        )];

        let messages = handle_search(
            &session,
            &directory(),
            1,
            &request,
            Some(&controls),
            &security(),
        );

        assert_eq!(result_code(&messages), ResultCode::Success);
    }

    #[test]
    fn search_on_unknown_base_returns_nothing() {
        let session = admin_session();
        let request = request(
            "dc=nowhere,dc=com",
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let messages = search(&session, &request, None);

        assert!(dns(&messages).is_empty());
        assert_eq!(result_code(&messages), ResultCode::Success);
    }

    #[test]
    fn wildcard_never_returns_the_password_hash() {
        let session = admin_session();
        let request = request(
            ALICE_DN,
            SearchRequestScope::BaseObject,
            present("objectClass"),
            0,
            &["*"],
        );

        let names = attribute_names(&search(&session, &request, None));

        assert!(
            !names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("userPassword")),
            "wildcard leaked the password hash: {names:?}"
        );
    }

    #[test]
    fn admin_gets_the_password_hash_when_naming_it_explicitly() {
        let session = admin_session();
        let request = request(
            ALICE_DN,
            SearchRequestScope::BaseObject,
            present("objectClass"),
            0,
            &["userPassword"],
        );

        assert_eq!(
            attribute_names(&search(&session, &request, None)),
            vec!["userPassword"]
        );
    }

    #[test]
    fn owner_naming_the_password_gets_nothing_because_the_default_rules_deny_it() {
        let session = user_session();
        let request = request(
            ALICE_DN,
            SearchRequestScope::BaseObject,
            present("objectClass"),
            0,
            &["userPassword"],
        );

        let messages = search(&session, &request, None);

        assert_eq!(
            dns(&messages),
            vec![ALICE_DN],
            "the entry itself is readable"
        );
        let attributes = match &messages[0].protocol_op {
            ProtocolOp::SearchResEntry(entry) => entry.attributes.len(),
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(attributes, 0, "but the password attribute is dropped");
    }

    #[test]
    fn acl_rule_can_open_the_password_to_its_owner() {
        use crate::acl::{Acl, Rights, Rule, Subject};

        let security = Security {
            acl: Acl::new(vec![
                Rule {
                    subject: Subject::SelfEntry,
                    base: None,
                    attributes: vec!["userPassword".to_string()],
                    rights: Rights {
                        read: true,
                        ..Rights::none()
                    },
                },
                Rule {
                    subject: Subject::SelfEntry,
                    base: None,
                    attributes: vec!["*".to_string()],
                    rights: Rights::self_service(),
                },
            ]),
            ..Security::default()
        };
        let session = user_session();
        let request = request(
            ALICE_DN,
            SearchRequestScope::BaseObject,
            present("objectClass"),
            0,
            &["userPassword"],
        );

        let messages = handle_search(&session, &directory(), 1, &request, None, &security);

        assert_eq!(attribute_names(&messages), vec!["userPassword"]);
    }

    #[test]
    fn group_rule_grants_read_on_another_entry() {
        use crate::acl::{AccessRuleConfig, Acl, Rights, Rule, Subject};

        let security = Security {
            acl: Acl::new(vec![
                // Attribute-scoped rules do not make an entry visible on their
                // own: an entry-wide rule has to allow seeing it at all.
                Rule {
                    subject: Subject::Group("group_a".to_string()),
                    base: None,
                    attributes: vec![],
                    rights: Rights {
                        read: true,
                        search: true,
                        ..Rights::none()
                    },
                },
                Rule {
                    subject: Subject::SelfEntry,
                    base: None,
                    attributes: vec!["*".to_string()],
                    rights: Rights {
                        read: true,
                        search: true,
                        ..Rights::none()
                    },
                },
            ]),
            ..Security::default()
        };
        let session = user_session();
        let request = request(
            ADMIN_DN,
            SearchRequestScope::BaseObject,
            present("objectClass"),
            0,
            &["mail", "cn"],
        );

        let messages = handle_search(&session, &directory(), 1, &request, None, &security);

        assert_eq!(dns(&messages), vec![ADMIN_DN]);
        assert_eq!(attribute_names(&messages), vec!["mail", "cn"]);
        // Unused import guard: the config type is exercised in acl tests.
        let _ = std::mem::size_of::<AccessRuleConfig>();
    }

    #[test]
    fn every_search_ends_with_done() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let messages = search(&session, &request, None);

        assert!(matches!(
            messages.last().expect("done").protocol_op,
            ProtocolOp::SearchResDone(_)
        ));
    }

    #[test]
    fn scope_helper_maps_rfc_values() {
        let base = request(BASE, SearchRequestScope::BaseObject, present("cn"), 0, &[]);
        let one = request(BASE, SearchRequestScope::SingleLevel, present("cn"), 0, &[]);
        let tree = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("cn"),
            0,
            &[],
        );

        assert_eq!(scope_of(&base), Scope::Base);
        assert_eq!(scope_of(&one), Scope::OneLevel);
        assert_eq!(scope_of(&tree), Scope::Subtree);
    }
}
