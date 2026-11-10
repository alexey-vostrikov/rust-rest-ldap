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

/// `manageDsaIT` (RFC 3296 §2): "do not redirect me, treat special objects as entries".
pub const MANAGEDSAIT_OID: &str = "2.16.840.1.113730.3.4.2";
use super::responses::{self, search_done_with_controls, search_result_entry};
use super::session::Session;
use super::sort;
use super::sync;
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
        return search_root_dse(message_id, request, directory.base_dn(), security);
    }

    // The subschema subentry does not live under the naming context; a client addresses
    // it by its own name (RFC 4512 §4.2).
    if super::schema_entry::is_schema_dn(&base_object) {
        // One read: the answer must describe one schema, not the one before a reload for
        // its first entry and the one after for its last.
        let schema = crate::security::current_schema(&security.schema);
        return super::schema_entry::search(message_id, request, &schema, &base_object);
    }

    // Started before the scan, because that is where the time goes: a filter that matches nothing
    // still visits every entry. The limit covers finding the entries, not sending them - a search
    // that has its answer and is writing it is nearly done, and cutting it off mid-answer leaves a
    // client with half a result and no way to tell why.
    let started = std::time::Instant::now();

    let mut page = Page::default();
    let mut has_paged_control = false;
    let mut sort_request: Option<sort::SortRequest> = None;
    let mut sort_critical = false;
    let mut virtual_list: Option<sort::VirtualList> = None;
    let mut manage_dsa_it = false;
    let mut sync_request: Option<sync::SyncRequest> = None;
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
        } else if control.control_type.as_ref() == sync::SYNC_OID.as_bytes() {
            let Some(value) = control.control_value.as_ref() else {
                return vec![responses::search_done(
                    message_id,
                    ResultCode::ProtocolError,
                    "the sync control carries no value",
                )];
            };
            match sync::decode_request(value.as_ref()) {
                Ok(request) => sync_request = Some(request),
                Err(err) => {
                    return vec![responses::search_done(
                        message_id,
                        ResultCode::ProtocolError,
                        &format!("error decoding the sync control: {err}"),
                    )];
                }
            }
        } else if control.control_type.as_ref() == MANAGEDSAIT_OID.as_bytes() {
            // RFC 3296: "treat referral and other special objects as ordinary entries". This
            // server has no referral *entries* - its subtrees are configured, not stored - so
            // what the control means here is the part that matters to a client: do not redirect
            // me, answer for this DN yourself. Recognising it is also what keeps a critical
            // ManageDsaIT from being refused as an unknown extension.
            manage_dsa_it = true;
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

    // `cn=config` is the server's own settings, not the directory's: it is generated from the
    // configuration document, so it cannot go through the directory lookup below. Handled
    // after the controls, because an unsupported critical control aborts any search.
    if super::config_entry::is_config_dn(&base_object) {
        return super::config_entry::search(
            session,
            message_id,
            request,
            security.config_document.as_ref(),
            &base_object,
        );
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

    // A base that does not exist is `noSuchObject`, not an empty success (RFC 4511
    // §4.5.1.1: "if the object does not exist, the server returns noSuchObject"). An empty
    // result and a wrong base look identical to a script, and the second is a typo the
    // operator needs to hear about.
    //
    // The naming context itself, the units and every entry are all in `directory`; only a
    // base outside the tree is missing from it.
    if directory.find(&base_object).is_none() {
        // A subtree this server does not hold, but knows where it lives: RFC 4511 §4.5.3 says
        // answer with a reference and then a successful done, so the client can ask the server
        // that does hold it. Anything else - a base nobody covers - is still `noSuchObject`.
        //
        // Not when the client sent ManageDsaIT: it asked not to be redirected.
        if !manage_dsa_it {
            let uris = security.referrals.uris(&base_object);
            if !uris.is_empty() {
                return vec![
                    responses::search_reference(message_id, uris),
                    responses::search_done(message_id, ResultCode::Success, ""),
                ];
            }
        }

        return vec![responses::search_done(
            message_id,
            ResultCode::NoSuchObject,
            &format!("no such object: {base_object}"),
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
    let mut visited: usize = 0;

    // When the index has narrowed the answer, walk only those entries. Walking the whole directory
    // and testing each entry against the bitmap is what a million-entry load test caught: a lookup
    // matching one entry cost 39 ms, because the index spared the filter but not the walk.
    let size_limit = security.limits.effective_size_limit(request.size_limit);

    // With candidates the walk covers only those; without them it covers the scope, which is the
    // whole directory for a filter nothing can narrow. In a snapshot that holds only skeletons the
    // records are read here - one keyed read per candidate - and that is the price of the mode, paid
    // where it is asked for rather than at start for everybody.
    let in_scope: Vec<(usize, std::borrow::Cow<'_, crate::model::Entry>)> = match &candidates {
        Some(candidates) => directory.resolved_at(candidates),
        // A skeleton holds identities, so a filter cannot be evaluated against it at all - not even
        // `(objectClass=*)`. The records in scope are read first, and that is the price of the mode,
        // paid here rather than at start for everybody. Without a skeleton this arm is the ordinary
        // one and nothing is copied.
        None if directory.is_skeleton() => {
            let ids = directory.scope_ids(&base_object, scope);
            directory.resolved_at(&ids)
        }
        None => directory
            .entries_with_ids(&base_object, scope)
            .into_iter()
            .map(|(position, entry)| (position, std::borrow::Cow::Borrowed(entry)))
            .collect(),
    };

    for (_, entry) in &in_scope {
        let entry: &crate::model::Entry = entry;
        // Every 256 entries, not every one: the clock read is cheap but not free, and a search that
        // spends its budget on `Instant::now` is a search that did not need the limit.
        visited += 1;
        if visited.is_multiple_of(256)
            && let Some(budget) = security.limits.time_limit
            && started.elapsed() > budget
        {
            return vec![responses::search_done(
                message_id,
                ResultCode::TimeLimitExceeded,
                &format!(
                    "the search took longer than this server allows ({}s) after visiting {visited}                      entries: narrow the filter, or ask an operator for a larger limits.time_limit",
                    budget.as_secs()
                ),
            )];
        }

        // The walk is already restricted when candidates exist; the scope check is what remains,
        // and `entries_at` cannot apply it because a bitmap knows positions, not subtrees.
        if !crate::directory::in_scope_for(entry.dn(), &base_object, scope) {
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

        // Stop as soon as the answer is known to be truncated, but only when nothing downstream
        // needs the whole set. Without this, `-z 1000` over a million entries processed and cloned
        // all of them before throwing away all but a thousand: measured at 2.8 s for a search whose
        // answer was one kilobyte.
        //
        // One past the limit, because "exceeded" has to be knowable - and only when there is no
        // sort, no VLV window and no paging, each of which is defined over the complete list.
        if size_limit > 0
            && matched.len() > size_limit
            && sort_request.is_none()
            && virtual_list.is_none()
            && !has_paged_control
        {
            break;
        }
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

    // Size limit: the smaller of what the client asked for and what this server allows, applied to
    // the entries that matched - after the filter, as RFC 4511 requires. A limit checked before
    // the filter refuses a search that would have returned one entry.
    let size_limit_exceeded = size_limit > 0 && matched.len() > size_limit;
    if size_limit_exceeded {
        matched.truncate(size_limit);
    }

    // Paging: the cookie is the offset of the first entry of this page.
    let offset = if has_paged_control {
        match parse_cookie(&page.cookie, directory.snapshot()) {
            Ok(cursor) => cursor.offset,
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

    // The identity each entry is reported under. Taken from the entry's own `entryUUID` when it
    // has one, and from the DN otherwise: a replica that is given a made-up identity files the
    // entry under the wrong object, and the deterministic UUID depends only on the DN, so it is
    // the same after a restart.
    let sync_cookie = sync_request
        .as_ref()
        .map(|_| sync::encode_cookie(directory.snapshot(), directory.csn()));

    // What the client already has, if it said. `None` means "send me everything with attributes",
    // which is what a first refresh is.
    //
    // A cookie older than the journal's floor is a cookie this server cannot honour: the changes
    // between then and the oldest surviving record were pruned, and nothing in what remains says
    // so. RFC 4533 §3.1 puts it exactly that way - an unrecognised cookie means initial content
    // as if no cookie had been provided, or an empty answer with `syncRefreshRequired`, and the
    // choice may follow the client's `reloadHint`. A client that asked for a reload is told so
    // explicitly; one that did not gets the content, which is expensive and correct.
    let client_cookie = sync_request
        .as_ref()
        .and_then(|request| request.cookie.as_deref())
        .and_then(sync::decode_cookie);

    let recognized = match (&client_cookie, directory.floor()) {
        // A cookie that decodes but points before the oldest surviving change is not recognised,
        // even though it is well formed. This is the case that would otherwise be silent.
        (Some((_, Some(csn))), Some(floor)) => csn.as_str() >= floor,
        _ => true,
    };

    if !recognized
        && let Some(request) = sync_request.as_ref()
        && request.reload_hint
    {
        return vec![responses::search_done(
            message_id,
            ResultCode::SyncRefreshRequired,
            "the cookie describes a state this server can no longer answer about: the changes \
             since then were pruned, so a full refresh is required",
        )];
    }

    let client_csn = match (&client_cookie, recognized) {
        (Some((_, csn)), true) => csn.clone(),
        _ => None,
    };

    // Whether present entries are collapsed into a `syncIdSet` depends on how many there are,
    // which is only known once every entry is classified - and an entry cannot be written and then
    // taken back. Hence two passes: classify, then write.
    let mut unchanged: Vec<bool> = Vec::with_capacity(page_end.saturating_sub(page_start));
    let mut unchanged_uuids: Vec<[u8; 16]> = Vec::new();

    for (dn, attributes) in &matched[page_start..page_end] {
        let is_unchanged = match (&client_csn, &sync_request) {
            (Some(since), Some(_)) => attributes
                .get(crate::operational::ATTR_ENTRY_CSN)
                .and_then(|attribute| attribute.values.first())
                .is_some_and(|csn| !sync::is_newer(csn, since)),
            _ => false,
        };

        if is_unchanged {
            let uuid = attributes
                .get(crate::model::ATTR_ENTRY_UUID)
                .and_then(|attribute| attribute.values.first().cloned())
                .unwrap_or_else(|| crate::directory::entry_uuid(dn));
            if let Some(uuid) = sync::uuid_bytes(&uuid) {
                unchanged_uuids.push(uuid);
            }
        }

        unchanged.push(is_unchanged);
    }

    // Below the threshold an empty entry per unchanged entry costs less than a set message plus
    // what it takes to say which entries went into it.
    let collapse = unchanged_uuids.len() > PRESENT_SET_THRESHOLD;

    let mut messages: Vec<LdapMessage> = Vec::with_capacity(page_end.saturating_sub(page_start));

    // Whether this answer is a replication stream. Only then are the attributes a server derives
    // about an entry left out: `entryDN` and `subschemaSubentry` describe the server that computed
    // them, and a replica that stored them would fail its own schema check on every poll. An
    // ordinary client asking for `+` is owed them - RFC 5020 says `entryDN` comes back for `+`,
    // and a tool that renders an entry reads it from there.
    let replication_stream = sync_request.is_some();

    for (index, (dn, attributes)) in matched[page_start..page_end].iter().enumerate() {
        let is_unchanged = unchanged[index];

        // A collapsed present entry is not written at all: its UUID went into the set below.
        if is_unchanged && collapse {
            continue;
        }

        let visible: Vec<Attribute> = attributes
            .select(dn, &selection)
            .into_iter()
            .filter(|attribute| {
                // A synchronised answer carries the entry as data, so what the server derived
                // about it is left out; the receiving side strips it too, for peers that predate
                // this rule.
                !(replication_stream && crate::model::is_derived(&attribute.name))
            })
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

        // RFC 4533 §1.3.1: an entry whose content the client does not have goes as `add` *with*
        // its attributes; an unchanged entry goes as an **empty** entry (no attributes) with state
        // `present`, which is what lets a resumed refresh cost the changes rather than the
        // directory.
        let state_controls = match (&sync_request, &sync_cookie) {
            (Some(_), Some(cookie)) => {
                let uuid = attributes
                    .get(crate::model::ATTR_ENTRY_UUID)
                    .and_then(|attribute| attribute.values.first().cloned())
                    .unwrap_or_else(|| crate::directory::entry_uuid(dn));
                match sync::uuid_bytes(&uuid) {
                    Some(uuid) => {
                        let state = if is_unchanged {
                            sync::State::Present
                        } else {
                            sync::State::Add
                        };
                        vec![sync::state_control(state, &uuid, Some(cookie))]
                    }
                    None => Vec::new(),
                }
            }
            _ => Vec::new(),
        };

        let selected = if is_unchanged { Vec::new() } else { selected };

        messages.push(responses::search_result_entry_with_controls(
            message_id,
            dn,
            &selected,
            state_controls,
        ));
    }

    if collapse {
        for batch in unchanged_uuids.chunks(SYNC_ID_SET_BATCH) {
            let mut message = sync::info_id_set(batch, false, sync_cookie.as_deref());
            message.message_id = message_id;
            messages.push(message);
        }
    }

    let mut controls_out: Controls = Vec::new();

    // The end of a synchronised answer carries its own control, and only that: RFC 4533 §2.5
    // says a client that does not find it must treat the refresh as failed even if every entry
    // arrived.
    //
    // `refreshDeletes` is how a refreshOnly answer reports deletions at all, and it means "delete
    // anything you did not receive". That is only honest when the client received everything: a
    // paged answer, a VLV window or a size-limited one leaves entries out for reasons that are not
    // "it was deleted", and saying TRUE there would make a client delete live entries.
    //
    // A client with no cookie is not told to delete either: it is asking for the directory for the
    // first time, and "you did not receive it" says nothing about what it holds.
    //
    // RFC 4533 §1.3.1: `refreshDeletes` FALSE means the client drops every entry this answer did
    // not identify as present - which is safe only when the answer is the whole content, because
    // an entry left out of a page was not deleted. TRUE means "drop only what I named", so an
    // incomplete answer must say TRUE and name nothing: the client then keeps what it has and a
    // later complete poll reconciles it.
    if let Some(cookie) = &sync_cookie {
        let paging = has_paged_control && page.is_requested();
        let complete = window.is_none() && !paging && !size_limit_exceeded;

        controls_out.push(sync::done_control(Some(cookie), !complete));
    }

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
            cursor_cookie(Cursor {
                offset: page_end,
                snapshot: directory.snapshot(),
            })
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

    // The diagnostic says whose limit it was. A client that asked for ten and got ten knows why;
    // one that asked for everything and got a thousand needs to be told the server has a policy,
    // or it pages for ever and never understands what stopped it.
    let diagnostic = if size_limit_exceeded && security.limits.server_bound(request.size_limit) {
        format!(
            "this server returns at most {} entries per search (limits.size_limit); the answer was \
             truncated. Narrow the filter, or ask an operator for a larger limit",
            security.limits.size_limit
        )
    } else {
        String::new()
    };
    // A persistent search does not end: RFC 4533 §1.3.2 says the refresh stage is closed by a
    // `syncInfo` message and the connection then carries changes, so a `searchResDone` here would
    // tell the client the answer is over and it should stop listening.
    let persistent = sync_request
        .as_ref()
        .is_some_and(|request| request.mode == sync::Mode::RefreshAndPersist);

    if persistent && code == ResultCode::Success {
        let mut info = sync::info_refresh_present(sync_cookie.as_deref());
        info.message_id = message_id;
        messages.push(info);
    } else {
        messages.push(search_done_with_controls(
            message_id,
            code,
            &diagnostic,
            controls_out,
        ));
    }

    messages
}

fn without_values(attribute: crate::model::Attribute) -> crate::model::Attribute {
    crate::model::Attribute {
        values: Vec::new().into_boxed_slice(),
        ..attribute
    }
}

/// How many unchanged entries justify a `syncIdSet` instead of one empty entry each.
const PRESENT_SET_THRESHOLD: usize = 8;

/// How many UUIDs go into one `syncIdSet` message.
///
/// Two hundred and fifty-six UUIDs is four kilobytes of payload: small enough that a set message
/// still fits an ordinary frame, large enough that a ten thousand entry refresh is forty messages
/// rather than ten thousand.
const SYNC_ID_SET_BATCH: usize = 256;

/// A search that stays open: what it asked for, and who asked.
///
/// Built when the answer is sent, then used to decide which of the changes the server announces
/// belong to this search. It holds the *request*, not its results: a change is evaluated against
/// the same base, scope and filter the original search used, which is the only way a pushed entry
/// can be trusted to be one the client would have received from a fresh search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub message_id: MessageId,
    pub base_object: String,
    pub scope: crate::directory::Scope,
    pub filter: rasn_ldap::Filter,
    /// The connection this belongs to, for the access rules.
    pub requester: crate::acl::Requester,
    /// The selection the client asked for, so a pushed entry carries the attributes it wants.
    pub selection: Vec<String>,
}

impl Subscription {
    /// The messages a change produces for this search, if it is in the content.
    ///
    /// A deletion is reported when the DN is in scope: the entry is gone, so there is no filter to
    /// evaluate it against, and scope is the most that can honestly be asked.
    ///
    /// A change that moves an entry *out* of the content - a DN edit into another subtree, or an
    /// attribute edit that stops it matching the filter - is not reported as a deletion. Knowing
    /// that would mean remembering what this subscription has already sent, and a wrong `delete`
    /// makes a client drop an entry it should keep.
    pub fn messages_for(
        &self,
        notice: &sync::Notice,
        directory: &crate::directory::Directory,
        security: &crate::security::Security,
    ) -> Vec<rasn_ldap::LdapMessage> {
        let cookie = sync::encode_cookie(directory.snapshot(), directory.csn());
        let uuid = match sync::uuid_bytes(&notice.uuid) {
            Some(uuid) => uuid,
            None => return Vec::new(),
        };

        let in_scope = crate::directory::in_scope_for(&notice.dn, &self.base_object, self.scope);
        if !in_scope {
            return Vec::new();
        }

        match (&notice.entry, notice.kind) {
            (None, _) => {
                // A deletion: an empty entry carrying the state, which is how RFC 4533 §1.3.2
                // says a removal is sent.
                let control = sync::state_control(sync::State::Delete, &uuid, Some(&cookie));
                vec![responses::search_result_entry_with_controls(
                    self.message_id,
                    &notice.dn,
                    &[],
                    vec![control],
                )]
            }
            (Some(entry), _) => {
                if !self.matches(entry) {
                    return Vec::new();
                }
                let visible: Vec<crate::model::Attribute> = entry
                    .attributes()
                    .select(entry.dn(), &self.selection)
                    .into_iter()
                    // Same rule as the refresh above: what a server derived about an entry is
                    // not part of the entry a replica should store.
                    .filter(|attribute| !crate::model::is_derived(&attribute.name))
                    .filter(|attribute| {
                        security
                            .acl
                            .rights(
                                &self.requester,
                                directory,
                                entry.dn(),
                                Some(&*attribute.name),
                            )
                            .read
                    })
                    .collect();

                let control = sync::state_control(sync::State::Add, &uuid, Some(&cookie));
                vec![responses::search_result_entry_with_controls(
                    self.message_id,
                    entry.dn(),
                    &visible,
                    vec![control],
                )]
            }
        }
    }

    fn matches(&self, entry: &crate::model::Entry) -> bool {
        crate::ldap::filter::matches(entry.attributes(), entry.dn(), &self.filter).unwrap_or(false)
    }
}

/// Where a page continues, and which snapshot it continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cursor {
    offset: usize,
    /// The directory snapshot the previous page was cut from.
    snapshot: u64,
}

/// The cookie a page hands back: `<offset>:<snapshot>`.
///
/// Two numbers because one is not enough. The offset says where to continue; the snapshot says
/// what the offset was an offset *into*. Between two pages the directory can be reloaded, or
/// another client can add and delete entries, and then the same offset lands on a different
/// entry - the client silently skips records or sees the same one twice. RFC 2696 leaves the
/// cookie opaque, so this is a legal use of it.
fn cursor_cookie(cursor: Cursor) -> Vec<u8> {
    format!("{}:{}", cursor.offset, cursor.snapshot).into_bytes()
}

fn parse_cookie(cookie: &[u8], snapshot: u64) -> Result<Cursor, String> {
    if cookie.is_empty() {
        return Ok(Cursor {
            offset: 0,
            snapshot,
        });
    }

    let text = std::str::from_utf8(cookie).map_err(|_| {
        format!(
            "paged results cookie '{}' is not readable",
            String::from_utf8_lossy(cookie)
        )
    })?;

    // A cookie without a snapshot is from a client that stored one before this server recorded
    // it: continuing it would be guessing, so it is refused as an unknown cursor.
    let (offset, found) = text.split_once(':').ok_or_else(|| {
        format!("paged results cookie '{text}' is not a cursor this server issued")
    })?;

    let offset: usize = offset
        .parse()
        .map_err(|_| format!("paged results cookie '{text}' has no position"))?;
    let found: u64 = found
        .parse()
        .map_err(|_| format!("paged results cookie '{text}' has no snapshot"))?;

    if found != snapshot {
        return Err(format!(
            "the directory changed while this search was paged (snapshot {found} → {snapshot}), so the offset no longer points where it did; start the search again without a cookie"
        ));
    }

    Ok(Cursor { offset, snapshot })
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
    security: &Security,
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
        ))
        // RFC 4512 5.1: the DSA's notion of the current time, so a client can measure the
        // difference without guessing from its own clock. Advisory clients print nothing without
        // it - `net ads info` reports "Failed to get server's current time" and a server time of
        // 1970 - and a clock difference is the first thing anybody checks when Kerberos rejects
        // a ticket, so an absence here sends that check to the wrong place.
        .push(crate::model::Attribute::single(
            "currentTime",
            &crate::operational::generalized_time(std::time::SystemTime::now()),
        ));

    // RFC 4512 §5.1: the SASL mechanisms this server answers to, published so that a client can
    // choose one without guessing. Samba's `ads_sasl_bind` reads exactly this attribute and
    // compares each value literally against `GSS-SPNEGO`; a server that implements SASL and does
    // not publish it is a domain controller that a joining machine refuses with "Authentication
    // method not supported" - before it has sent a single token, which is what made that refusal
    // read like a missing implementation rather than a missing line here.
    //
    // Published only when an acceptor exists: a server with no keytab cannot accept a ticket, and
    // naming a mechanism in discovery that every attempt must refuse is the same lie in the other
    // direction.
    let attributes = match security.gssapi.is_some() {
        true => attributes.push(crate::model::Attribute::new(
            "supportedSASLMechanisms",
            crate::ldap::sasl_bind::MECHANISMS
                .iter()
                .map(|name| name.to_string())
                .collect(),
        )),
        false => attributes,
    };

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

    /// The values of one attribute of the first entry, as text.
    fn attribute_values(messages: &[LdapMessage], name: &str) -> Vec<String> {
        match &messages[0].protocol_op {
            ProtocolOp::SearchResEntry(entry) => entry
                .attributes
                .iter()
                .find(|attribute| attribute.r#type.0.eq_ignore_ascii_case(name))
                .map(|attribute| {
                    attribute
                        .vals
                        .iter()
                        .map(|value| String::from_utf8_lossy(value).into_owned())
                        .collect()
                })
                .unwrap_or_default(),
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
                // RFC 4512 5.1: without it, a client cannot compare clocks.
                "currentTime",
            ]
        );
        assert_eq!(result_code(&messages), ResultCode::Success);
    }

    #[test]
    fn root_dse_current_time_is_the_present_moment_in_generalized_time() {
        // The value is read back rather than matched as a string: a test that compared text
        // would pass on a server whose clock is set to 1970, which is the failure the attribute
        // exists to expose.
        let session = admin_session();
        let request = request(
            "",
            SearchRequestScope::BaseObject,
            present("objectClass"),
            0,
            &[],
        );

        let before = std::time::SystemTime::now();
        let messages = search(&session, &request, None);
        let after = std::time::SystemTime::now();

        let text = attribute_values(&messages, "currentTime");
        let value = text.first().expect("the root DSE carries currentTime");
        let at = crate::operational::parse_generalized_time(value)
            .unwrap_or_else(|| panic!("currentTime is a generalized time, got {value:?}"));
        assert!(
            at >= before && at <= after,
            "the timestamp falls between the two reads of the clock: {value:?}"
        );
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
        // Approximate matching is the filter this server still refuses; answering it with an
        // empty result would look like "no such person" instead of "not implemented".
        let session = admin_session();
        let filter = Filter::ApproxMatch(AttributeValueAssertion::new(
            AttributeDescription::from("cn"),
            rasn::types::OctetString::from(b"a".as_slice()),
        ));
        let request = request(BASE, SearchRequestScope::WholeSubtree, filter, 0, &[]);

        let messages = search(&session, &request, None);

        assert!(dns(&messages).is_empty());
        assert_eq!(result_code(&messages), ResultCode::UnwillingToPerform);
        assert_eq!(
            diagnostic(&messages),
            "unsupported filter type 'approxMatch'"
        );
    }

    #[test]
    fn an_ordering_filter_is_answered() {
        // `(uidNumber>=100)` used to be refused; now the filter compares and the ordered
        // index narrows, and the two have to agree about who is above the bound.
        let session = admin_session();
        // The fixture's users are `admin` and `alice`, so `(cn>=alice)` is the pair the
        // ordering has to separate: "admin" sorts before "alice" and is excluded, "alice"
        // and the group `group_a` sort after it and are kept.
        let filter = Filter::GreaterOrEqual(AttributeValueAssertion::new(
            AttributeDescription::from("cn"),
            rasn::types::OctetString::from(b"alice".as_slice()),
        ));
        let request = request(BASE, SearchRequestScope::WholeSubtree, filter, 0, &[]);

        let messages = search(&session, &request, None);

        assert_eq!(result_code(&messages), ResultCode::Success);
        let found = dns(&messages);

        assert!(
            found.contains(&"cn=alice,ou=users,dc=example,dc=com".to_string()),
            "the bound itself matches: {found:?}"
        );
        assert!(
            !found.contains(&"cn=admin,ou=users,dc=example,dc=com".to_string()),
            "'admin' sorts before 'alice' and must be excluded: {found:?}"
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
        assert_eq!(
            returned_cookie(&messages),
            b"2:0".to_vec(),
            "the offset, and the snapshot it is an offset into"
        );
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
            "paged results cookie 'nonsense' is not a cursor this server issued"
        );
    }

    /// A directory whose entries carry `entryCSN`, so a resumed refresh can tell them apart.
    fn stamped_directory() -> Directory {
        use crate::model::{Attribute, Attributes, Entry};

        let person = |cn: &str, csn: &str| {
            Entry::new(
                format!("cn={cn},ou=users,{BASE}"),
                Attributes::new()
                    .push(Attribute::new(
                        "objectClass",
                        vec!["top".to_string(), "person".to_string()],
                    ))
                    .push(Attribute::single("cn", cn))
                    .push(Attribute::single("sn", "Person"))
                    .push(Attribute::single("entryCSN", csn).operational()),
            )
        };

        Directory::from_entries(
            BASE,
            "users",
            "groups",
            vec![
                person("alice", "20260101000000.000001Z#000001#001#000000"),
                person("bob", "20260101000000.000002Z#000001#001#000000"),
            ],
        )
    }

    fn sync_control(mode: u8, cookie: Option<&[u8]>, reload_hint: bool) -> Controls {
        let mut body = vec![0x0a, 0x01, mode];
        if let Some(cookie) = cookie {
            body.push(0x04);
            body.push(cookie.len() as u8);
            body.extend_from_slice(cookie);
        }
        if reload_hint {
            body.extend_from_slice(&[0x01, 0x01, 0xff]);
        }

        let mut value = vec![0x30, body.len() as u8];
        value.extend_from_slice(&body);

        vec![Control::new(
            LdapOid::from(crate::ldap::sync::SYNC_OID.as_bytes()),
            true,
            Some(rasn::types::OctetString::from(value)),
        )]
    }

    #[test]
    fn a_cookie_older_than_the_journal_floor_gets_the_content_and_not_a_resume() {
        // The silent case this closes: the journal was pruned, so the changes between the client's
        // cookie and the oldest surviving record are gone, and nothing in what remains says so. A
        // resume would answer as if nothing had happened in between.
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &["entryCSN"],
        );

        // The client is at a change older than anything the journal still holds.
        let cookie =
            crate::ldap::sync::encode_cookie(1, Some("20250101000000.000001Z#000001#001#000000"));
        let directory = stamped_directory()
            .with_csn(Some("20260101000000.000009Z#000001#001#000000".to_string()))
            .with_floor(Some("20260101000000.000001Z#000001#001#000000".to_string()));

        let messages = handle_search(
            &session,
            &directory,
            1,
            &request,
            Some(&sync_control(1, Some(&cookie), false)),
            &security(),
        );

        assert_eq!(
            result_code(&messages),
            ResultCode::Success,
            "without a reload hint the client is simply given the content"
        );
        let entries = synchronised_entries(&messages);
        assert_eq!(
            entries.len(),
            5,
            "the naming context, both units and both users"
        );
        assert!(
            entries.iter().all(|(_, state, _)| *state == 1),
            "every entry arrives as add, not as an unchanged present: the client cannot be told \
             which changes it missed, so it is given the content: {entries:?}"
        );
        assert!(
            entries
                .iter()
                .filter(|(dn, _, _)| dn.starts_with("cn="))
                .all(|(_, _, attributes)| *attributes > 0),
            "and with their attributes, which a resume would have left out: {entries:?}"
        );
    }

    #[test]
    fn a_cookie_older_than_the_floor_is_refused_outright_when_the_client_asked_for_a_reload() {
        // RFC 4533 §3.1: an unrecognised cookie means initial content or an empty answer with
        // `syncRefreshRequired`, and the choice may follow `reloadHint`. A client that asked to be
        // told is told; one that did not gets the content.
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let cookie =
            crate::ldap::sync::encode_cookie(1, Some("20250101000000.000001Z#000001#001#000000"));
        let directory = stamped_directory()
            .with_csn(Some("20260101000000.000009Z#000001#001#000000".to_string()))
            .with_floor(Some("20260101000000.000001Z#000001#001#000000".to_string()));

        let messages = handle_search(
            &session,
            &directory,
            1,
            &request,
            Some(&sync_control(1, Some(&cookie), true)),
            &security(),
        );

        assert!(dns(&messages).is_empty(), "no entry is served");
        assert_eq!(
            result_code(&messages),
            ResultCode::SyncRefreshRequired,
            "the code RFC 4533 §2.6 defines for exactly this"
        );
    }

    #[test]
    fn a_cookie_inside_the_journal_is_still_resumed() {
        // The control case: the floor must not turn every resume into a full refresh, or the
        // journal exists for nothing.
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &["entryCSN"],
        );

        // At the floor itself: everything after it is still in the journal, so this resumes.
        let cookie =
            crate::ldap::sync::encode_cookie(1, Some("20260101000000.000001Z#000001#001#000000"));
        let directory = stamped_directory()
            .with_csn(Some("20260101000000.000009Z#000001#001#000000".to_string()))
            .with_floor(Some("20260101000000.000001Z#000001#001#000000".to_string()));

        let messages = handle_search(
            &session,
            &directory,
            1,
            &request,
            Some(&sync_control(1, Some(&cookie), true)),
            &security(),
        );

        assert_eq!(result_code(&messages), ResultCode::Success);
        let entries = synchronised_entries(&messages);
        assert_eq!(
            entries.len(),
            5,
            "the naming context, both units and both users"
        );
        assert!(
            entries
                .iter()
                .any(|(dn, state, _)| dn.starts_with("cn=alice") && *state == 0),
            "an unchanged entry is present and empty, not resent: {entries:?}"
        );
    }

    /// `(dn, state, attribute count)` for the entries in an answer.
    fn synchronised_entries(messages: &[LdapMessage]) -> Vec<(String, u8, usize)> {
        messages
            .iter()
            .filter_map(|message| {
                let ProtocolOp::SearchResEntry(entry) = &message.protocol_op else {
                    return None;
                };
                let control = message.controls.as_ref()?.iter().find(|control| {
                    control.control_type.as_ref() == crate::ldap::sync::SYNC_OID.as_bytes()
                })?;
                let state =
                    crate::ldap::sync::decode_state(control.control_value.as_ref()?.as_ref())
                        .ok()?;
                let code = match state.state {
                    crate::ldap::sync::State::Present => 0,
                    crate::ldap::sync::State::Add => 1,
                    crate::ldap::sync::State::Modify => 2,
                    crate::ldap::sync::State::Delete => 3,
                };
                Some((
                    entry.object_name.0.to_string(),
                    code,
                    entry.attributes.len(),
                ))
            })
            .collect()
    }

    /// A policy that limits searches, for the tests below.
    fn limited(size_limit: usize, time_limit: Option<std::time::Duration>) -> Security {
        Security {
            limits: crate::limits::Limits {
                size_limit,
                time_limit,
                ..Default::default()
            },
            ..Security::default()
        }
    }

    /// A directory of `count` generated people, for a scan long enough to notice a clock.
    fn many_people(count: usize) -> Directory {
        use crate::model::{Attribute, Attributes, Entry};

        let entries: Vec<Entry> = (0..count)
            .map(|index| {
                let cn = format!("user{index:04}");
                Entry::new(
                    format!("cn={cn},ou=users,{BASE}"),
                    Attributes::new()
                        .push(Attribute::new(
                            "objectClass",
                            vec!["top".to_string(), "person".to_string()],
                        ))
                        .push(Attribute::single("cn", &cn))
                        .push(Attribute::single("sn", "Person")),
                )
            })
            .collect();

        Directory::from_entries(BASE, "users", "groups", entries)
    }

    #[test]
    fn the_servers_own_size_limit_truncates_and_says_so() {
        // The hole this closes: `ldapsearch -z 0` against an unconfigured server returns the whole
        // directory, and nothing an operator wrote has any say in it.
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let messages = handle_search(&session, &directory(), 1, &request, None, &limited(2, None));

        assert_eq!(
            dns(&messages).len(),
            2,
            "at most the server's limit, whatever the client asked for"
        );
        assert_eq!(result_code(&messages), ResultCode::SizeLimitExceeded);
        assert!(
            diagnostic(&messages).contains("limits.size_limit"),
            "the client is told the server has a policy: {}",
            diagnostic(&messages)
        );
    }

    #[test]
    fn a_client_limit_below_the_servers_is_not_the_servers_fault() {
        // A client that asked for two and got two knows why. Blaming the server would send it
        // looking for a setting nobody needs to change.
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            2,
            &[],
        );

        let messages = handle_search(
            &session,
            &directory(),
            1,
            &request,
            None,
            &limited(100, None),
        );

        assert_eq!(dns(&messages).len(), 2);
        assert_eq!(result_code(&messages), ResultCode::SizeLimitExceeded);
        assert!(
            diagnostic(&messages).is_empty(),
            "no server policy was involved: {}",
            diagnostic(&messages)
        );
    }

    #[test]
    fn the_server_limit_is_applied_after_the_filter() {
        // The rule from RFC 4511 and from the plan: a limit checked before the filter refuses a
        // search that would have returned exactly one entry. A directory of five with a limit of
        // two must still answer a filter that matches one.
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("mail"),
            0,
            &[],
        );

        let messages = handle_search(&session, &directory(), 1, &request, None, &limited(2, None));

        assert_eq!(
            dns(&messages).len(),
            2,
            "the two entries that carry a mail attribute"
        );
        assert_eq!(
            result_code(&messages),
            ResultCode::Success,
            "the limit was not reached, so nothing was truncated"
        );
    }

    #[test]
    fn a_truncated_answer_does_not_let_a_replica_prune() {
        // The interaction that would be dangerous: RFX 4533 `refreshDeletes` FALSE tells a replica
        // to delete everything the answer did not name. A server limit truncates the answer for a
        // reason that is not "it was deleted", so the answer must not carry that instruction.
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let cookie = crate::ldap::sync::encode_cookie(1, None);
        let big = stamped_directory()
            .with_csn(Some("20260101000000.000009Z#000001#001#000000".to_string()));

        let messages = handle_search(
            &session,
            &big,
            1,
            &request,
            Some(&sync_control(1, Some(&cookie), false)),
            &limited(2, None),
        );

        // Controls ride on the message, not on the result op inside it.
        let done = messages
            .iter()
            .find(|message| matches!(message.protocol_op, ProtocolOp::SearchResDone(_)))
            .expect("a done");

        let control = done
            .controls
            .as_ref()
            .and_then(|controls| controls.iter().next())
            .expect("a sync done control");
        let value = control.control_value.as_ref().expect("a value").as_ref();

        let (_, refresh_deletes) =
            crate::ldap::sync::decode_done(value).expect("a decodable sync done");
        assert!(
            refresh_deletes,
            "a truncated answer must tell the client to prune only what was named, or it would \
             delete every entry the limit left out"
        );
    }

    #[test]
    fn a_search_that_runs_out_of_time_is_stopped_with_the_reason() {
        // A filter over three hundred entries with a one-nanosecond budget: the deadline is checked
        // every 256 entries, which is why the directory has more than that. The point is that the
        // search stops and says why, rather than running to completion because nothing was
        // watching the clock.
        let session = admin_session();
        let directory = many_people(300);
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let messages = handle_search(
            &session,
            &directory,
            1,
            &request,
            None,
            &limited(0, Some(std::time::Duration::from_nanos(1))),
        );

        assert_eq!(result_code(&messages), ResultCode::TimeLimitExceeded);
        assert!(
            diagnostic(&messages).contains("limits.time_limit"),
            "the diagnostic names the setting an operator would change: {}",
            diagnostic(&messages)
        );
    }

    #[test]
    fn a_search_within_its_time_budget_is_answered() {
        // The control case: a generous budget must not turn into a refusal, or the limit would be
        // a switch that turns the server off.
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let messages = handle_search(
            &session,
            &directory(),
            1,
            &request,
            None,
            &limited(0, Some(std::time::Duration::from_secs(30))),
        );

        assert_eq!(result_code(&messages), ResultCode::Success);
        assert!(!dns(&messages).is_empty());
    }

    #[test]
    fn a_page_continued_after_the_directory_changed_is_refused_not_answered_wrongly() {
        // The defect this closes: the cookie was a bare offset, so a reload or another client's
        // write between two pages made the offset point at a different entry - the client
        // silently skipped records or saw one twice, and nothing said so.
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        // The first page, cut from snapshot 1.
        let first = handle_search(
            &session,
            &directory().at_snapshot(1),
            1,
            &request,
            Some(&paged_control(2, b"")),
            &security(),
        );
        let cookie = returned_cookie(&first);
        assert_eq!(cookie, b"2:1".to_vec(), "the cookie carries snapshot 1");

        // The directory was reloaded since: same entries, different snapshot.
        let second = handle_search(
            &session,
            &directory().at_snapshot(2),
            2,
            &request,
            Some(&paged_control(2, &cookie)),
            &security(),
        );

        assert!(
            dns(&second).is_empty(),
            "no entry is served from a snapshot this page does not belong to"
        );
        assert_eq!(result_code(&second), ResultCode::UnwillingToPerform);
        assert_eq!(
            diagnostic(&second),
            "the directory changed while this search was paged (snapshot 1 → 2), so the offset no longer points where it did; start the search again without a cookie"
        );
    }

    #[test]
    fn a_page_continued_within_the_same_snapshot_is_served() {
        let session = admin_session();
        let request = request(
            BASE,
            SearchRequestScope::WholeSubtree,
            present("objectClass"),
            0,
            &[],
        );

        let first = handle_search(
            &session,
            &directory().at_snapshot(7),
            1,
            &request,
            Some(&paged_control(2, b"")),
            &security(),
        );
        let cookie = returned_cookie(&first);
        assert_eq!(cookie, b"2:7".to_vec());

        let second = handle_search(
            &session,
            &directory().at_snapshot(7),
            2,
            &request,
            Some(&paged_control(2, &cookie)),
            &security(),
        );

        assert_eq!(result_code(&second), ResultCode::Success);
        assert!(
            !dns(&second).is_empty(),
            "the next page is served while the snapshot stands"
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

        let messages = search(&session, &request, Some(&paged_control(2, b"99:0")));

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
    fn search_on_unknown_base_is_no_such_object() {
        // Not an empty success: RFC 4511 §4.5.1.1 requires `noSuchObject` when the base does
        // not exist, and an empty result is indistinguishable from a wrong base to every
        // script that reads it. This test used to assert `Success`, which is what the server
        // did before `ldapsearch` against a real directory with a typo showed an empty answer.
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
        assert_eq!(result_code(&messages), ResultCode::NoSuchObject);
    }

    #[test]
    fn every_base_that_exists_still_answers() {
        // The check must not turn a legitimate base into a refusal: the naming context, both
        // units and an ordinary entry all exist and all answer.
        let session = admin_session();

        for base in [
            BASE,
            "ou=users,dc=example,dc=com",
            "ou=groups,dc=example,dc=com",
            ALICE_DN,
        ] {
            let request = request(
                base,
                SearchRequestScope::BaseObject,
                present("objectClass"),
                0,
                &[],
            );
            let messages = search(&session, &request, None);

            assert_eq!(
                result_code(&messages),
                ResultCode::Success,
                "base {base} must answer"
            );
            assert_eq!(dns(&messages), vec![base.to_string()]);
        }
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
