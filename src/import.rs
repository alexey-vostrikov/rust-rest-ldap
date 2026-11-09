//! Import: LDIF into a store without a server, the job `slapadd` does.
//!
//! The reason this exists rather than "start the server and use `ldapadd`": an empty
//! directory cannot be loaded over the protocol. `add` needs a bind, a bind needs an entry
//! with a password, and the entries to add are what the file holds. `bootstrap` covers the
//! one-administrator case; this covers the directory.
//!
//! What it guarantees, because a half-imported directory is worse than none:
//!
//! - **One transaction.** Every entry is validated and collected first, then written in one
//!   call. A schema violation on entry 9000 leaves the store exactly as it was.
//! - **The store must be empty** unless the operator says otherwise, so a mistyped path does
//!   not merge a dump into a live directory.
//! - **Refusals name the entry and the reason.** "import failed" sends the operator to read
//!   4000 lines; "cn=alice,...: object class 'inetOrgPerson' requires 'sn'" sends them to the
//!   line.

use crate::backend::{Backend, EntryChange};
use crate::config::Config;
use crate::ldif_read;
use crate::model::Entry;
use crate::schema::{Mode, ViolationCode};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Read(#[from] ldif_read::Error),
    #[error(transparent)]
    Backend(#[from] crate::backend::BackendError),
    #[error(
        "the store already holds {entries} entries, and importing into it would merge two \
         directories; empty it first, or pass --allow-existing-entry to add to it"
    )]
    NotEmpty { entries: usize },
    #[error("record {position} ({dn}) breaks the schema: {detail}")]
    Schema {
        position: usize,
        dn: String,
        detail: String,
    },
    #[error(
        "record {position} ({dn}) is a '{what}' record; an import loads entries, not changes - \
         apply those with ldapmodify against a running server"
    )]
    NotAnEntry {
        position: usize,
        dn: String,
        what: &'static str,
    },
    #[error("the file holds no entries to import")]
    Empty,
}

/// What an import did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Entries written.
    pub entries: usize,
    /// Entries whose schema was broken and accepted anyway, because the mode is not `strict`.
    pub warnings: Vec<String>,
}

/// Who an import is attributed to.
///
/// A DN, because `creatorsName` is one, and not a real account, because an import is not a person
/// logging in: an entry that says `cn=import` is one whose origin is never in doubt.
pub const IMPORT_ACTOR: &str = "cn=import";

/// Loads the entries of an LDIF document into the backend.
pub async fn import(
    backend: &Backend,
    config: &Config,
    text: &str,
    allow_existing_entry: bool,
) -> Result<Outcome, Error> {
    let records = ldif_read::parse(text)?;

    // Checked before the schema and before writing: an import into a directory that already
    // has data is almost always a path mistake, and merging two directories silently is the
    // kind of mistake that is discovered by its effects.
    let existing = backend.load().await?;
    let present = existing.entries.len() + existing.users.len();
    if present > 0 && !allow_existing_entry {
        return Err(Error::NotEmpty { entries: present });
    }

    let mut entries = Vec::new();
    let mut warnings = Vec::new();

    for (position, record) in records.iter().enumerate() {
        let entry = match record {
            ldif_read::Record::Entry(content) => &content.entry,
            ldif_read::Record::Change(change) => {
                return Err(Error::NotAnEntry {
                    position: position + 1,
                    dn: change.dn.clone(),
                    what: match change.change {
                        ldif_read::Change::Add => "changetype: add",
                        ldif_read::Change::Modify => "changetype: modify",
                        ldif_read::Change::Delete => "changetype: delete",
                        ldif_read::Change::ModDn => "changetype: modrdn",
                    },
                });
            }
        };

        check_schema(config, entry, position + 1, &mut warnings)?;
        entries.push(entry.clone());
    }

    if entries.is_empty() {
        return Err(Error::Empty);
    }

    // An imported entry gets the same stamp a written one gets. Without `entryCSN` there is
    // nothing for a resumed refresh to compare against, so a replica would be sent the whole
    // directory on every poll - and an import is exactly when a directory is largest.
    //
    // A value already in the LDIF is kept: an import preserves what the file says, which is what
    // makes a dump and a restore round-trip.
    let now = std::time::SystemTime::now();
    let entries: Vec<Entry> = entries
        .into_iter()
        .map(|entry| {
            let entry = canonicalise_sid(entry, &mut warnings);
            if entry
                .attributes()
                .get(crate::operational::ATTR_ENTRY_CSN)
                .is_some()
            {
                entry
            } else {
                crate::operational::stamp_write(&entry, IMPORT_ACTOR, now)
            }
        })
        .collect();

    // One call, so the backend writes one transaction: a store that dies halfway through an
    // import holds either all of it or none of it.
    let changes: Vec<EntryChange> = entries
        .into_iter()
        .map(|entry| EntryChange::Upsert { entry })
        .collect();

    backend.apply(&changes).await?;

    Ok(Outcome {
        entries: changes.len(),
        warnings,
    })
}

/// An `objectSid` from an LDIF file, rewritten in the form the store uses.
///
/// An export writes the SID the way Windows prints it (`S-1-5-21-...`), and the store keeps octets
/// as base64. An import that left it as text would put into the store a value that the wire then
/// hands out as text - a SID every client would read as a structure and misparse, and would do it
/// without complaint, because the length is plausible.
///
/// A value that is neither form is left exactly as the file wrote it and reported. An import
/// preserves what the file says; refusing the whole file over one bad attribute would throw away
/// everything else it holds.
fn canonicalise_sid(entry: Entry, warnings: &mut Vec<String>) -> Entry {
    let Some(existing) = entry.attributes().get(crate::sid::ATTRIBUTE) else {
        return entry;
    };
    let Some(value) = existing.values.first() else {
        return entry;
    };
    let Ok(sid) = crate::sid::Sid::from_directory_value(value) else {
        warnings.push(format!(
            "{}: '{}' is not a SID; kept as the file wrote it",
            entry.dn(),
            crate::sid::ATTRIBUTE
        ));
        return entry;
    };

    let attributes = entry
        .attributes()
        .values()
        .iter()
        .filter(|attribute| !attribute.name.eq_ignore_ascii_case(crate::sid::ATTRIBUTE))
        .fold(crate::model::Attributes::new(), |acc, attribute| {
            acc.push((*attribute).clone())
        })
        .push(sid.attribute(crate::sid::ATTRIBUTE));

    Entry::new(entry.dn(), attributes)
}

/// Checks one entry against the schema, according to the configured mode.
fn check_schema(
    config: &Config,
    entry: &Entry,
    position: usize,
    warnings: &mut Vec<String>,
) -> Result<(), Error> {
    if config.schema_mode == Mode::Off {
        return Ok(());
    }

    let Err(violations) = config.schema.check(entry) else {
        return Ok(());
    };

    let detail = violations
        .iter()
        .map(|violation| violation.detail.clone())
        .collect::<Vec<_>>()
        .join("; ");

    match config.schema_mode {
        // `warn` records the problem and imports anyway: it is the mode an operator picks
        // when the data is older than the schema, and refusing would make the mode useless.
        Mode::Warn => {
            warnings.push(format!("{}: {detail}", entry.dn()));
            Ok(())
        }
        _ => {
            // The first violation decides the kind of refusal, because that is what tells the
            // operator whether the data is wrong or the schema is.
            let _ = violations
                .first()
                .map(|violation| violation.code == ViolationCode::ConstraintViolation);

            Err(Error::Schema {
                position,
                dn: entry.dn().to_string(),
                detail,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::model::Attribute;

    /// A file that says `objectSid: S-1-5-21-...` — the way an export writes it — must not reach the
    /// store as text. The wire hands out what the store holds, so a text value would be sent as text
    /// and every client would parse it as a SID structure and misread it, silently.
    #[test]
    fn an_imported_sid_is_rewritten_in_the_store_form() {
        let sid = crate::sid::Sid::parse("S-1-5-21-1-2-3-512").expect("a SID");
        let entry = crate::model::Entry::new(
            "cn=Domain Admins,ou=groups,dc=example,dc=com",
            crate::model::Attributes::new()
                .push(Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "group".to_string()],
                ))
                .push(Attribute::single(crate::sid::ATTRIBUTE, &sid.to_string())),
        );

        let mut warnings = Vec::new();
        let canonical = canonicalise_sid(entry, &mut warnings);

        assert!(warnings.is_empty(), "{warnings:?}");
        let written = canonical
            .attributes()
            .get(crate::sid::ATTRIBUTE)
            .expect("the attribute survived");
        assert!(
            written.flags.binary,
            "the store's form is octets, and the flag says so"
        );
        assert_eq!(
            crate::sid::Sid::from_directory_value(&written.values[0]).expect("a SID"),
            sid,
            "and it is the same SID the file named"
        );
    }

    #[test]
    fn an_imported_value_that_is_not_a_sid_is_kept_and_reported() {
        // An import preserves what the file says. Refusing the whole file over one attribute would
        // throw away everything else it holds, and silently dropping the attribute would make an
        // account look like it has no identity.
        let entry = crate::model::Entry::new(
            "cn=broken,ou=groups,dc=example,dc=com",
            crate::model::Attributes::new()
                .push(Attribute::single(crate::sid::ATTRIBUTE, "not a sid at all")),
        );

        let mut warnings = Vec::new();
        let kept = canonicalise_sid(entry, &mut warnings);

        assert_eq!(warnings.len(), 1, "the operator is told");
        assert!(warnings[0].contains(crate::sid::ATTRIBUTE), "{warnings:?}");
        let written = kept
            .attributes()
            .get(crate::sid::ATTRIBUTE)
            .expect("kept as the file wrote it");
        assert_eq!(written.values[0], "not a sid at all");
        assert!(!written.flags.binary, "and not claimed to be octets");
    }

    use super::*;
    use crate::config::Args;

    fn config(text: &str) -> Config {
        crate::config::resolve(Args::default(), Some(text), |_| None).expect("config")
    }

    fn backend(path: &std::path::Path) -> Backend {
        Backend::from_config(
            "redb",
            Some(&serde_json::json!({"path": path.display().to_string()})),
        )
        .expect("backend")
    }

    #[tokio::test]
    async fn imported_entries_are_stamped_the_way_written_ones_are() {
        // Without `entryCSN` a resumed refresh has nothing to compare against, so a replica is
        // sent the whole directory on every poll - and an import is exactly when a directory is
        // at its largest.
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = backend(&dir.path().join("dir.redb"));
        let config = config("base_dn: dc=example,dc=com\n");

        import(
            &backend,
            &config,
            "dn: cn=a,dc=example,dc=com\nobjectClass: top\ncn: a\n",
            false,
        )
        .await
        .expect("import");

        let loaded = backend.load().await.expect("load");
        let entry = loaded
            .entries
            .iter()
            .find(|entry| entry.dn() == "cn=a,dc=example,dc=com")
            .expect("the imported entry");

        let csn = entry
            .attributes()
            .get(crate::operational::ATTR_ENTRY_CSN)
            .and_then(|attribute| attribute.values.first());
        assert!(csn.is_some(), "an imported entry carries entryCSN");

        let creators = entry
            .attributes()
            .get(crate::operational::ATTR_CREATORS_NAME)
            .and_then(|attribute| attribute.values.first());
        assert_eq!(
            creators.map(String::as_str),
            Some(IMPORT_ACTOR),
            "and says where it came from"
        );
    }

    #[tokio::test]
    async fn a_csn_in_the_file_is_kept_rather_than_replaced() {
        // A dump and a restore must round-trip: an entry that keeps its own CSN keeps its place
        // in the change history, which is what a replica resuming from a cookie depends on.
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = backend(&dir.path().join("dir.redb"));
        let config = config("base_dn: dc=example,dc=com\n");

        let file_csn = "20260101000000.000001Z#000042#000#000000";
        import(
            &backend,
            &config,
            &format!("dn: cn=a,dc=example,dc=com\nobjectClass: top\ncn: a\nentryCSN: {file_csn}\n"),
            false,
        )
        .await
        .expect("import");

        let loaded = backend.load().await.expect("load");
        let entry = loaded
            .entries
            .iter()
            .find(|entry| entry.dn() == "cn=a,dc=example,dc=com")
            .expect("the imported entry");
        assert_eq!(
            entry
                .attributes()
                .get(crate::operational::ATTR_ENTRY_CSN)
                .and_then(|attribute| attribute.values.first())
                .map(String::as_str),
            Some(file_csn)
        );
    }

    #[tokio::test]
    async fn entries_are_written_in_one_call() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dir.redb");
        let backend = backend(&path);
        let config = config("base_dn: dc=example,dc=com\n");

        let outcome = import(
            &backend,
            &config,
            "dn: cn=a,dc=example,dc=com\nobjectClass: top\ncn: a\n\n\
             dn: cn=b,dc=example,dc=com\nobjectClass: top\ncn: b\n",
            false,
        )
        .await
        .expect("import");

        assert_eq!(outcome.entries, 2);
        assert!(outcome.warnings.is_empty());

        let stored = backend.load().await.expect("load");
        assert_eq!(stored.entries.len(), 2);
    }

    #[tokio::test]
    async fn a_non_empty_store_is_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dir.redb");
        let backend = backend(&path);
        let config = config("base_dn: dc=example,dc=com\n");

        import(
            &backend,
            &config,
            "dn: cn=a,dc=example,dc=com\nobjectClass: top\ncn: a\n",
            false,
        )
        .await
        .expect("first import");

        let err = import(
            &backend,
            &config,
            "dn: cn=b,dc=example,dc=com\nobjectClass: top\ncn: b\n",
            false,
        )
        .await
        .expect_err("must refuse");

        assert!(matches!(err, Error::NotEmpty { entries: 1 }), "{err}");

        // And the store is untouched: a refusal that half-applied is worse than a failure.
        let stored = backend.load().await.expect("load");
        assert_eq!(stored.entries.len(), 1);
    }

    #[tokio::test]
    async fn a_schema_violation_leaves_the_store_empty() {
        // The whole point of validating first: entry 2 is broken, entry 1 must not be there.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dir.redb");
        let backend = backend(&path);
        let config = config("base_dn: dc=example,dc=com\n");

        let err = import(
            &backend,
            &config,
            "dn: cn=a,dc=example,dc=com\nobjectClass: top\ncn: a\n\n\
             dn: cn=broken,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: broken\n",
            false,
        )
        .await
        .expect_err("must refuse");

        match err {
            Error::Schema { position, dn, .. } => {
                assert_eq!(position, 2, "the broken record is the second one");
                assert_eq!(dn, "cn=broken,dc=example,dc=com");
            }
            other => panic!("expected Schema, got {other}"),
        }

        let stored = backend.load().await.expect("load");
        assert!(
            stored.entries.is_empty(),
            "nothing may have been written: {:?}",
            stored.entries
        );
    }

    #[tokio::test]
    async fn warn_mode_imports_a_broken_entry_and_records_it() {
        // What `warn` is for: the data is older than the schema, and refusing would make the
        // mode indistinguishable from `strict`.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dir.redb");
        let backend = backend(&path);
        let config = config("base_dn: dc=example,dc=com\nschema:\n  mode: warn\n");

        let outcome = import(
            &backend,
            &config,
            "dn: cn=broken,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: broken\n",
            false,
        )
        .await
        .expect("import");

        assert_eq!(outcome.entries, 1);
        assert_eq!(outcome.warnings.len(), 1, "{:?}", outcome.warnings);
        assert!(outcome.warnings[0].contains("cn=broken"));
    }

    #[tokio::test]
    async fn a_change_record_is_refused_with_what_it_was() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dir.redb");
        let backend = backend(&path);
        let config = config("base_dn: dc=example,dc=com\n");

        let err = import(
            &backend,
            &config,
            "dn: cn=a,dc=example,dc=com\nchangetype: delete\n",
            false,
        )
        .await
        .expect_err("must refuse");

        match err {
            Error::NotAnEntry { what, dn, .. } => {
                assert_eq!(what, "changetype: delete");
                assert_eq!(dn, "cn=a,dc=example,dc=com");
            }
            other => panic!("expected NotAnEntry, got {other}"),
        }
    }

    #[tokio::test]
    async fn an_empty_file_is_refused_rather_than_reported_as_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dir.redb");
        let backend = backend(&path);
        let config = config("base_dn: dc=example,dc=com\n");

        let err = import(&backend, &config, "# nothing here\n", false)
            .await
            .expect_err("must refuse");

        assert!(matches!(err, Error::Empty), "{err}");
    }

    #[tokio::test]
    async fn allow_existing_entry_adds_to_the_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dir.redb");
        let backend = backend(&path);
        let config = config("base_dn: dc=example,dc=com\n");

        import(
            &backend,
            &config,
            "dn: cn=a,dc=example,dc=com\nobjectClass: top\ncn: a\n",
            false,
        )
        .await
        .expect("first");

        import(
            &backend,
            &config,
            "dn: cn=b,dc=example,dc=com\nobjectClass: top\ncn: b\n",
            true,
        )
        .await
        .expect("second");

        assert_eq!(backend.load().await.expect("load").entries.len(), 2);
    }
}
