//! SASL: proving who a client is without sending a password.
//!
//! This module holds the half of GSSAPI that can be decided without a socket - the keytab, the
//! realm table, and the rule that turns a Kerberos principal into a DN in this directory. The
//! accept loop lives in [`crate::ldap::sasl_bind`] and does nothing but carry tokens in and
//! [`Identity`]s out.
//!
//! # Why GSSAPI at all
//!
//! A password bind needs the password: on the client machine, in a file, readable by the service
//! that runs as that account. Kerberos replaces it with a ticket the client already holds - a
//! machine account, a service account under systemd credentials, an sssd-managed user - and the
//! server never sees a secret that could be reused elsewhere. That is the whole argument, and it
//! is why this is worth the complexity the protocol brings.
//!
//! # No C
//!
//! The usual way to accept a Kerberos ticket is to link `libgssapi`. That would end the rule this
//! server is built on, so the accept path uses [`rskrb5`] instead: pure Rust, ticket decryption,
//! authenticator checks and replay detection included. The one thing it does not do is channel
//! binding (`tls-server-end-point`), which is a recorded limitation and the reason a ticket is
//! only accepted on a TLS connection.
//!
//! # The mapping, and why it refuses
//!
//! A ticket proves *a principal*, and the directory holds *an entry*: something has to connect the
//! two. Guessing - "the principal is alice, so the entry is the first thing called alice" - is how
//! a directory hands one person's record to another. So the realm table says exactly which
//! subtree a realm maps to, and a realm that is not listed is refused rather than approximated.
use std::collections::BTreeMap;
use std::path::PathBuf;

/// What the `sasl:` section says.
///
/// `None` in the configuration is "no SASL at all", which is what every existing deployment is and
/// stays: the section is additive and a server without a keytab refuses `GSSAPI` with
/// `authMethodNotSupported`, exactly as it does today.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct SaslConfig {
    /// The keytab holding this service's key.
    ///
    /// The file a `ktpass`/`kadmin ktadd` produced: `ldap/host.example.com@EXAMPLE.COM` and its
    /// key, version number included. Read once at startup - a keytab is a secret and re-reading it
    /// on every bind would turn a file permission mistake into a per-request failure.
    pub keytab: Option<PathBuf>,
    /// The principal the ticket is addressed to, when it differs from the default.
    ///
    /// Default: the `sname` in the ticket, which is `ldap/<host>` by convention. Here for a
    /// deployment whose keytab holds several keys and whose clients ask for a specific one.
    pub service_principal: Option<String>,
    /// Accepted realms and where their principals live.
    ///
    /// Empty with a `keytab` set is a configuration error, not a permissive default: a ticket
    /// from a realm nobody configured has no subtree to land in.
    pub realms: Vec<RealmConfig>,
}

/// One `realms:` entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct RealmConfig {
    /// The Kerberos realm, matched without regard to case.
    ///
    /// Realm names are case-sensitive by the letter of RFC 4120 and uppercase by every convention
    /// that exists; a file that says `example.com` and a ticket that says `EXAMPLE.COM` are the
    /// same realm, and refusing that difference would be a support call, not a security property.
    pub name: String,
    /// The entry a principal maps to.
    ///
    /// `{user}` is the first component of the principal (`alice` in `alice/admin`), `{principal}`
    /// is all of them joined by `/`, `{realm}` is the realm and `{base}` is the naming context.
    /// Every value is escaped before it becomes an RDN, so a principal called `a,b` cannot address
    /// a DN outside the intended subtree.
    ///
    /// Default: `uid={user},ou=users,{base}` - the shape this server created for its own users.
    #[serde(default)]
    pub dn: Option<String>,
}

/// A configuration the server cannot honour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaslError {
    /// A keytab that is missing, unreadable, or holds no keys.
    Keytab { path: PathBuf, detail: String },
    /// A realm name that is empty, or listed twice with different rules.
    Realm { name: String, detail: String },
    /// A template that produces a DN outside the naming context.
    Template { realm: String, dn: String },
    /// The sentence that acknowledges tickets on an unencrypted connection is absent.
    PlaintextNotAcknowledged,
}

impl std::fmt::Display for SaslError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keytab { path, detail } => write!(
                formatter,
                "keytab '{}' cannot be used: {detail}",
                path.display()
            ),
            Self::Realm { name, detail } => write!(formatter, "realm '{name}': {detail}"),
            Self::Template { realm, dn } => write!(
                formatter,
                "realm '{realm}': the template produces '{dn}', which is not under the naming \
                 context; a principal must not be able to name an entry outside the directory \
                 this server serves"
            ),
            Self::PlaintextNotAcknowledged => write!(
                formatter,
                "GSSAPI is configured without TLS: a ticket carries no channel binding here, so a \
                 captured one can be replayed; set `sasl.AllowUnencryptedGssapi` to the sentence \
                 if that is really intended"
            ),
        }
    }
}

/// A configured realm, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Realm {
    /// Normalized to upper case, which is how a realm is compared.
    pub name: String,
    template: String,
}

/// A verified principal, and the entry it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// `alice@EXAMPLE.COM`, as the ticket said.
    pub principal: String,
    /// The DN the realm table produced, already normalized.
    pub dn: String,
}

/// The accept side: a keytab, the realms it serves, and one replay cache for the process.
pub struct Gssapi {
    keytab: rskrb5::keytab::Keytab,
    service_principal: Option<Vec<String>>,
    realms: BTreeMap<String, Realm>,
    /// One cache for every connection.
    ///
    /// Per connection would be no cache at all: a captured AP-REQ replayed on a *new* connection
    /// would be accepted, which is precisely the attack the cache exists to stop.
    replay: rskrb5::service::SharedReplayCache,
}

/// Prints what was configured, never the keys.
///
/// A derived `Debug` would put key material into any log line, panic message or test failure that
/// formats a `Config`, which is exactly how a secret leaves a host.
impl std::fmt::Debug for Gssapi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Gssapi")
            .field(
                "service_principal",
                &self.service_principal.as_ref().map(|parts| parts.join("/")),
            )
            .field("realms", &self.realms.keys().collect::<Vec<_>>())
            .field("keytab_entries", &self.keytab.entries().len())
            .finish_non_exhaustive()
    }
}

impl Gssapi {
    /// Checks everything about the section that can be checked without reading a file.
    ///
    /// Separate from [`Gssapi::load`] so that `--check-config` answers the question it is asked -
    /// "is this configuration usable" - without needing read access to a keytab, which on a
    /// hardened host belongs to root and to the service account only. The two share the realm
    /// table and the template rules, so they cannot disagree about what is valid.
    pub fn validate(config: &SaslConfig, base_dn: &str) -> Result<(), SaslError> {
        let realms = Self::check_realms(config, base_dn)?;

        if config.keytab.is_some() && realms.is_empty() {
            return Err(SaslError::Realm {
                name: String::new(),
                detail: "a keytab is configured but no realms are, so no principal has a subtree \
                         to land in"
                    .to_string(),
            });
        }

        Ok(())
    }

    /// Loads the keytab and builds the acceptor.
    pub fn load(config: &SaslConfig, base_dn: &str) -> Result<Option<Self>, SaslError> {
        let Some(path) = &config.keytab else {
            // A `realms:` list with no keytab describes something the server cannot do; saying so
            // is better than starting and refusing every bind.
            if !config.realms.is_empty() {
                return Err(SaslError::Keytab {
                    path: PathBuf::new(),
                    detail: "a keytab is required when realms are configured".to_string(),
                });
            }
            return Ok(None);
        };

        let keytab = rskrb5::keytab::Keytab::load(path).map_err(|err| SaslError::Keytab {
            path: path.clone(),
            detail: err.to_string(),
        })?;

        if keytab.entries().is_empty() {
            return Err(SaslError::Keytab {
                path: path.clone(),
                detail: "the keytab holds no keys".to_string(),
            });
        }

        let service_principal = match &config.service_principal {
            None => None,
            Some(text) => {
                let (name, _realm) = match text.split_once('@') {
                    Some((name, realm)) => (name.to_string(), Some(realm)),
                    None => (text.clone(), None),
                };
                let components: Vec<String> = name.split('/').map(str::to_string).collect();
                if components.iter().any(|part| part.is_empty()) {
                    return Err(SaslError::Realm {
                        name: text.clone(),
                        detail: "a service principal has an empty component".to_string(),
                    });
                }
                Some(components)
            }
        };

        let realms = Self::check_realms(config, base_dn)?;

        if realms.is_empty() {
            return Err(SaslError::Realm {
                name: String::new(),
                detail: "a keytab is configured but no realms are, so no principal has a subtree \
                         to land in"
                    .to_string(),
            });
        }

        Ok(Some(Self {
            keytab,
            service_principal,
            realms,
            replay: rskrb5::service::SharedReplayCache::new(),
        }))
    }

    /// The realm table, checked against the naming context.
    fn check_realms(
        config: &SaslConfig,
        base_dn: &str,
    ) -> Result<BTreeMap<String, Realm>, SaslError> {
        let mut realms: BTreeMap<String, Realm> = BTreeMap::new();

        for entry in &config.realms {
            let name = entry.name.trim().to_ascii_uppercase();
            if name.is_empty() {
                return Err(SaslError::Realm {
                    name: entry.name.clone(),
                    detail: "the realm name is empty".to_string(),
                });
            }
            if let Some(existing) = realms.get(&name) {
                if existing.template != template_of(entry) {
                    return Err(SaslError::Realm {
                        name,
                        detail: "the same realm is configured twice with different templates"
                            .to_string(),
                    });
                }
                continue;
            }

            let template = template_of(entry);

            // Checked against the naming context with a stand-in value, so a template that points
            // outside is a startup error rather than a wrong answer at the first bind.
            let sample = render(&template, "probe", "probe", &name, base_dn);
            if !crate::dn::is_descendant_or_self(base_dn, &sample)
                && sample != crate::dn::normalize(base_dn)
            {
                return Err(SaslError::Template {
                    realm: name,
                    dn: sample,
                });
            }

            realms.insert(name.clone(), Realm { name, template });
        }

        Ok(realms)
    }

    /// The keys this service holds.
    pub fn keytab(&self) -> &rskrb5::keytab::Keytab {
        &self.keytab
    }

    /// The principal the ticket must be addressed to, when one is configured.
    pub fn service_principal(&self) -> Option<&[String]> {
        self.service_principal.as_deref()
    }

    /// The replay cache shared by every connection.
    pub fn replay(&self) -> rskrb5::service::SharedReplayCache {
        self.replay.clone()
    }

    /// Turns a verified principal into the entry it names.
    ///
    /// `None` when the realm is not configured - and that is a refusal, not a fallback: a ticket
    /// from a realm nobody mapped has no honest subtree, and inventing one would put a stranger's
    /// principal into somebody's directory.
    pub fn identity(
        &self,
        principal: &rskrb5::service::Principal,
        base_dn: &str,
    ) -> Option<Identity> {
        let realm = self.realms.get(&principal.realm.to_ascii_uppercase())?;

        let user = principal.components.first()?.clone();
        let full = principal.name();
        let dn = render(&realm.template, &user, &full, &principal.realm, base_dn);

        Some(Identity {
            principal: format!("{full}@{}", principal.realm),
            dn: crate::dn::normalize(&dn),
        })
    }

    /// The realms this server accepts, for a startup banner or a diagnostic.
    pub fn realms(&self) -> impl Iterator<Item = &str> {
        self.realms.keys().map(String::as_str)
    }
}

/// The template a realm entry configures, with the default filled in.
fn template_of(entry: &RealmConfig) -> String {
    entry
        .dn
        .clone()
        .unwrap_or_else(|| "uid={user},ou=users,{base}".to_string())
}

/// Substitutes the placeholders, escaping every value that becomes an RDN.
fn render(template: &str, user: &str, principal: &str, realm: &str, base_dn: &str) -> String {
    // The base is a DN, not a value: it is taken apart and rejoined, not escaped into one
    // enormous RDN. Every other substitution is a value and is escaped.
    template
        .replace("{user}", &crate::dn::escape_value(user))
        .replace("{principal}", &crate::dn::escape_value(principal))
        .replace("{realm}", &crate::dn::escape_value(realm))
        .replace("{base}", base_dn)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "dc=example,dc=com";

    fn realm(name: &str, dn: Option<&str>) -> RealmConfig {
        RealmConfig {
            name: name.to_string(),
            dn: dn.map(str::to_string),
        }
    }

    fn principal(text: &str) -> rskrb5::service::Principal {
        let (name, realm) = text.split_once('@').expect("realm");
        rskrb5::service::Principal {
            realm: realm.to_string(),
            name_type: 1,
            components: name.split('/').map(str::to_string).collect(),
        }
    }

    #[test]
    fn a_realm_maps_a_principal_to_an_entry() {
        let realms = BTreeMap::from([(
            "EXAMPLE.COM".to_string(),
            Realm {
                name: "EXAMPLE.COM".to_string(),
                template: "uid={user},ou=users,{base}".to_string(),
            },
        )]);

        let gssapi = Gssapi {
            keytab: rskrb5::keytab::Keytab::new(),
            service_principal: None,
            realms,
            replay: rskrb5::service::SharedReplayCache::new(),
        };

        let identity = gssapi
            .identity(&principal("alice@EXAMPLE.COM"), BASE)
            .expect("a mapping");

        assert_eq!(identity.dn, "uid=alice,ou=users,dc=example,dc=com");
        assert_eq!(identity.principal, "alice@EXAMPLE.COM");
    }

    #[test]
    fn a_realm_is_matched_without_regard_to_case() {
        // A file says `example.com`, a ticket says `EXAMPLE.COM`. Refusing that difference is a
        // support call, not a security property.
        let realms = BTreeMap::from([(
            "EXAMPLE.COM".to_string(),
            Realm {
                name: "EXAMPLE.COM".to_string(),
                template: "uid={user},ou=users,{base}".to_string(),
            },
        )]);

        let gssapi = Gssapi {
            keytab: rskrb5::keytab::Keytab::new(),
            service_principal: None,
            realms,
            replay: rskrb5::service::SharedReplayCache::new(),
        };

        assert!(
            gssapi
                .identity(&principal("alice@example.com"), BASE)
                .is_some()
        );
    }

    #[test]
    fn an_unconfigured_realm_is_refused_rather_than_approximated() {
        let realms = BTreeMap::from([(
            "EXAMPLE.COM".to_string(),
            Realm {
                name: "EXAMPLE.COM".to_string(),
                template: "uid={user},ou=users,{base}".to_string(),
            },
        )]);

        let gssapi = Gssapi {
            keytab: rskrb5::keytab::Keytab::new(),
            service_principal: None,
            realms,
            replay: rskrb5::service::SharedReplayCache::new(),
        };

        assert_eq!(gssapi.identity(&principal("alice@EVIL.ORG"), BASE), None);
    }

    #[test]
    fn a_principal_that_would_escape_the_subtree_is_escaped_into_one_rdn() {
        // The value comes from the client's ticket, so it is attacker-chosen. A comma in it would
        // otherwise end the RDN and name an entry somewhere else entirely.
        let template = "uid={user},ou=users,{base}";
        let rendered = render(
            template,
            "alice,dc=evil",
            "alice,dc=evil",
            "EXAMPLE.COM",
            BASE,
        );

        assert_eq!(rendered, "uid=alice\\,dc=evil,ou=users,dc=example,dc=com");

        let (_, value, _) = crate::dn::split_first_rdn(&rendered);
        assert_eq!(crate::dn::unescape(&value), "alice,dc=evil");
    }

    #[test]
    fn a_multi_component_principal_uses_its_first_component() {
        let template = "uid={user},ou=users,{base}";
        assert_eq!(
            render(template, "alice", "alice/admin", "EXAMPLE.COM", BASE),
            "uid=alice,ou=users,dc=example,dc=com"
        );
        // ...while a template that asks for the whole principal gets all of it, escaped.
        assert_eq!(
            render(
                "cn={principal},{base}",
                "alice",
                "alice/admin",
                "EXAMPLE.COM",
                BASE
            ),
            "cn=alice/admin,dc=example,dc=com"
        );
    }

    #[test]
    fn a_template_outside_the_naming_context_is_refused_at_startup() {
        // The template is configuration, so getting it wrong is an operator mistake - and one that
        // would let a ticket name an entry in another directory. Caught here, not at the first
        // bind.
        let error = Gssapi::load(
            &SaslConfig {
                keytab: Some(PathBuf::from("/tmp/nonexistent.keytab")),
                service_principal: None,
                realms: vec![realm("EXAMPLE.COM", Some("uid={user},dc=other,dc=org"))],
            },
            BASE,
        )
        .expect_err("must refuse");

        // The keytab is checked first, so a missing file is what a fresh configuration hits; the
        // template check is exercised with a keytab that exists.
        assert!(matches!(error, SaslError::Keytab { .. }), "{error}");
    }

    #[test]
    fn a_realm_list_without_a_keytab_is_refused() {
        let error = Gssapi::load(
            &SaslConfig {
                keytab: None,
                service_principal: None,
                realms: vec![realm("EXAMPLE.COM", None)],
            },
            BASE,
        )
        .expect_err("must refuse");

        assert!(matches!(error, SaslError::Keytab { .. }), "{error}");
    }

    #[test]
    fn no_keytab_and_no_realms_is_no_sasl() {
        // Every deployment that exists today. Additive, and silent.
        assert!(
            Gssapi::load(&SaslConfig::default(), BASE)
                .expect("no sasl")
                .is_none()
        );
    }

    /// A keytab on disk holding one key, as `kadmin ktadd` would have written it.
    fn keytab_at(dir: &std::path::Path) -> (PathBuf, Vec<u8>) {
        let path = dir.join("test.keytab");
        let mut keytab = rskrb5::keytab::Keytab::new();
        // AES256-CTS-HMAC-SHA1-96, the etype every modern KDC issues by default.
        keytab
            .add_entry_from_password(
                rskrb5::keytab::Principal::new("EXAMPLE.COM", 1, ["ldap", "host.example.com"]),
                b"secret",
                std::time::SystemTime::now(),
                1,
                18,
            )
            .expect("an entry");
        keytab.save(&path).expect("saved");

        let bytes = std::fs::read(&path).expect("read back");
        (path, bytes)
    }

    #[test]
    fn a_keytab_with_a_key_is_loaded_and_its_realms_are_kept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _) = keytab_at(dir.path());

        let gssapi = Gssapi::load(
            &SaslConfig {
                keytab: Some(path),
                service_principal: Some("ldap/host.example.com@EXAMPLE.COM".to_string()),
                realms: vec![realm("example.com", None)],
            },
            BASE,
        )
        .expect("loaded")
        .expect("some sasl");

        assert_eq!(gssapi.keytab().entries().len(), 1);
        assert_eq!(
            gssapi.service_principal().map(|parts| parts.join("/")),
            Some("ldap/host.example.com".to_string()),
            "the realm is dropped: the keytab lookup matches components and realm separately"
        );
        assert_eq!(gssapi.realms().collect::<Vec<_>>(), vec!["EXAMPLE.COM"]);
    }

    #[test]
    fn a_keytab_that_is_not_there_is_a_startup_error_naming_the_file() {
        let error = Gssapi::load(
            &SaslConfig {
                keytab: Some(PathBuf::from("/nonexistent/dir/ldap.keytab")),
                ..SaslConfig::default()
            },
            BASE,
        )
        .expect_err("must refuse");

        match error {
            SaslError::Keytab { path, .. } => {
                assert_eq!(path, PathBuf::from("/nonexistent/dir/ldap.keytab"))
            }
            other => panic!("expected a keytab error, got {other:?}"),
        }
    }

    #[test]
    fn a_keytab_with_no_keys_is_refused() {
        // The shape a mistyped `ktutil add_entry` leaves behind. Starting with it would mean every
        // bind fails at run time instead of the server failing at startup.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty.keytab");
        rskrb5::keytab::Keytab::new().save(&path).expect("saved");

        let error = Gssapi::load(
            &SaslConfig {
                keytab: Some(path),
                ..SaslConfig::default()
            },
            BASE,
        )
        .expect_err("must refuse");

        assert!(matches!(error, SaslError::Keytab { .. }), "{error}");
    }

    #[test]
    fn validate_answers_without_reading_the_keytab() {
        // What `--check-config` needs: a full answer about the section, with no access to a file
        // that on a hardened host belongs to root and to the service account.
        Gssapi::validate(
            &SaslConfig {
                keytab: Some(PathBuf::from("/root/only/ldap.keytab")),
                service_principal: None,
                realms: vec![realm("EXAMPLE.COM", None)],
            },
            BASE,
        )
        .expect("valid without reading the file");

        let error = Gssapi::validate(
            &SaslConfig {
                keytab: Some(PathBuf::from("/root/only/ldap.keytab")),
                service_principal: None,
                realms: vec![realm("EXAMPLE.COM", Some("uid={user},dc=other,dc=org"))],
            },
            BASE,
        )
        .expect_err("must refuse");

        assert!(matches!(error, SaslError::Template { .. }), "{error}");
    }

    #[test]
    fn the_debug_output_does_not_carry_key_material() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _) = keytab_at(dir.path());

        let gssapi = Gssapi::load(
            &SaslConfig {
                keytab: Some(path),
                service_principal: None,
                realms: vec![realm("EXAMPLE.COM", None)],
            },
            BASE,
        )
        .expect("loaded")
        .expect("some sasl");

        let rendered = format!("{gssapi:?}");
        assert!(rendered.contains("EXAMPLE.COM"), "{rendered}");
        assert!(
            !rendered.contains("secret"),
            "the key or the password it came from must never be printable: {rendered}"
        );
    }

    #[test]
    fn a_message_names_the_file_and_the_reason() {
        // An operator reads this at startup, so it has to say which file and what about it.
        let error = SaslError::Keytab {
            path: PathBuf::from("/etc/ldap/ldap.keytab"),
            detail: "permission denied".to_string(),
        };
        let text = error.to_string();
        assert!(text.contains("/etc/ldap/ldap.keytab"), "{text}");
        assert!(text.contains("permission denied"), "{text}");
    }

    #[test]
    fn the_default_template_is_the_servers_own_shape() {
        assert_eq!(
            template_of(&realm("EXAMPLE.COM", None)),
            "uid={user},ou=users,{base}"
        );
    }
}
