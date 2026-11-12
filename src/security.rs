//! Everything the request handlers need to know about security policy.

use crate::acl::Acl;
use std::sync::Arc;

use crate::config::Config;
use crate::integrity::IntegrityConfig;
use crate::password::PasswordPolicy;
use crate::schema::{Mode as SchemaMode, Schema};

/// A schema that a running server can replace.
///
/// The inner `Arc` is swapped, not mutated, so a caller that read it before the swap keeps
/// one consistent schema for the length of its operation - which is what a single request
/// needs. The lock is a `std` one because the handlers are synchronous; it is held only for
/// the length of a clone.
pub type SharedSchema = Arc<std::sync::RwLock<Arc<Schema>>>;

/// A shared schema holding `schema`.
pub fn shared_schema(schema: Schema) -> SharedSchema {
    Arc::new(std::sync::RwLock::new(Arc::new(schema)))
}

/// The schema inside `shared`, as it stands right now.
///
/// A poisoned lock is not a reason to fail a search: the schema is replaced wholesale and
/// never half-written, so the value inside is still a schema somebody finished building.
pub fn current_schema(shared: &SharedSchema) -> Arc<Schema> {
    match shared.read() {
        Ok(guard) => Arc::clone(&guard),
        Err(poisoned) => Arc::clone(&poisoned.into_inner()),
    }
}

/// The policy of a running server: what is in force, and what it started with.
///
/// The inner `Arc` is swapped, not mutated, so a connection that read it before the swap keeps
/// one consistent policy for the length of its operation. The same shape as [`SharedSchema`],
/// and for the same reason: a `modify` of `cn=config` has to reach every connection at once,
/// without a window in which two connections enforce different rules.
///
/// The starting configuration is kept because it is the only thing that can say which settings
/// a `modify` changed that this process cannot adopt. Comparing the new document with the one in
/// force is not enough: after two changes both documents say `listen_addr: <new>`, and nothing
/// remembers that the socket is still bound to the old address.
pub struct Live {
    running: Config,
    current: std::sync::RwLock<Arc<Security>>,
}

/// The handles the server passes around: one clone per connection.
pub type Shared = Arc<Live>;

/// A live policy for a server that started with `running`.
pub fn live(running: Config, security: Security) -> Shared {
    Arc::new(Live {
        running,
        current: std::sync::RwLock::new(Arc::new(security)),
    })
}

impl Live {
    /// The policy in force, as it stands right now.
    ///
    /// A poisoned lock is not a reason to fail a search: the value is replaced wholesale and
    /// never half-written, so what is inside is still a policy somebody finished building.
    pub fn current(&self) -> Arc<Security> {
        match self.current.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// The configuration the process started with.
    pub fn running(&self) -> &Config {
        &self.running
    }

    /// Publishes `document` as the configuration subtree's contents.
    ///
    /// Separate from [`Shared::apply`] because it is not a policy change: `Security` compares
    /// equal when the rules are equal, and a commit that changed one setting would otherwise
    /// leave the subtree describing the settings before it. The schema handle travels with the
    /// policy, so replacing one here keeps the other.
    pub fn publish_document(&self, document: crate::config::Document) {
        let current = self.current();
        let mut next = (*current).clone();
        next.config_document = Some(document);

        let mut guard = match self.current.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Arc::new(next);
    }

    /// Adopts `config` as the policy in force, keeping the schema handle.
    ///
    /// The schema is not taken from the configuration: a schema reload through the `Source` is
    /// the only thing that replaces it, and building a new handle here would cut a running
    /// server off from that reload - the write path would then enforce a schema the server had
    /// already stopped publishing.
    pub fn apply(&self, config: &Config) -> Applied {
        let before = self.current();
        let schema = Arc::clone(&before.schema);

        let after = Security::from_config(config).with_schema(schema);
        let policy_changed = *before != after;
        let needs_restart = needs_restart(&self.running, config);

        // Applied even when something else needs a restart: the policy has no socket and no
        // certificate, so a change to `acl` next to a change to `listen_addr` takes effect now
        // rather than being held back by the neighbour.
        if policy_changed {
            let mut guard = match self.current.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *guard = Arc::new(after);
        }

        Applied {
            changed: policy_changed || !needs_restart.is_empty(),
            needs_restart,
            policy_changed,
        }
    }
}

/// What replacing the policy did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Applied {
    /// True when the document differs from what is in force in any way this server cares about.
    pub changed: bool,
    /// Settings the document changed that this process cannot adopt. Empty when a restart
    /// would change nothing.
    pub needs_restart: Vec<&'static str>,
    /// True when the change made the policy say something different from what it said before:
    /// the rules a client meets are now different.
    pub policy_changed: bool,
}

/// The settings a running server cannot adopt, named.
///
/// A list rather than a bool: the answer to the operator says which of the settings they just
/// changed is waiting for a restart, and a bare "restart required" leaves them checking all of
/// them. The order is fixed so the message reads the same way twice.
///
/// What is here is here for one of two reasons: it is bound to a socket that is already
/// listening (the addresses, the certificates), or it decides the shape of the directory and
/// therefore what the entries loaded at startup mean (`base_dn`, the two OU names, the backend).
pub fn needs_restart(before: &Config, after: &Config) -> Vec<&'static str> {
    let mut waiting = Vec::new();

    if before.listen_addr != after.listen_addr {
        waiting.push("listen_addr");
    }
    if before.use_tls != after.use_tls
        || before.server_cert != after.server_cert
        || before.server_key != after.server_key
    {
        waiting.push("tls");
    }
    if before.http_listen_addr != after.http_listen_addr {
        waiting.push("http_listen_addr");
    }
    if before.backend != after.backend || before.backends != after.backends {
        waiting.push("backend");
    }
    if before.base_dn != after.base_dn {
        waiting.push("base_dn");
    }
    if before.users_ou_name != after.users_ou_name || before.groups_ou_name != after.groups_ou_name
    {
        waiting.push("organizational units");
    }
    if before.update_interval != after.update_interval {
        waiting.push("update_interval");
    }

    waiting
}

/// What a domain controller calls itself, for the root DSE alone.
///
/// `Add-Computer` reads these before it authenticates and takes its idea of the domain from
/// `defaultNamingContext`. A server that publishes only the RFC 4512 attributes joins from Linux -
/// Samba's `ads_connect` uses `namingContexts` - and is refused by Windows with `0x78`, having asked
/// nothing more. Measured on the AD-join stand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdNames {
    /// `dnsHostName`: the controller's DNS name, as the KDC's service principal spells it.
    pub dns_host_name: String,
    /// `ldapServiceName`: `REALM:host/fqdn@REALM`, which a client uses to pick the realm.
    pub ldap_service_name: String,
    /// `serverName`: the controller, in the form a client shows its user.
    pub server_name: String,
    /// `configurationNamingContext`, when this tree really has one.
    pub configuration_naming_context: Option<String>,
    /// What this domain says it is when a client asks like Windows: the product name, the build, and
    /// the schema version it publishes as `objectVersion`.
    pub emulation: crate::emulation::EmulationConfig,
}

/// Policy bundle passed to the handlers.
///
/// One value instead of a growing parameter list: every new policy knob lands
/// here and reaches the handlers without touching their signatures again.
#[derive(Debug, Clone)]
pub struct Security {
    /// Unsupported critical controls abort the request when true.
    pub respect_control_criticality: bool,
    /// Which password schemes may be verified, and what is written.
    pub passwords: PasswordPolicy,
    /// Access rules.
    pub acl: Acl,
    /// Simple bind over an unencrypted connection is refused when false.
    pub allow_unencrypted_bind: bool,
    /// The listener speaks TLS from the first byte (LDAPS).
    pub ldaps: bool,
    /// A certificate and key are configured, so StartTLS can be offered.
    pub starttls: bool,
    /// The RFC 5929 `tls-server-end-point` binding for that certificate, when one is defined.
    ///
    /// Handed to the Kerberos acceptor, which then refuses a ticket whose client bound it to a
    /// different TLS session. `None` is "no binding": either no certificate, or one whose signature
    /// algorithm names no hash. That is not a weakened check - it is the same check a client that
    /// sent no binding gets, and sending no binding was always allowed.
    pub channel_binding: Option<krb5::ChannelBindings>,
    /// Uniqueness and referential integrity of account attributes.
    pub integrity: IntegrityConfig,
    /// The published schema: writes are checked against it in `strict` mode.
    ///
    /// Shared and replaceable rather than cloned into each connection, because a reload has
    /// to be visible to every client at once. A `Security` per connection would mean a window
    /// during which two connections validate against different rules.
    pub schema: SharedSchema,
    /// How strictly the schema is enforced on writes.
    pub schema_mode: SchemaMode,
    /// The configuration document, published as the `cn=config` subtree.
    ///
    /// It rides here because `Security` is the per-server handle the protocol layer already
    /// receives: a second parameter through every `ldap::handle` call site would be threaded
    /// for one subtree. What it is used for belongs to the protocol layer, not to security -
    /// the field is a carrier, and a reader looking for the access rules should look at `acl`.
    pub config_document: Option<crate::config::Document>,
    /// Whether a password-hash upgrade can be persisted at all.
    ///
    /// The file backend stores a fixed user/group document and refuses a whole entry, so an
    /// upgrade it cannot keep was being attempted on every successful bind and refused every
    /// time - a line on stderr per bind, forever. Deciding once, here, is what makes it a
    /// startup statement instead of a per-request one.
    pub can_upgrade_password_hashes: bool,
    /// The domain's identity, when this server issues SIDs.
    ///
    /// Rides here for the same reason `config_document` does: `Security` is the per-server handle the
    /// protocol layer already receives, and a second parameter through every `ldap::handle` call
    /// site would be threaded for one attribute. `None` means "not a domain": an ordinary directory
    /// has no SID to give, and an entry created in it carries none.
    pub domain: Option<std::sync::Arc<crate::sid::domain::Issuer>>,
    /// Subtrees this server does not hold, and where the client is sent for them.
    pub referrals: crate::referral::Referrals,
    /// The server's own size and time limits.
    ///
    /// Here rather than in each handler for the same reason as the access rules: a search has to
    /// answer to it, and a second parameter threaded through every call site for one number is how
    /// a policy gets forgotten in one place and enforced in another.
    pub limits: crate::limits::Limits,
    /// The names a domain controller publishes in its root DSE, when this server is one.
    ///
    /// Separate from `domain`, which is the SID issuer: the issuer knows the domain's identity and
    /// nothing about how it is spelled on the network, and a client that reads `defaultNamingContext`
    /// needs the spelling.
    pub ad_names: Option<AdNames>,
    /// The GSSAPI acceptor, when a keytab was configured.
    ///
    /// `None` means SASL is not offered: a `GSSAPI` bind is refused with
    /// `authMethodNotSupported`, which is what every deployment without a keytab got before this
    /// existed. Loaded once, here, because reading a keytab per bind would turn a file-permission
    /// mistake into a per-request failure.
    pub gssapi: Option<std::sync::Arc<crate::sasl::Gssapi>>,
}

impl Default for Security {
    fn default() -> Self {
        Self {
            respect_control_criticality: true,
            can_upgrade_password_hashes: true,
            domain: None,
            referrals: crate::referral::Referrals::default(),
            gssapi: None,
            ad_names: None,
            limits: crate::limits::Limits::default(),
            passwords: PasswordPolicy::strict(),
            acl: Acl::default(),
            // Off, like the configuration default: a test or a caller that wants a
            // plaintext bind has to say so, which is the same rule an operator follows.
            allow_unencrypted_bind: false,
            ldaps: false,
            starttls: false,
            channel_binding: None,
            integrity: IntegrityConfig::default(),
            schema: shared_schema(Schema::core()),
            schema_mode: SchemaMode::Strict,
            config_document: None,
        }
    }
}

impl PartialEq for Security {
    /// Compares the schema by value rather than by the lock holding it.
    ///
    /// Two policies that publish the same schema are the same policy, whichever `Arc` they
    /// happen to share; comparing the pointers would say "different" after a reload that
    /// changed nothing.
    fn eq(&self, other: &Self) -> bool {
        self.respect_control_criticality == other.respect_control_criticality
            && self.passwords == other.passwords
            && self.acl == other.acl
            && self.allow_unencrypted_bind == other.allow_unencrypted_bind
            && self.ldaps == other.ldaps
            && self.starttls == other.starttls
            && self.integrity == other.integrity
            && self.can_upgrade_password_hashes == other.can_upgrade_password_hashes
            && self.referrals == other.referrals
            && self.limits == other.limits
            // Two acceptors are equal when they accept the same realms: the keytab itself is a
            // secret and has no meaningful identity to compare.
            && self.gssapi.as_ref().map(|one| one.realms().collect::<Vec<_>>())
                == other.gssapi.as_ref().map(|one| one.realms().collect::<Vec<_>>())
            && current_schema(&self.schema) == current_schema(&other.schema)
            && self.schema_mode == other.schema_mode
    }
}

impl Eq for Security {}

impl Security {
    pub fn from_config(config: &Config) -> Self {
        Self {
            respect_control_criticality: config.respect_control_criticality,
            // A domain is attached by the daemon once the store is open, not derived from the
            // configuration here: the SID lives in the store, and this function has no store.
            domain: None,
            passwords: config.passwords.clone(),
            acl: config.acl.clone(),
            allow_unencrypted_bind: config.allow_unencrypted_bind,
            ldaps: config.use_tls,
            // Both, because the same certificate serves LDAPS and StartTLS and
            // config load already refuses use_tls without material.
            starttls: config.server_cert.is_some() && config.server_key.is_some(),
            // Computed once, from the certificate that will be presented. A read error here is not
            // fatal: `tls::acceptor` fails on it a moment later with the better message, and a
            // binding computed from half a file would be worse than none.
            channel_binding: config
                .server_cert
                .as_deref()
                .and_then(|path| crate::tls::channel_binding(path).ok().flatten()),
            integrity: config.integrity.clone(),
            schema: shared_schema(config.schema.clone()),
            schema_mode: config.schema_mode,
            config_document: config.document.clone(),
            // Left true and corrected by the server once it has a backend in hand: the
            // configuration does not know which backend was chosen, and `Security::from_config`
            // is also what tests and the protocol layer build from a bare configuration.
            can_upgrade_password_hashes: true,
            referrals: config.referrals.clone(),
            limits: config.limits,
            // Left empty: the keytab is read by the server that has one, not by every caller that
            // builds a policy from a configuration.
            gssapi: None,
            // Left empty for the same reason: only the daemon knows the names it answers to.
            ad_names: None,
        }
    }

    /// Says that this server is a domain controller answering to these names.
    #[must_use]
    pub fn with_ad_names(mut self, names: AdNames) -> Self {
        self.ad_names = Some(names);
        self
    }

    /// The same policy, able to accept Kerberos tickets.
    pub fn with_gssapi(mut self, gssapi: Option<std::sync::Arc<crate::sasl::Gssapi>>) -> Self {
        self.gssapi = gssapi;
        self
    }

    /// The same policy, publishing `schema` instead of its own copy.
    ///
    /// The server builds its `Security` from the configuration and then hands it the schema
    /// the `Source` holds, so that one reload reaches both the write path and everything
    /// that answers questions about the schema.
    pub fn with_schema(mut self, schema: SharedSchema) -> Self {
        self.schema = schema;
        self
    }

    /// The same policy, knowing whether a hash upgrade can be stored at all.
    /// Makes this server the issuer of a domain's SIDs.
    pub fn with_domain(mut self, domain: std::sync::Arc<crate::sid::domain::Issuer>) -> Self {
        self.domain = Some(domain);
        self
    }

    pub fn with_password_upgrade(mut self, possible: bool) -> Self {
        self.can_upgrade_password_hashes = possible;
        self
    }

    /// Whether StartTLS can be offered on a plain connection.
    pub fn tls_available(&self) -> bool {
        self.starttls
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Args;

    fn config_from(text: &str) -> Config {
        crate::config::resolve(Args::default(), Some(text), |_| None).expect("config")
    }

    #[test]
    fn a_published_document_replaces_the_one_the_subtree_shows() {
        // The defect this guards: `apply` compares policy, and a commit that changed a setting
        // publishes equal policy, so the subtree would keep describing the settings before it -
        // a client would read its own change back and not find it.
        let config = config_from("base_dn: dc=example,dc=com\n");
        let shared = live(config.clone(), Security::from_config(&config));
        let schema_before = Arc::as_ptr(&current_schema(&shared.current().schema));

        shared.publish_document(crate::config::Document {
            text: "base_dn: dc=example,dc=com\nschema:\n  mode: warn\n".to_string(),
            origin: "store:/etc/rust-rest-ldap/config.d".to_string(),
            store: Some(std::path::PathBuf::from("/etc/rust-rest-ldap/config.d")),
        });

        let published = shared
            .current()
            .config_document
            .clone()
            .expect("the subtree has a document");
        assert!(
            published.text.contains("mode: warn"),
            "the new text is what the subtree publishes"
        );
        assert_eq!(
            published.store.as_deref(),
            Some(std::path::Path::new("/etc/rust-rest-ldap/config.d")),
            "and the store travels with it, or the next change would find nothing to commit to"
        );
        assert_eq!(
            Arc::as_ptr(&current_schema(&shared.current().schema)),
            schema_before,
            "the schema handle is the same one: a published document must not cut the server \
             off from the signal that replaces it"
        );
    }

    #[test]
    fn defaults_match_the_documented_behaviour() {
        let security = Security::default();

        assert!(security.respect_control_criticality);
        assert!(
            !security.allow_unencrypted_bind,
            "the safe default refuses a password in the clear; a lab turns it on in \
             words, and the server still starts without TLS material either way"
        );
        assert_eq!(security.passwords, PasswordPolicy::strict());
        assert_eq!(security.acl, Acl::default());
    }

    #[test]
    fn config_values_reach_the_bundle() {
        let config = config_from(
            r#"
respect_control_criticality: false
AllowDangerousSettings: "Yes I know this is bad idea"
bind:
  AllowUnencryptedBind: "Yes I know this is bad idea"
passwords:
  AllowWeakHashes: "Yes I know this is bad idea"
  AllowedWeakHashes: "ssha"
  store_scheme: pbkdf2-sha512
access:
  - subject: users
    attributes: [cn]
    rights: [read]
"#,
        );

        let security = Security::from_config(&config);

        assert!(!security.respect_control_criticality);
        assert!(
            security.allow_unencrypted_bind,
            "the configuration said the sentence, so the unsafe bind is on"
        );
        assert!(security.passwords.may_verify(crate::password::Scheme::Ssha));
        assert_eq!(
            security.passwords.store_scheme(),
            crate::password::StoreScheme::Pbkdf2Sha512
        );
        assert_eq!(security.acl.rules().len(), 1);
    }
    /// A configuration built from a document, so the test says what it means.
    fn config(text: &str) -> Config {
        crate::config::resolve(crate::config::Args::default(), Some(text), |_| None)
            .expect("the document must resolve")
    }

    fn live_from(text: &str) -> Shared {
        let config = config(text);
        let security = Security::from_config(&config);
        live(config, security)
    }

    #[test]
    fn a_change_to_the_rules_is_adopted_without_a_restart() {
        let shared = live_from("respect_control_criticality: true\n");

        let applied = shared.apply(&config("respect_control_criticality: false\n"));

        assert!(applied.policy_changed, "the rules changed");
        assert!(
            applied.needs_restart.is_empty(),
            "and nothing about it needs a restart: {:?}",
            applied.needs_restart
        );
        assert!(
            !shared.current().respect_control_criticality,
            "adopted at once"
        );
    }

    #[test]
    fn an_access_rule_takes_effect_at_once() {
        // A document that names rules replaces the defaults rather than adding to them: the
        // rules are what the operator wrote, and a default left behind could grant something
        // the new document does not.
        let shared = live_from("listen_addr: 127.0.0.1:1389\n");
        assert_eq!(shared.current().acl.rules().len(), 3, "the defaults");

        let applied = shared.apply(&config(
            "listen_addr: 127.0.0.1:1389\naccess:\n  - subject: anonymous\n    attributes: ['*']\n    rights: [read]\n",
        ));

        assert!(applied.policy_changed);
        assert_eq!(
            shared.current().acl.rules().len(),
            1,
            "the one rule the document names, and not the defaults"
        );
    }

    #[test]
    fn a_setting_bound_to_a_socket_waits_for_a_restart_and_is_named() {
        let shared = live_from("listen_addr: 127.0.0.1:1389\n");

        let applied = shared.apply(&config("listen_addr: 0.0.0.0:389\n"));

        assert_eq!(applied.needs_restart, vec!["listen_addr"]);
        assert!(applied.changed, "the document did change something");
        assert!(
            !applied.policy_changed,
            "but no rule a client meets has changed"
        );
    }

    #[test]
    fn a_change_to_both_is_adopted_where_it_can_be() {
        // The change that matters: a policy setting next to a socket setting must not be held
        // back by its neighbour.
        let shared = live_from("listen_addr: 127.0.0.1:1389\nrespect_control_criticality: true\n");

        let applied = shared.apply(&config(
            "listen_addr: 0.0.0.0:389\nrespect_control_criticality: false\n",
        ));

        assert_eq!(applied.needs_restart, vec!["listen_addr"]);
        assert!(applied.policy_changed);
        assert!(!shared.current().respect_control_criticality, "taken now");
    }

    #[test]
    fn every_setting_that_needs_a_restart_is_named_in_one_list() {
        let acknowledgement = "AllowDangerousSettings: \"Yes I know this is bad idea\"\n";
        let base = format!(
            "{acknowledgement}listen_addr: 127.0.0.1:1389\nhttp_listen_addr: 127.0.0.1:8080\n\
             AllowPlainHttpRest: \"Yes I know this is bad idea\"\n"
        );
        let changed = format!(
            "{acknowledgement}listen_addr: 0.0.0.0:389\nhttp_listen_addr: 0.0.0.0:8080\n\
             AllowPlainHttpRest: \"Yes I know this is bad idea\"\nuse_tls: true\n\
             server_cert: /tmp/c.pem\nserver_key: /tmp/k.pem\nbase_dn: dc=other,dc=com\n\
             users_ou_name: people\ngroups_ou_name: teams\nupdate_interval: 10m\n"
        );

        let waiting = needs_restart(&config(&base), &config(&changed));

        assert_eq!(
            waiting,
            vec![
                "listen_addr",
                "tls",
                "http_listen_addr",
                "base_dn",
                "organizational units",
                "update_interval"
            ],
            "the list names every setting, in a fixed order"
        );
    }

    #[test]
    fn an_unchanged_document_reports_nothing_at_all() {
        let shared = live_from("listen_addr: 127.0.0.1:1389\nrespect_control_criticality: true\n");

        let applied = shared.apply(&config(
            "listen_addr: 127.0.0.1:1389\nrespect_control_criticality: true\n",
        ));

        assert_eq!(
            applied,
            Applied {
                changed: false,
                needs_restart: Vec::new(),
                policy_changed: false,
            }
        );
    }

    #[test]
    fn the_schema_handle_survives_a_policy_change() {
        // A new handle here would cut the running server off from a schema reload, and the
        // write path would then enforce a schema the server had stopped publishing.
        let shared = live_from("listen_addr: 127.0.0.1:1389\n");
        let schema = Arc::clone(&shared.current().schema);

        shared.apply(&config(
            "listen_addr: 127.0.0.1:1389\nrespect_control_criticality: false\n",
        ));

        assert!(
            Arc::ptr_eq(&schema, &shared.current().schema),
            "the same handle, not a new one"
        );
    }
}
