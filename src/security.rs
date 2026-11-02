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
}

impl Default for Security {
    fn default() -> Self {
        Self {
            respect_control_criticality: true,
            passwords: PasswordPolicy::strict(),
            acl: Acl::default(),
            // Off, like the configuration default: a test or a caller that wants a
            // plaintext bind has to say so, which is the same rule an operator follows.
            allow_unencrypted_bind: false,
            ldaps: false,
            starttls: false,
            integrity: IntegrityConfig::default(),
            schema: shared_schema(Schema::core()),
            schema_mode: SchemaMode::Strict,
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
            && current_schema(&self.schema) == current_schema(&other.schema)
            && self.schema_mode == other.schema_mode
    }
}

impl Eq for Security {}

impl Security {
    pub fn from_config(config: &Config) -> Self {
        Self {
            respect_control_criticality: config.respect_control_criticality,
            passwords: config.passwords.clone(),
            acl: config.acl.clone(),
            allow_unencrypted_bind: config.allow_unencrypted_bind,
            ldaps: config.use_tls,
            // Both, because the same certificate serves LDAPS and StartTLS and
            // config load already refuses use_tls without material.
            starttls: config.server_cert.is_some() && config.server_key.is_some(),
            integrity: config.integrity.clone(),
            schema: shared_schema(config.schema.clone()),
            schema_mode: config.schema_mode,
        }
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
}
