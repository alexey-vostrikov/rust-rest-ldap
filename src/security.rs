//! Everything the request handlers need to know about security policy.

use crate::acl::Acl;
use crate::config::Config;
use crate::password::PasswordPolicy;
use crate::schema::{Mode as SchemaMode, Schema};

/// Policy bundle passed to the handlers.
///
/// One value instead of a growing parameter list: every new policy knob lands
/// here and reaches the handlers without touching their signatures again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Security {
    /// Unsupported critical controls abort the request when true.
    pub respect_control_criticality: bool,
    /// Which password schemes may be verified, and what is written.
    pub passwords: PasswordPolicy,
    /// Access rules.
    pub acl: Acl,
    /// Simple bind over an unencrypted connection is refused when false.
    pub allow_plaintext_simple_bind: bool,
    /// The listener speaks TLS from the first byte (LDAPS).
    pub ldaps: bool,
    /// A certificate and key are configured, so StartTLS can be offered.
    pub starttls: bool,
    /// The published schema: writes are checked against it in `strict` mode.
    pub schema: Schema,
    /// How strictly the schema is enforced on writes.
    pub schema_mode: SchemaMode,
}

impl Default for Security {
    fn default() -> Self {
        Self {
            respect_control_criticality: true,
            passwords: PasswordPolicy::strict(),
            acl: Acl::default(),
            allow_plaintext_simple_bind: true,
            ldaps: false,
            starttls: false,
            schema: Schema::core(),
            schema_mode: SchemaMode::Strict,
        }
    }
}

impl Security {
    pub fn from_config(config: &Config) -> Self {
        Self {
            respect_control_criticality: config.respect_control_criticality,
            passwords: config.passwords.clone(),
            acl: config.acl.clone(),
            allow_plaintext_simple_bind: config.allow_plaintext_simple_bind,
            ldaps: config.use_tls,
            // Both, because the same certificate serves LDAPS and StartTLS and
            // config load already refuses use_tls without material.
            starttls: config.server_cert.is_some() && config.server_key.is_some(),
            schema: config.schema.clone(),
            schema_mode: config.schema_mode,
        }
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
            security.allow_plaintext_simple_bind,
            "a plain lab server must start without TLS material"
        );
        assert_eq!(security.passwords, PasswordPolicy::strict());
        assert_eq!(security.acl, Acl::default());
    }

    #[test]
    fn config_values_reach_the_bundle() {
        let config = config_from(
            "
respect_control_criticality: false
bind:
  allow_plaintext_simple: false
passwords:
  allow_weak: [ssha]
  store_scheme: pbkdf2-sha512
access:
  - subject: users
    attributes: [cn]
    rights: [read]
",
        );

        let security = Security::from_config(&config);

        assert!(!security.respect_control_criticality);
        assert!(!security.allow_plaintext_simple_bind);
        assert!(security.passwords.may_verify(crate::password::Scheme::Ssha));
        assert_eq!(
            security.passwords.store_scheme(),
            crate::password::StoreScheme::Pbkdf2Sha512
        );
        assert_eq!(security.acl.rules().len(), 1);
    }
}
