//! Everything the request handlers need to know about security policy.

use crate::acl::Acl;
use crate::config::Config;
use crate::integrity::IntegrityConfig;
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
    pub allow_unencrypted_bind: bool,
    /// The listener speaks TLS from the first byte (LDAPS).
    pub ldaps: bool,
    /// A certificate and key are configured, so StartTLS can be offered.
    pub starttls: bool,
    /// Uniqueness and referential integrity of account attributes.
    pub integrity: IntegrityConfig,
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
            // Off, like the configuration default: a test or a caller that wants a
            // plaintext bind has to say so, which is the same rule an operator follows.
            allow_unencrypted_bind: false,
            ldaps: false,
            starttls: false,
            integrity: IntegrityConfig::default(),
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
            allow_unencrypted_bind: config.allow_unencrypted_bind,
            ldaps: config.use_tls,
            // Both, because the same certificate serves LDAPS and StartTLS and
            // config load already refuses use_tls without material.
            starttls: config.server_cert.is_some() && config.server_key.is_some(),
            integrity: config.integrity.clone(),
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
