//! Settings that weaken security, and the sentence that unlocks them.
//!
//! A boolean is too easy to set. `allow_plaintext: true` gets copied between configs, is
//! switched on to make a test pass, and then stays. So a setting that knowingly weakens
//! the server does not take a boolean: it takes a sentence that says what it does.
//!
//! ```yaml
//! bind:
//!   AllowUnencryptedBind: "Yes I know this is bad idea"
//! passwords:
//!   AllowWeakHashes: "Yes I know this is bad idea"
//!   AllowedWeakHashes: "ssha, crypt-md5"
//! ```
//!
//! The sentence is compared after trimming and case folding — the point is not the exact
//! spelling, it is that the operator has to write down that they meant it. `true`,
//! `yes`, `1` and every other shorthand are refused with the text to write instead, so a
//! configuration that copied a flag from somewhere cannot silently weaken the server.
//!
//! Omitting the setting leaves it off. That is the fail-safe direction: a missing line
//! is a safe server, and only a written sentence is a dangerous one.

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer};
use thiserror::Error;

/// The sentence, word for word. Compared case-insensitively after trimming.
pub const ACKNOWLEDGEMENT: &str = "Yes I know this is bad idea";

/// State of a dangerous setting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Danger {
    /// Absent or removed: the safe behaviour.
    #[default]
    Off,
    /// The operator wrote the sentence.
    On,
}

impl Danger {
    /// The unsafe behaviour was explicitly acknowledged.
    pub fn is_on(&self) -> bool {
        matches!(self, Danger::On)
    }

    /// Parses a configuration value.
    ///
    /// Reports what to write when the value is not the sentence, because "invalid value"
    /// in a security setting is a dead end for the operator.
    pub fn parse(value: &str) -> Result<Self, DangerError> {
        if value.trim().eq_ignore_ascii_case(ACKNOWLEDGEMENT) {
            Ok(Danger::On)
        } else {
            Err(DangerError::NotAcknowledged {
                value: value.trim().to_string(),
            })
        }
    }

    /// True when `value` names the sentence, for callers that only need the verdict.
    pub fn acknowledges(value: &str) -> bool {
        Self::parse(value).is_ok()
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DangerError {
    #[error(
        "'{value}' does not switch this on: it weakens security, so it must be written as \
         the sentence '{ACKNOWLEDGEMENT}' (or left out to keep it off)"
    )]
    NotAcknowledged { value: String },
}

impl<'de> Deserialize<'de> for Danger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // A string is the only shape accepted: `true` is exactly the shorthand this type
        // exists to refuse, so it must not deserialize at all.
        let text = String::deserialize(deserializer)?;
        Danger::parse(&text).map_err(|err| D::Error::custom(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_yaml(text: &str) -> Result<Danger, serde_saphyr::Error> {
        serde_saphyr::from_str::<Danger>(text)
    }

    #[test]
    fn the_sentence_switches_it_on() {
        assert_eq!(Danger::parse(ACKNOWLEDGEMENT), Ok(Danger::On));
        assert!(Danger::parse(ACKNOWLEDGEMENT).expect("on").is_on());
    }

    #[test]
    fn the_sentence_is_matched_leniently_in_case_and_spacing() {
        for spelling in [
            "Yes I know this is bad idea",
            "yes i know this is bad idea",
            "  YES I KNOW THIS IS BAD IDEA  ",
            "Yes I know this is bad IDEA",
        ] {
            assert_eq!(Danger::parse(spelling), Ok(Danger::On), "{spelling}");
        }
    }

    #[test]
    fn shorthands_are_refused_and_the_message_says_what_to_write() {
        for shorthand in ["true", "yes", "1", "on", "bad idea", ""] {
            let error = Danger::parse(shorthand).expect_err(shorthand);
            let text = error.to_string();
            assert!(
                text.contains(ACKNOWLEDGEMENT),
                "the error must tell the operator what to write: {text}"
            );
        }
    }

    #[test]
    fn a_missing_setting_is_off() {
        assert_eq!(Danger::default(), Danger::Off);
        assert!(!Danger::default().is_on());
    }

    #[test]
    fn it_deserializes_from_the_sentence_only() {
        assert_eq!(
            from_yaml(r#""Yes I know this is bad idea""#).expect("parsed"),
            Danger::On
        );
        assert!(from_yaml("true").is_err(), "a boolean must not unlock it");
        assert!(from_yaml(r#""true""#).is_err());
        assert!(from_yaml("1").is_err());
    }

    #[test]
    fn the_error_names_the_offered_value() {
        let error = Danger::parse("allowed").expect_err("refused");
        assert!(
            error.to_string().contains("'allowed'"),
            "an operator has to see which value was refused: {error}"
        );
    }

    #[test]
    fn acknowledgement_check_does_not_build_the_value() {
        assert!(Danger::acknowledges(ACKNOWLEDGEMENT));
        assert!(!Danger::acknowledges("nope"));
    }
}
