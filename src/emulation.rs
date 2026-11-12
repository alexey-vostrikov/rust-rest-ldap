//! What this directory says it is, to a client that asks the way a Windows one does.
//!
//! Active Directory has no functional level of its own for Windows Server 2019 or 2022: both run at
//! the 2016 level, and the only thing that moved between them is the schema (`objectVersion` 87 for
//! 2016, 88 for 2019 and 2022, 89 through 91 for 2025). So "behave like 2022" is not a level to claim
//! but a **number to publish**, and an operator who wants a client to believe it is talking to a
//! particular release has to choose both.
//!
//! What is published says it is an emulation. A domain that claims to be Microsoft's product without
//! saying otherwise is a domain an operator cannot tell apart from a real one in a log, and this
//! server's answers are not Microsoft's.

use serde::{Deserialize, Serialize};

/// The lowest and highest `objectVersion` this server can publish.
///
/// `sch70` is the first file Windows Server 2016 brought and `sch91` the last of Windows Server 2025's,
/// so the range covers every release a client might be asked to recognise. Lower versions describe a
/// schema this server does not implement at all, and a higher one names a release that does not exist.
pub const MIN_SCHEMA_VERSION: u8 = 70;
/// See [`MIN_SCHEMA_VERSION`].
pub const MAX_SCHEMA_VERSION: u8 = 91;

/// The Windows Server a domain says it emulates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmulationConfig {
    /// The product a client displays: `Windows Server 2022`.
    #[serde(default = "default_product")]
    pub product: String,
    /// The kernel version: `10.0`.
    #[serde(default = "default_version")]
    pub version: String,
    /// The build number: `20348` for 2022, `17763` for 2019, `14393` for 2016.
    #[serde(default = "default_build")]
    pub build: String,
    /// A marker of this server's own, so an emulated answer is recognisable as one.
    ///
    /// Unset is the usual case, and then the tag is `git describe --all --abbrev=4` for the tree this
    /// was built from: a release tag when the build sits on one, and the nearest tag with its distance
    /// and a short hash when it does not. A release that has a name of its own sets it here.
    #[serde(default)]
    pub tag: Option<String>,
    /// The schema version to publish, as `objectVersion` numbers it: `sch70` through `sch91`.
    #[serde(default = "default_schema_version")]
    pub schema_version: u8,
}

fn default_product() -> String {
    "Windows Server 2022".to_string()
}

fn default_version() -> String {
    "10.0".to_string()
}

fn default_build() -> String {
    "20348".to_string()
}

/// The tag when the operator named none: `git describe --all --abbrev=4` of the built tree, from
/// `build.rs`.
///
/// A constant would say the same thing about every build, which is exactly what a tag is for not
/// doing. A repository with no tags answers with its branch (`heads/main`), which is what `describe`
/// can honestly say there. The build script falls back to the crate version and then to `unknown`, so
/// this is never empty.
pub fn build_tag() -> &'static str {
    option_env!("RRL_BUILD_TAG_VALUE").unwrap_or("unknown")
}

fn default_schema_version() -> u8 {
    // 88 is `sch88`, the file Windows Server 2019 introduced and 2022 inherited: the highest schema
    // that promises nothing beyond what this server answers.
    88
}

impl Default for EmulationConfig {
    fn default() -> Self {
        Self {
            product: default_product(),
            version: default_version(),
            build: default_build(),
            tag: None,
            schema_version: default_schema_version(),
        }
    }
}

impl EmulationConfig {
    /// `operatingSystem`: what a client shows its user, and it says it is an emulation.
    ///
    /// The value is deliberately not a product name alone. A client reads this for display, an
    /// operator reads it in a log, and "Windows Server 2022" with no qualification would claim this
    /// server is Microsoft's build - which it is not, and which an operator diagnosing a difference in
    /// behaviour needs to see at a glance.
    pub fn operating_system(&self) -> String {
        format!("RRL Domain «{}» emulation", self.product)
    }

    /// `operatingSystemVersion`: `<WinVer> (<WinCode>) <TAG>`, the shape Windows itself writes.
    ///
    /// The tag names the build: a configured one when an operator gave it a release name, and the
    /// short commit hash otherwise. "10.0 (20348) RRL" would say the same thing about every build of
    /// this server, which is the one thing a tag must not do.
    pub fn operating_system_version(&self) -> String {
        let tag = self.tag.as_deref().unwrap_or(build_tag());
        format!("{} ({}) {}", self.version, self.build, tag)
    }

    /// `domainFunctionality` and `forestFunctionality`, as the schema version implies them.
    ///
    /// The two are not one ladder. `sch87` (2016) and `sch88` (2019, 2022) both answer **7**: 2019 and
    /// 2022 raised the schema and left the level alone. `sch89` and later answer **10**, the first new
    /// level since 2016, which Windows Server 2025 introduced for the 32k-page database.
    pub fn functionality(&self) -> &'static str {
        if self.schema_version >= 89 { "10" } else { "7" }
    }

    /// `objectVersion`, as the string a client reads.
    pub fn object_version(&self) -> String {
        self.schema_version.to_string()
    }

    /// Whether the configured version is one this server can honestly publish.
    pub fn validate(&self) -> Result<(), String> {
        if !(MIN_SCHEMA_VERSION..=MAX_SCHEMA_VERSION).contains(&self.schema_version) {
            return Err(format!(
                "schema_version {} is outside {}..={}: sch70 is the oldest schema a Windows client \
                 recognises and sch91 the newest that exists",
                self.schema_version, MIN_SCHEMA_VERSION, MAX_SCHEMA_VERSION
            ));
        }
        for (name, value) in [
            ("product", &self.product),
            ("version", &self.version),
            ("build", &self.build),
        ] {
            if value.trim().is_empty() {
                return Err(format!(
                    "emulation.{name} is empty: a client that reads an empty name shows nothing, and \
                     an operator cannot tell which release this domain claims"
                ));
            }
        }
        // Set-and-empty is a mistake; unset is the normal case and means "this build".
        if self.tag.as_deref().is_some_and(|tag| tag.trim().is_empty()) {
            return Err(
                "emulation.tag is empty: leave it unset for this build's commit hash, or name the \
                 release"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schema_version_decides_the_level_and_not_the_other_way_round() {
        // 2016 and 2019/2022 are the same level: the schema moved and the level did not.
        assert_eq!(
            EmulationConfig {
                schema_version: 87,
                ..Default::default()
            }
            .functionality(),
            "7"
        );
        assert_eq!(
            EmulationConfig {
                schema_version: 88,
                ..Default::default()
            }
            .functionality(),
            "7"
        );
        // 2025 is the first new level since 2016.
        assert_eq!(
            EmulationConfig {
                schema_version: 89,
                ..Default::default()
            }
            .functionality(),
            "10"
        );
        assert_eq!(
            EmulationConfig {
                schema_version: 91,
                ..Default::default()
            }
            .functionality(),
            "10"
        );
        // And the whole range is answerable, which is what makes it configurable.
        for version in MIN_SCHEMA_VERSION..=MAX_SCHEMA_VERSION {
            let config = EmulationConfig {
                schema_version: version,
                ..Default::default()
            };
            assert!(config.validate().is_ok(), "{version} must be publishable");
        }
    }

    #[test]
    fn what_is_published_says_it_is_an_emulation() {
        let config = EmulationConfig::default();
        assert_eq!(
            config.operating_system(),
            "RRL Domain «Windows Server 2022» emulation"
        );
        // Unset tag: the build's own commit hash, which is what tells two builds apart.
        assert_eq!(
            config.operating_system_version(),
            format!("10.0 (20348) {}", build_tag())
        );
        assert!(
            !build_tag().is_empty() && build_tag() != "RRL",
            "a tag that is the same for every build names no build: {}",
            build_tag()
        );
        assert_eq!(config.object_version(), "88");
    }

    #[test]
    fn a_version_outside_the_range_is_refused_with_the_reason() {
        let too_old = EmulationConfig {
            schema_version: 69,
            ..Default::default()
        };
        let message = too_old.validate().expect_err("69 is below the range");
        assert!(message.contains("70..=91"), "{message}");
        let too_new = EmulationConfig {
            schema_version: 92,
            ..Default::default()
        };
        assert!(too_new.validate().is_err());
    }

    #[test]
    fn a_tag_that_is_configured_is_what_a_client_reads() {
        // A release with a name of its own says so instead of the hash.
        let config = EmulationConfig {
            tag: Some("0.0.1".to_string()),
            ..Default::default()
        };
        assert_eq!(config.operating_system_version(), "10.0 (20348) 0.0.1");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn an_empty_name_is_refused() {
        let empty_product = EmulationConfig {
            product: String::new(),
            ..Default::default()
        };
        let message = empty_product
            .validate()
            .expect_err("an empty product is not a name");
        assert!(message.contains("emulation.product"), "{message}");

        // Set-and-empty is a mistake; unset is the normal case.
        let empty_tag = EmulationConfig {
            tag: Some(String::new()),
            ..Default::default()
        };
        let message = empty_tag
            .validate()
            .expect_err("an empty tag is not a name");
        assert!(message.contains("emulation.tag"), "{message}");
        assert!(EmulationConfig::default().validate().is_ok());
    }
}
