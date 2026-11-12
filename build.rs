//! The build's own identity, so a client can be told which build it is talking to.
//!
//! `operatingSystemVersion` ends with a tag, and the tag is `git describe --all --abbrev=4`: a release
//! tag when the build sits on one (`tags/v0.1.0`), and the nearest tag plus the distance and a short
//! hash when it does not (`tags/v0.1.0-3-gab12`). On a repository with no tags at all it is the branch
//! itself (`heads/main`), which is what `describe` can honestly say there.
//!
//! Two fallbacks, both deliberate. No git, or a source tree without `.git` (a release tarball, a
//! container build from a copied directory), falls back to the crate version: a wrong tag is worse than
//! a version, because a tag that names someone else's commit sends an operator to the wrong place. And
//! nothing at all leaves `unknown`, which reads as "this build does not know", not as a
//! plausible-looking lie.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    println!("cargo:rerun-if-env-changed=RRL_BUILD_TAG");

    // An explicit override, for a build that knows its own release name.
    if let Ok(tag) = std::env::var("RRL_BUILD_TAG") {
        println!("cargo:rustc-env=RRL_BUILD_TAG_VALUE={tag}");
        return;
    }

    let tag = Command::new("git")
        .args(["describe", "--all", "--abbrev=4"])
        .current_dir(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string()))
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty());

    let value = tag.unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_default());
    let value = if value.is_empty() {
        "unknown".to_string()
    } else {
        value
    };
    println!("cargo:rustc-env=RRL_BUILD_TAG_VALUE={value}");
}
