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
    // What `describe` reads. Naming `.git/refs` alone is not enough: a tag is written *inside*
    // `.git/refs/tags`, which leaves the parent directory's mtime untouched, so cargo would keep the
    // previous answer and the published version would name a build that no longer exists. Measured:
    // the tag was created, git reported `tags/0.0.1`, and the server still answered `heads/main`.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    println!("cargo:rerun-if-env-changed=RRL_BUILD_TAG");

    // An explicit override, for a build that knows its own release name.
    if let Ok(tag) = std::env::var("RRL_BUILD_TAG") {
        println!("cargo:rustc-env=RRL_BUILD_TAG_VALUE={tag}");
        return;
    }

    // The ref name a tag or branch has, when `describe` names one. `--all` reports the namespace, and
    // the namespace is not part of a version: a client reading `operatingSystemVersion` wants `0.0.1`,
    // not `tags/0.0.1`.
    let describe = |args: &[&str]| -> Option<String> {
        Command::new("git")
            .args(args)
            .current_dir(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string()))
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty())
    };

    // A tag when one is reachable, with the distance and hash of a describe past it (`0.0.1-3-gab12` is
    // a version, and it is the honest one: a build three commits after a release is not that release).
    //
    // `--tags`, not `--all`. `--all` also searches branch heads, and a branch that points at HEAD wins
    // over a tag one commit back — measured: with `0.0.1` on the parent commit, `describe --all`
    // answered `heads/main` and the published version said the branch instead of the release. A branch
    // name identifies no build in any case: two builds a week apart both answer `main`.
    let tag = describe(&["describe", "--tags", "--abbrev=4"]).or_else(|| {
        // No tag reachable: the commit hash is what identifies the build.
        describe(&["rev-parse", "--short=4", "HEAD"])
    });

    let value = tag.unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_default());
    let value = if value.is_empty() {
        "unknown".to_string()
    } else {
        value
    };
    println!("cargo:rustc-env=RRL_BUILD_TAG_VALUE={value}");
}
