# The toolchain image these crates build, test and measure in: Rust 1.99.1 on Debian 11 (bullseye).
#
# Why a local image rather than a tag. `rust:1.99.1-bullseye` is not published: the official project
# stopped shipping bullseye variants after 1.90, and the tag that does exist,
# `rust:1.99.1-bookworm`, carries glibc 2.36. A binary linked there will not start on the stands
# these crates are meant to run on - Debian 11 and Astra Linux both ship glibc 2.31 - so the image
# has to be assembled. Assembling it by hand on one machine and calling it a tag is how a build
# starts depending on somebody's laptop, so the assembly lives here and the project's `scripts/`
# build from this file when the image is absent.
#
# THIS FILE IS IDENTICAL, BYTE FOR BYTE, IN EVERY PROJECT THAT SHARES THE IMAGE:
#
#   ~/DevOps/rrl-kdc/docker/toolchain.Dockerfile              (rrl-kdc)
#   ~/DevOps/rrl-crypto/docker/toolchain.Dockerfile           (rrl-crypto)
#   ~/DevOps/rrl-krb-common/docker/toolchain.Dockerfile       (rrl-krb-common)
#   ~/DevOps/3part/rrl-krb5/docker/toolchain.Dockerfile       (rrl-krb5)
#   ~/DevOps/3part/rrl-smb/docker/toolchain.Dockerfile        (rrl-smb, the rust-smb-server fork)
#   ~/DevOps/3part/rust-rest-ldap/docker/toolchain.Dockerfile (rust-rest-ldap)
#
# One image name, so the assembly must be one text: whoever builds first decides what everyone
# else gets. Two copies that differ are two toolchains and a build that works in one repository
# and fails in another for a reason nobody can see. Check with
#
#   sha256sum ~/DevOps/*/docker/toolchain.Dockerfile ~/DevOps/3part/*/docker/toolchain.Dockerfile
#
# and keep the set in step when the file changes here.
#
# The toolchain is *copied* out of the official slim-bookworm image rather than installed with
# rustup: official Rust builds link against glibc 2.17, so a bullseye base runs them unchanged, and
# the libc that ends up in our binaries comes from the base - 2.31.
FROM rust:1.99.1-slim-bookworm AS toolchain

# The official slim image ships `cargo` and `rustc` and nothing else; `rustfmt`, `clippy` and
# `llvm-tools-preview` are rustup components and have to be named. They are added here, in the
# bookworm stage, because the component tarballs are what get copied and they are libc-agnostic -
# while any *binary* built here would not be, which is why the measurement tools are built later.
#
# `llvm-tools-preview` is not an optional extra: `cargo-llvm-cov` only drives the measurement, the
# work is done by `llvm-profdata` and `llvm-cov`, and those two ship in this component, not in the
# default toolchain. Without it the plugin stops at `rustup component add llvm-tools-preview` and
# waits for the network - measured: a coverage run sat at 0% CPU for nine minutes and looked hung.
# The gate below therefore asserts the binary, not just the plugin.
RUN rustup component add rustfmt clippy llvm-tools-preview

FROM rust:1.90-bullseye

ARG RUST_TOOLCHAIN=1.99.1

# The rustup and cargo trees from the bookworm stage: the pinned version becomes the default, and
# the 1.90 that ships with the base is shadowed rather than removed - the base's own
# `/usr/local/bin/cargo` is a symlink into that tree, which is why both directories come over whole.
COPY --from=toolchain /usr/local/rustup /usr/local/rustup
COPY --from=toolchain /usr/local/cargo /usr/local/cargo
ENV RUSTUP_TOOLCHAIN=${RUST_TOOLCHAIN} \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Bullseye left LTS and moved to the archive: `deb.debian.org/debian-security` answers 404 for its
# own package versions and every `apt-get install` fails with code 100. The archive works but is
# signed with an expired date, hence `Check-Valid-Until=false`.
RUN printf '%s\n' \
      'deb http://archive.debian.org/debian bullseye main' \
      'deb http://archive.debian.org/debian-security bullseye-security main' \
      > /etc/apt/sources.list

# `build-essential` for the link step, `pkg-config` for the TLS crates behind optional features.
RUN apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config ca-certificates git \
 && rm -rf /var/lib/apt/lists/*

# `cargo-llvm-cov` is built here, not copied from the bookworm stage: the published binary and one
# built there need glibc 2.34 and die on bullseye with "version `GLIBC_2.34' not found". Pinned, so
# a coverage figure does not move because somebody published a release.
RUN cargo install cargo-llvm-cov --locked --version 0.6.18 \
 && cargo llvm-cov --version

# The mutator. `cargo-mutants` is a Rust binary, so measurement and build stay one image and one
# compiler - which is the property that makes a mutation score mean anything. Pinned, so a kill
# count does not move under us.
#
# Not the published release binary: it has no musl build, and the gnu one is made on a recent
# Ubuntu and requires GLIBC_2.39 - measured with `objdump -T`. Built from source here, it lands at
# GLIBC_2.30, the same floor as the crates themselves.
RUN cargo install cargo-mutants --locked --version 27.1.0 \
 && cargo mutants --version

# CRAP and duplicates, both in Rust, because ub-mode's own tools are Python and would need a second
# runtime here: `cargo-crap` reads the same LCOV `cargo-llvm-cov` writes and computes the same
# formula, `cargo-dupes` compares normalised ASTs with the same 0.8 similarity threshold ub-mode
# names. A Python toolchain in a Rust image is a second interpreter to keep patched for a metric
# that has a native implementation.
#
# Pinned for the same reason as the rest: a CRAP figure or a duplicate count that moves because
# somebody published a release is not a measurement.
RUN cargo install cargo-crap --locked --version 0.9.0 \
 && cargo crap --version
RUN cargo install cargo-dupes --locked --version 0.2.1 \
 && cargo dupes --version

# The gates assert their tools exist rather than discovering at report time that `rustfmt` was
# missing and the check silently did nothing. `cargo llvm-cov --version` only proves the plugin is
# installed; the measurement itself needs `llvm-cov` from the toolchain, so that file is asserted
# too - otherwise the absence shows up as a coverage run waiting on the network.
RUN rustc --version && cargo --version && rustfmt --version && cargo clippy --version
RUN cargo llvm-cov --version && cargo mutants --version && cargo crap --version && cargo dupes --version \
 && llvm_cov="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-cov" \
 && test -x "$llvm_cov" \
 && echo "llvm-cov: $llvm_cov"
