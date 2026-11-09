# The toolchain image this crate builds, tests and measures in: Rust 1.99.1 on Debian 11 (bullseye).
#
# Why a local image rather than a tag. `rust:1.99.1-bullseye` is not published: the official project
# stopped shipping bullseye variants after 1.90, and the tag that does exist,
# `rust:1.99.1-bookworm`, carries glibc 2.36. A binary linked there will not start on the stands
# this server is meant to run on - Debian 11 and Astra Linux both ship glibc 2.31 - so the image
# has to be assembled. Assembling it by hand on one machine and calling it a tag is how a build
# starts depending on somebody's laptop, so the assembly lives here and `scripts/cargo.sh`
# builds from this file when the image is absent.
#
# The same file, byte for byte, as the one in rust-smb-server: two copies of an assembly that
# differ are two toolchains, and a build that works in one repository and not the other for a
# reason nobody can see.
#
# The toolchain is *copied* out of the official slim-bookworm image rather than installed with
# rustup: official Rust builds link against glibc 2.17, so a bullseye base runs them unchanged, and
# the libc that ends up in our binaries comes from the base - 2.31.
FROM rust:1.99.1-slim-bookworm AS toolchain

# The official slim image ships `cargo` and `rustc` and nothing else; `rustfmt` and `clippy` are
# rustup components and have to be named. They are added here, in the bookworm stage, because the
# component tarballs are what get copied and they are libc-agnostic - while any *binary* built here
# would not be, which is why the measurement tools are built later.
RUN rustup component add rustfmt clippy

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
# missing and the check silently did nothing.
RUN rustc --version && cargo --version && rustfmt --version && cargo clippy --version
