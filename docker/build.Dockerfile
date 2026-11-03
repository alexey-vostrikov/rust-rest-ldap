# The build image: the pinned toolchain plus what the quality gates need.
#
# Why a derived image rather than `rust:1.99.1-slim-trixie` directly: `cargo-fuzz` drives
# libFuzzer, which ships with LLVM, and the base image has only GCC. Installing clang into the
# base image would mean the fuzzer and the build could disagree about the toolchain, and a
# nightly component (miri, rust-src) has to live somewhere that survives the container - so
# both are baked in here.
#
# What is NOT here: cargo-llvm-cov. It is a large install and only the mutation/coverage work
# needs it; the skill notes say how to add it inside the mounted cargo cache when that work
# starts, without growing this image for everyone.
FROM rust:1.99.1-slim-trixie

# clang: libFuzzer for `cargo fuzz`, and the linker the sanitizers use.
# rustfmt/clippy come with the base image; rust-src and miri are what the interpreter needs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang lld \
    && rm -rf /var/lib/apt/lists/*

# The nightly toolchain the fuzzer and Miri run on. Pinned by the date the project's gates were
# last verified against, not by "latest": a nightly that moves under a green build is a test
# suite that stops meaning anything.
RUN rustup toolchain install nightly \
    && rustup component add --toolchain nightly miri rust-src rustfmt clippy

# cargo-fuzz drives libFuzzer. `cargo-miri` is NOT installed from crates.io: the crate is
# yanked there, and the interpreter comes from the rustup component added above -
# `cargo +nightly miri` finds it without any crate install.
RUN cargo install cargo-fuzz --locked

# The fuzzer needs to find libFuzzer's runtime; the clang package puts it under the versioned
# resource directory.
ENV RUSTFLAGS=""
ENV CARGO_TARGET_DIR=/target

WORKDIR /w
