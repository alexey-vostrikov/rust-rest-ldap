# The measurement image: the build image plus the coverage tool.
#
# Separate from docker/build.Dockerfile on purpose. `cargo-llvm-cov` is a large install, and
# only the metrics work needs it; a build that runs on every commit should not carry it. What
# the coverage run adds to the build image is llvm-tools (the profiler runtime) and the tool.
FROM rust-rest-ldap-build:1.99.1

# llvm-tools is the profiler runtime `cargo-llvm-cov` instruments against; without it the tool
# reports "no llvm-tools" and refuses to measure.
RUN rustup component add llvm-tools-preview \
    && rustup component add llvm-tools-preview --toolchain nightly

RUN cargo install cargo-llvm-cov --locked

WORKDIR /w
