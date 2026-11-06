#!/bin/sh
# Run cargo inside the pinned build container.
# Host has no rust toolchain on purpose (see docs/ub-log.md): every build,
# test, fmt, clippy and metrics run goes through this wrapper, so the toolchain
# version is the one pinned in rust-toolchain.toml and the image below.
set -eu

IMAGE="${RR_LDAP_IMAGE:-rust:1.99.1-slim-trixie}"
repo=$(cd "$(dirname "$0")/.." && pwd)
cargo_cache="${RR_LDAP_CARGO_CACHE:-$HOME/.cache/rrl/cargo}"
rustup_cache="${RR_LDAP_RUSTUP_CACHE:-$HOME/.cache/rrl/rustup}"
target_cache="${RR_LDAP_TARGET_CACHE:-$HOME/.cache/rrl/target}"

mkdir -p "$cargo_cache" "$rustup_cache" "$target_cache"

# MIRIFLAGS is passed through because otherwise `-Zmiri-disable-isolation` is dropped silently, and
# a test that needs the filesystem fails with "mkdir not available when isolation is enabled" - which
# reads as a defect in the code under test rather than in the harness.
exec docker run --rm \
  -v "$repo:/w" \
  -v "$cargo_cache:/cargo" \
  -v "$rustup_cache:/rustup" \
  -v "$target_cache:/target" \
  -w /w \
  -u "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e CARGO_HOME=/cargo \
  -e RUSTUP_HOME=/rustup \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=never \
  -e "MIRIFLAGS=${MIRIFLAGS:-}" \
  "$IMAGE" cargo "$@"
