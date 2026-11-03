#!/bin/sh
# Run a command inside the measurement image (build image + cargo-llvm-cov).
#
# Usage: scripts/metrics.sh <cargo subcommand and args>
#   scripts/metrics.sh llvm-cov --lcov --output-path /w/.metrics/lcov.info --no-cfg-coverage
#
# Separate from scripts/cargo.sh on purpose: the coverage tool is a large install and only the
# metrics work needs it, so the build image does not carry it.
set -eu

IMAGE="${RR_LDAP_METRICS_IMAGE:-rust-rest-ldap-metrics:1.99.1}"
repo=$(cd "$(dirname "$0")/.." && pwd)
cargo_cache="${RR_LDAP_CARGO_CACHE:-$HOME/.cache/rrl/cargo}"
rustup_cache="${RR_LDAP_RUSTUP_CACHE:-$HOME/.cache/rrl/rustup}"
target_cache="${RR_LDAP_TARGET_CACHE:-$HOME/.cache/rrl/target}"

mkdir -p "$cargo_cache" "$rustup_cache" "$target_cache" "$repo/.metrics"

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
  "$IMAGE" cargo "$@"
