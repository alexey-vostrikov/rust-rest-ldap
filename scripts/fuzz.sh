#!/bin/sh
# Run a fuzz target inside the build image.
#
# Usage: scripts/fuzz.sh <target> [seconds]
#   scripts/fuzz.sh codec 60
#
# The corpus lives in fuzz/corpus/<target>/ and is written back, so a run that finds something
# keeps the input that found it: a crash without its input is a report nobody can reproduce.
set -eu

TARGET="${1:?usage: scripts/fuzz.sh <target> [seconds]}"
SECONDS_TO_RUN="${2:-60}"

IMAGE="${RR_LDAP_IMAGE:-rust-rest-ldap-build:1.99.1}"
repo=$(cd "$(dirname "$0")/.." && pwd)
cargo_cache="${RR_LDAP_CARGO_CACHE:-$HOME/.cache/rrl/cargo}"
rustup_cache="${RR_LDAP_RUSTUP_CACHE:-$HOME/.cache/rrl/rustup}"
target_cache="${RR_LDAP_TARGET_CACHE:-$HOME/.cache/rrl/target}"

mkdir -p "$cargo_cache" "$rustup_cache" "$target_cache" "$repo/fuzz/corpus/$TARGET" "$repo/fuzz/artifacts"

# The corpus is generated and never committed: it reaches tens of megabytes after a few minutes.
# What IS committed is fuzz/seeds - a handful of hand-written inputs that put the fuzzer inside
# the grammar instead of making it rediscover `(` from random bytes. They are copied in on the
# first run, so a fresh clone starts where the last one did.
if [ -d "$repo/fuzz/seeds/$TARGET" ] && [ -z "$(ls -A "$repo/fuzz/corpus/$TARGET" 2>/dev/null)" ]; then
  cp "$repo/fuzz/seeds/$TARGET"/*.bin "$repo/fuzz/corpus/$TARGET/" 2>/dev/null || true
fi

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
  "$IMAGE" \
  cargo +nightly fuzz run "$TARGET" "fuzz/corpus/$TARGET" -- \
  -max_total_time="$SECONDS_TO_RUN" -artifact_prefix=/w/fuzz/artifacts/
