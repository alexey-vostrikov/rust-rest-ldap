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

# The KDC is a sibling checkout, not a published crate, so the container has to see it at the path
# the manifest names: `/w/../rust-kdc` resolves to `/rust-kdc`. Mounted read-only - this repository
# only ever consumes it, and a build that could write into a neighbouring project is a build that
# can corrupt one. Where it lives is a checkout detail (`RR_LDAP_KDC` overrides it), so a missing
# one is not fatal: `cargo` then reports the missing package itself, which is the honest failure
# rather than a mount that quietly succeeds nowhere.
for candidate in "${RR_LDAP_KDC:-}" "$repo/../rust-kdc" "$repo/../../rust-kdc" "$repo/../rust-heimdal-kdc"; do
  if [ -n "$candidate" ] && [ -d "$candidate" ]; then
    kdc=$(cd "$candidate" && pwd)
    break
  fi
done
mounts=""
if [ -n "${kdc:-}" ]; then
  mounts="-v $kdc:/rust-kdc:ro"
fi

# The SMB server is a sibling checkout for the same reason and with the same rules: mounted
# read-only at the path the manifest names, and a missing one is `cargo`'s error to report.
# `RR_LDAP_SMB` overrides where it lives.
for candidate in "${RR_LDAP_SMB:-}" "$repo/../rust-smb-server" "$repo/../../rust-smb-server"; do
  if [ -n "$candidate" ] && [ -d "$candidate" ]; then
    smb=$(cd "$candidate" && pwd)
    break
  fi
done
if [ -n "${smb:-}" ]; then
  mounts="$mounts -v $smb:/rust-smb-server:ro"
fi

# MIRIFLAGS is passed through because otherwise `-Zmiri-disable-isolation` is dropped silently, and
# a test that needs the filesystem fails with "mkdir not available when isolation is enabled" - which
# reads as a defect in the code under test rather than in the harness.
exec docker run --rm \
  -v "$repo:/w" \
  $mounts \
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
