#!/bin/sh
# Run cargo inside the pinned build container.
# Host has no rust toolchain on purpose (see docs/ub-log.md): every build,
# test, fmt, clippy and metrics run goes through this wrapper, so the toolchain
# version is the one pinned in rust-toolchain.toml and the image below.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
# One registry for every Rust project on this machine, named after the base it serves: a registry
# filled under one glibc is one the next toolchain may not be able to use. `RR_LDAP_CARGO_CACHE`
# still overrides it for a one-off run.
cargo_cache="${RR_LDAP_CARGO_CACHE:-rrl-cargo-bullseye}"
rustup_cache="${RR_LDAP_RUSTUP_CACHE:-$HOME/.cache/rrl/rustup}"
target_cache="${RR_LDAP_TARGET_CACHE:-$HOME/.cache/rrl/target}"

# Bullseye, assembled locally: `rust:<version>-bullseye` is not published, and the reason to want
# it is glibc - bullseye gives 2.31, which the stands and Astra Linux run, while bookworm gives 2.36
# and a binary built there will not start. The assembly is `docker/toolchain.Dockerfile`, the same
# file rust-smb-server uses, so the two crates build on one toolchain.
TOOLCHAIN_CHANNEL=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$repo/rust-toolchain.toml")
IMAGE="${RR_LDAP_IMAGE:-rust:${TOOLCHAIN_CHANNEL}-bullseye}"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "building $IMAGE from docker/toolchain.Dockerfile (once)" >&2
    docker build -f "$repo/docker/toolchain.Dockerfile" -t "$IMAGE" \
        --build-arg "RUST_TOOLCHAIN=${TOOLCHAIN_CHANNEL}" "$repo/docker" >&2
fi

mkdir -p "$target_cache"
case "$cargo_cache" in
/* | .*) mkdir -p "$cargo_cache" ;;
*) docker volume create "$cargo_cache" >/dev/null ;;
esac
case "$rustup_cache" in
/* | .*) mkdir -p "$rustup_cache" ;;
esac

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
  -v "$target_cache:/target" \
  -w /w \
  -u "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e CARGO_HOME=/cargo \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=never \
  -e "MIRIFLAGS=${MIRIFLAGS:-}" \
  "$IMAGE" cargo "$@"
