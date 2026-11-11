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

# Both Kerberos dependencies are git dependencies, so there is no sibling checkout to mount: cargo
# fetches `rrl-kdc` and `smb-server` into `$CARGO_HOME/git` and the container needs only that cache,
# which every run already has. The mounts this replaced pointed at paths the manifest no longer
# names, and one of them named a directory that had since been renamed - a mount that resolves to
# nothing is invisible, which is why they are gone rather than left in place.

# MIRIFLAGS is passed through because otherwise `-Zmiri-disable-isolation` is dropped silently, and
# a test that needs the filesystem fails with "mkdir not available when isolation is enabled" - which
# reads as a defect in the code under test rather than in the harness.
exec docker run --rm \
  -v "$repo:/w" \
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
