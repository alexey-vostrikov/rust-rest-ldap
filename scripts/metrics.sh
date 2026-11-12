#!/bin/sh
# Run cargo or one of the measurement tools inside the metrics image.
#
# Usage:
#   scripts/metrics.sh cargo llvm-cov --lcov --output-path /w/target/coverage/lcov.info --no-cfg-coverage
#   scripts/metrics.sh crapper --root /w -s /w/src --use-existing-coverage
#   scripts/metrics.sh dryer --root /w -s /w/src
#   scripts/metrics.sh mutator --root /w -s /w/src --use-existing-coverage --mutate-all /w/src/dn.rs
#
# The tools are baked into the image (docker/metrics.Dockerfile, pinned by commit), so this
# script mounts the project and nothing else: a measurement reproduces from the image, and a tool
# that changes in somebody's checkout cannot change a number.
set -eu

[ "$#" -ge 1 ] || { echo "usage: scripts/metrics.sh <cargo|crapper|dryer|mutator> [args...]" >&2; exit 2; }

tool="$1"
shift

case "$tool" in
  cargo|crapper|dryer|mutator) ;;
  *) echo "'$tool' is not one of cargo, crapper, dryer, mutator" >&2; exit 2 ;;
esac

repo=$(cd "$(dirname "$0")/.." && pwd)
image="${RR_LDAP_METRICS_IMAGE:-rrl-directory-metrics:1.99.1}"
cargo_cache="${RR_LDAP_CARGO_CACHE:-$HOME/.cache/rrl/cargo}"
rustup_cache="${RR_LDAP_RUSTUP_CACHE:-$HOME/.cache/rrl/rustup}"
target_cache="${RR_LDAP_TARGET_CACHE:-$HOME/.cache/rrl/target}"

# The tree-sitter grammars are baked into the metrics image, so a host cache is no longer required
# - the image works with no network and no home directory. `TS_CACHE` stays as an override for the
# case it was originally for: a host that warmed a newer language pack than the image pins.
grammars="${TS_CACHE:-$HOME/.cache/tree-sitter-language-pack}"
# A plain string, not an array: this script runs under `sh`, which is dash on Debian, and dash
# has no arrays. The path is a cache directory under $HOME, so it has no spaces to split on.
grammar_flag=
if [ -d "$grammars" ]; then
  grammar_flag="-v $grammars:/opt/cache/tree-sitter-language-pack:ro"
fi

mkdir -p "$cargo_cache" "$rustup_cache" "$target_cache" "$repo/.metrics"

exec docker run --rm \
  -v "$repo:/w" \
  $grammar_flag \
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
  "$image" "$tool" "$@"
