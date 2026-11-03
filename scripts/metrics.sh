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
image="${RR_LDAP_METRICS_IMAGE:-rust-rest-ldap-metrics:1.99.1}"
cargo_cache="${RR_LDAP_CARGO_CACHE:-$HOME/.cache/rrl/cargo}"
rustup_cache="${RR_LDAP_RUSTUP_CACHE:-$HOME/.cache/rrl/rustup}"
target_cache="${RR_LDAP_TARGET_CACHE:-$HOME/.cache/rrl/target}"

# The tree-sitter grammars cannot be downloaded from here: behind this network the fetch times
# out, which is what a six-hour "hang" turned out to be. crapper warms the cache on the host once;
# without it crapper and mutator would sit on a socket, so their absence is a loud failure.
grammars="${TS_CACHE:-$HOME/.cache/tree-sitter-language-pack}"
case "$tool" in
  crapper|dryer|mutator)
    [ -d "$grammars" ] || {
      echo "нет кэша грамматик tree-sitter в '$grammars':" >&2
      echo "запустите crapper на хосте один раз, он скачает их, и повторите" >&2
      exit 1
    }
    ;;
esac

mkdir -p "$cargo_cache" "$rustup_cache" "$target_cache" "$repo/.metrics"

exec docker run --rm \
  -v "$repo:/w" \
  -v "$grammars:/opt/cache/tree-sitter-language-pack:ro" \
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
