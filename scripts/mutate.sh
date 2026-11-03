#!/bin/sh
# Run the mutation measurement inside the container, where the overlay actually works.
#
# Usage: scripts/mutate.sh src/dn.rs [more files...]
#        MUTATOR_SECONDS=0 scripts/mutate.sh src/acl.rs      # whole file, no limit
#
# Why inside: mutator writes the mutated file into a symlink overlay and runs the test command
# with the overlay as its working directory. On the host our test command is scripts/cargo.sh,
# which mounts the REAL repository into Docker, so the container never sees the mutation and
# every mutant counts as killed - 1259 sites "in" 356 seconds against a 17-second test command.
# In here the test command is plain `cargo test`, the working directory is the overlay, and cargo
# builds the worker's own `src`.
#
# Coverage has to be on disk and fresh (target/coverage/lcov.info), or mutator runs zero mutants:
# it does not say "no coverage", it reports "killed 0 survived 0" and looks like it worked.
set -eu

[ "$#" -ge 1 ] || { echo "usage: scripts/mutate.sh <src/file.rs> [more...]" >&2; exit 2; }

repo=$(cd "$(dirname "$0")/.." && pwd)
image="${RR_LDAP_METRICS_IMAGE:-rust-rest-ldap-metrics:1.99.1}"

cargo_cache="${RR_LDAP_CARGO_CACHE:-$HOME/.cache/rrl/cargo}"
rustup_cache="${RR_LDAP_RUSTUP_CACHE:-$HOME/.cache/rrl/rustup}"
target_cache="${RR_LDAP_TARGET_CACHE:-$HOME/.cache/rrl/target}"

grammars="${TS_CACHE:-$HOME/.cache/tree-sitter-language-pack}"
[ -d "$grammars" ] || {
  echo "нет кэша грамматик tree-sitter в '$grammars': запустите crapper на хосте один раз" >&2
  exit 1
}

if [ ! -f "$repo/target/coverage/lcov.info" ]; then
  echo "нет покрытия: соберите его (make metrics) — без него mutator запускает ноль мутантов" >&2
  exit 1
fi

# One file at a time, one worker: workers of one process share CARGO_TARGET_DIR, and two cargo
# builds over one target directory give wrong numbers in both directions.
for name in "$@"; do
  echo "=== $name"
  docker run --rm \
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
    "$image" \
    python3 -m mutator --root /w -s /w/src \
      --use-existing-coverage --mutate-all --max-workers 1 \
      --test-command "cargo test --lib --quiet" \
      "/w/$name" 2>&1 | grep -E "^(KILLED|SURVIVED|UNCOVERED|Total)" | tail -20
done
