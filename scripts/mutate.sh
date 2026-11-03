#!/bin/sh
# Run the mutation measurement inside the container, where the overlay actually works.
#
# Usage: scripts/mutate.sh src/dn.rs [more files...]
#        scripts/mutate.sh              # the whole tree (hours; not for a merge request)
#
# Every target, not only the library: a mutation that the integration tests would catch came back
# as SURVIVED while the command was `--lib`, which reads as "the tests are weak" when what was
# weak was the command.
#
# One file at a time is the point: `mutator` walks a directory but is only told about files, and
# `-s` takes precedence over any path argument (cli.py: `if options.source_roots: return
# iter_source_files(...)` runs before the explicit paths are looked at). So `-s` is passed only
# when no file was named - with it, "mutate src/dn.rs" quietly mutated all 63 files.
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

# No arguments means the whole tree: slow, but honest about what it costs.

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

# The source root is what discovery walks, and it wins over any path argument, so it is only
# given when the argument already is the whole tree.
if [ "$#" -ge 1 ]; then
  sources=""
else
  sources="-s /w/src"
  # The loop below prepends `/w/`, so this stays relative.
  set -- src
fi

# The output is shown, not filtered. Filtering it to the verdict lines hid the reason a run
# produced none: a container that failed on startup printed its complaint to stderr, grep dropped
# it, and the script reported nothing in a third of a second - which reads exactly like a run that
# found nothing to say.
#
# One file at a time, one worker: workers of one process share CARGO_TARGET_DIR, and two cargo
# builds over one target directory give wrong numbers in both directions.
for name in "$@"; do
  echo "=== $name"
  # `$sources` is unquoted on purpose: it is either empty or the two words `-s /w/src`.
  # shellcheck disable=SC2086
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
    -e PATH=/opt/venv-tools/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin \
    "$image" \
    python3 -m mutator --root /w $sources \
      --use-existing-coverage --mutate-all --max-workers 1 \
      --test-command "cargo test --all-targets --quiet" \
      "/w/$name" 2>&1 | tail -25
done
