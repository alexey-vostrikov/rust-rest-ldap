#!/bin/sh
# Run the mutation measurement over a list of files, one file at a time.
#
# Why one at a time with --max-workers 1: workers of one mutator process share CARGO_TARGET_DIR,
# and two cargo builds fighting over the same target directory produce wrong numbers in both
# directions. One file at a time is slow and honest.
#
# Why in the background: a single file of 30 covered sites takes about eight minutes at ~15
# seconds a mutant, and six files would outlive any foreground timeout.
#
# Usage: scripts/mutate-files.sh acl.rs ldap/filter.rs config_entry.rs
#
# The summary is read from the per-file logs, not from one "Total" line: a run can fail on its
# own file while the others finish, and the logs are what says which.
#
# KNOWN LIMITATION, and it makes the numbers wrong today: mutator creates a symlink overlay of
# the project and expects the test command to build the MUTATED file. Our test command is
# scripts/cargo.sh, which mounts the REAL repository into Docker by a path computed from its own
# location - so the container never sees the mutation. The run then finishes in a fraction of the
# time a real one would take (1259 sites in 356 s against a 17-second test command) and reports
# everything as killed. Read such a result as "the mutation did not land", never as "the tests are
# strong". The fix is to run mutator inside the image (D8 in docs/plan.md), not from the host.
set -u

repo=$(cd "$(dirname "$0")/.." && pwd)
mutator="${MUTATOR_PYTHON:-$HOME/DevOps/3part/mutator/.venv/bin/python}"
cargo="${CARGO_WRAPPER:-$repo/scripts/cargo.sh}"
logs="$repo/.metrics/mutate-logs"

mkdir -p "$logs"

if [ ! -f "$repo/target/coverage/lcov.info" ]; then
  echo "нет покрытия: сначала соберите его (scripts/metrics.sh llvm-cov ...) и положите в target/coverage/lcov.info" >&2
  exit 1
fi

for name in "$@"; do
  log="$logs/$(echo "$name" | tr '/' '-').log"
  echo "=== $name"
  "$mutator" -m mutator --root "$repo" -s "$repo/src" \
    --use-existing-coverage \
    --max-workers 1 \
    --test-command "$cargo test --lib --quiet" \
    "$repo/src/$name" > "$log" 2>&1
  tail -3 "$log" | sed 's/^/    /'
done

echo "=== сводка"
for log in "$logs"/*.log; do
  name=$(basename "$log" .log)
  line=$(grep -E "killed [0-9]+|Total|score" "$log" | tail -1)
  echo "  $name: ${line:-нет итога}"
done
