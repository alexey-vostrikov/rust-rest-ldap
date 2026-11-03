#!/usr/bin/env python3
"""Give the mutation worker a stable directory, so cargo's cache survives between mutants.

Why this is needed at all: mutator writes each worker to
`target/mutation-workers/run-<uuid>/worker-0` with a fresh UUID per run. cargo's unit hash
includes the package's absolute path, so every mutant looks like a different crate and the whole
tree plus its tests is rebuilt from scratch - measured at 27 minutes for seven sites, which is
about eighty hours over this project. The tool would then measure how fast cargo rebuilds, not
how strong the tests are.

What it changes: the run directory becomes `run-stable` and is deleted before use, so a reused
directory cannot keep a file the repo no longer has (a stale `src/foo.rs` would still compile).
Nothing else about mutator's behaviour is touched.

The substitution asserts that it matched: if upstream moves the line, the build fails here
instead of producing a green run that measures the wrong thing.
"""

import pathlib
import sys

TARGET = pathlib.Path("/opt/mutator/src/mutator/workers.py")

BEFORE = '''    directory = root / "target" / "mutation-workers" / f"run-{uuid.uuid4()}"
    directory.mkdir(parents=True)'''

AFTER = '''    directory = root / "target" / "mutation-workers" / "run-stable"
    # A stable path is what makes cargo's cache usable: the unit hash includes the package's
    # absolute path, so a fresh UUID per run defeats it. The directory is emptied first, or a
    # file that the repository no longer has would stay in the worker and still compile.
    if directory.exists():
        delete_tree(directory)
    directory.mkdir(parents=True)'''


def main() -> int:
    if not TARGET.is_file():
        print(f"{TARGET} is missing: the image is not the one this patch was written for", file=sys.stderr)
        return 1

    text = TARGET.read_text()

    if AFTER in text:
        print("already patched")
        return 0

    if BEFORE not in text:
        print(
            "the upstream text moved: mutation measurement would silently rebuild everything.\n"
            "Look at new_run_dir() in workers.py and update this patch.",
            file=sys.stderr,
        )
        return 1

    TARGET.write_text(text.replace(BEFORE, AFTER))
    print("patched the worker to use a stable run directory")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
