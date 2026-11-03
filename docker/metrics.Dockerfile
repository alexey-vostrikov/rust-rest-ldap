# The measurement image: the build image plus every tool the metrics work needs.
#
# Separate from docker/build.Dockerfile on purpose: cargo-llvm-cov is a large install and the
# Python tools pull tree-sitter grammars, so only the metrics work needs any of it; a build that
# runs on every commit should not carry them.
#
# The tools are baked in rather than taken from the host, so a measurement reproduces from this
# file alone and a tool that changes in somebody's checkout cannot silently change a number. All
# three are pinned to commits, not to branches - a moving ref under a green result is a test
# suite that stops meaning anything.
FROM rust-rest-ldap-build:1.99.1

# llvm-tools is the profiler runtime cargo-llvm-cov instruments against; without it the tool
# reports "no llvm-tools" and refuses to measure.
RUN rustup component add llvm-tools-preview \
    && rustup component add llvm-tools-preview --toolchain nightly

RUN cargo install cargo-llvm-cov --locked

# python3 for the three tools, and a compiler for tree-sitter's per-language grammars: the
# language pack builds a grammar per language, and a missing compiler shows up only at first use.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-venv build-essential git \
    && rm -rf /var/lib/apt/lists/*

ARG CRAPPER_COMMIT=6fd92c4c9bcc56efb64a2f8743d5a2993bcfd42d
ARG DRYER_COMMIT=66ff6d21a42c04afcad89c78a80066176d1294b0
ARG MUTATOR_COMMIT=a5a0cb803b66e0cdb8bf471b3b08af701d424a41

RUN git clone https://github.com/unclebob/crapper.git /opt/crapper \
    && git -C /opt/crapper checkout "$CRAPPER_COMMIT" \
    && git clone https://github.com/unclebob/dryer.git /opt/dryer \
    && git -C /opt/dryer checkout "$DRYER_COMMIT" \
    && git clone https://github.com/unclebob/mutator.git /opt/mutator \
    && git -C /opt/mutator checkout "$MUTATOR_COMMIT"

# The language pack is pinned to the version whose cache is warmed on the host: the pack looks for
# grammars under a version-named directory, and a newer pack asks for a directory that does not
# exist, then tries to download into a read-only mount and fails. Pinning makes the mount usable.
#
# Installed rather than merely put on the path: each one declares a console script, and running
# `crapper`/`dryer`/`mutator` as commands is what everyone expects to type.
RUN python3 -m venv /opt/venv-tools \
    && /opt/venv-tools/bin/pip install --no-cache-dir \
        "tree-sitter>=0.24" "tree-sitter-language-pack==1.22.1" \
        /opt/crapper /opt/dryer /opt/mutator

# The tree-sitter grammars are downloaded on first parse. Behind this network the download
# times out - which is exactly what a six-hour "hang" turned out to be, not a slow mutation run.
# They cannot be fetched at build time either, so the cache is mounted by scripts/metrics.sh and
# scripts/mutate.sh from the host, where crapper has warmed it once. This ENV is what makes the
# mounted directory the place the language pack looks in.
ENV XDG_CACHE_HOME=/opt/cache

# The one local patch, and why it exists: mutator writes each worker to a directory with a fresh
# UUID per run, and cargo's unit hash includes the package path - so every mutant rebuilds the
# whole crate. Measured: 27 minutes for seven sites. The patch gives the worker a stable path and
# fails the build if upstream moves the line it edits.
COPY docker/patch-mutator.py /opt/patch-mutator.py
RUN python3 /opt/patch-mutator.py

# The tools know each other: mutator takes function names from crapper's report and looks for
# crapper's source next to its own, so all three source trees go on the path.
ENV PATH="/opt/venv-tools/bin:$PATH"
ENV PYTHONPATH="/opt/mutator/src:/opt/crapper/src:/opt/dryer/src"

WORKDIR /w
