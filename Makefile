CARGO ?= ./scripts/cargo.sh

.PHONY: build test lint fmt fmt-check check all install miri fuzz fuzz-all metrics coverage-html dup mutate

build:
	$(CARGO) build --release

test:
	$(CARGO) test --all-targets

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --all-targets -- -D warnings

check: fmt-check lint test

# Miri over the modules that contain no system calls. The interpreted run is ten to a hundred
# times slower, so it is a module list and not the whole suite: the rest cannot run under Miri
# at all, because it opens sockets and files.
#
# What this buys: the crate forbids unsafe, so undefined behaviour cannot be written here - what
# Miri checks is that this code does not rely on undefined behaviour in the standard library on
# the paths it actually executes.
# `index_file` is absent on purpose, and the reason is not size: Miri supports neither a file
# mapping nor a temporary directory, so those tests abort inside `tempfile` before the code under
# test is reached. Their job - the bounds arithmetic - is done by the tests themselves: a truncated
# file, a foreign plan, a table pointing into the records.
MIRI_MODULES = dn ldap::codec ldap::filter ldap::filter_parse ldap::assertion ldap::paged sort index mutate schema

miri:
	@for module in $(MIRI_MODULES); do \
		echo "=== miri: $$module"; \
		$(CARGO) +nightly miri test --lib "$$module::" || exit 1; \
	done

# A fuzz target per parser that reads something an outsider controls. A panicking parser is a
# server that can be stopped from outside; `forbid(unsafe_code)` does not prevent a panic.
fuzz:
	./scripts/fuzz.sh $(TARGET) $(SECONDS)

# One minute each, which is enough to keep the corpus alive between longer runs.
fuzz-all:
	@for target in codec filter ldif schema dn endpoint; do \
		echo "=== fuzz: $$target"; \
		./scripts/fuzz.sh "$$target" 60 || exit 1; \
	done

all: check build

# The binary comes from the container's target directory, not from ./target: the build
# directory lives outside the repository so that root inside the container cannot leave
# files in the tree.
install: build
	install -m 0755 "$${RR_LDAP_TARGET_CACHE:-$$HOME/.cache/rrl/target}/release/rust-rest-ldap" /usr/local/bin/rust-rest-ldap
	install -m 0755 "$${RR_LDAP_TARGET_CACHE:-$$HOME/.cache/rrl/target}/release/ldapsearch" /usr/local/bin/ldapsearch
	install -m 0755 "$${RR_LDAP_TARGET_CACHE:-$$HOME/.cache/rrl/target}/release/ldapmodify" /usr/local/bin/ldapmodify
	install -m 0755 "$${RR_LDAP_TARGET_CACHE:-$$HOME/.cache/rrl/target}/release/ldaputil" /usr/local/bin/ldaputil
	# These names are programs, not copies: each reads its own name and runs the operation it
	# names. ldapadd is ldapmodify refusing change records; the five utilities share one
	# binary in OpenLDAP too, and the name is what selects the operation.
	ln -sf ldapmodify /usr/local/bin/ldapadd
	for tool in ldapdelete ldapmodrdn ldapcompare ldapwhoami ldappasswd; do \
		ln -sf ldaputil "/usr/local/bin/$$tool"; \
	done

# Coverage, then the complexity report over it. crapper only looks for lcov under
# target/coverage/**, so the report is copied there; and it must be fresh, or the numbers
# describe a tree that no longer exists.
metrics:
	./scripts/metrics.sh cargo llvm-cov --lcov --output-path /w/target/coverage/lcov.info --no-cfg-coverage
	./scripts/metrics.sh crapper --root /w -s /w/src --use-existing-coverage

# The same coverage as a browsable report. Not part of `metrics`: writing a directory of HTML on
# every run is noise, and the numbers live in crap.edn. This target is for reading line by line -
# which lines of a function the tests never reached.
#
# `--output-dir` appends `html/` itself: given target/coverage it writes target/coverage/html, and
# given target/coverage/html it writes target/coverage/html/html. Hence the shorter argument, and
# the echo prints the path that exists rather than the one that looks right.
coverage-html:
	./scripts/metrics.sh cargo llvm-cov --html --output-dir /w/target/coverage --no-cfg-coverage --remap-path-prefix
	@echo "отчёт: $$PWD/target/coverage/html/index.html"

# Duplicates only: no coverage needed, so this is the cheap one and the one worth running often.
dup:
	./scripts/metrics.sh dryer --root /w -s /w/src

# Mutation, inside the image where the overlay reaches the build. One file at a time.
#
# Known cost: the worker path carries a fresh UUID per run, so cargo's package fingerprint never
# matches and the crate is rebuilt from scratch for every mutant - 27 minutes for 7 sites. D8 in
# docs/plan.md has the fix; until then a mutation score from this project is not a number.
mutate:
	./scripts/mutate.sh $(FILES)
