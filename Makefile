CARGO ?= ./scripts/cargo.sh
CRAPPER ?= $(HOME)/DevOps/3part/crapper/.venv/bin/python -m crapper
DRYER ?= $(HOME)/DevOps/3part/dryer/.venv/bin/python -m dryer

.PHONY: build test lint fmt fmt-check check all install miri fuzz fuzz-all metrics dup mutate

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
	./scripts/metrics.sh llvm-cov --lcov --output-path /w/.metrics/lcov.info --no-cfg-coverage
	sed -i 's|^SF:/w/|SF:'"$$PWD"'/|' .metrics/lcov.info
	mkdir -p target/coverage
	cp .metrics/lcov.info target/coverage/lcov.info
	$(CRAPPER) --root . -s ./src --use-existing-coverage

# Duplicates only: no coverage needed, so this is the cheap one and the one worth running often.
dup:
	$(DRYER) --root . -s ./src

# Mutation over a list of files. See the limitation in scripts/mutate-files.sh: today the numbers
# come out wrong because the test command runs in a container that cannot see the overlay.
mutate:
	./scripts/mutate-files.sh $(FILES)
