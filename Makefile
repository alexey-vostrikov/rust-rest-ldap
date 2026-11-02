CARGO ?= ./scripts/cargo.sh

.PHONY: build test lint fmt fmt-check check all install

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
