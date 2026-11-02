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
