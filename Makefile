CARGO ?= ./scripts/cargo.sh

.PHONY: build test lint fmt fmt-check check all

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
