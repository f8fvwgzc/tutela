# Tutela developer tasks. CI (.github/workflows/ci.yml) calls these same targets.
#
#   make            # = make all: format check, clippy, tests, docs, cargo-deny, cargo-audit
#
# Requirements: Rust (pinned by rust-toolchain.toml), cargo-deny and cargo-audit.

CARGO  ?= cargo
# Cargo resolution flags; `make lint LOCKED=` while you are still adding dependencies.
LOCKED ?= --locked

.DEFAULT_GOAL := all

.PHONY: help all ci fmt fmt-check lint test doc deny audit clean

help:
	@echo "Targets: all (fmt-check lint test doc deny audit), fmt, fmt-check, lint, test, doc, deny, audit, clean"

all: fmt-check lint test doc deny audit

ci: all

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --workspace --all-targets --all-features $(LOCKED) -- -D warnings

test:
	$(CARGO) test --workspace --all-features $(LOCKED)

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps --all-features $(LOCKED)

deny:
	$(CARGO) deny --all-features check

audit:
	$(CARGO) audit --deny warnings

clean:
	$(CARGO) clean
