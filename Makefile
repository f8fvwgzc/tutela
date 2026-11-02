# Tutela developer tasks. CI (.github/workflows/ci.yml) calls these same targets.
#
#   make            # = make all: the Rust gates (format check, clippy, tests, docs,
#                   #   cargo-deny, cargo-audit) and the JavaScript SDKs' gates (js)
#
# Requirements: Rust (pinned by rust-toolchain.toml), cargo-deny and cargo-audit;
# node >= 22.12 and pnpm 10 for `make js` (ADR-0047). Plain `cargo build` and
# `cargo test` never need node.

CARGO  ?= cargo
PNPM   ?= pnpm
# Cargo resolution flags; `make lint LOCKED=` while you are still adding dependencies.
LOCKED ?= --locked

.DEFAULT_GOAL := all

.PHONY: help all ci fmt fmt-check lint test doc deny audit clean \
	js js-install js-build js-typecheck js-lint js-test js-it js-audit js-licenses

help:
	@echo "Targets: all (fmt-check lint test doc deny audit js), fmt, fmt-check, lint, test, doc, deny, audit, clean"
	@echo "         js (js-install js-build js-typecheck js-lint js-test js-it js-audit js-licenses)"

all: fmt-check lint test doc deny audit js

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

# ---------- The JavaScript SDKs: sdk/js and sdk/react (ADR-0047) ----------

js: js-install js-build js-typecheck js-lint js-test js-it js-audit js-licenses

js-install:
	$(PNPM) install --frozen-lockfile

# Builds first: @f8fvwgzc/tutela-react type-checks against tutela-js's output.
js-build:
	$(PNPM) -r run build

js-typecheck:
	$(PNPM) -r run typecheck

js-lint:
	$(PNPM) run lint

js-test:
	$(PNPM) -r run test

# @f8fvwgzc/tutela-js against a real tutelad on a real Postgres: the Rust test
# makes the world and runs sdk/js/test-integration with vitest. Like every
# database test it needs TUTELA_TEST_DATABASE_URL, and fails without it when
# TUTELA_REQUIRE_DATABASE=1.
js-it:
	TUTELA_JS_INTEGRATION=1 $(CARGO) test -p tutelad --all-features $(LOCKED) --test js_client -- --nocapture

js-audit:
	$(PNPM) audit

js-licenses:
	node scripts/js-licenses.mjs
