# Tutela developer tasks. CI (.github/workflows/ci.yml) calls these same targets.
#
#   make            # = make all: the Rust gates (format check, clippy, tests, docs,
#                   #   cargo-deny, cargo-audit), the JavaScript SDKs' gates (js)
#                   #   the image's Dockerfile lint (image-lint), the Helm chart (helm)
#                   #   and, with TUTELA_REQUIRE_KEYCLOAK=1, the real Keycloak (keycloak)
#
# Requirements: Rust (pinned by rust-toolchain.toml), cargo-deny and cargo-audit;
# node >= 22.12 and pnpm 10 for `make js` (ADR-0047). Plain `cargo build` and
# `cargo test` never need node.

CARGO  ?= cargo
PNPM   ?= pnpm
# Cargo resolution flags; `make lint LOCKED=` while you are still adding dependencies.
LOCKED ?= --locked

.DEFAULT_GOAL := all

.PHONY: help all ci fmt fmt-check lint test doc deny audit clean image-lint helm keycloak \
	js js-install js-build js-typecheck js-lint js-test js-it js-e2e js-audit js-licenses

help:
	@echo "Targets: all (fmt-check lint test doc deny audit js image-lint helm keycloak), fmt, fmt-check, lint, test, doc, deny, audit, clean"
	@echo "         js (js-install js-build js-typecheck js-lint js-test js-it js-e2e js-audit js-licenses)"

all: fmt-check lint test doc deny audit js image-lint helm keycloak

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

# The OCI image's Dockerfile (ADR-0055), linted by hadolint. Without hadolint
# it says it is skipped, unless TUTELA_REQUIRE_HADOLINT=1, which fails it.
HADOLINT ?= hadolint
image-lint:
	@if command -v $(HADOLINT) >/dev/null 2>&1; then \
		$(HADOLINT) Dockerfile && echo "hadolint: Dockerfile passes"; \
	elif [ "$$TUTELA_REQUIRE_HADOLINT" = "1" ]; then \
		echo "hadolint is not installed and TUTELA_REQUIRE_HADOLINT=1"; exit 1; \
	else \
		echo "skipped: hadolint is not installed (set TUTELA_REQUIRE_HADOLINT=1 to fail instead)"; \
	fi

# The Helm chart deploy/helm/tutela (ADR-0056): helm lint, helm template with
# the default and the production-like values, and checks on the rendered
# manifests (scripts/helm-check.mjs). Without helm it says it is skipped,
# unless TUTELA_REQUIRE_HELM=1, which fails it.
helm:
	node scripts/helm-check.mjs

# Token exchange and the Console's browser check against a real Keycloak 26
# (#87, ADR-0057): scripts/keycloak-check.mjs starts the pinned image on
# loopback, makes the realm with the chart's Console client, and runs
# crates/tutelad/tests/keycloak.rs and console_e2e.rs against it. It pulls an
# image and starts a container, so it says it is skipped unless
# TUTELA_REQUIRE_KEYCLOAK=1, which runs it and fails it when docker, helm,
# the image or the database is missing. Like js-e2e it needs
# TUTELA_TEST_DATABASE_URL and the built Console (js-build runs first in all).
keycloak:
	node scripts/keycloak-check.mjs

# ---------- The JavaScript SDKs: sdk/js and sdk/react (ADR-0047) ----------

js: js-install js-build js-typecheck js-lint js-test js-it js-e2e js-audit js-licenses

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

# The Phase B exit check in a real browser (ADR-0053): the Rust test makes
# the world (a real tutelad on a real Postgres serving the built Console, the
# test OpenID provider) and runs console/e2e with Playwright's Chromium. Like
# js-it it needs TUTELA_TEST_DATABASE_URL and fails without it when
# TUTELA_REQUIRE_DATABASE=1; a missing browser fails it. Set TUTELA_E2E_SHOTS
# to a directory to keep screenshots of the main pages.
js-e2e:
	TUTELA_CONSOLE_E2E=1 $(CARGO) test -p tutelad --all-features $(LOCKED) --test console_e2e -- --nocapture

js-audit:
	$(PNPM) audit

js-licenses:
	node scripts/js-licenses.mjs
