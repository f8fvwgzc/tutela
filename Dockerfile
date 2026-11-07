# The tutelad image (issue #49, ADR-0055): the service and the built Tutela
# Console, on a distroless runtime with no shell, as a non-root user.
#
#   docker build -t tutelad:dev \
#     --build-arg VERSION=0.2.0 --build-arg REVISION="$(git rev-parse HEAD)" .
#
# Three stages: node builds console/dist, Rust builds tutelad, and the
# runtime gets the binary and the Console only. The base images are pinned
# by digest (each an image index, so linux/amd64 and linux/arm64 both
# build); change a digest on purpose, never a tag alone. No HEALTHCHECK:
# Kubernetes probes /healthz and /readyz on the ops port.

ARG NODE_IMAGE=node:22.12-bookworm-slim@sha256:35531c52ce27b6575d69755c73e65d4468dba93a25644eed56dc12879cae9213
ARG RUST_IMAGE=rust:1.99.0-slim-bookworm@sha256:2c3a22f0a5533ea2dd5a16627bc841228151faa2d4de2644ac9987e4a2f1f2fa
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

# ---------- The Console: node 22.12 and pnpm 10.18 (ADR-0047) ----------
FROM ${NODE_IMAGE} AS console
ARG PNPM_VERSION=10.18.1
WORKDIR /src
ENV CI=true
RUN npm install --global --no-audit --no-fund "pnpm@${PNPM_VERSION}"
# The manifests first, so the install is cached while only sources change.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc tsconfig.base.json ./
COPY sdk/js/package.json sdk/js/
COPY sdk/react/package.json sdk/react/
COPY console/package.json console/
RUN pnpm install --frozen-lockfile
COPY sdk/js/ sdk/js/
COPY sdk/react/ sdk/react/
COPY console/ console/
RUN pnpm -r run build \
    && test -f console/dist/index.html

# ---------- tutelad: Rust 1.99.0 (rust-toolchain.toml) ----------
FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked -p tutelad --bin tutelad \
    && mkdir -p /out \
    && cp target/release/tutelad /out/tutelad

# ---------- The runtime: glibc, CA certificates, no shell, uid 65532 ----------
FROM ${RUNTIME_IMAGE}
ARG VERSION=0.0.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="tutelad" \
      org.opencontainers.image.description="Tutela's service: token exchange, the check API, the admin API and the Tutela Console" \
      org.opencontainers.image.source="https://github.com/f8fvwgzc/tutela" \
      org.opencontainers.image.url="https://github.com/f8fvwgzc/tutela" \
      org.opencontainers.image.documentation="https://github.com/f8fvwgzc/tutela/tree/main/deploy" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="f8fvwgzc" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /out/tutelad /usr/local/bin/tutelad
# The Console is read once at start (ADR-0050): a new Console is a new image.
COPY --from=console /src/console/dist/ /srv/tutela/console/
# Panics print a backtrace; anyhow errors do not capture one (deploy/tutelad.env).
# The Console is on: set TUTELA_CONSOLE_ISSUER, TUTELA_CONSOLE_CLIENT_ID and
# TUTELA_ADMIN_ACR, or set TUTELA_CONSOLE_DIR to "" to turn it off.
ENV RUST_BACKTRACE=1 \
    RUST_LIB_BACKTRACE=0 \
    TUTELA_LISTEN=0.0.0.0:8080 \
    TUTELA_OPS_LISTEN=0.0.0.0:9090 \
    TUTELA_CONSOLE_DIR=/srv/tutela/console
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/tutelad"]
CMD ["serve"]
