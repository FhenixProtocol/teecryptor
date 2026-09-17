# syntax=docker/dockerfile:1
# Multi-stage build → distroless. The runtime image runs as root because the
# Confidential Space launcher socket (/run/container_launcher/teeserver.sock) is
# only readable by root (documented CS quirk).
#
# Build caching (borrowed from cofhe's ct-server): cargo-chef splits the
# expensive dependency compile (tfhe et al. — the bulk of the ~17min build) into
# its own layer that is ONLY rebuilt when Cargo.toml / Cargo.lock change. An
# app-code edit then rebuilds in ~1-2min instead of cold-compiling tfhe every
# time. In CI this layer is persisted across runs via buildx `--cache-to=gha`.

# --- chef base: cargo-chef + the pinned toolchain in one stable, cached layer ---
FROM rust:1-bookworm AS chef
# cmake: required by aws-lc-sys, the rustls crypto provider cofhe-keys uses for
# its pinned TLS 1.3 + X25519MLKEM768 googleapis egress (not in buildpack-deps).
RUN apt-get update && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef@0.1.71 --locked
WORKDIR /build
# rust-toolchain.toml pins the toolchain; install it once here so the planner /
# cook / build stages reuse it instead of re-resolving + re-downloading.
COPY rust-toolchain.toml ./
RUN rustup show

# --- planner: distill Cargo.{toml,lock} into a dependency-only recipe ---
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY abi ./abi
RUN cargo chef prepare --recipe-path recipe.json

# --- builder: cook deps (CACHED layer), then compile the app ---
FROM chef AS builder
# FEATURES is empty for production images. ONLY set FEATURES=mock for local
# smoke testing (docker-compose) — a mock image skips attestation and must never
# be deployed. It MUST match between `chef cook` and `cargo build`, or the
# dependency set (and thus the cached layer) differs and the cache is missed.
ARG FEATURES=""
COPY --from=planner /build/recipe.json recipe.json
# cofhe-keys is fetched from the public cofhe-tdx-keygen repo over https — no
# credential needed. CARGO_NET_GIT_FETCH_WITH_CLI makes cargo shell out to git.
# The expensive layer (tfhe). Cached and only re-run when recipe.json
# (i.e. Cargo.toml / Cargo.lock) changes — NOT on app-code edits.
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true \
    cargo chef cook --locked --release ${FEATURES:+--features "$FEATURES"} --recipe-path recipe.json
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# permit.rs's `alloy::sol!` reads these ABI JSONs at COMPILE time — required,
# or the build fails with "failed to canonicalize path abi/TaskManager.json".
COPY abi ./abi
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true \
    cargo build --locked --release --bin teecryptor ${FEATURES:+--features "$FEATURES"}

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /build/target/release/teecryptor /usr/local/bin/teecryptor

# Confidential Space publishes ONLY the ports the image EXPOSEs to the VM host.
# Without this, the workload binds 0.0.0.0:8080 inside its own netns and nothing
# on the VM (or via IAP / in-VPC callers) can reach it. Must match BIND_ADDR.
# 9090 is the text exposition. It is NOT a scrape target in production —
# metrics reach Cloud Monitoring by OTLP push — it is a debug surface, opened
# in the VM firewall to Google's IAP range only (compute/main.tf), so an
# operator can read the in-process counters over `gcloud compute
# start-iap-tunnel` when a push looks wrong. Must match METRICS_ADDR.
EXPOSE 8080 9090

# Confidential Space launch policy. Only these env vars may be set by the
# operator via tee-env-* instance metadata; anything else is ignored.
#
# COFHE_ENV is the baked-environment selector: the key SOURCE (partner set + WIF
# audiences + public bucket/object + Shamir threshold, from cofhe-keys) and the
# security POLICY (permit/commitment gates, from src/env_policy.rs +
# src/envs/<env>.toml) are compiled into the binary per environment; COFHE_ENV only
# picks WHICH blessed environment applies and the binary fails closed on anything
# else. Overriding it can at most point boot at another blessed env, whose
# partner-side attested WIF gates (pinned to this image digest) still decide
# whether reads succeed.
#
# BAKED, NOT overridable: the permit + commitment gate policy — require_permit,
# enable_commitment_verification, the commitment version / registry address /
# warning_instead_of_enforcement flag, the Shamir threshold, AND the permit
# TaskManager contract address — is security policy an operator must not be able to
# weaken at launch (the partner CEL attests only the image digest, never the env). It
# lives in the per-env baked policy (+ the shared cofhe-keys map); changing it needs a
# rebuild + partner re-pin. The GCP endpoint URLs (STS / SM / GCS / metadata) and the
# FHE_PRIV_SECRET name are likewise compile-time consts, not here.
#
# Still overridable, and why:
#  - PERMIT_CHAINS_JSON (rpc URLs only; TaskManager is baked) / COMMITMENT_REGISTRY_RPC_URL
#    carry API-keyed RPC URLs that must NOT be embedded in a publicly-pullable image, so
#    they stay env.
#    With a baked gate ON but its RPC/chains unset, the VM refuses to boot.
#  - CT_SOURCE_URL / BIND_ADDR are per-deployment endpoints (no secret).
#  - GETCT_TIMEOUT_MS / DECRYPT_CONCURRENCY / MAX_INFLIGHT / COMMITMENT_TIMEOUT_MS
#    / COMMITMENT_CACHE_SIZE / COMMITMENT_CACHE_TTL_SECS / RUST_LOG are
#    operational tuning + logging (no key-access path).
#  - METRICS_ADDR is deliberately NOT here: the port is pinned by EXPOSE and
#    the IAP firewall rule, so an override could only break the debug surface.
LABEL "tee.launch_policy.allow_env_override"="CT_SOURCE_URL,BIND_ADDR,GETCT_TIMEOUT_MS,RUST_LOG,COFHE_ENV,PERMIT_CHAINS_JSON,DECRYPT_CONCURRENCY,MAX_INFLIGHT,COMMITMENT_REGISTRY_RPC_URL,COMMITMENT_TIMEOUT_MS,COMMITMENT_CACHE_SIZE,COMMITMENT_CACHE_TTL_SECS"
LABEL "tee.launch_policy.log_redirect"="always"

USER root
ENTRYPOINT ["/usr/local/bin/teecryptor"]
