---
description: "Instructions for SSL Proxy contributors: build, test, and project conventions."
---

# SSL Proxy Instructions

These instructions help Copilot understand the repository structure, core workflows, and important conventions for `ssl-proxy` development.

## What this repository is

- A Rust project implementing a high-performance HTTP/HTTPS forward proxy with WireGuard VPN integration.
- Uses kernel WireGuard (not userspace) for VPN tunneling.
- Includes Docker-based deployment with CoreDNS for DNS resolution.

## Key paths

- `Cargo.toml` — package manifest.
- `src/` — Rust source code (proxy, tunnel, blocklist, obfuscation, dashboard, etc.).
- `config/` — WireGuard and CoreDNS configuration files.
- `docker/` — container entrypoint and WireGuard setup scripts.
- `static/` — dashboard web assets.
- `sql/` — database schema and migrations.
- `tests/` — integration tests and smoke tests.
- `Dockerfile` — container build definition.
- `docker-compose.yaml` — container orchestration.

## Build commands

- Build: `cargo build --release`
- Build with Oracle DB: `cargo build --release --features oracle-db`
- Test: `cargo test`
- Lint: `cargo clippy -- -D warnings`
- Format: `cargo fmt --all --check`
- Docker: `docker compose build`

## Project conventions

- Configuration is loaded from environment variables at startup via `src/config.rs`.
- The `oracle-db` feature gate controls Oracle database integration.
- WireGuard is managed via kernel module (`ip link add type wireguard`), not userspace.
- The container entrypoint (`docker/entrypoint.sh`) starts CoreDNS, WireGuard, and the proxy in sequence.

## Notes for Copilot

- Prefer `cargo build` and `cargo test` from the repository root.
- The proxy source is in `src/`, not in any subdirectory.
- Docker builds use the root `Dockerfile` with `docker compose build`.
