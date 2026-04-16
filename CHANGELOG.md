# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Split the tunnel and Oracle DB integrations into focused submodules for TLS parsing, classification, dialing, tarpitting, transparent proxying, writer orchestration, Oracle readiness, and SQL inserts.
- Consolidated proxy, tunnel, and QUIC event emission through a shared event helper and removed the extra detached `spawn_blocking` path from proxy event writes.
- Refactored runtime configuration into nested typed sub-structs, precomputed the obfuscation lookup map at startup, moved the blocklist to `ArcSwap`, and split host eviction into its own periodic task.

## [0.7.0] - 2026-01-09

### Changes

- Breaking: make `noise::Tunn::new` infallible
- Upgrade vulnerable dependencies: ring, x25519-dalek
- Fix a compilation error on freebsd
- Fix incorrect socket type in `device::Peer::connect_endpoint`
