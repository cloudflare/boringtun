---
description: "Workspace instructions for BoringTun contributors: build, test, platform, and project conventions."
---

# BoringTun Workspace Instructions

These instructions help Copilot understand the repository structure, core workflows, and important conventions for `boringtun` development.

## What this repository is

- A Rust workspace with two members: `boringtun` (library) and `boringtun-cli` (userspace WireGuard executable).
- The root `README.md` is the primary project overview and contains build/test guidance.
- The repository also contains an `ssl/` folder with a separate SSL proxy/configuration subproject and Docker-based tooling.

## Key paths

- `Cargo.toml` — workspace manifest for the Rust project.
- `boringtun/Cargo.toml` — main library crate with platform-specific features.
- `boringtun/src/` — core WireGuard implementation, platform abstraction, and JNI/FFI bindings.
- `boringtun/src/device/` — device/peer/runtime and OS-specific tunnel implementations.
- `boringtun/benches/` — benchmark harnesses for crypto and performance.
- `boringtun-cli/src/main.rs` — CLI entry point.
- `ssl/` — separate SSL proxy and tooling, not part of the Rust workspace.

## Build commands

Use `cargo` from the repository root when working with the Rust workspace.

- Build library only:
  - `cargo build --lib --no-default-features --release`
- Build executable:
  - `cargo build --bin boringtun-cli --release`
- Install executable:
  - `cargo install boringtun-cli`
- Run workspace tests:
  - `cargo test`

## Testing notes

- `sudo` is usually required for tests that create network tunnels.
- `cargo test` may prompt for a password.
- Docker is required for some integration or environment-isolated tests in this repository.

## Project conventions

- Default Rust features are empty; optional features enable JNI, FFI, and device behavior.
- Platform-specific code is isolated behind OS-target modules such as `tun_linux.rs` and `tun_darwin.rs`.
- The library exposes both C ABI bindings (`wireguard_ffi.h`) and JNI bindings (`src/jni.rs`).
- Keep changes focused to the appropriate crate: `boringtun` for protocol/device behavior, `boringtun-cli` for the runtime CLI.

## When to use these instructions

Use this guidance for general development tasks in this repo:

- building or testing the Rust workspace
- understanding which crate owns a change
- working on cross-platform tunnel support
- interpreting `README.md` build/test conventions
- recognizing that `ssl/` is a separate support subproject, not the core Rust crate

## Notes for Copilot

- Prefer `cargo build` and `cargo test` rooted at the repository root.
- Do not treat `ssl/` as part of the main `boringtun` workspace unless the task explicitly mentions it.
- Honor platform-specific module boundaries in `boringtun/src/device/`.
- When a request is about an executable or integration path, check `boringtun-cli/src/main.rs` first.
