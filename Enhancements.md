# ssl-proxy + BoringTun — Unified Integration Workmap

> **Scope:** Merge `ssl/` (Rust HTTP/CONNECT proxy) and `boringtun/` into a single Cargo workspace, separate proxy and WireGuard ports, implement a Linux router/TUN flow, and add an obfuscation profile for Fox News / Fox Sports traffic.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| `[ ]`  | Not started |
| `[~]`  | In progress |
| `[x]`  | Done |
| ⚠️     | Needs decision / blocker |
| 🔗     | Depends on another task |

---

## Phase 1 — Workspace Unification

**Goal:** One `cargo build` compiles everything. No duplicate dependencies; shared `Cargo.lock`.

### 1.1 Root `Cargo.toml`

- `[ ]` **1.1.1** Create `/Cargo.toml` as the workspace manifest if it does not already exist.
- `[ ]` **1.1.2** Add workspace members:
  ```toml
  [workspace]
  members = ["boringtun", "boringtun-cli", "ssl"]
  resolver = "2"
  ```
- `[ ]` **1.1.3** Move shared `[patch.crates-io]` overrides (if any) to the workspace root so they apply uniformly.
- `[ ]` **1.1.4** Run `cargo check --workspace` and resolve any version-conflict errors.
- `[ ]` **1.1.5** Confirm that `ssl/Cargo.lock` and the root `Cargo.lock` are consolidated into one root-level file; delete `ssl/Cargo.lock`.

### 1.2 Dependency alignment

- `[ ]` **1.2.1** Align `ring` version across all crates (currently `0.17` in boringtun, verify ssl uses the same).
- `[ ]` **1.2.2** Align `tokio` version (boringtun-cli uses `tracing 0.1.40`; ssl uses `0.1.44` — pin to the higher).
- `[ ]` **1.2.3** Align `parking_lot` (boringtun uses `0.12`; confirm ssl's transitive version matches).
- `[ ]` **1.2.4** Audit for duplicate major versions with `cargo tree --duplicates` and deduplicate where safe.
- `[ ]` **1.2.5** ⚠️ Decide whether `ssl` should depend on `boringtun` as a **path dep** (library API) or invoke `boringtun-cli` as a subprocess. Document the decision here before Phase 4 begins.

### 1.3 CI / build scripts

- `[ ]` **1.3.1** Update `ssl/Dockerfile` `WORKDIR` and `COPY` paths to reference workspace root rather than `ssl/`.
- `[ ]` **1.3.2** Update the `cargo build` invocation in `Dockerfile` to `cargo build --release -p ssl-proxy`.
- `[ ]` **1.3.3** Keep the `cargo install boringtun-cli` step or replace it with `cargo build --release -p boringtun-cli` from workspace source.
- `[ ]` **1.3.4** Add a `Makefile` or shell helper at the repo root with targets: `build`, `test`, `docker`, `lint`.

---

## Phase 2 — Port Separation & Configuration

**Goal:** Proxy traffic and WireGuard traffic never share a listener socket. Configuration is explicit and testable.

### 2.1 Port assignment table

| Variable | Default | Owner | Purpose |
|----------|---------|-------|---------|
| `PROXY_PORT` | `3000` | ssl-proxy | Dashboard + REST API |
| `TPROXY_PORT` | `3001` | ssl-proxy | iptables REDIRECT destination |
| `WG_PORT` | `443/udp` | boringtun-cli | WireGuard handshake + data |
| *(reserved)* | `51820/udp` | boringtun-cli | Alternative WG port |

- `[ ]` **2.1.1** Verify that `ssl/src/main.rs` never binds to `WG_PORT`; add a startup assertion if needed.
- `[ ]` **2.1.2** Verify that `boringtun-cli` never opens a TCP socket on `PROXY_PORT` or `TPROXY_PORT`.
- `[ ]` **2.1.3** Add an env-var validation block in `ssl/src/main.rs` that panics with a clear message if `PROXY_PORT == WG_PORT`.

### 2.2 ssl-proxy configuration

- `[ ]` **2.2.1** Move all port constants out of hard-coded defaults into a `config.rs` module loaded from environment at startup.
- `[ ]` **2.2.2** Expose `WG_INTERFACE` env var so ssl-proxy knows the TUN device name for optional diagnostics.
- `[ ]` **2.2.3** Add `MAX_CONNECTIONS` env var (default `4096`) and wire it into the `JoinSet` accept loops.
- `[ ]` **2.2.4** Add `TARPIT_MAX_CONNECTIONS` env var wired to `MAX_TARPIT` in `tunnel.rs` (currently hard-coded to `64`).

### 2.3 boringtun-cli configuration

- `[ ]` **2.3.1** Confirm `WG_PORT` is passed to boringtun-cli via `--uapi-fd` or by setting `listen_port` through the UAPI socket in the entrypoint.
- `[ ]` **2.3.2** Document the exact `wg setconf` invocation used in `entrypoint.sh` so port binding is auditable.
- `[ ]` **2.3.3** Add a readiness check in `entrypoint.sh`: wait for `wg show <interface>` to report a `listening port` before starting ssl-proxy.

---

## Phase 3 — Linux Router / TUN Traffic Flow

**Goal:** Packets from the WireGuard tunnel peer are decrypted by BoringTun → arrive on the TUN interface → routed to ssl-proxy for policy enforcement → leave through the host's egress interface.

### 3.1 Architecture diagram (to be drawn in docs)

```
WG Peer (UDP 443)
      │
      ▼
[ boringtun-cli / TUN device wg0 ]
      │  decrypted plaintext
      ▼
[ kernel routing table ]
      │
      ├──► TCP 443/80 → iptables PREROUTING REDIRECT → TPROXY_PORT (3001) → ssl-proxy transparent handler
      │
      └──► other traffic → forward via eth0 (MASQUERADE)
```

### 3.2 iptables rules

Current rules in `config/templates/server.conf` `PostUp`:

```
iptables -t nat -A PREROUTING -i %i -p tcp --dport 443 -j REDIRECT --to-port 3001
iptables -t nat -A PREROUTING -i %i -p tcp --dport 80  -j REDIRECT --to-port 3001
iptables -t nat -A POSTROUTING -o eth+ -j MASQUERADE
iptables -A FORWARD -i %i -j ACCEPT
iptables -A FORWARD -o %i -j ACCEPT
```

- `[ ]` **3.2.1** Verify REDIRECT rules are applied **after** the TUN interface is up (currently done in PostUp — confirm ordering with boringtun-cli startup).
- `[ ]` **3.2.2** Add an explicit ACCEPT rule for UDP port `WG_PORT` on `eth+` so BoringTun packets are not accidentally caught by the REDIRECT rule.
- `[ ]` **3.2.3** Add `iptables -t mangle -A PREROUTING -i wg0 -j MARK --set-mark 0x100` and a corresponding ip rule for policy-based routing if multi-path egress is needed.
- `[ ]` **3.2.4** Ensure matching `PostDown` rules exist for every `PostUp` rule (audit current template — currently they are symmetric; add any new rules' mirrors).
- `[ ]` **3.2.5** ⚠️ Decide: keep iptables or migrate to nftables. Document the decision and update entrypoint.sh accordingly.

### 3.3 TUN device lifecycle

- `[x]` **3.3.1** In `entrypoint.sh`, add a trap that calls `ip link delete wg0` on EXIT/INT/TERM (currently present, verify completeness).
- `[x]` **3.3.2** Add a health check loop that verifies `boringtun-cli` PID is alive every 5 s; restart it if it dies without taking down the whole container.
- `[x]` **3.3.3** Ensure MTU on `wg0` matches `MTU = 1280` in `server.conf`; verify `ip link set mtu` is called in `entrypoint.sh` (currently done — confirm value).
- `[x]` **3.3.4** Set `net.core.rmem_max` and `net.core.wmem_max` sysctls in `docker-compose.yaml` for high-throughput WireGuard use.

### 3.4 Kernel sysctls

- `[x]` **3.4.1** Already present in `docker-compose.yaml`: `net.ipv4.ip_forward=1`, `net.ipv4.conf.all.src_valid_mark=1`. Add `net.ipv4.conf.wg0.rp_filter=0` to prevent reverse-path filter drops.
- `[x]` **3.4.2** Add IPv6 forwarding sysctls if IPv6 peer support is required: `net.ipv6.conf.all.forwarding=1`.

---

## Phase 4 — ssl-proxy + BoringTun Runtime Coordination

**Goal:** Both processes start, stay alive, and shut down cleanly under a single supervisor (entrypoint.sh or an in-process coordinator).

### 4.1 Supervisor (entrypoint.sh)

- `[x]` **4.1.1** Extract the `configure_interface` logic into a dedicated `wg_up.sh` sourced by `entrypoint.sh` for testability.
- `[x]` **4.1.2** After `configure_interface`, poll `wg show wg0 listen-port` in a loop (max 10 s) to confirm the UAPI socket is accepting connections before starting ssl-proxy.
- `[x]` **4.1.3** Start CoreDNS, then BoringTun, then ssl-proxy — in that order — with each step gated on a readiness check.
- `[x]` **4.1.4** Use `wait -n` (bash 5.1+) or a PID-watcher loop so that if any child exits unexpectedly, `cleanup` runs and the container exits with a non-zero code.
- `[x]` **4.1.5** Forward SIGTERM to all child PIDs explicitly before `wait` to allow graceful shutdown.

### 4.2 Embedded BoringTun (if chosen in 1.2.5)

*Only needed if the team decides to embed rather than subprocess.*

- `[ ]` **4.2.1** Add `boringtun` as a path dependency in `ssl/Cargo.toml` with `features = ["device"]`.
- `[ ]` **4.2.2** Create `ssl/src/wg.rs` with a `start_tunnel(config: DeviceConfig, iface_name: &str)` function that calls `DeviceHandle::new` and returns the handle.
- `[ ]` **4.2.3** Integrate the `DeviceHandle` into `AppState` so the proxy can query tunnel stats (bytes, handshake time) via `wg show`-equivalent calls.
- `[ ]` **4.2.4** Ensure `DeviceHandle::wait` is called on a dedicated OS thread (not the Tokio runtime) to avoid blocking the async executor.
- `[ ]` **4.2.5** Wire `CancellationToken` into the embedded tunnel so a graceful proxy shutdown also tears down the WireGuard device.

### 4.3 Shared configuration state

- `[x]` **4.3.1** Create a `Config` struct (in a new `ssl/src/config.rs`) loaded once at startup from environment and passed as `Arc<Config>` everywhere.
- `[x]` **4.3.2** Fields: `proxy_port`, `tproxy_port`, `wg_port`, `wg_interface`, `admin_api_key`, `cors_allowed_origins`, `log_format`, `oracle_*`, `obfuscation_profiles`.
- `[x]` **4.3.3** Replace all `std::env::var(...)` call sites in `main.rs`, `state.rs`, `dashboard.rs`, `db.rs` with reads from `Config`.
- `[x]` **4.3.4** Validate all required fields at startup and emit a clear error before binding any socket.

---

## Phase 5 — Fox News / Fox Sports Obfuscation Profile

**Goal:** Traffic to `foxnews.com` and `foxsports.com` and their CDN/API subdomains is transparently forwarded (not blocked) while its observable characteristics are normalized to avoid fingerprinting.

### 5.1 Domain taxonomy

Domains to include in the `fox-media` obfuscation profile:

| Domain pattern | Category |
|----------------|----------|
| `*.foxnews.com` | fox-news |
| `*.foxsports.com` | fox-sports |
| `*.fox.com` | fox-general |
| `*.foxbusiness.com` | fox-general |
| `fox-cdn.com`, `*.akamaized.net` (Fox origin) | fox-cdn |
| `*.fxnetworks.com` | fx-network |

- `[ ]` **5.1.1** Audit actual hostnames seen in proxy logs (or from a test run) and expand the list above.
- `[ ]` **5.1.2** Hardcode the initial set in `ssl/src/obfuscation.rs` (new file) as a `const` slice alongside the blocklist SEED pattern.

### 5.2 New `ssl/src/obfuscation.rs` module

- `[ ]` **5.2.1** Create the file with:
  ```rust
  pub enum Profile { FoxNews, FoxSports, None }
  pub fn classify_obfuscation(host: &str) -> Profile { ... }
  pub fn apply_request_headers(headers: &mut HeaderMap, profile: &Profile) { ... }
  pub fn apply_response_headers(headers: &mut HeaderMap, profile: &Profile) { ... }
  ```
- `[ ]` **5.2.2** `classify_obfuscation`: walk the domain hierarchy (same pattern as `is_blocked`) against the profile table; return the matching `Profile`.
- `[ ]` **5.2.3** `apply_request_headers` for Fox profiles:
  - Strip `X-Forwarded-For`, `Via`, `Forwarded` headers.
  - Normalize `User-Agent` to a generic browser string configurable via `FOX_UA_OVERRIDE` env var.
  - Remove `DNT`, `Sec-GPC` and other privacy-signal headers that could cause server-side fingerprint deviation.
- `[ ]` **5.2.4** `apply_response_headers` for Fox profiles:
  - Strip `X-Cache`, `X-Edge-IP`, `X-Served-By` and other CDN leak headers.
  - Ensure `Content-Security-Policy` is not stripped (leave security headers intact).
- `[ ]` **5.2.5** Add a unit test module in `obfuscation.rs` with at least 8 cases covering subdomain matching, header stripping, and `Profile::None` pass-through.

### 5.3 Integrate obfuscation into proxy.rs (HTTP flow)

- `[ ]` **5.3.1** In `proxy::handler`, call `classify_obfuscation(hostname)` after the blocklist check.
- `[ ]` **5.3.2** If profile is not `None`, call `apply_request_headers` before forwarding to upstream.
- `[ ]` **5.3.3** If profile is not `None`, call `apply_response_headers` on the upstream response before returning to the client.
- `[ ]` **5.3.4** Emit an audit log event `http_obfuscated` with `profile = "fox-news"` / `"fox-sports"` for observability.
- `[ ]` **5.3.5** Ensure `emit_full` in `proxy.rs` includes a `obfuscation_profile` field.

### 5.4 Integrate obfuscation into tunnel.rs (CONNECT / transparent flow)

- `[ ]` **5.4.1** In `tunnel::handle` (CONNECT), call `classify_obfuscation` on `hostname` after the blocklist check.
- `[ ]` **5.4.2** In `handle_transparent`, call `classify_obfuscation` on `tls.sni` when the SNI is resolved.
- `[ ]` **5.4.3** For Fox profiles in the transparent path, override the resolved IP with a pinned IP list (optional; protects against DNS-based targeting) — gate behind `FOX_PIN_IPS=1` env var.
- `[ ]` **5.4.4** Emit `tunnel_obfuscated` audit event (kind, host, profile, category).

### 5.5 Configuration

- `[ ]` **5.5.1** Add `OBFUSCATION_ENABLED` env var (default `true`); when `false`, `classify_obfuscation` always returns `Profile::None`.
- `[ ]` **5.5.2** Add `OBFUSCATION_PROFILE` env var accepting a comma-separated list: `fox-news,fox-sports` (default = both enabled).
- `[ ]` **5.5.3** Add `FOX_UA_OVERRIDE` env var (default: `Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15`).
- `[ ]` **5.5.4** Wire all three vars through `Config` struct (Phase 4.3).

### 5.6 Dashboard / API visibility

- `[ ]` **5.6.1** Add `obfuscated_count: AtomicU64` to `AppState`.
- `[ ]` **5.6.2** Increment it in `proxy.rs` and `tunnel.rs` when a Fox profile is applied.
- `[ ]` **5.6.3** Include `obfuscated` in the stats WebSocket broadcast JSON in `dashboard.rs`.
- `[ ]` **5.6.4** Add `obfuscated_count` to the stats grid in `static/index.html`.

---

## Phase 6 — Validation & Testing

### 6.1 Unit tests

- `[ ]` **6.1.1** `obfuscation.rs`: 8+ cases (see 5.2.5).
- `[ ]` **6.1.2** `config.rs`: test that missing required vars produce a descriptive error at validation time.
- `[ ]` **6.1.3** `blocklist.rs`: add a test that `is_blocked` walks parent domains correctly (`sub.sub.tracker.com` → match `tracker.com`).
- `[ ]` **6.1.4** `tunnel.rs`: add a unit test for `parse_tls_info` using a crafted byte slice with known SNI and ALPN values.
- `[ ]` **6.1.5** `state.rs`: add tests for `record_host_block` verdict transition and `evict_stale_hosts`.
- `[ ]` **6.1.6** `boringtun/src/device/allowed_ips.rs`: existing tests pass — confirm with `cargo test -p boringtun`.

### 6.2 Integration tests

- `[ ]` **6.2.1** Add `ssl/tests/port_separation.rs`: bind a mock server on `PROXY_PORT` and `TPROXY_PORT`, confirm that sending a WireGuard handshake packet to `PROXY_PORT` is rejected cleanly.
- `[ ]` **6.2.2** Add `ssl/tests/obfuscation_e2e.rs`: spin up an `axum` test server, send an HTTP CONNECT to `foxnews.com:443`, verify the forwarded request has the UA override applied.
- `[ ]` **6.2.3** Add `ssl/tests/blocklist_refresh.rs`: mock the blocklist CDN URL, verify the refresh task updates the in-memory set and the seed fallback activates on fetch error.
- `[ ]` **6.2.4** Add `boringtun/src/device/integration_tests/` test for TUN device creation + teardown under `--ignore` (existing pattern) to ensure the embedded path (Phase 4.2) works.

### 6.3 Docker / container validation

- `[ ]` **6.3.1** Update `ssl/docker-compose.yaml` `healthcheck` to verify both ports are reachable: `/health` on `PROXY_PORT` and a UDP `wg show` equivalent.
- `[ ]` **6.3.2** Add a `docker compose run --rm rust-proxy cargo test --workspace` CI step.
- `[ ]` **6.3.3** Add a smoke-test shell script `ssl/tests/smoke.sh` that:
  - Brings up the stack with `docker compose up -d`.
  - Waits for the health check to pass.
  - Sends a `CONNECT foxnews.com:443` request via `curl --proxy`.
  - Asserts the response has the expected User-Agent override in the upstream request log.
  - Tears down the stack.
- `[ ]` **6.3.4** Run the smoke test in CI against the Docker image (GitHub Actions or equivalent).

---

## Phase 7 — Database Schema Updates

- `[ ]` **7.1** Add `obfuscation_profile VARCHAR2(32)` column to `proxy_events` in `ssl/sql/schema.sql`.
- `[ ]` **7.2** Add a migration file `ssl/sql/migrate_obfuscation.sql`:
  ```sql
  ALTER TABLE proxy_events ADD (obfuscation_profile VARCHAR2(32));
  ```
- `[ ]` **7.3** Update `db.rs` `ProxyEvent` struct and `insert_batch` to bind the new column.
- `[ ]` **7.4** Add `ix_pe_obfuscation` index on `(obfuscation_profile, event_time)` in `sql/indexes.sql`.
- `[ ]` **7.5** Add a `v_fox_traffic` view in `sql/views.sql` that aggregates obfuscated events by host and hour for Grafana panels.

---

## Phase 8 — Documentation & Cleanup

### 8.1 Architecture document

- `[ ]` **8.1.1** Create `docs/architecture.md` (or `README.md` at repo root) with:
  - System diagram (ASCII or Mermaid) showing the full traffic flow.
  - Port assignment table (from Phase 2.1).
  - Startup order (CoreDNS → BoringTun → ssl-proxy).
  - Obfuscation profile description.
- `[ ]` **8.1.2** Add a "Quick Start" section with the exact `docker compose up` command and how to configure a WireGuard client to connect.

### 8.2 Operator runbook

- `[ ]` **8.2.1** Create `docs/runbook.md` covering:
  - How to add a new obfuscation profile.
  - How to update the blocklist URL.
  - How to rotate the WireGuard key pair.
  - How to connect to the Oracle ADB and run the views.
  - Prometheus / Vector pipeline setup with `vector.toml`.

### 8.3 Code cleanup

- `[ ]` **8.3.1** Remove the dead `boringtun = { path = "../boringtun", features = ["device"] }` import from `ssl/Cargo.toml` if it is not actively used by ssl-proxy today (it is listed but no `use boringtun` is found in `ssl/src/`).
- `[ ]` **8.3.2** Remove the `ssl/Cargo.lock` once the workspace lock is consolidated.
- `[ ]` **8.3.3** Run `cargo clippy --workspace -- -D warnings` and fix all lints.
- `[ ]` **8.3.4** Run `cargo fmt --all` and commit the result.
- `[ ]` **8.3.5** Remove debug `eprintln!` calls in `boringtun/src/device/mod.rs` (lines inside `register_conn_handler`); replace with `tracing::debug!`.

---

## Dependency Graph (simplified)

```
Phase 1 (Workspace)
  └─► Phase 2 (Port Config)
        └─► Phase 3 (Linux TUN/iptables)
              └─► Phase 4 (Runtime Coordination)
                    ├─► Phase 5 (Fox Obfuscation)
                    │     └─► Phase 6 (Tests)
                    │           └─► Phase 7 (DB Schema)
                    └─► Phase 8 (Docs) ◄── can start after Phase 5 design is stable
```

---

## Open Questions / Decisions Required

| # | Question | Owner | Due |
|---|----------|-------|-----|
| Q1 | Embed BoringTun in ssl-proxy (library) or keep as subprocess? (see 1.2.5) | Arch team | Before Phase 4 |
| Q2 | iptables vs nftables for routing rules? (see 3.2.5) | Infra team | Before Phase 3 |
| Q3 | Should Fox obfuscation also apply to transparent (TUN) path, or only to CONNECT proxy path? | Product | Before Phase 5 |
| Q4 | Is `foxnews.com` allowed (not on blocklist) by policy, or should only specific subdomains be allowed? | Legal/Policy | Before Phase 5.1 |
| Q5 | Should `obfuscation_profile` be logged to Oracle DB in the same `proxy_events` table or a separate `obfuscated_events` table? | Data Eng | Before Phase 7 |

---

*Last updated: generated from codebase analysis of `boringtun/`, `boringtun-cli/`, and `ssl/` directories.*


{"type":"finding","severity":"minor","fileName":"src/config.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/config.rs around lines 38 - 39, The enum variant MissingAdminApiKey is unused—either remove it or add a validation that returns it; update the configuration validation (the function that currently checks other fields, e.g., the validate or try_from_env routine) to verify the admin_api_key field is present and not empty and return ConfigError::MissingAdminApiKey when it is empty, or if you prefer to remove dead code, delete the MissingAdminApiKey variant from the ConfigError enum; reference the MissingAdminApiKey variant and the admin_api_key field when making the change.","suggestions":[]}
{"type":"finding","severity":"major","fileName":"src/db.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/db.rs around lines 1 - 8, The db.rs module is missing a cfg gate for the \"oracle-db\" feature and will pull in the oracle crate even when the feature is disabled; add #[cfg(feature = \"oracle-db\")] as a module-level attribute (placed above the existing doc comment or at the top of the file) to conditionally compile the module, or alternatively ensure the mod db; declaration where this file is included is itself gated with #[cfg(feature = \"oracle-db\")]; update any top-level module attributes so the code referencing oracle (in db.rs) is only compiled when the \"oracle-db\" feature is enabled.","suggestions":["#![cfg(feature = \"oracle-db\")]\n\n/// Oracle DB integration — compiled only with `--features oracle-db`.\n///\n/// All proxy_events inserts are serialised through a single background writer\n/// task (one persistent connection, one blocking thread).  The hot path just\n/// sends to an mpsc channel and returns immediately — no pool, no contention.\nuse std::sync::Arc;\nuse tokio::sync::mpsc;\nuse tracing::{error, info, warn};"]}
{"type":"finding","severity":"major","fileName":"sql/views.sql","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @sql/views.sql around lines 113 - 118, The BETWEEN range join on wg_events.event_time vs proxy_events.event_time (we.event_time BETWEEN pe.event_time - INTERVAL '5' SECOND AND pe.event_time + INTERVAL '5' SECOND) causes expensive range scans; add composite indexes on (event_time, endpoint_ip) for both wg_events and proxy_events (or at least on (endpoint_ip, event_time) depending on your planner) and/or convert this live view into a materialized/pre-aggregated table refreshed periodically to avoid repeated windowed lookups; update the view/query to rely on those indexed columns (referencing tables wg_events and proxy_events / aliases we and pe) or switch to a scheduled materialized table instead.","suggestions":[]}
{"type":"finding","severity":"minor","fileName":"sql/views.sql","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @sql/views.sql around lines 123 - 138, The view v_slow_queries currently exposes sql_preview (SUBSTR(sql_text, 1, 200)) from db_query_log which can leak sensitive parameters or schema details; update v_slow_queries to either remove sql_preview, replace it with a sanitized/masked version (e.g., redact literals or return a fixed token like '<REDACTED_QUERY_PREVIEW>'), or enforce access controls by documenting/restricting grants on v_slow_queries to only privileged roles—locate the SELECT that defines sql_preview in v_slow_queries and implement one of these mitigations (remove the SUBSTR(sql_text...), apply masking logic, or restrict view grants) so dashboards cannot see raw query text.","suggestions":[]}
{"type":"finding","severity":"minor","fileName":"src/config.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/config.rs around lines 194 - 203, The doc comment for from_env_or_panic() is wrong: the function calls std::process::exit(1) (via match on from_env()) rather than panic!, so update the documentation to state that it will exit the process immediately on failure (no unwinding/destructors), and note it's unsuitable for tests; alternatively, if you want true panic semantics for tests, replace the std::process::exit(1) call in from_env_or_panic() with a panic! including the error (e) so the behavior matches the original \"panic on failure\" wording; locate symbols from_env_or_panic and from_env to implement the chosen fix.","suggestions":[]}
{"type":"finding","severity":"critical","fileName":"src/config.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/config.rs around lines 50 - 57, The test test_config_port_conflict_error expects a panic but calls Config::from_env() which returns Result; change the test to force a panic by unwrapping the result (e.g., Config::from_env().unwrap()) or call a helper that panics (e.g., from_env_or_panic()) so the Err actually triggers a panic; apply the same change to the other #[should_panic] tests that currently call Config::from_env() to ensure they panic on error.","suggestions":["    #[test]\n    #[should_panic(expected = \"PROXY_PORT must not equal WG_PORT\")]\n    fn test_config_port_conflict_error() {\n        std::env::set_var(\"PROXY_PORT\", \"51820\");\n        std::env::set_var(\"WG_PORT\", \"51820\");\n\n        Config::from_env().unwrap();\n    }"]}
{"type":"finding","severity":"major","fileName":"src/config.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/config.rs around lines 46 - 78, The tests manipulating environment variables (test_config_port_conflict_error, test_config_missing_oracle_conn_error, test_config_missing_oracle_user_error) race because std::env::set_var/remove_var is not thread-safe; update the tests to run serially by adding serial_test as a dev-dependency and annotating each of these test functions with the #[serial] attribute so Config::from_env() is executed without concurrent env mutations (or alternatively run the suite with a single test thread), ensuring deterministic test behavior.","suggestions":[]}
{"type":"finding","severity":"minor","fileName":"tests/smoke.sh","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @tests/smoke.sh around lines 37 - 49, The test mislabels the proxy interaction and wrongly treats certain curl exit codes as success: update the echo from \"Testing CONNECT proxy request\" to \"Testing HTTP proxy request\" (or switch the curl target to an https:// URL if you really intend to exercise CONNECT), and tighten the exit-code check in the CURL_EXIT logic by removing acceptance of 56 and 35 so any non-zero CURL_EXIT is treated as failure; keep references to CURL_OUTPUT, CURL_EXIT and the curl invocation so you modify the same block.","suggestions":["echo \"🔌 Testing HTTP proxy request\"\necho \"Using proxy health endpoint for reliable testing\"\nCURL_OUTPUT=$(curl -v --proxy http://localhost:3000 --connect-timeout 10 --max-time 15 http://localhost:3000/health 2>&1) || CURL_EXIT=$?\n\n# Fail on any non-zero exit code\nif [ \"${CURL_EXIT:-0}\" -ne 0 ]; then\n    echo \"⚠️ Curl request failed with exit code ${CURL_EXIT:-0}\"\n    echo \"Curl output:\"\n    echo \"$CURL_OUTPUT\"\n    echo \"Proxy logs:\"\n    docker compose logs ssl-proxy | tail -20\n    exit 1\nfi"]}
{"type":"finding","severity":"minor","fileName":"src/proxy.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/proxy.rs around lines 62 - 76, The ProxyEvent being persisted sets obfuscation_profile to None even though callers (e.g., the http_proxied event) have a profile; update emit_full to accept an obfuscation_profile parameter (optionally Option<String> or the same type used in http_proxied), propagate that value from callers into the call site that constructs crate::db::ProxyEvent, and set ProxyEvent.obfuscation_profile to the passed parameter instead of None; alternatively, if the omission is intentional, add a clear comment in emit_full and in the ProxyEvent creation explaining why obfuscation_profile is always None so future maintainers understand the decision.","suggestions":[]}
{"type":"finding","severity":"major","fileName":"src/config.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/config.rs around lines 113 - 116, The code stores oracle_pass_file but never reads it; update the config initialization to mirror the proxy password logic: if oracle_pass (the Option from ORACLE_PASS) is None or empty, attempt to read the file at oracle_pass_file using std::fs::read_to_string, trim the contents and set oracle_pass = Some(trimmed) when non-empty, and handle/read errors the same way proxy_password_file/proxy_password are handled to avoid panics and preserve behavior; locate and modify the oracle_pass/oracle_pass_file handling in src/config.rs to implement this fallback.","suggestions":[]}
{"type":"finding","severity":"major","fileName":"src/db.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/db.rs around lines 116 - 134, The match arms handling the result of insert_batch currently drop the failed batch (match branches under Ok(Err(e)) and Err(e)), causing silent data loss; update the error handling in the insert_batch path to (a) capture the failed batch value before breaking out, (b) attempt to re-queue it onto the producer channel (use the send/try_send on the existing tx used by the consumer loop) or, if the channel is full/fails, write the batch to a durable DLQ/fallback (append to a file or database) from a spawned task to avoid blocking, and (c) log the full batch contents and an identifier along with the error when re-queue/DLQ actions are taken; ensure this change is implemented in the match arms that currently call error!(...) and break so the batch is not silently dropped.","suggestions":[]}
{"type":"finding","severity":"minor","fileName":"src/obfuscation.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/obfuscation.rs around lines 82 - 85, The comment on the wildcard handling is inaccurate: the code in pattern.starts_with(\"*.\") then computing let base = &pattern[2..]; and inserting profile_map.insert(format!(\".{}\", base), profile) actually allows matching the apex (example.com) because keys are stored with a leading dot; update the comment to state that the stored \".example.com\" key will match both \"sub.example.com\" and \"example.com\" in the lookup logic, or alternatively change the insertion/lookup logic if you truly want to exclude apex domains—modify the comment near pattern.starts_with(\"*.\") and the profile_map.insert(format!(\".{}\", base), profile) lines to accurately describe the implemented behavior (or change the insertion to exclude the apex if that is the desired behavior).","suggestions":["        if pattern.starts_with(\"*.\") {\n            // Wildcard pattern: *.example.com matches sub.example.com and example.com itself\n            let base = &pattern[2..]; // Remove *.\n            profile_map.insert(format!(\".{}\", base), profile);"]}
{"type":"finding","severity":"critical","fileName":"tests/smoke.sh","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @tests/smoke.sh around lines 51 - 62, The test is grepping for \"foxnews.com\" even though the script only makes a request to \"http://localhost:3000/health\" and never calls foxnews.com; either change the grep to assert the actual request (check LOGS for \"GET /health\" or \"localhost:3000/health\" instead of \"foxnews.com\") or make an explicit external request to exercise the proxy (e.g., perform a curl to \"http://foxnews.com\" through the proxy before capturing LOGS); update the LOGS/GREP check (the LOGS variable and the grep \"foxnews.com\" string) or add the external curl so the assertion matches what the script actually does.","suggestions":[]}
{"type":"finding","severity":"major","fileName":"src/quic.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/quic.rs around lines 221 - 236, The hostname/port extraction using rsplit_once(':') is fragile for IPv6 literals; update the logic in src/quic.rs where hostname and port are computed to first detect bracketed IPv6 authorities (strings starting with '[') and, if so, extract the text between '[' and ']' as the hostname and parse an optional port only if characters follow the closing ']' (e.g., \"]:port\"); otherwise, for non-bracketed authorities fall back to splitting on the last ':' to separate host and port (parsing port to u16 with default 443) and trim brackets for safety; apply this change to the code that sets the hostname and port variables so IPv6 addresses like \"[2001:db8::1]\" are handled correctly.","suggestions":["    let (hostname, port) = if host.starts_with('[') {\n        // IPv6: look for ']:' to find port separator\n        if let Some(bracket_end) = host.find(']') {\n            let ip = &host[1..bracket_end];\n            let port = host[bracket_end + 1..]\n                .strip_prefix(':')\n                .and_then(|p| p.parse::<u16>().ok())\n                .unwrap_or(443);\n            (ip.to_string(), port)\n        } else {\n            // Malformed, best effort\n            (host.trim_matches(|c| c == '[' || c == ']').to_string(), 443)\n        }\n    } else {\n        // IPv4 or hostname: last colon is port separator\n        match host.rsplit_once(':') {\n            Some((h, p)) => match p.parse::<u16>() {\n                Ok(port) => (h.to_string(), port),\n                Err(_) => (host.clone(), 443),\n            },\n            None => (host.clone(), 443),\n        }\n    };"]}
{"type":"finding","severity":"major","fileName":"docker/wg_up.sh","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @docker/wg_up.sh around lines 42 - 63, The loop that parses \"$WG_CONFIG_PATH\" and runs \"cmd ip -6 address add\" / \"cmd ip -4 address add\" is piped into a while which creates a subshell so failures inside (e.g., ip address add) don't crash the main script; change the pipeline to use process substitution so the while loop runs in the main shell (replace the `... | while IFS= read -r addr; do` pattern with reading from `< <(awk ... \"$WG_CONFIG_PATH\")`), keep the same awk body and the same checks for IPv6 vs IPv4 using INTERFACE_NAME and cmd, so that set -e will correctly make the script exit on address-add failures.","suggestions":[]}
{"type":"finding","severity":"critical","fileName":"src/main.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/main.rs around lines 40 - 50, The current constant_time_eq implementation ignores input lengths by copying up to a fixed MAX_LEN into buffers, causing different-length strings with identical prefixes to compare equal; to fix, remove the fixed-size buffers and MAX_LEN and use the slices directly: get a.as_bytes() and b.as_bytes() and call the subtle::ConstantTimeEq implementation on those slices (e.g., a_bytes.ct_eq(b_bytes).into()), or otherwise ensure length is incorporated in the constant-time comparison; update the function constant_time_eq accordingly and delete the unused a_buf/b_buf logic.","suggestions":["pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {\n    use subtle::ConstantTimeEq;\n    let a_bytes = a.as_bytes();\n    let b_bytes = b.as_bytes();\n    // Length must match; use constant-time length comparison\n    let len_eq: subtle::Choice = (a_bytes.len() as u64).ct_eq(&(b_bytes.len() as u64));\n    // Content comparison (only meaningful if lengths match)\n    let content_eq: subtle::Choice = a_bytes.ct_eq(b_bytes);\n    (len_eq & content_eq).into()\n}"]}
{"type":"finding","severity":"minor","fileName":"src/dashboard.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/dashboard.rs around lines 267 - 270, Guard against NaN risk scores when updating highest_risk: in the loop where you compute let rs = e.risk_score() and compare against highest_risk, first skip or treat rs as invalid if rs.is_nan() (e.g., continue) so NaN never becomes highest_risk; additionally when comparing with the existing highest value check existing r.is_nan() and prefer a non-NaN rs over a NaN stored value (i.e., if current rs is not NaN and existing r.is_nan(), replace), otherwise perform the normal rs > *r comparison; update the logic around highest_risk = Some((e.key().clone(), rs)) accordingly so NaNs cannot lock in as the maximum.","suggestions":[]}
{"type":"finding","severity":"minor","fileName":"src/state.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/state.rs around lines 72 - 82, The test is asserting a transition to \"TARPIT\" but never resets the host's last_verdict, so calling state.record_host_block(host, 100, \"telemetry\") returns None; update the test to reset last_verdict to \"AGGRESSIVE_POLLING\" (or set it to None/initial state) before modifying host_stats and calling record_host_block again. Locate the host entry in state.host_stats and set its last_verdict field (or call the appropriate setter) to \"AGGRESSIVE_POLLING\" so the subsequent record_host_block invocation computes a change from \"AGGRESSIVE_POLLING\" to \"TARPIT\" and the assertions pass.","suggestions":["        // Increase frequency further to trigger TARPIT\n        {\n            let mut stats = state.host_stats.get_mut(host).unwrap();\n            stats.blocked_attempts = 100;\n            stats.first_seen = Instant::now() - Duration::from_secs(1); // 100 Hz\n            stats.last_verdict = \"AGGRESSIVE_POLLING\"; // Reset to test transition\n        }\n\n        let verdict_change = state.record_host_block(host, 100, \"telemetry\");\n        assert!(verdict_change.is_some());\n        assert_eq!(verdict_change.unwrap(), (\"AGGRESSIVE_POLLING\", \"TARPIT\"));"]}
{"type":"finding","severity":"minor","fileName":"src/state.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/state.rs around lines 241 - 246, The current password loading for variable pass (using config.oracle_pass.clone().unwrap_or_else and std::fs::read_to_string(...).unwrap_or_default()) silently yields an empty password on I/O errors; change it to detect and log/read errors instead of swallowing them: replace the unwrap_or_default() usage with explicit error handling around std::fs::read_to_string(&config.oracle_pass_file) so that failures (Err) are logged via the existing logger or returned as an error, and only fall back to an empty string when the file is genuinely empty; reference the pass variable, config.oracle_pass_file, and the read_to_string call to locate and update the code.","suggestions":[]}
