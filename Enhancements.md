# ssl-proxy — Developer Instructions & Workmap

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Immediate Bug Fix — WebSocket / Dashboard Unreachable](#2-immediate-bug-fix)
3. [Architecture Overview](#3-architecture-overview)
4. [Local Development Setup](#4-local-development-setup)
5. [Configuration Reference](#5-configuration-reference)
6. [Comprehensive Workmap](#6-comprehensive-workmap)
7. [Security Hardening Roadmap](#7-security-hardening-roadmap)
8. [Testing Strategy](#8-testing-strategy)
9. [Observability & Ops](#9-observability--ops)
10. [Contributing Guidelines](#10-contributing-guidelines)

---

## 1. Project Overview

`ssl-proxy` is a Rust-based security proxy that combines:

- **HTTPS CONNECT tunnel proxy** (port 3000) with TLS termination
- **Transparent proxy** (port 3001) via iptables `REDIRECT`
- **QUIC/HTTP3 proxy** (UDP 443) via quinn + h3
- **WireGuard VPN** integration via CoreDNS sidecar
- **Real-time dashboard** via WebSocket (`/ws`, `/events`)
- **Blocklist engine** with remote refresh (hagezi pro+) + hardcoded seed
- **Traffic obfuscation profiles** (Fox News / Fox Sports domain normalization)
- **Oracle ADB persistence** (optional, feature-gated)
- **Tarpit** for high-frequency telemetry abusers

Stack: `axum 0.7`, `hyper 1`, `quinn 0.11`, `h3 0.0.8`, `tokio-rustls 0.26`, `hickory-resolver`, `dashmap`, `oracle` (optional).

---

## 2. Immediate Bug Fix

### Root Cause: TLS on Port 3000 Breaks Plaintext WebSocket and curl

From the startup logs:

```
INFO ssl_proxy: TLS enabled on proxy listener
```

The main listener on port 3000 wraps **every** accepted TCP connection with `TlsAcceptor` before handing it to hyper. This means:

- `ws://192.168.1.221:3000/events` fails → the client speaks plaintext HTTP Upgrade but the server expects a TLS ClientHello → `bytes remaining on stream`
- `curl http://192.168.1.221:3000/events` fails → same mismatch → curl sees garbage and reports `HTTP/0.9 when not allowed`

The WebSocket endpoint (`/events`, `/ws`) and the REST dashboard (`/health`, `/hosts`, etc.) are intended for local/internal use and should not require TLS from the admin client. There are three valid fixes; **Fix A is the recommended minimal change**:

---

### Fix A — Split Dashboard onto a Separate Plaintext Port (Recommended)

Add a second listener bound to a dedicated admin port (e.g., `3002`) that serves only dashboard/WebSocket routes without TLS. The existing port 3000 remains the TLS proxy listener.

**`src/config.rs`** — add field:

```rust
pub admin_port: u16,
```

In `from_env()`:

```rust
let admin_port = std::env::var("ADMIN_PORT")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(3002);
```

**`src/main.rs`** — add after the main listener is set up:

```rust
// Admin / dashboard listener — plaintext, internal only
let admin_router = Router::new()
    .route("/ws",     get(dashboard::ws_stats))
    .route("/events", get(dashboard::ws_events))
    .route("/health", get(dashboard::health))
    .merge(admin_routes)
    .nest_service("/dashboard", ServeDir::new("static"))
    .layer(TraceLayer::new_for_http())
    .layer(cors.clone())
    .with_state(state.clone());

let admin_addr = SocketAddr::from(([0, 0, 0, 0], config.admin_port));
let admin_listener = tokio::net::TcpListener::bind(admin_addr)
    .await
    .unwrap_or_else(|e| {
        error!(%admin_addr, %e, "failed to bind admin listener");
        std::process::exit(1)
    });
info!(%admin_addr, "admin/dashboard listener active (plaintext)");

let admin_shutdown = shutdown.clone();
tokio::spawn(async move {
    axum::serve(admin_listener, admin_router)
        .with_graceful_shutdown(async move { admin_shutdown.cancelled().await })
        .await
        .ok();
});
```

Then remove `/ws`, `/events`, `/health`, and `/dashboard` from the main `router` so they are only served on the admin port.

**After this fix:**

```bash
# Works — plaintext admin port
websocat ws://192.168.1.221:3002/events
curl http://192.168.1.221:3002/health

# Proxy traffic still uses TLS on 3000
```

---

### Fix B — Accept Both TLS and Plaintext on Port 3000 (Protocol Sniffing)

Peek the first byte of each accepted TCP connection. If it is `0x16` (TLS ClientHello), wrap with `TlsAcceptor`; otherwise serve plaintext. This avoids a second port but adds complexity and is less secure (the proxy port becomes accessible plaintext).

```rust
// In the accept loop, before serve_io!:
let mut peek_buf = [0u8; 1];
let is_tls = stream.peek(&mut peek_buf).await.map(|_| peek_buf[0] == 0x16).unwrap_or(false);

if is_tls {
    match acceptor.accept(stream).await {
        Ok(tls_stream) => serve_io!(TokioIo::new(tls_stream)),
        Err(e) => { debug!(%peer, %e, "TLS handshake failed"); return; }
    }
} else {
    serve_io!(TokioIo::new(stream));
}
```

---

### Fix C — Connect Dashboard Clients via `wss://` (No Code Change)

If the TLS certificate is trusted (or you accept the self-signed cert), connect using TLS:

```bash
# Using websocat with self-signed cert ignored
websocat --insecure wss://192.168.1.221:3000/events

# Using curl
curl -k --http1.1 -i -N \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  https://192.168.1.221:3000/events
```

This is suitable for quick testing but not a production fix since it requires every dashboard client to handle TLS.

---

### Summary

| Fix | Code change | Security | Complexity |
|-----|-------------|----------|------------|
| A — separate admin port | Yes, ~30 lines | Best (admin isolated) | Low |
| B — protocol sniffing | Yes, ~15 lines | Moderate | Medium |
| C — use `wss://` | None | Acceptable | Client-side only |

**Recommended: Fix A.**

---

## 3. Architecture Overview

```
                  ┌─────────────────────────────────────────────────┐
                  │                  ssl-proxy process               │
  Client ──TLS──▶ │  :3000  axum router + hyper                     │
  iOS/macOS       │    ├─ CONNECT ──▶ tunnel::handle()              │──▶ upstream TCP
                  │    ├─ HTTP    ──▶ proxy::handler()              │──▶ upstream TCP
                  │    ├─ /ws         dashboard WebSocket           │
                  │    ├─ /events     audit event stream            │
                  │    └─ /health /hosts /stats                     │
                  │                                                  │
  iptables ──────▶│  :3001  transparent proxy                       │──▶ orig_dst TCP
  REDIRECT        │    └─ tunnel::handle_transparent()              │
                  │                                                  │
  UDP ───────────▶│  :443   QUIC/H3  quinn + h3                    │──▶ upstream TCP
                  │    └─ quic::run_quic_listener()                 │
                  │                                                  │
                  │  Background tasks:                               │
                  │    blocklist::spawn_refresh_task()   24h cycle  │──▶ jsdelivr CDN
                  │    dashboard::spawn_stats_poller()   1s tick    │
                  │    dashboard::spawn_oracle_flusher() 60s tick   │──▶ Oracle ADB
                  │    db::spawn_writer()  batch mpsc               │──▶ Oracle ADB
                  └─────────────────────────────────────────────────┘
                  ┌──────────────────┐
                  │  CoreDNS sidecar │──▶ DoH (Cloudflare)
                  └──────────────────┘
                  ┌──────────────────┐
                  │  WireGuard (wg0) │──▶ VPN peer
                  └──────────────────┘
```

**Data flow for a blocked CONNECT request:**

1. `tunnel::handle()` → blocklist check → `record_blocked()` + `record_host_block()`
2. Verdict computed (`BLOCKED` / `AGGRESSIVE_POLLING` / `TARPIT` / etc.)
3. If `TARPIT`: upgrade accepted, connection drained to `/dev/null` for up to 5 min
4. Audit event emitted to `events_tx` broadcast channel
5. Oracle writer task picks up event from mpsc channel (if feature enabled)
6. Dashboard WebSocket clients receive the event JSON

---

## 4. Local Development Setup

### Prerequisites

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable

# Required system libraries (Debian/Ubuntu)
sudo apt-get install -y pkg-config libssl-dev libaio1

# Optional: Oracle Instant Client (only for oracle-db feature)
# Download from https://www.oracle.com/database/technologies/instant-client.html
# Extract to /opt/instantclient, then:
export OCI_LIB_DIR=/opt/instantclient
export LD_LIBRARY_PATH=/opt/instantclient
```

### Build

```bash
# Default build (no Oracle)
cargo build

# With Oracle DB support
OCI_LIB_DIR=/opt/instantclient cargo build --features oracle-db

# Release build
cargo build --release
```

### Run Locally (without Docker, no TLS)

```bash
# Unset TLS paths so the proxy runs plaintext — WebSocket will work on :3000
unset TLS_CERT_PATH
unset TLS_KEY_PATH

PROXY_PORT=3000 \
TPROXY_PORT=3001 \
LOG_FORMAT=human \
ADMIN_API_KEY=devkey \
CORS_ALLOWED_ORIGINS=http://localhost:3000 \
cargo run
```

Then test:

```bash
curl http://localhost:3000/health
websocat ws://localhost:3000/events
curl -H "x-api-key: devkey" http://localhost:3000/hosts
```

### Run with Docker

```bash
# Build image
docker build -t ssl-proxy .

# Run without TLS (dev mode)
docker run --rm -it \
  -p 3000:3000 -p 3001:3001 \
  -e ADMIN_API_KEY=devkey \
  -e LOG_FORMAT=human \
  ssl-proxy

# Run with TLS (production mode)
docker run --rm -it \
  -p 3000:3000 -p 3001:3001 -p 443:443/udp \
  -v /path/to/certs:/ssl:ro \
  -e TLS_CERT_PATH=/ssl/tls.crt \
  -e TLS_KEY_PATH=/ssl/tls.key \
  -e ADMIN_API_KEY=changeme \
  -e ADMIN_PORT=3002 \
  -p 3002:3002 \
  ssl-proxy
```

---

## 5. Configuration Reference

All configuration is via environment variables. Sensible defaults are provided for development.

| Variable | Default | Description |
|---|---|---|
| `PROXY_PORT` | `3000` | Main HTTPS proxy + dashboard port |
| `TPROXY_PORT` | `3001` | Transparent proxy port (iptables target) |
| `WG_PORT` | `51820` | WireGuard UDP port |
| `WG_INTERFACE` | *(none)* | WireGuard TUN interface name |
| `ADMIN_PORT` | `3002` | *(after Fix A)* Plaintext admin/dashboard port |
| `MAX_CONNECTIONS` | `4096` | Max concurrent TCP connections |
| `TARPIT_MAX_CONNECTIONS` | `64` | Max concurrent tarpit slots |
| `ADMIN_API_KEY` | *(none)* | Required for `/hosts`, `/stats` endpoints. If unset, returns 404 |
| `CORS_ALLOWED_ORIGINS` | *(none)* | Comma-separated origins. In release builds, empty = restrictive CORS |
| `LOG_FORMAT` | `human` | `human` or `json` (for Vector/Filebeat) |
| `TLS_CERT_PATH` | *(none)* | Path to PEM certificate. If absent, proxy runs plaintext |
| `TLS_KEY_PATH` | *(none)* | Path to PEM private key |
| `OBFUSCATION_ENABLED` | `true` | Enable Fox profile traffic normalization |
| `OBFUSCATION_PROFILE` | `fox-news,fox-sports` | Active obfuscation profiles (comma-separated) |
| `FOX_UA_OVERRIDE` | Mobile Safari UA | User-Agent string injected for Fox profiles |
| `ORACLE_CONN` | *(none)* | Oracle ADB TNS connect string (oracle-db feature) |
| `ORACLE_USER` | *(none)* | Oracle username (oracle-db feature) |
| `ORACLE_PASS` | *(none)* | Oracle password (prefer `ORACLE_PASS_FILE`) |
| `ORACLE_PASS_FILE` | *(none)* | Path to file containing Oracle password |
| `COREDNS_CONFIG` | `/config/coredns/Corefile` | CoreDNS config path |
| `WG_CONFIG_PATH` | `/config/wg_confs/wg0.conf` | WireGuard config path |

---

## 6. Comprehensive Workmap

This workmap is organized by priority tier. Each item lists the affected file(s), a brief description, and the expected outcome.

---

### Tier 0 — Critical Bugs (Fix First)

#### T0-1 — WebSocket/Dashboard Inaccessible When TLS Enabled ✦ **(Described in §2)**

**Files:** `src/main.rs`, `src/config.rs`
**Problem:** TLS wraps port 3000 entirely; plaintext WebSocket and curl requests fail.
**Fix:** Implement Fix A (separate admin port) as described in §2.
**Acceptance:** `websocat ws://host:3002/events` streams events; `curl http://host:3002/health` returns `ok`.

#### T0-2 — `Config::from_env()` Return Type Mismatch

**Files:** `src/config.rs`, `src/state.rs` (test module)
**Problem:** `from_env()` was refactored to return `Result<Self, ConfigError>` but the test module in `state.rs` still calls `crate::config::Config::default()` which does not exist. This will fail to compile.
**Fix:** Replace `Config::default()` in test helpers with `Config::from_env_or_panic()` or construct a complete `Config { ... }` literal matching the one in `obfuscation.rs` tests.

#### T0-3 — Oracle Flusher Uses `std::env::var` Instead of `config`

**Files:** `src/dashboard.rs` (`spawn_oracle_flusher`)
**Problem:** The Oracle flusher re-reads `ORACLE_CONN`, `ORACLE_USER`, `ORACLE_PASS` from environment variables instead of using the already-parsed `config` stored in `AppState`. This bypasses validation and the password-file fallback.
**Fix:** Pass `state.config.oracle_conn.clone()` etc. from `AppState` instead of calling `std::env::var` inside the task.

---

### Tier 1 — High Priority (Security & Correctness)

#### T1-1 — Proxy Authentication Middleware Missing from Source

**Files:** `src/main.rs`
**Problem:** Startup logs show `proxy authentication enabled username=iphoneuser` but no such middleware exists in the provided source. This suggests there is a divergence between the deployed binary and the source tree, or it was removed. Unauthenticated proxy access means any device on the LAN can tunnel arbitrary traffic.
**Fix:** Add `Proxy-Authorization: Basic` validation middleware in the main accept loop, before routing to `tunnel::handle()` and `proxy::handler()`. Use `subtle::ConstantTimeEq` (already imported) for the credential comparison. Store credentials via `PROXY_USER` / `PROXY_PASS_FILE` env vars.

```rust
// In the service_fn closure, before method check:
if !validate_proxy_auth(&req, &state.config) {
    return Ok(Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("Proxy-Authenticate", "Basic realm=\"ssl-proxy\"")
        .body(Body::empty())
        .unwrap());
}
```

#### T1-2 — Admin API Accessible from Proxy Port

**Files:** `src/main.rs`
**Problem:** `/hosts`, `/stats/summary` are merged into the same router that handles all proxy traffic on port 3000. With TLS, clients connecting to the proxy port for tunneling can also reach admin endpoints (if they know the API key and it leaks). Additionally, if TLS is disabled (dev mode), the admin API is completely exposed on the proxy port.
**Fix:** Part of Fix A (§2). After splitting the admin port, remove admin routes from the main router entirely.

#### T1-3 — Tarpit Semaphore Leaks on Panic

**Files:** `src/tunnel.rs` (`handle`)
**Problem:** The tarpit task acquires a `permit` via `try_acquire_owned()` and drops it at task completion. If `run_tarpit` panics, the permit is dropped correctly via RAII — this is fine. However, in `handle_transparent`, the tarpit runs inline (not spawned) with no permit tracking for the `transparent` path. The `_permit` is dropped at the end of the `if verdict == "TARPIT"` block, not when the tarpit actually releases.
**Fix:** In `handle_transparent`, spawn the tarpit in a separate task just like `handle()` does, holding the permit for the full duration.

#### T1-4 — DNS Cache Has No Eviction

**Files:** `src/state.rs`, `src/dashboard.rs`
**Problem:** `AppState::dns_cache` is a `DashMap` that grows unbounded. The 5-minute TTL is only checked per-lookup (lazy expiry), not proactively evicted.
**Fix:** In `spawn_stats_poller`, add DNS cache eviction alongside the `evict_stale_hosts` call:

```rust
if ticks % 60 == 0 {
    state.evict_stale_hosts(600);
    let ttl = std::time::Duration::from_secs(300);
    state.dns_cache.retain(|_, v| v.resolved_at.elapsed() < ttl);
}
```

#### T1-5 — Blocklist Write Lock Blocks All Requests During Refresh

**Files:** `src/blocklist.rs`
**Problem:** `spawn_refresh_task` holds a write lock on `state.blocklist` while calling `bl.clear()` and `bl.extend(remote)` — a potentially 500k-entry operation. All concurrent requests that need to check the blocklist are blocked for the full duration.
**Fix:** Build the new set completely off-lock, then swap atomically:

```rust
let mut new_set: HashSet<String> = HashSet::with_capacity(remote.len() + SEED.len());
new_set.extend(SEED.iter().map(|s| s.to_string()));
new_set.extend(remote);
let old_len = {
    let mut bl = state.blocklist.write().await;
    let old = bl.len();
    *bl = new_set;   // single pointer swap
    old
};
```

#### T1-6 — `emit_full` in `proxy.rs` Swallows Audit Event Errors Silently After Fix

**Files:** `src/proxy.rs`
**Problem:** `emit_full` logs a `warn!` when the events channel is full, but the Oracle DB path (`insert_proxy_event`) silently drops the event when the mpsc channel is full (by design). Under high load this means events are silently lost without any metric.
**Fix:** Add an `AtomicU64` counter `dropped_events` to `AppState` and increment it in `EventSender::send()` on drop. Expose it in the `/stats/summary` response and the WebSocket stats broadcast.

---

### Tier 2 — Feature Improvements

#### T2-1 — Rate Limit the Admin API

**Files:** `src/main.rs`
**Problem:** The admin API has no rate limiting. An attacker who obtains the `ADMIN_API_KEY` can enumerate all tracked hosts or flood the stats endpoint.
**Fix:** Add a simple token-bucket rate limiter (use `tower::limit::RateLimitLayer` or a custom `DashMap<IpAddr, Instant>` counter) to the admin router middleware stack.

#### T2-2 — Propagate `obfuscation_profile` to Oracle DB

**Files:** `src/proxy.rs`, `src/tunnel.rs`, `src/db.rs`
**Problem:** `emit_full` is called with `obfuscation_profile: None` even when a Fox profile is active. The ClickHouse schema has an `obfuscation_profile` column; the Oracle schema has it too (via `migrate_obfuscation.sql`). The data is simply never written.
**Fix:** Thread the active `profile.as_str()` into `emit_full` and pass `Some(profile.as_str().to_string())` to `ProxyEvent::obfuscation_profile`.

#### T2-3 — QUIC Listener Missing Obfuscation Header Manipulation

**Files:** `src/quic.rs`
**Problem:** `classify_obfuscation` is called in `handle_h3_request` but the result is bound to `_profile` and never used. QUIC tunnels receive no header normalization.
**Fix:** Apply obfuscation logic at the QUIC layer. Since QUIC tunnels are raw TCP post-CONNECT (just like the TCP tunnel path), the obfuscation happens at the TCP stream level. Log the profile in the `tunnel_open` event and count it in `obfuscated_count`.

#### T2-4 — WireGuard Event Polling Not Implemented

**Files:** `src/main.rs` (no `wg_poller` module exists)
**Problem:** The Oracle schema has a `wg_events` table and the dashboard has views (`v_wg_peer_timeline`, `v_correlated_activity`) that join against it, but no code polls `wg show` or reads WireGuard kernel events to populate this table.
**Fix:** Add `src/wg_poller.rs` that runs `wg show wg0 dump` periodically (every 5s) via `tokio::process::Command`, parses the output, and sends `wg_events` rows to a dedicated Oracle mpsc writer. Expose peer stats via a new `/wg/peers` REST endpoint.

#### T2-5 — TLS Fingerprint Not Recorded for CONNECT Tunnels

**Files:** `src/tunnel.rs` (`handle`)
**Problem:** `record_tls_fingerprint` is called in `handle_transparent` (which peeks the raw TCP stream), but the CONNECT tunnel path in `handle()` never sees the inner TLS — it only sees the outer HTTP CONNECT headers. The inner TLS ClientHello is forwarded opaquely.
**Fix:** After the `upgrade_fut.await` in `run_tunnel`, peek the first 512 bytes of the `upgraded` stream before starting `copy_bidirectional`, parse with `parse_tls_info`, and call `state.record_tls_fingerprint()`.

#### T2-6 — Blocklist Subdomain Matching Is O(depth) Per Request

**Files:** `src/blocklist.rs`
**Problem:** `is_blocked` walks up the domain hierarchy with repeated `HashSet::contains` lookups. For a deeply nested host (`a.b.c.d.e.com`) this is 5 lookups per request, all under a read lock.
**Fix:** Replace the read-lock `HashSet` with an `Arc<HashSet<String>>` protected by `ArcSwap` (or a `tokio::sync::watch`). This allows lock-free reads. The writer task swaps the pointer atomically, eliminating any lock contention on the hot path.

```toml
# Cargo.toml
arc-swap = "1"
```

```rust
// state.rs
pub blocklist: arc_swap::ArcSwap<std::collections::HashSet<String>>,

// blocklist.rs — is_blocked becomes sync:
pub fn is_blocked(hostname: &str, state: &SharedState) -> bool {
    let bl = state.blocklist.load();
    // ... walk hierarchy against *bl
}
```

#### T2-7 — Graceful Shutdown Does Not Wait for Oracle Flush

**Files:** `src/main.rs`
**Problem:** On SIGINT, the cancellation token fires, the Oracle flusher's `token.cancelled()` branch returns immediately, but any events queued in the mpsc channel at shutdown time are silently dropped. The 5s drain timeout only waits for in-flight TCP connections, not for the Oracle writer.
**Fix:** After `shutdown.cancel()`, drain the Oracle mpsc channel by closing the sender side and waiting for the writer task to exit before the process ends.

---

### Tier 3 — Polish & Observability

#### T3-1 — Dashboard Static Assets Missing Cache Headers

**Files:** `src/main.rs`
**Problem:** `ServeDir::new("static")` serves assets with no `Cache-Control` header. Every dashboard refresh fetches all assets.
**Fix:** Add `tower_http::services::ServeDir` with `append_index_html_on_directories` and wrap with `tower_http::set_header::SetResponseHeaderLayer` to inject `Cache-Control: public, max-age=3600`.

#### T3-2 — Structured Logging Target Not Consistent

**Files:** `src/proxy.rs`, `src/tunnel.rs`, `src/quic.rs`
**Problem:** Some audit events use `target: "audit"` in `tracing::info!` but others (e.g., `emit_full` in `tunnel.rs`) do not. Log aggregators filtering on `target=audit` will miss events.
**Fix:** Audit all `info!` / `error!` calls in proxy.rs, tunnel.rs, and quic.rs and ensure every user-visible event uses `target: "audit"`.

#### T3-3 — `/stats/summary` Missing Throughput Fields

**Files:** `src/dashboard.rs`
**Problem:** The `StatsSummary` struct exposed at `/stats/summary` lacks `bytes_up`, `bytes_down`, `active_tunnels`, and `obfuscated` counters. These are available in the WebSocket broadcast but not the REST endpoint.
**Fix:** Extend `StatsSummary`:

```rust
pub struct StatsSummary {
    pub total_hosts: usize,
    pub tarpit_count: usize,
    pub top_category: Option<String>,
    pub highest_risk_host: Option<String>,
    // Add:
    pub active_tunnels: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub blocked_total: u64,
    pub obfuscated_total: u64,
}
```

#### T3-4 — ClickHouse Schema Missing `obfuscation_profile`

**Files:** `sql/clickhouse.sql`
**Problem:** The Oracle schema has `obfuscation_profile` (added via `migrate_obfuscation.sql`) but the ClickHouse schema does not. Events forwarded to ClickHouse via Vector will have this field silently dropped.
**Fix:**

```sql
ALTER TABLE proxy_events ADD COLUMN IF NOT EXISTS
    obfuscation_profile LowCardinality(String) DEFAULT '';
```

Add this to `clickhouse.sql` as a comment-noted addition.

#### T3-5 — `/hosts/{hostname}` Allows Timing Oracle on Existence

**Files:** `src/dashboard.rs`
**Problem:** `host_detail` returns `200 + body` for known hosts and `404` for unknown ones. An attacker with the API key can enumerate tracked hosts in O(1) per guess.
**Fix:** Not critical if `ADMIN_API_KEY` is strong, but consider returning a fixed-time response shape (always 200, with a `"found": bool` field) or ensuring the key is sufficiently random (≥32 bytes).

---

## 7. Security Hardening Roadmap

Beyond the workmap items above, the following changes move this proxy from "good" to "excellent" security posture:

### 7.1 — Certificate Pinning for Blocklist Fetch

The blocklist is fetched from `jsdelivr.net` with no certificate pinning. A MITM or CDN compromise could inject allowed domains. Pin the expected root CA:

```rust
// In blocklist::fetch(), build client with:
.tls_built_in_root_certs(false)
.add_root_certificate(/* pinned jsDelivr/Fastly root */)
```

### 7.2 — Connection Coalescing / Request Smuggling Protection

The hop-by-hop header removal in `proxy::handler` is thorough, but does not handle `Content-Length` + `Transfer-Encoding` conflicts (HTTP request smuggling). Add explicit rejection:

```rust
if req.headers().contains_key("transfer-encoding") && req.headers().contains_key("content-length") {
    return Err(StatusCode::BAD_REQUEST);
}
```

### 7.3 — SSRF Prevention

Currently any hostname (including `localhost`, `169.254.x.x`, RFC-1918 ranges) can be proxied. Add a blocklist of private/loopback ranges to prevent server-side request forgery:

```rust
fn is_private_ip(ip: std::net::IpAddr) -> bool {
    matches!(ip, 
        IpAddr::V4(a) if a.is_loopback() || a.is_private() || a.is_link_local() || a.is_broadcast(),
        IpAddr::V6(a) if a.is_loopback() || a.is_unspecified(),
    )
}
```

Apply this check after DNS resolution in `run_tunnel` and `handle_transparent`.

### 7.4 — Audit Log Integrity

Current audit events are emitted to a broadcast channel and optionally written to Oracle. There is no signing or tamper evidence. For compliance use cases, consider writing a rolling HMAC chain over audit events (each event includes `prev_hmac`) so the log cannot be silently altered.

### 7.5 — Rate Limiting Per Client IP

The tarpit handles high-frequency blocklist hits, but there is no rate limiting for legitimate-looking traffic. Add a sliding window counter per `peer_ip` (using `DashMap<IpAddr, (u32, Instant)>`) and return `429 Too Many Requests` after a configurable threshold.

---

## 8. Testing Strategy

### Unit Tests (existing)

```bash
cargo test                           # all unit tests
cargo test blocklist                 # blocklist domain walking
cargo test obfuscation               # profile classification + header manipulation
cargo test tunnel                    # TLS ClientHello parsing
cargo test state                     # verdict transitions, host eviction
```

### Integration Tests (to add)

Create `tests/integration/` with:

- **`proxy_blocks_ad_domain.rs`** — Start the proxy on a random port (no TLS), send `CONNECT doubleclick.net:443`, assert `200 OK` response followed by immediate close (not tarpit).
- **`proxy_tarpits_telemetry.rs`** — Drive `record_host_block` to `TARPIT` verdict, then initiate CONNECT and verify connection is held open.
- **`blocklist_refresh.rs`** — Stub the blocklist URL, trigger refresh, verify new domains are blocked and removed domains are allowed.
- **`dashboard_websocket.rs`** — Connect to `/events` on the admin port (no TLS), trigger a block, verify the JSON event appears on the socket within 1s.

### Load Tests

```bash
# Install oha
cargo install oha

# Benchmark proxy throughput (plaintext, no TLS)
oha -n 10000 -c 100 --proxy http://localhost:3000 http://example.com/

# Benchmark blocklist check speed
oha -n 50000 -c 200 --proxy http://localhost:3000 http://doubleclick.net/
```

---

## 9. Observability & Ops

### Log Pipeline (Vector → ClickHouse)

Configure Vector to read the proxy's JSON stdout and forward to ClickHouse:

```toml
# vector.toml
[sources.proxy_logs]
type = "stdin"
decoding.codec = "json"

[transforms.parse_proxy]
type = "remap"
inputs = ["proxy_logs"]
source = '''
  .timestamp = parse_timestamp!(.timestamp, format: "%+")
'''

[sinks.clickhouse]
type = "clickhouse"
inputs = ["parse_proxy"]
endpoint = "http://clickhouse:8123"
database = "default"
table = "proxy_events"
```

### Grafana Dashboard Panels (using `sql/views.sql`)

| Panel | View | Key metric |
|---|---|---|
| Blocked hosts (24h) | `v_blocked_hosts_24h` | `block_count` |
| Threat scores | `v_host_threat_score` | `threat_score DESC` |
| Tunnel throughput | `v_tunnel_throughput` | `total_bytes_up + total_bytes_down` per minute |
| WireGuard peers | `v_wg_peer_timeline` | `handshakes`, `avg_latency_ms` |
| Slow queries | `v_slow_queries` | `elapsed_ms DESC` |
| Pipeline health | `v_pipeline_health` | `health_status` alert on `STALE` |
| Fox traffic | `v_fox_traffic` | obfuscated event volume by profile |

### Health Check

```bash
# Liveness
curl http://localhost:3002/health   # → "ok"

# With Oracle feature: returns 503 if DB unreachable within 5s
```

### Useful One-Liners

```bash
# Watch live audit events
websocat ws://localhost:3002/events | jq .

# Get top 10 riskiest hosts
curl -s -H "x-api-key: $ADMIN_API_KEY" http://localhost:3002/hosts \
  | jq '[.[] | {host, risk_score, verdict, blocked_attempts}] | sort_by(-.risk_score) | .[0:10]'

# Get summary stats
curl -s -H "x-api-key: $ADMIN_API_KEY" http://localhost:3002/stats/summary | jq .

# Check blocklist size
# (inferred from logs: "blocklist refreshed entries=...")
docker logs ssl-proxy 2>&1 | grep "blocklist refreshed" | tail -1
```

---

## 10. Contributing Guidelines

### Branch Naming

- `fix/<T0|T1|T2|T3>-<number>-short-description` — e.g., `fix/T0-1-admin-port-split`
- `feat/<description>` — new features
- `refactor/<description>` — non-functional changes

### Commit Style

Follow Conventional Commits:

```
fix(tunnel): prevent tarpit semaphore leak on transparent path (T1-3)
feat(config): add ADMIN_PORT for plaintext dashboard listener (T0-1)
refactor(blocklist): replace RwLock with ArcSwap for lock-free reads (T2-6)
```

### PR Checklist

- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] If touching Oracle path: tested with `oracle-db` feature enabled
- [ ] Config changes documented in §5 of this file
- [ ] Workmap item marked complete (strike through + commit reference)

### Code Style

- Use `tracing` structured fields (`key = %value`) for all log lines — never interpolated strings
- All audit-visible events must include `target: "audit"` (see T3-2)
- Sensitive values (passwords, keys) must never appear in log output
- Use `subtle::ConstantTimeEq` for any secret comparison (already available in deps)


{"type":"finding","severity":"minor","fileName":"src/state.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/state.rs around lines 87 - 120, The test test_record_host_block_verdict_transition contains an impossible sequence of expected prior verdicts: after calling state.record_host_block and forcing stats to 100 attempts over 10s (10 Hz) the host's verdict() will already be \"TARPIT\", so the later expectation that the previous verdict is \"AGGRESSIVE_POLLING\" is invalid; update the test by removing or changing the final block to simulate a different prior state (e.g., reset host_stats or set stats so verdict() returns \"AGGRESSIVE_POLLING\" before calling record_host_block), or simply assert the transition from \"TARPIT\" to the expected new verdict, ensuring you reference the state.record_host_block calls, state.host_stats manipulations, and the verdict() checks when making the fix.","suggestions":[]}
{"type":"finding","severity":"minor","fileName":"src/state.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/state.rs around lines 281 - 286, The current construction that sets pass by falling back to std::fs::read_to_string(&config.oracle_pass_file).unwrap_or_default() silently hides file-read errors; change the fallback to explicitly match the Result from std::fs::read_to_string and log a warning when Err(e) occurs (including the file path from config.oracle_pass_file and the error e) before using an empty string or other safe default, keeping the same trimming logic (trim_end_matches) on the Ok branch; update the code where pass is assigned (the block referencing config.oracle_pass.clone().unwrap_or_else(...) and std::fs::read_to_string) to perform this match and use a logging macro available in the crate (e.g., log::warn! or tracing::warn!) so unreadable/missing password files are visible in logs.","suggestions":["            let pass = config.oracle_pass.clone().unwrap_or_else(|| {\n                std::fs::read_to_string(&config.oracle_pass_file)\n                    .inspect_err(|e| {\n                        if !config.oracle_pass_file.is_empty() {\n                            tracing::warn!(path = %config.oracle_pass_file, error = %e, \"Failed to read oracle password file\");\n                        }\n                    })\n                    .unwrap_or_default()\n                    .trim_end_matches(&['\\n', '\\r'][..])\n                    .to_string()\n            });"]}
{"type":"finding","severity":"minor","fileName":"src/tunnel.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/tunnel.rs around lines 396 - 407, The TLS peek buffer in peek_tls_info is currently only 512 bytes which can miss larger ClientHello messages; increase the peek buffer to 1024 bytes (change the local buf in async fn peek_tls_info from [0u8; 512] to [0u8; 1024]) so parse_tls_info receives a larger slice, or alternatively add a comment documenting the 512-byte limitation if you don't want to change the size.","suggestions":[]}
{"type":"finding","severity":"minor","fileName":"src/proxy.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/proxy.rs around lines 329 - 340, The response header-stripping loop currently removes \"upgrade\" via res.headers_mut().remove(...) which conflicts with the request handling that preserves \"upgrade\" for WebSocket handshakes (see the request-preserve logic around line 216); adjust the response logic to also preserve the \"upgrade\" header—either remove \"upgrade\" from the list of headers to strip or only strip it for non-101 responses (check for status == 101 Switching Protocols before removing); ensure the change references the same header name \"upgrade\" and the existing res.headers_mut().remove usage so WebSocket upgrades are not dropped.","suggestions":["            for h in &[\n                \"connection\",\n                \"keep-alive\",\n                \"proxy-connection\",\n                \"te\",\n                \"trailer\",\n                \"trailers\",\n                \"transfer-encoding\",\n            ] {\n                res.headers_mut().remove(*h);\n            }"]}
{"type":"finding","severity":"major","fileName":"src/tunnel.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/tunnel.rs around lines 1023 - 1029, The TcpStream::connect call in this branch (the raw TCP path using tokio::net::TcpStream::connect, creating local variable upstream and then calling set_keepalive and tokio::io::copy_bidirectional) lacks a connect timeout and can hang indefinitely; wrap the connect attempt in tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(&host)).await, handle both the timeout Err and connection Result::Err by returning/closing the task (or logging and continuing), only call set_keepalive and tokio::io::copy_bidirectional after a successful connect, and propagate or log errors instead of letting the await block forever or using unwrap_or for copy results.","suggestions":[]}
{"type":"finding","severity":"minor","fileName":"src/tunnel.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/tunnel.rs around lines 356 - 366, The code currently swallows both timeout and connection errors in the match after calling tokio::time::timeout and TcpStream::connect; replace the `_ => {}` arm with explicit handling for Err(timeout_err) and Ok(Err(connect_err)) so failures are logged (include orig_dst and the error) before returning. Locate the match around tokio::time::timeout/tokio::net::TcpStream::connect and add logging (e.g., tracing::warn/error) for connection errors and timeout cases, keeping the successful Ok(Ok(mut upstream)) branch unchanged and still calling set_keepalive and tokio::io::copy_bidirectional.","suggestions":["            match tokio::time::timeout(\n                tokio::time::Duration::from_secs(10),\n                tokio::net::TcpStream::connect(orig_dst),\n            ).await {\n                Ok(Ok(mut upstream)) => {\n                    set_keepalive(&upstream);\n                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;\n                },\n                Ok(Err(e)) => {\n                    debug!(host = %name, %e, \"bypass connect failed\");\n                }\n                Err(_) => {\n                    debug!(host = %name, \"bypass connect timed out\");\n                }\n            }\n            return;"]}
{"type":"finding","severity":"major","fileName":"src/main.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/main.rs around lines 40 - 50, The current constant_time_eq function truncates inputs to 256 bytes and omits a constant-time length check, allowing long-equals-first-256-bits attacks; fix by removing the fixed-size stack buffers and instead allocate buffers sized to the full max length of the two inputs (let max_len = a_bytes.len().max(b_bytes.len()); let mut a_buf = vec![0u8; max_len]; let mut b_buf = vec![0u8; max_len]; copy full slices), then use subtle::ConstantTimeEq on those slices (a_buf.ct_eq(&b_buf).into()) and also include a constant-time length equality check (encode both lengths as a fixed-size integer byte array, ct_eq those and AND the result) so both content and length are compared without early/short-circuit returns; update function constant_time_eq accordingly.","suggestions":[]}
{"type":"finding","severity":"major","fileName":"src/tunnel.rs","codegenInstructions":"Verify each finding against the current code and only fix it if needed.\n\nIn @src/tunnel.rs around lines 339 - 368, The bypass logic in the hostname branch is insecure and inconsistent: replace the current bypass_list and substring check so it matches the CONNECT bypass semantics and performs proper suffix/domain matching instead of contains; update the bypass_list entries to the canonical domain patterns used in the CONNECT branch (e.g., \"facebook.com\", \"instagram.com\", etc.) and change the check from name.contains(domain) to a safe test like name == domain || name.ends_with(&format!(\".{}\", domain)) (apply this in the block that references hostname and bypass_list) so subdomain matches work but unrelated domains like \"evilfacebook.com\" do not.","suggestions":[]}