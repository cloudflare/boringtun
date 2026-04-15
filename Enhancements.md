# Proxy Reliability and Compatibility Enhancements

This document tracks durable engineering improvements for the explicit proxy
path (`CONNECT` and HTTP forwarding). It is intended as a permanent project
reference and currently retains some historical diagnostic notes for context
until they are migrated into a separate investigation record.

## Scope

- Client traffic path: `Client -> ssl-proxy:3000 -> Internet`
- Focus areas: reliability, compatibility, observability, and safe hardening
- Out of scope: new temporary debugging transcripts; historical diagnostic and
  hypothesis notes retained below are legacy context, not the target format for
  future updates

## Confirmed Improvement Areas

### 1) Resolver consistency in tunnel paths

Use a shared resolver strategy for CONNECT and bypass flows to avoid behavior
drift across code paths.

- Prefer one dial helper for all tunnel kinds
- Keep timeout and error classification consistent
- Record selected upstream IP in telemetry

Primary file: `src/tunnel.rs`

### 2) CONNECT failure behavior after upgrade

Ensure failed upstream dials do not look like successful established tunnels to
clients.

- Fail fast and close upgraded streams on upstream failure
- Keep clear audit/error logs for dial and upgrade failures

Primary file: `src/tunnel.rs`

### 3) Pinned-domain matching consistency

Use one suffix-based matcher for pinned domains across tunnel entry points.

- Avoid fragmented, path-specific domain lists
- Keep matching rules centralized and testable

Primary file: `src/tunnel.rs`

### 4) Request mutation safety

Constrain request mutations so app-critical behavior is preserved.

- Do not apply global User-Agent overrides
- Preserve required application `x-*` headers
- Keep profile-specific obfuscation scoped to intended profiles only

Primary file: `src/proxy.rs`

### 5) Upgrade/WebSocket semantics

Do not strip headers that break expected upgrade semantics in proxied traffic.

- Keep response-side handling compatible with upgrade flows

Primary file: `src/proxy.rs`

### 6) Authentication and deployment hygiene

Keep runtime credentials and exposure settings production-safe.

- Require explicit non-placeholder proxy credentials
- Verify network accessibility for proxy listener port

Primary files: deployment configuration and runtime environment

## Recommended Validation Matrix

Use a repeatable validation matrix for every major proxy behavior change:

- Auth check via proxy with known-good credentials
- CONNECT success and failure path verification
- Domain-specific compatibility checks (Instagram/YouTube and similar)
- Resolver and upstream-IP observability checks
- WebSocket/upgrade smoke tests

## Prioritized Work Order

1. Resolver and dial-path unification
2. CONNECT post-upgrade failure handling
3. Pinned-domain matcher consolidation
4. Request mutation constraints (`UA` and `x-*` handling)
5. Upgrade semantics compatibility
6. Deployment credential/accessibility guardrails

## Change Management Notes

- Keep this file high signal: architecture decisions, confirmed behaviors,
  and implementation priorities only
- Move temporary diagnostics into issue/PR comments or incident notes
- When adding new items, include owner, status, and target file(s)
Got it — WireGuard is irrelevant here. The proxy itself is the only thing between clients and the internet. Let me re-diagnose with fresh eyes.

---

## Actual Architecture
```
Client (iPhone/Android) → configures proxy → ssl-proxy:3000 → internet
```

Clients set the proxy manually in their WiFi settings (or via MDM). No WireGuard, no transparent proxy needed. Just CONNECT tunneling and HTTP forwarding.

---

## Re-Diagnosis: Why Instagram/YouTube Specifically Fail

---

## Verification Status

- Confirmed in code: T1, T2, T3.
- Plausible but environment-dependent: T6, T7.
- Hypotheses requiring traffic capture/trace validation before treating as root cause: T5, T8, T9, T10, T11, T12.

---

### 🔴 CRITICAL

**T1 — The cert-pinned bypass in `tunnel.rs` `handle()` returns `200 OK` but then does `TcpStream::connect(&host)` using the container's system DNS — if that DNS isn't resolving correctly, the upstream connect silently fails and the client hangs**

`tunnel.rs` `run_tunnel()`:
```rust
let connect = async {
    tokio::net::TcpStream::connect(&host).await
    // host = "instagram.com:443"
    // uses /etc/resolv.conf inside container
    // if container DNS is broken → silent hang
};
```

Meanwhile `quic.rs` correctly uses the DoH resolver. Inconsistency.

**Quick checkpoint first:**
```bash
# Inside the running container
docker exec -it <container> bash

# Test system DNS
nslookup instagram.com
nslookup i.instagram.com
nslookup scontent.cdninstagram.com

# Test actual proxy tunnel
curl -v --proxy http://iphoneuser:yourpasswordhere@localhost:3000 \
  https://www.instagram.com/

# Test YouTube
curl -v --proxy http://iphoneuser:yourpasswordhere@localhost:3000 \
  https://www.youtube.com/
```

---

**T2 — The cert-pinned bypass intercepts Instagram/YouTube at the `handle()` level (CONNECT proxy path) but sends `200 OK` back immediately, then connects to upstream in a spawned task — if that connect fails, the client already got 200 and just hangs with an open tunnel that goes nowhere**

```rust
// tunnel.rs ~line 490
if is_pinned_app {
    tokio::spawn(async move {           // ← spawned, fire-and-forget
        let upgraded = match upgrade_fut.await { Ok(u) => u, Err(_) => return };
        let mut client_io = TokioIo::new(upgraded);
        if let Ok(mut upstream) = tokio::net::TcpStream::connect(&host).await {
            // if this fails → return → client hangs forever
        } else {
            error!(%host, "bypass tunnel connect failed");
            // ← no response sent to client, client waits forever
        }
    });

    return Ok(Response::builder()
        .status(StatusCode::OK)   // ← client already got 200
        .body(Body::empty())
        .unwrap());
}
```

The client (Instagram app) gets `200 OK`, thinks the tunnel is established, starts sending TLS ClientHello, and gets nothing back. The app eventually times out and shows a network error.

---

**T3 — The non-pinned app path (`run_tunnel`) also uses `TcpStream::connect(&host)` with system DNS, same problem as T1**

```rust
async fn run_tunnel(...) {
    let (name, port) = ...;
    let connect = async {
        tokio::net::TcpStream::connect(&host).await  // system DNS
    };
```

The `name` variable is extracted correctly but never actually used for DNS — it just passes `&host` (the full `hostname:port` string) to `connect()` which does a blocking DNS lookup via libc. Inside a container on a cloud VM, this is whatever Docker sets in `/etc/resolv.conf`, usually the host's DNS or `8.8.8.8` — which should work but adds latency and has no fallback.

---

**T4 — The bypass list in `handle()` is a superset of `handle_transparent()` but they're completely separate code paths with different logic — the transparent handler barely covers Instagram/YouTube**

`handle()` bypass (CONNECT proxy path — what iPhone proxy settings use):
```rust
hostname.contains("instagram.com")   ✓
hostname.contains("youtube.com")     ✓
hostname.contains("googlevideo.com") ✓
hostname.contains("fbcdn.net")       ✓
```

`handle_transparent()` bypass (iptables redirect path — NOT used when client sets proxy):
```rust
"graph.facebook.com",
"graph.instagram.com",
"googlevideo.com",
"s.youtube.com",         // ← only one youtube subdomain
```

Since your clients are using explicit proxy settings, only `handle()` matters here. But `handle_transparent()` needs fixing too for completeness.

---

**T5 — Instagram and YouTube use many subdomains that aren't covered by simple `.contains()` checks**
_Status: hypothesis (now mitigated by suffix-based matching; still validate with logs)._

Instagram CDN domains your bypass misses:
- `scontent-*.cdninstagram.com` — profile pics, feed images
- `video-*.cdninstagram.com` — reels/stories
- `*.cdninstagram.com` generally
- `i.instagram.com` — API calls

YouTube domains your bypass misses:
- `*.googlevideo.com` — covered ✓ (contains check)
- `i.ytimg.com` — thumbnails ✗
- `yt3.ggpht.com` — channel avatars ✗
- `*.gvt1.com` — Google video ✗
- `googleapis.com` — partially (classified as google-services, not bypassed)

Apps don't just connect to `instagram.com` — they connect to 10-20 different subdomains per session. Missing even one causes partial load failures that look like "Instagram doesn't work."

---

**T6 — The `PROXY_PASSWORD=yourpasswordhere` placeholder in `docker-compose.yaml` is likely not what your clients have configured**

```yaml
- PROXY_USERNAME=iphoneuser
- PROXY_PASSWORD=yourpasswordhere    # ← placeholder, never changed?
```

If the client has a different password, every request returns `407 Proxy Authentication Required` and the app shows a generic network error with no indication it's an auth failure.

**Checkpoint:**
```bash
# Test with exact credentials
curl -v --proxy http://iphoneuser:yourpasswordhere@<your-server-ip>:3000 \
  https://instagram.com/
# If you get 407 → password mismatch
# If you get connection refused → port not open
# If you get 200 + data → auth works
```

---

**T7 — `docker-compose.yaml` exposes port 3000 on all interfaces (`0.0.0.0`) but ports 3001 and 3002 are localhost-only — this is correct for the proxy but verify firewall allows 3000 from clients**

```yaml
ports:
  - "3000:3000"              # proxy — public ✓
  - "127.0.0.1:3001:3001"   # tproxy — internal ✓
  - "127.0.0.1:3002:3002"   # admin — internal ✓
```

**Checkpoint:**
```bash
# From client machine or phone hotspot
nc -zv <server-ip> 3000
# or
curl -v --proxy http://<server-ip>:3000 http://example.com
```

---

### 🟠 HIGH — Causes partial failures

**T8 — HTTP header scrubbing in `proxy.rs` removes ALL `x-` headers except a whitelist, but some app APIs require specific `x-` headers to function**
_Status: hypothesis supported by known app header requirements._

```rust
let x_headers: Vec<_> = headers.keys()
    .filter(|k| {
        let name = k.as_str();
        name.starts_with("x-") &&
        !name.eq("x-amz-target") &&
        !name.eq("x-client-data")
    })
    .map(|k| k.clone())
    .collect();

for name in x_headers {
    headers.remove(name);   // removes EVERYTHING else
}
```

Instagram API uses `x-ig-app-id`, `x-ig-www-claim`, `x-instagram-ajax` — these are stripped. Instagram's API will reject requests missing these headers with 400/403 errors, which look like "app not working."

**Fix — expand the whitelist:**
```rust
name.starts_with("x-") &&
!name.eq("x-amz-target") &&
!name.eq("x-client-data") &&
!name.eq("x-ig-app-id") &&
!name.eq("x-ig-www-claim") &&
!name.eq("x-instagram-ajax") &&
!name.eq("x-csrftoken") &&
!name.eq("x-requested-with") &&
!name.eq("x-youtube-client-name") &&
!name.eq("x-youtube-client-version") &&
!name.eq("x-goog-api-key") &&
!name.eq("x-goog-visitor-id")
```

---

**T9 — User-Agent rotation in `proxy.rs` overwrites the app's real UA with a desktop Chrome UA**
_Status: high-confidence compatibility risk._

```rust
static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...",
    // all desktop Chrome
];
let ua = USER_AGENTS[ts as usize % USER_AGENTS.len()];
headers.insert("user-agent", ua.parse().unwrap());
```

Instagram and YouTube serve completely different content (and may reject requests) when they see a desktop UA coming from a mobile IP. Instagram's API in particular returns different response shapes for mobile vs desktop UAs. Since this runs for ALL non-Fox-profile traffic, every Instagram API call looks like it came from a Windows desktop.

**Fix:** Only override UA for Fox profiles, not globally:
```rust
// Remove the global UA override block from proxy.rs handler()
// Keep it only inside the obfuscation::apply_request_headers() for Fox profiles
```

---

**T10 — `proxy.rs` strips the `upgrade` header comment says "DO NOT REMOVE" but then removes it anyway further down**
_Status: confirmed mismatch in behavior/comment (response-side stripping)._

```rust
req.headers_mut().remove("connection");
// ... comment: DO NOT REMOVE upgrade header
```

But then:
```rust
for h in &["connection", "keep-alive", ..., "upgrade"] {
    res.headers_mut().remove(*h);   // removed from RESPONSE
}
```

This is on the response side so it's less critical, but WebSocket upgrades through the proxy would fail. Instagram uses WebSockets for realtime features (DMs, notifications).

---

### 🟡 MEDIUM

**T11 — No timeout on the CONNECT tunnel upstream connect failure path for non-pinned apps**

If `run_tunnel()` connect times out after 10s, the error is logged but the client has already received `200 OK` and is waiting. The client will eventually time out on its end (usually 30-60s for iOS), causing a very slow failure UX.

**T12 — `record_host_allow` and `record_host_block` both do DashMap lookups on every single request** — not a correctness issue but adds latency on the hot path when `host_stats` grows large.

---

## Priority Work Order

| # | Task | File | Effort | Impact |
|---|---|---|---|---|
| 1 | **Run validation matrix first** — confirm auth/routing/DNS behavior with curl and container checks | — | 10min | Confirms active failure mode |
| 2 | **Implement shared resolver-based dial helper** for CONNECT + bypass paths | `tunnel.rs` | 45min | Resolver consistency + reliability |
| 3 | **Fast-fail post-200 errors** — close client stream when upgrade/dial fails | `tunnel.rs` | 30min | Removes silent hangs |
| 4 | **Unify pinned-domain matcher** with suffix-based matching across paths | `tunnel.rs` | 30min | Prevents partial bypass misses |
| 5 | **Constrain proxy request mutations** — remove global UA override and preserve required `x-*` headers | `proxy.rs` | 25min | App/API compatibility |
| 6 | **Keep response upgrade semantics intact** — stop stripping `upgrade` on response cleanup | `proxy.rs` | 10min | WebSocket compatibility |
| 7 | **Verify/fix credentials** — confirm `PROXY_PASSWORD` matches clients | `docker-compose.yaml` | 10min | Auth unblock |
| 8 | **Keep enhanced connect telemetry** — include resolved IP list and selected IP in tunnel logs/events | `tunnel.rs` | 20min | Faster diagnosis |

---

Start with the `curl` test from T1/T6 checkpoints — that single command will immediately tell you if it's an auth problem (407), a DNS problem (connection hang), or a routing problem (connection refused), and narrows down which of these tasks to tackle first.
