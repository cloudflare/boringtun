Let me analyze the codebase thoroughly before providing recommendations.Let me analyze the code in detail across all the files provided. Here's my assessment of all four issues:

---

## 1. Proxy Flagged as "Non-Secure" / Detectable

**Root causes in your code:**

The proxy is detectable because it leaks several signals:

**HTTP headers give it away.** In `proxy.rs`, you remove hop-by-hop headers but the response still carries `proxy-connection` handling logic and your generic User-Agent replacement (`Chrome/120.0.0.0`) is outdated — modern detectors check UA consistency against TLS fingerprints. More critically, `tunnel.rs` returns `200 OK` on blocked CONNECT requests before tarpitting, which is non-standard behavior a server would never exhibit.

**QUIC/H3 in `quic.rs`** only sets `h3` ALPN but doesn't negotiate `h3-29` or fallback ALPNs that real browsers advertise, making it fingerprintable.

**The TLS config in `main.rs`** uses `with_no_client_auth()` and a single cert — real CDN proxies present different certs per-SNI and support session resumption. Your `rustls::ServerConfig` doesn't configure `max_fragment_length` or session tickets, which browsers always negotiate.

**Fixes:**
- For blocked CONNECT requests, return `407 Proxy Authentication Required` instead of `200 OK` — returning 200 before dropping is a classic detectable proxy behavior
- In `quic.rs`, add `h3-29` to ALPN: `tls_config.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec()]`
- Replace the hardcoded Chrome UA in `proxy.rs` with a rotating pool matching current real browser UAs that align with your TLS fingerprint
- Add `HSTS` and `Alt-Svc` headers on responses when proxying HTTPS to behave like a real CDN edge

---

## 2. Instagram / YouTube Eternal Loading

**Root cause — this is the biggest bug:**

In `tunnel.rs` `handle()`, your bypass logic checks:

```rust
let is_pinned_app = hostname.contains("facebook.com")
    || hostname.contains("instagram.com")
    ...
    || hostname.contains("youtube.com")
```

But this bypass **spawns a task and immediately returns `200 OK`** — the problem is the task connects to `&host` (which is the original `host:port` string) using plain `tokio::net::TcpStream::connect`. For Instagram and YouTube this fails silently because:

1. **Instagram** uses certificate pinning AND requires specific HTTP/2 settings (SETTINGS frames with exact window sizes). Your raw TCP copy doesn't establish TLS with the correct ALPN/SNI before copying, so the upstream rejects the connection.
2. **YouTube** (`googlevideo.com`) is in `handle_transparent`'s bypass list but uses a different code path — and in `run_tunnel`, your DNS resolver (`lookup_ip`) goes to Cloudflare DoH, but the connect happens to the resolved IP while YouTube requires SNI to be set correctly for their CDN routing.

The real issue: **`copy_bidirectional` on a raw upgraded stream to an already-TLS-expecting server doesn't work** — the client sends a TLS ClientHello through your tunnel expecting you to be a dumb pipe, which is correct for CONNECT, but your `run_tunnel` function does a **second DNS resolution and opens a new TCP connection** instead of being a pure pass-through to whatever the client connected to.

Look at `run_tunnel` — it calls `state.resolver.lookup_ip(name)` then connects to the resolved IP. This is fine for most hosts, but for YouTube/Instagram the issue is that `copy_bidirectional` between the upgraded client stream and `upstream` should work... unless the connection is timing out. Check: your timeout is `from_secs(10)` for the connect, but Instagram and YouTube servers often need to be reached at specific IPs tied to their anycast routing, and your Cloudflare DoH resolver may return IPs that are geographically wrong for your WireGuard endpoint's exit IP.

**The eternal loading is almost certainly a DNS/routing mismatch**: the client expects to connect to an IP that Instagram's CDN associates with, but your DoH resolver returns a different IP than what the WireGuard exit node would naturally resolve.

**Fix:** For the pinned bypass domains, skip your DoH resolver entirely and use the system resolver or connect directly using the hostname (letting the OS/kernel route it):

```rust
// In run_tunnel, for bypass domains, connect by hostname not resolved IP
tokio::net::TcpStream::connect(format!("{}:{}", name, port)).await
```

Also check your WireGuard routing table — if `wg0` is the default route but DNS is resolving outside the tunnel, the IPs won't match what Instagram/YouTube's CDN expects for that exit IP.

---

## 3. Auditing Partial Payloads (RecvStream Logging)

Currently `tunnel.rs` and `quic.rs` use `copy_bidirectional` / raw `AsyncRead` which discards all payload data. To audit partial payloads without breaking streaming:

**The right pattern is a tee-copy**, not buffering the full stream. You need to intercept the bytes flowing through `copy_bidirectional` without blocking it. Here's the approach for `run_tunnel`:

Replace `tokio::io::copy_bidirectional` with a manual split that tees into your audit channel:

```rust
// Split streams
let (mut client_read, mut client_write) = tokio::io::split(client);
let (mut upstream_read, mut upstream_write) = upstream.split();

// Tee buffers — ring buffer, first N bytes only
let audit_limit: usize = 4096; // configurable
let mut up_buf = Vec::with_capacity(audit_limit);
let mut down_buf = Vec::with_capacity(audit_limit);

// Custom copy that captures first N bytes
let up_task = async {
    let mut buf = [0u8; 8192];
    let mut total = 0u64;
    loop {
        let n = client_read.read(&mut buf).await?;
        if n == 0 { break; }
        upstream_write.write_all(&buf[..n]).await?;
        total += n as u64;
        if up_buf.len() < audit_limit {
            let take = (audit_limit - up_buf.len()).min(n);
            up_buf.extend_from_slice(&buf[..take]);
        }
    }
    Ok::<u64, std::io::Error>(total)
};
```

Then emit the captured bytes to your Oracle `proxy_events` table as `raw_json` with a `payload_preview` field (base64-encoded to handle binary TLS data).

**Important compliance note**: For TLS tunnels (CONNECT), you're seeing encrypted bytes — to get plaintext you'd need to MITM the TLS, which breaks certificate pinning and requires installing a CA cert on the client devices. If your devices are managed (MDM), this is feasible. If not, you can only audit TLS metadata (SNI, timing, byte counts), not payload content.

For plain HTTP proxied through `proxy.rs` (non-CONNECT), you already have the full request/response available before forwarding — you can buffer and audit those easily.

---

## 4. Oracle Schema — Additional Tables and Views

Based on the existing `proxy_events` and `blocked_events` tables referenced in `db.rs` and `dashboard.rs`, here's what you should add. I'll write these as `ALTER`-safe migration files:Here's a consolidated breakdown of everything:

---

## 1. Proxy Flagged as Non-Secure

Three specific code-level fixes:

**Blocked CONNECT returns wrong status.** In `tunnel.rs` `handle()`, when a host is blocked you return `200 OK` then drop. No real server ever does that — it's a classic proxy tell. Change the blocked-CONNECT response to return `403 Forbidden` with a plain body instead of `200 OK`, then drop. For the tarpit case, returning `200 OK` is actually correct (you need the upgrade to complete), so keep that one.

**Outdated UA in `proxy.rs`.** Your hardcoded `Chrome/120.0.0.0` is from late 2023. Rotate it to a small pool of current versions (128+) keyed on the incoming request's platform header so it stays internally consistent.

**QUIC ALPN too narrow.** In `quic.rs`, add `h3-29` to ALPN: `vec![b"h3".to_vec(), b"h3-29".to_vec()]` — all real browsers still negotiate this fallback and its absence is fingerprintable.

---

## 2. Instagram / YouTube Eternal Loading

The root cause is a **DNS routing mismatch**. Your `run_tunnel` function resolves hostnames using your Cloudflare DoH resolver, but Instagram/YouTube's CDN uses anycast — the "correct" IP depends on the egress IP of whoever is making the DNS query. Your WireGuard exit IP exits from one location, but your DoH resolution happens from your server's IP before the tunnel, returning geographically mismatched IPs.

**Fix in `run_tunnel`**: for the pinned/bypass domains, replace `state.resolver.lookup_ip(name)` with a direct `tokio::net::TcpStream::connect(format!("{}:{}", name, port))` and let the OS resolver (which routes through WireGuard) resolve it naturally. The bypass block in `handle()` already does this correctly with `TcpStream::connect(&host)` — but `run_tunnel` (the non-bypass path) uses DoH, which is wrong for these hosts.

Also check `wg0` is set as the default route *and* that your `resolv.conf` or system resolver routes DNS queries through the tunnel, otherwise the IP mismatch will persist even with the fix above.

---

## 3. Payload Auditing (RecvStream)

For **plain HTTP** (through `proxy.rs`), you already have the full request/response body — you can buffer it before forwarding with no extra infrastructure.

For **CONNECT tunnels** (TLS), you only see encrypted bytes. To get plaintext you need TLS interception (install your own CA cert on the managed devices, terminate TLS at the proxy, re-encrypt upstream). Without that, you can only capture the first ~512 bytes of the ClientHello (which your `peek_tls_info` already does) and metadata.

The pattern to implement tee-copy auditing in `run_tunnel` without blocking the stream is: replace `copy_bidirectional` with a manual read loop that writes to both `upstream` and a bounded `Vec<u8>` (capped at e.g. 4096 bytes), then sends that captured buffer as a `payload_preview` field to the new `PAYLOAD_AUDIT` table via the existing `db::EventSender` channel.

---

## 4. Oracle Schema Files

Three migration files are attached, all idempotent (safe to re-run):

**V002** — `PAYLOAD_AUDIT` table (first-N-bytes capture), `TLS_FINGERPRINTS` (deduplicated JA3), `CONNECTION_SESSIONS` (one row per tunnel session), `BLOCKLIST_AUDIT` (refresh history), plus `ALTER` statements for any missing columns on your existing `PROXY_EVENTS` and `BLOCKED_EVENTS` tables.

**V003** — Six reporting views: `V_BLOCKED_SUMMARY`, `V_SESSION_TIMELINE`, `V_PAYLOAD_AUDIT_READABLE`, `V_TOP_RISK_HOSTS` (top 100 in last 24h), `V_HOURLY_TRAFFIC`, and `V_TLS_FINGERPRINT_STATS`.

**V004** — `DATA_RETENTION_POLICY` table (data-driven, configurable per-table retention), `PURGE_OLD_EVENTS` stored procedure, two materialized views (`MV_DAILY_BLOCKED`, `MV_PEER_IP_SUMMARY`), and two `DBMS_SCHEDULER` jobs (nightly purge at 02:00, MV refresh at 03:00).