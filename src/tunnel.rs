use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use tracing::{debug, error, info};

use crate::{blocklist, obfuscation, state::SharedState};

/// Maximum time a single tarpit connection is held open.
const MAX_TARPIT_MS: u64 = 10_000; // 10 seconds

/// Process-wide semaphore — initialised once, shared via Arc in AppState.
pub fn tarpit_semaphore(max_tarpit: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(max_tarpit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tls_info_crafted_client_hello() {
        // Crafted minimal TLS 1.2 Client Hello with:
        // - SNI: example.com
        // - ALPN: h2
        // - 2 cipher suites
        let client_hello: &[u8] = &[
            0x16, // ContentType: Handshake
            0x03, 0x03, // TLS 1.2
            0x00, 0x5d, // Record length
            0x01, // HandshakeType: ClientHello
            0x00, 0x00, 0x59, // Handshake length
            0x03, 0x03, // Client version TLS 1.2
            // Random (32 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, // Session ID length
            0x00, 0x04, // Cipher suites length (2 suites)
            0x13, 0x01, // TLS_AES_256_GCM_SHA384
            0x13, 0x02, // TLS_CHACHA20_POLY1305_SHA256
            0x01, // Compression methods length
            0x00, // NULL compression
            0x00, 0x1e, // Extensions length
            // SNI extension
            0x00, 0x00, // Extension type: SNI
            0x00, 0x0f, // Extension length
            0x00, 0x0d, // Server name list length
            0x00, // Name type: host_name
            0x00, 0x0a, // Name length
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
            // ALPN extension
            0x00, 0x10, // Extension type: ALPN
            0x00, 0x05, // Extension length
            0x00, 0x03, // Protocol list length
            0x02, // Protocol length
            b'h', b'2',
        ];

        let info = parse_tls_info(client_hello);

        assert_eq!(info.sni, Some("example.com".to_string()));
        assert_eq!(info.alpn, Some("h2".to_string()));
        assert_eq!(info.tls_ver, Some("TLS1.2".to_string()));
        assert_eq!(info.cipher_suites_count, Some(2));
        assert!(info.ja3_lite.is_some());
    }

    #[test]
    fn test_parse_tls_info_invalid_input() {
        // Empty buffer
        let info = parse_tls_info(&[]);
        assert_eq!(info.sni, None);
        assert_eq!(info.alpn, None);
        assert_eq!(info.tls_ver, None);

        // Invalid first byte
        let info = parse_tls_info(&[0x17, 0x03, 0x03, 0x00, 0x00]);
        assert_eq!(info.tls_ver, None);
    }
}

async fn run_tarpit(upgrade_fut: hyper::upgrade::OnUpgrade, host: String, state: SharedState) {
    let upgraded = match upgrade_fut.await {
        Ok(u) => u,
        Err(e) => {
            debug!(%host, %e, "tarpit upgrade failed");
            return;
        }
    };
    let start = Instant::now();
    let mut stream = TokioIo::new(upgraded);
    let _ = tokio::time::timeout(
        tokio::time::Duration::from_millis(MAX_TARPIT_MS),
        tokio::io::copy(&mut stream, &mut tokio::io::sink()),
    )
    .await;
    let held_ms = start.elapsed().as_millis() as u64;
    state.record_tarpit_held(&host, held_ms);
    info!(
        target: "audit",
        event = "tarpit_released",
        host = %host,
        held_ms = held_ms,
        "tarpit connection released"
    );
}

/// Apply TCP keep-alive so the OS holds the connection open without data.
fn set_keepalive(stream: &tokio::net::TcpStream) {
    use std::time::Duration;
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(5));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
}

fn emit_full(
    state: &SharedState,
    event: &str,
    host: &str,
    peer_ip: Option<String>,
    bytes_up: u64,
    bytes_down: u64,
    status_code: Option<u16>,
    blocked: bool,
    extra: serde_json::Value,
) {
    let mut v = serde_json::json!({
        "type": event,
        "host": host,
        "time": chrono::Utc::now().to_rfc3339(),
    });
    if let (Some(obj), Some(ext)) = (v.as_object_mut(), extra.as_object()) {
        obj.extend(ext.clone());
    }
    let raw = v.to_string();
    let _ = state.events_tx.send(raw.clone());
    #[cfg(feature = "oracle-db")]
    crate::db::insert_proxy_event(
        state.db.clone(),
        crate::db::ProxyEvent {
            obfuscation_profile: None,
            event_type: event.to_string(),
            host: host.to_string(),
            peer_ip,
            bytes_up,
            bytes_down,
            status_code,
            blocked,
            raw_json: raw,
        },
    );
}
/// Transparent proxy entry point: called for raw TCP connections redirected by
/// iptables REDIRECT. Reads SO_ORIGINAL_DST to find the real destination, peeks
/// the TLS SNI for the hostname, then does blocklist check + bidirectional copy.
pub async fn handle_transparent(mut stream: tokio::net::TcpStream, state: SharedState) {
    let peer_ip = stream.peer_addr().ok().map(|a| a.ip().to_string());
    let orig_dst = match original_dst(&stream) {
        Ok(a) => a,
        Err(e) => {
            error!(%e, "SO_ORIGINAL_DST failed");
            return;
        }
    };

    let tls = if orig_dst.port() == 443 {
        peek_tls_info(&mut stream).await
    } else {
        TlsInfo::default()
    };

    let hostname = tls.sni.clone();
    let host = match &hostname {
        Some(name) => format!("{}:{}", name, orig_dst.port()),
        None => format!("{}:{}", orig_dst.ip(), orig_dst.port()),
    };
    let category = classify(
        hostname.as_deref().unwrap_or(""),
        orig_dst.port(),
        tls.alpn.as_deref(),
    );

    if let Some(ref name) = hostname {
        if blocklist::is_blocked(name, &state).await {
            state.record_blocked();
            let approx_bytes = (50 + name.len()) as u64;
            // Epic 4.1 — store TLS fingerprint before block counters
            state.record_tls_fingerprint(
                name,
                tls.tls_ver.clone(),
                tls.alpn.clone(),
                tls.cipher_suites_count,
                tls.ja3_lite.clone(),
            );
            let verdict_change = state.record_host_block(name, approx_bytes, category);
            let (attempts, blocked_bytes, freq_hz, verdict, iat_ms, streak, risk) = state
                .host_stats
                .get(name.as_str())
                .map(|s| {
                    (
                        s.blocked_attempts,
                        s.blocked_bytes_approx,
                        s.frequency_hz(),
                        s.verdict(),
                        s.iat_ms,
                        s.consecutive_blocks,
                        (s.risk_score() * 100.0).round() / 100.0,
                    )
                })
                .unwrap_or((1, approx_bytes, 0.0, "BLOCKED", None, 1, 0.0));
            // Epic 3.3 — emit verdict_change event
            if let Some((prev, next)) = verdict_change {
                let vc = serde_json::json!({
                    "type": "verdict_change", "host": name,
                    "prev_verdict": prev, "next_verdict": next,
                    "attempt_count": attempts, "frequency_hz": (freq_hz * 100.0).round() / 100.0,
                    "time": chrono::Utc::now().to_rfc3339(),
                });
                let _ = state.events_tx.send(vc.to_string());
            }
            // Epic 2.1 — async DNS resolution with 500 ms timeout + 5-min cache
            {
                let state2 = state.clone();
                let name2 = name.clone();
                tokio::spawn(async move {
                    const TTL_SECS: u64 = 300;
                    if state2
                        .dns_cache
                        .get(&name2)
                        .map(|e| e.resolved_at.elapsed().as_secs() < TTL_SECS)
                        .unwrap_or(false)
                    {
                        return;
                    }
                    if let Ok(Ok(addrs)) = tokio::time::timeout(
                        tokio::time::Duration::from_millis(500),
                        state2.resolver.lookup_ip(name2.as_str()),
                    )
                    .await
                    {
                        if let Some(ip) = addrs.iter().next() {
                            let ip_str = ip.to_string();
                            state2.dns_cache.insert(
                                name2.clone(),
                                crate::state::ResolvedMeta {
                                    ip: ip_str.clone(),
                                    resolved_at: Instant::now(),
                                },
                            );
                            state2.record_resolved(&name2, ip_str, None);
                        }
                    }
                });
            }
            info!(
                target: "audit",
                event = "tunnel_blocked",
                kind = "transparent",
                host = %name,
                orig_dst = %orig_dst,
                category = category,
                attempt_count = attempts,
                verdict = verdict,
                "blocked snitch (transparent)"
            );
            let event = serde_json::json!({
                "type":     "block",
                "host":     name,
                "time":     chrono::Utc::now().to_rfc3339(),
                "category": category,
                "fingerprint": {
                    "tls_ver":             tls.tls_ver,
                    "alpn":               tls.alpn,
                    "cipher_suites_count": tls.cipher_suites_count,
                    "ja3_lite":           tls.ja3_lite,
                },
                "metrics": {
                    "attempt_count":              attempts,
                    "total_blocked_bytes_approx": blocked_bytes,
                    "frequency_hz":               (freq_hz * 100.0).round() / 100.0,
                    "risk_score":                 risk,
                    "iat_ms":                     iat_ms,
                    "consecutive_blocks":          streak,
                },
                "verdict": verdict,
            });
            let raw = event.to_string();
            let _ = state.events_tx.send(raw.clone());
            #[cfg(feature = "oracle-db")]
            crate::db::insert_proxy_event(
                state.db.clone(),
                crate::db::ProxyEvent {
                    obfuscation_profile: None,
                    event_type: "block".to_string(),
                    host: name.clone(),
                    peer_ip: peer_ip.clone(),
                    bytes_up: 0,
                    bytes_down: 0,
                    status_code: None,
                    blocked: true,
                    raw_json: raw,
                },
            );
            if verdict == "TARPIT" {
                if let Ok(_permit) = state.tarpit_sem.clone().try_acquire_owned() {
                    let tarpit_start = Instant::now();
                    let _ = tokio::time::timeout(
                        tokio::time::Duration::from_millis(MAX_TARPIT_MS),
                        tokio::io::copy(&mut stream, &mut tokio::io::sink()),
                    )
                    .await;
                    state.record_tarpit_held(name, tarpit_start.elapsed().as_millis() as u64);
                }
            }
            return;
        }
    }

    // Certificate Pinning Bypass: Pass through domains with hardcoded certificate pins
    let bypass_list = [
        "graph.facebook.com",
        "graph.instagram.com",
        "googlevideo.com",
        "s.youtube.com"
    ];

    if let Some(ref name) = hostname {
        if bypass_list.iter().any(|&domain| name.contains(domain)) {
            // Raw TCP pass-through - no obfuscation, no TLS termination
            info!(
                target: "audit",
                event = "tunnel_bypass",
                host = %name,
                "Certificate pinned domain detected, bypassing interception"
            );
            
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(10),
                tokio::net::TcpStream::connect(orig_dst),
            ).await {
                Ok(Ok(mut upstream)) => {
                    set_keepalive(&upstream);
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                },
                _ => {}
            }
            return;
        }
    }

    // Classify obfuscation profile after blocklist check
    let profile = if let Some(ref name) = hostname {
        obfuscation::classify_obfuscation(name, &state.config)
    } else {
        obfuscation::Profile::None
    };

    // Epic 3.4 — record allow for streak reset
    if let Some(ref name) = hostname {
        state.record_host_allow(name);
    }
    run_transparent(
        stream, orig_dst, host, state, category, tls, peer_ip, profile,
    )
    .await;
}

#[derive(Default)]
struct TlsInfo {
    sni: Option<String>,
    alpn: Option<String>,
    tls_ver: Option<String>,
    cipher_suites_count: Option<u8>,
    ja3_lite: Option<String>,
}

async fn peek_tls_info(stream: &mut tokio::net::TcpStream) -> TlsInfo {
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(
        tokio::time::Duration::from_millis(500),
        stream.peek(&mut buf),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or(0);
    parse_tls_info(&buf[..n])
}

fn parse_tls_info(buf: &[u8]) -> TlsInfo {
    let mut info = TlsInfo::default();
    if buf.len() < 5 || buf[0] != 22 {
        return info;
    }
    info.tls_ver = match (buf[1], buf[2]) {
        (3, 3) => Some("TLS1.2".into()),
        (3, 1) => Some("TLS1.0".into()),
        _ => None,
    };
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let hs = match buf.get(5..5 + record_len.min(buf.len().saturating_sub(5))) {
        Some(s) => s,
        None => return info,
    };
    if hs.first() != Some(&1) || hs.len() < 6 {
        return info;
    }
    let mut pos = 4 + 2 + 32;
    let sid_len = match hs.get(pos) {
        Some(&v) => v as usize,
        None => return info,
    };
    pos += 1 + sid_len;
    let cs_len = match hs.get(pos..pos + 2) {
        Some(s) => u16::from_be_bytes([s[0], s[1]]) as usize,
        None => return info,
    };
    // Epic 4.2 — cipher suite count (each suite is 2 bytes)
    info.cipher_suites_count = Some((cs_len / 2).min(255) as u8);
    let cs_start = pos + 2;
    let cs_end = cs_start + cs_len;
    pos += 2 + cs_len;
    let cm_len = match hs.get(pos) {
        Some(&v) => v as usize,
        None => return info,
    };
    pos += 1 + cm_len;
    if pos + 2 > hs.len() {
        return info;
    }
    let ext_total = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(hs.len());

    // Epic 4.3 — JA3-lite: collect extension types, curves, point formats
    let mut ext_types: Vec<u16> = Vec::new();
    let mut curves: Vec<u16> = Vec::new();
    let mut point_fmts: Vec<u8> = Vec::new();

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;
        let ext_data = match hs.get(pos..pos + ext_len) {
            Some(s) => s,
            None => break,
        };
        // Collect all extension types for JA3 (skip GREASE: 0x?a?a)
        if ext_type & 0x0f0f != 0x0a0a {
            ext_types.push(ext_type);
        }
        match ext_type {
            // SNI
            0 if ext_len >= 5 => {
                let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                if ext_data.len() >= 5 + name_len {
                    info.sni = String::from_utf8(ext_data[5..5 + name_len].to_vec()).ok();
                }
            }
            // ALPN
            16 if ext_len >= 4 => {
                let proto_len = ext_data[2] as usize;
                if ext_data.len() >= 3 + proto_len {
                    info.alpn = String::from_utf8(ext_data[3..3 + proto_len].to_vec()).ok();
                }
            }
            // Supported versions — detect TLS 1.3
            43 if ext_len >= 3 => {
                let list_len = ext_data[0] as usize;
                let mut i = 1;
                while i + 2 <= (1 + list_len).min(ext_data.len()) {
                    if ext_data[i] == 0x03 && ext_data[i + 1] == 0x04 {
                        info.tls_ver = Some("TLS1.3".into());
                        break;
                    }
                    i += 2;
                }
            }
            // Supported groups (elliptic curves) — ext 10
            10 if ext_len >= 4 => {
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let mut i = 2;
                while i + 2 <= (2 + list_len).min(ext_data.len()) {
                    let g = u16::from_be_bytes([ext_data[i], ext_data[i + 1]]);
                    if g & 0x0f0f != 0x0a0a {
                        curves.push(g);
                    }
                    i += 2;
                }
            }
            // EC point formats — ext 11
            11 if ext_len >= 2 => {
                let list_len = ext_data[0] as usize;
                for &b in ext_data.get(1..1 + list_len).unwrap_or(&[]) {
                    point_fmts.push(b);
                }
            }
            _ => {}
        }
        pos += ext_len;
    }

    // Build JA3-lite string: TLSVersion,Ciphers,Extensions,Curves,PointFormats
    let tls_ver_num: u16 = match info.tls_ver.as_deref() {
        Some("TLS1.3") => 772,
        Some("TLS1.2") => 771,
        Some("TLS1.0") => 769,
        _ => 0,
    };
    let cs_nums: Vec<u16> = hs
        .get(cs_start..cs_end)
        .unwrap_or(&[])
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|&v| v & 0x0f0f != 0x0a0a)
        .collect();
    let join_u16 = |v: &[u16]| {
        v.iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    let join_u8 = |v: &[u8]| {
        v.iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    info.ja3_lite = Some(format!(
        "{},{},{},{},{}",
        tls_ver_num,
        join_u16(&cs_nums),
        join_u16(&ext_types),
        join_u16(&curves),
        join_u8(&point_fmts),
    ));
    info
}

/// Maps hostname + port + ALPN to a human-readable traffic category.
fn classify(host: &str, port: u16, alpn: Option<&str>) -> &'static str {
    let h = host.to_ascii_lowercase();
    if h.contains("firebaselogging")
        || h.contains("firebase-settings")
        || h.contains("app-measurement")
        || h.contains("crashlytics")
        || h.contains("sentry.io")
        || h.contains("analytics")
        || h.contains("telemetry")
        || h.contains("metrics")
        || h.contains("datadog")
        || h.contains("newrelic")
        || h.contains("segment.io")
    {
        return "telemetry";
    }
    if h.contains("doubleclick")
        || h.contains("googlesyndication")
        || h.contains("adnxs")
        || h.contains("criteo")
        || h.contains("pubmatic")
        || h.contains("rubiconproject")
        || h.contains("scorecardresearch")
    {
        return "ads/tracking";
    }
    if h.contains("push.apple.com")
        || h.contains("push.googleapis")
        || h.contains("fcm.googleapis")
        || h.contains("notify.windows")
    {
        return "push-notifications";
    }
    if h.contains("accounts.google")
        || h.contains("oauth")
        || h.contains("auth0.com")
        || h.contains("okta")
        || h.contains("login.microsoft")
        || h.contains("appleid.apple")
    {
        return "auth";
    }
    if h.contains("akamai")
        || h.contains("cloudfront")
        || h.contains("fastly.net")
        || h.contains(".cdn.")
        || h.contains("static.")
        || h.contains("assets.")
    {
        return "cdn/media";
    }
    if h.contains("apple.com") {
        return "apple-services";
    }
    if h.contains("icloud.com") {
        return "icloud";
    }
    if h.contains("googleapis.com") {
        return "google-services";
    }
    if h.contains("whatsapp") {
        return "whatsapp";
    }
    if h.contains("instagram") {
        return "instagram";
    }
    if h.contains("facebook") {
        return "facebook";
    }
    if h.contains("twitter") || h.contains("twimg") {
        return "twitter/x";
    }
    if h.contains("netflix") {
        return "netflix";
    }
    if h.contains("spotify") {
        return "spotify";
    }
    match (port, alpn) {
        (443, Some("h2")) => "https/h2",
        (443, Some("http/1.1")) => "https/h1",
        (443, _) => "https",
        (80, _) => "http",
        (22, _) => "ssh",
        (5228, _) => "google-push",
        _ => "unknown",
    }
}

fn original_dst(stream: &tokio::net::TcpStream) -> std::io::Result<SocketAddr> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    // Try IPv6 first (IP6T_SO_ORIGINAL_DST = 80 on SOL_IPV6 = 41)
    let v6: Result<SocketAddr, _> = unsafe {
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let ret = libc::getsockopt(
            fd,
            41, // SOL_IPV6
            80, // IP6T_SO_ORIGINAL_DST
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret == 0 {
            let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            Ok(SocketAddr::from((ip, port)))
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    if let Ok(addr) = v6 {
        return Ok(addr);
    }
    // Fall back to IPv4 (SO_ORIGINAL_DST = 80 on SOL_IP = 0)
    let addr: libc::sockaddr_in = unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let ret = libc::getsockopt(
            fd,
            0,  // SOL_IP (IPPROTO_IP)
            80, // SO_ORIGINAL_DST
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        addr
    };
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::from((ip, port)))
}

async fn run_transparent(
    mut client: tokio::net::TcpStream,
    orig_dst: SocketAddr,
    host: String,
    state: SharedState,
    category: &'static str,
    tls: TlsInfo,
    peer_ip: Option<String>,
    profile: crate::obfuscation::Profile,
) {
    set_keepalive(&client);
    
    // Use configured tunnel endpoint if available, otherwise connect directly
    let connect_target = state.config.tunnel_endpoint.clone()
        .unwrap_or_else(|| orig_dst.to_string());

    match tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(&connect_target),
    )
    .await
    {
        Ok(Ok(mut upstream)) => {
            let start = Instant::now();
            info!(
                target: "audit",
                event = "tunnel_open",
                kind = "transparent",
                host = %host,
                category = category,
                "transparent tunnel established"
            );
            // Emit obfuscated event if profile is not None
            if !matches!(profile, crate::obfuscation::Profile::None) {
                state.obfuscated_count.fetch_add(1, Ordering::Relaxed);
                info!(
                    target: "audit",
                    event = "tunnel_obfuscated",
                    kind = "transparent",
                    host = %host,
                    profile = profile.as_str(),
                    category = category,
                    "transparent tunnel obfuscated"
                );
            }

            emit_full(
                &state,
                "tunnel_open",
                &host,
                peer_ip.clone(),
                0,
                0,
                None,
                false,
                serde_json::json!({
                    "kind":             "transparent",
                    "category":         category,
                    "alpn":             tls.alpn,
                    "tls_ver":          tls.tls_ver,
                    "obfuscation_profile": profile.as_str(),
                }),
            );
            state.record_tunnel_open();
            match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
                Ok((up, down)) => {
                    state.record_tunnel_close(up, down);
                    info!(
                        target: "audit",
                        event = "tunnel_close",
                        kind = "transparent",
                        host = %host,
                        bytes_up = up,
                        bytes_down = down,
                        duration_ms = start.elapsed().as_millis(),
                        category = category,
                        "transparent tunnel closed"
                    );
                    emit_full(
                        &state,
                        "tunnel_close",
                        &host,
                        peer_ip,
                        up,
                        down,
                        None,
                        false,
                        serde_json::json!({
                            "kind":        "transparent",
                            "category":    category,
                            "bytes_up":    up,
                            "bytes_down":  down,
                            "duration_ms": start.elapsed().as_millis(),
                        }),
                    );
                }
                Err(e) => {
                    state.record_tunnel_close(0, 0);
                    debug!(%host, %e, "transparent tunnel closed by peer");
                }
            }
        }
        Ok(Err(e)) => error!(%host, %e, "transparent tunnel connect failed"),
        Err(_) => error!(%host, "transparent tunnel connect timed out"),
    }
}

pub async fn handle(
    mut req: Request<Body>,
    state: SharedState,
    peer_ip: Option<String>,
) -> Result<Response<Body>, hyper::Error> {
    let host = match req.uri().authority().map(|a| a.to_string()) {
        Some(h) => h,
        None => {
            error!(uri = %req.uri(), "CONNECT request missing host");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::empty())
                .unwrap());
        }
    };

    // Read headers before upgrade consumes req.
    // Epic 1.3 — User-Agent from CONNECT request headers
    let connect_ua: Option<String> = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(512).collect());

    let hostname_owned: String = host
        .rsplit_once(':')
        .and_then(|(h, p)| {
            p.parse::<u16>()
                .ok()
                .map(|_| h.trim_start_matches('[').trim_end_matches(']').to_string())
        })
        .unwrap_or_else(|| {
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .to_string()
        });
    let port = host
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(443);
    let category = classify(&hostname_owned, port, None);

    // Must be called before returning the response — registers the upgrade
    // channel on the live hyper connection while it's still owned by the caller.
    let upgrade_fut = hyper::upgrade::on(&mut req);

    let hostname = hostname_owned.as_str();

    if blocklist::is_blocked(hostname, &state).await {
        state.record_blocked();
        let approx_bytes = (50 + hostname.len()) as u64;
        let verdict_change = state.record_host_block(hostname, approx_bytes, category);
        let (attempts, blocked_bytes, freq_hz, verdict, iat_ms, streak, risk) = state
            .host_stats
            .get(hostname)
            .map(|s| {
                (
                    s.blocked_attempts,
                    s.blocked_bytes_approx,
                    s.frequency_hz(),
                    s.verdict(),
                    s.iat_ms,
                    s.consecutive_blocks,
                    (s.risk_score() * 100.0).round() / 100.0,
                )
            })
            .unwrap_or((1, approx_bytes, 0.0, "BLOCKED", None, 1, 0.0));
        // Epic 3.3 — verdict_change event
        if let Some((prev, next)) = verdict_change {
            let vc = serde_json::json!({
                "type": "verdict_change", "host": hostname,
                "prev_verdict": prev, "next_verdict": next,
                "attempt_count": attempts, "frequency_hz": (freq_hz * 100.0).round() / 100.0,
                "time": chrono::Utc::now().to_rfc3339(),
            });
            let _ = state.events_tx.send(vc.to_string());
        }
        // Epic 2.1 — async DNS resolution
        {
            let state2 = state.clone();
            let hostname2 = hostname.to_string();
            tokio::spawn(async move {
                const TTL_SECS: u64 = 300;
                if state2
                    .dns_cache
                    .get(&hostname2)
                    .map(|e| e.resolved_at.elapsed().as_secs() < TTL_SECS)
                    .unwrap_or(false)
                {
                    return;
                }
                if let Ok(Ok(addrs)) = tokio::time::timeout(
                    tokio::time::Duration::from_millis(500),
                    state2.resolver.lookup_ip(hostname2.as_str()),
                )
                .await
                {
                    if let Some(ip) = addrs.iter().next() {
                        let ip_str = ip.to_string();
                        state2.dns_cache.insert(
                            hostname2.clone(),
                            crate::state::ResolvedMeta {
                                ip: ip_str.clone(),
                                resolved_at: std::time::Instant::now(),
                            },
                        );
                        state2.record_resolved(&hostname2, ip_str, None);
                    }
                }
            });
        }
        info!(
            target: "audit",
            event = "tunnel_blocked",
            kind = "connect",
            host = %host,
            category = category,
            attempt_count = attempts,
            verdict = verdict,
            "blocked snitch"
        );
        let event = serde_json::json!({
            "type":     "block",
            "host":     hostname,
            "time":     chrono::Utc::now().to_rfc3339(),
            "category": category,
            "user_agent": connect_ua,
            "metrics": {
                "attempt_count":              attempts,
                "total_blocked_bytes_approx": blocked_bytes,
                "frequency_hz":               (freq_hz * 100.0).round() / 100.0,
                "risk_score":                 risk,
                "iat_ms":                     iat_ms,
                "consecutive_blocks":          streak,
            },
            "verdict": verdict,
        });
        let raw = event.to_string();
        let _ = state.events_tx.send(raw.clone());
        #[cfg(feature = "oracle-db")]
        crate::db::insert_proxy_event(
            state.db.clone(),
            crate::db::ProxyEvent {
                obfuscation_profile: None,
                event_type: "block".to_string(),
                host: hostname.to_string(),
                peer_ip: peer_ip.clone(),
                bytes_up: 0,
                bytes_down: 0,
                status_code: None,
                blocked: true,
                raw_json: raw,
            },
        );

        if verdict == "TARPIT" {
            // Acquire a permit; fall back to fast drop if at capacity.
            if let Ok(permit) = state.tarpit_sem.clone().try_acquire_owned() {
                let host_owned = hostname.to_string();
                tokio::spawn(async move {
                    run_tarpit(upgrade_fut, host_owned, state).await;
                    drop(permit);
                });
            } else {
                tokio::spawn(async move {
                    if let Ok(upgraded) = upgrade_fut.await {
                        drop(TokioIo::new(upgraded));
                    }
                });
            }
        } else {
            // Fast drop — iOS handles this as a natural close.
            tokio::spawn(async move {
                if let Ok(upgraded) = upgrade_fut.await {
                    drop(TokioIo::new(upgraded));
                }
            });
        }
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap());
    }

    // EPISODIC FIX: The Meta/Google Surgical Bypass - Certificate Pinning Domains
    let is_pinned_app = hostname.contains("facebook.com") 
                     || hostname.contains("instagram.com") 
                     || hostname.contains("googlevideo.com") 
                     || hostname.contains("apple.com")
                     || hostname.contains("youtube.com")
                     || hostname.contains("fbcdn.net")
                     || hostname.contains("instagramstatic.com");

    if is_pinned_app {
        let start = Instant::now();
        
        // 1. Return 200 OK immediately to establish the tunnel
        tokio::spawn(async move {
            let upgraded = match upgrade_fut.await {
                Ok(u) => u,
                Err(_) => return,
            };
            
            let mut client_io = TokioIo::new(upgraded);
            
            // 2. Raw TCP connection to upstream - NO MITM, NO OBFUSCATION
            let connect_target = state.config.tunnel_endpoint.clone()
                .unwrap_or_else(|| host.clone());
                
            if let Ok(mut upstream) = tokio::net::TcpStream::connect(&connect_target).await {
                set_keepalive(&upstream);
                
                let (bytes_up, bytes_down) = tokio::io::copy_bidirectional(&mut client_io, &mut upstream)
                    .await
                    .unwrap_or((0, 0));
                
                // Log completion with metrics
                info!(
                    target: "audit",
                    event="tunnel_close",
                    kind="bypass",
                    host=%host,
                    bytes_up=bytes_up,
                    bytes_down=bytes_down,
                    duration_ms = start.elapsed().as_millis(),
                );
            }
        });

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap());
    }

    // Classify obfuscation profile after blocklist check
    let profile = obfuscation::classify_obfuscation(hostname, &state.config);

    // Epic 3.4 — record allow for streak reset
    state.record_host_allow(hostname);

    tokio::spawn(async move {
        match upgrade_fut.await {
            Ok(upgraded) => run_tunnel(upgraded, host, state, category, peer_ip, profile).await,
            Err(e) => error!(%e, "CONNECT upgrade failed"),
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

async fn run_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    host: String,
    state: SharedState,
    category: &'static str,
    peer_ip: Option<String>,
    profile: crate::obfuscation::Profile,
) {
    let (name, port) = host
        .rsplit_once(':')
        .and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h, p)))
        .unwrap_or((&host, 443));
    let name = name.trim_start_matches('[').trim_end_matches(']');

    let connect = async {
        let addrs = state.resolver.lookup_ip(name).await?;
        let mut last_err =
            std::io::Error::new(std::io::ErrorKind::NotFound, "DoH returned no addresses");
        for ip in addrs.iter() {
            match tokio::net::TcpStream::connect((ip, port)).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    };

    match tokio::time::timeout(tokio::time::Duration::from_secs(10), connect).await {
        Ok(Ok(mut upstream)) => {
            let start = Instant::now();
            info!(
                target: "audit",
                event = "tunnel_open",
                kind = "connect",
                host = %host,
                category = category,
                "tunnel established"
            );

            // Emit obfuscated event if profile is not None
            if !matches!(profile, crate::obfuscation::Profile::None) {
                state.obfuscated_count.fetch_add(1, Ordering::Relaxed);
                info!(
                    target: "audit",
                    event = "tunnel_obfuscated",
                    kind = "connect",
                    host = %host,
                    profile = profile.as_str(),
                    category = category,
                    "connect tunnel obfuscated"
                );
            }

            emit_full(
                &state,
                "tunnel_open",
                &host,
                peer_ip.clone(),
                0,
                0,
                None,
                false,
                serde_json::json!({
                    "kind":             "connect",
                    "category":         category,
                    "obfuscation_profile": profile.as_str(),
                }),
            );
            state.record_tunnel_open();
            let mut client = TokioIo::new(upgraded);
            match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
                Ok((up, down)) => {
                    state.record_tunnel_close(up, down);
                    info!(
                        target: "audit",
                        event = "tunnel_close",
                        kind = "connect",
                        host = %host,
                        bytes_up = up,
                        bytes_down = down,
                        duration_ms = start.elapsed().as_millis(),
                        category = category,
                        "tunnel closed"
                    );
                    emit_full(
                        &state,
                        "tunnel_close",
                        &host,
                        peer_ip,
                        up,
                        down,
                        None,
                        false,
                        serde_json::json!({
                            "kind":        "connect",
                            "category":    category,
                            "bytes_up":    up,
                            "bytes_down":  down,
                            "duration_ms": start.elapsed().as_millis(),
                        }),
                    );
                }
                Err(e) => {
                    state.record_tunnel_close(0, 0);
                    debug!(%host, %e, "tunnel closed by peer");
                }
            }
        }
        Ok(Err(e)) => error!(%host, %e, "failed to connect to tunnel target"),
        Err(_) => error!(%host, "tunnel connect timed out"),
    }
}
