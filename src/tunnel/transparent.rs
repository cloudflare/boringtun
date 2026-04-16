//! Transparent proxy tunnel flow.
//!
//! This module handles raw TCP connections redirected by iptables, extracting
//! the original destination, optional TLS metadata, and then either blocking,
//! bypassing, or proxying the connection. It does not own CONNECT handling.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Instant;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info};

use crate::{
    blocklist,
    events::{self, EmitPayload},
    obfuscation,
    state::SharedState,
};

use super::classify::{classify, is_cert_pinned_host};
#[cfg(feature = "oracle-db")]
use super::db_helpers::{db_session_close, db_session_open};
use super::tarpit::MAX_TARPIT_MS;
use super::tls::{peek_tls_info, TlsInfo};

/// Handle one transparent-proxy TCP stream.
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
            #[derive(Serialize)]
            struct TransparentFingerprint {
                tls_ver: Option<String>,
                alpn: Option<String>,
                cipher_suites_count: Option<u8>,
                ja3_lite: Option<String>,
            }

            #[derive(Serialize)]
            struct TransparentMetrics {
                attempt_count: u64,
                total_blocked_bytes_approx: u64,
                frequency_hz: f64,
                risk_score: f64,
                iat_ms: Option<u64>,
                consecutive_blocks: u32,
            }

            #[derive(Serialize)]
            struct TransparentBlockExtra {
                category: &'static str,
                fingerprint: TransparentFingerprint,
                metrics: TransparentMetrics,
                verdict: &'static str,
            }

            #[cfg(feature = "oracle-db")]
            let blocked_session_id = uuid::Uuid::new_v4().to_string();
            state.record_blocked();
            let approx_bytes = (50 + name.len()) as u64;
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
            if let Some((prev, next)) = verdict_change {
                let vc = serde_json::json!({
                    "type": "verdict_change", "host": name,
                    "prev_verdict": prev, "next_verdict": next,
                    "attempt_count": attempts, "frequency_hz": (freq_hz * 100.0).round() / 100.0,
                    "time": chrono::Utc::now().to_rfc3339(),
                });
                let _ = state.events_tx.send(vc.to_string());
            }
            {
                let state2 = state.clone();
                let name2 = name.clone();
                if state2.config.proxy.enable_dns_lookups {
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
                                        resolved_at: Instant::now(),
                                    },
                                );
                                state2.record_resolved(&name2, ip_str, None);
                            }
                        }
                    });
                }
            }
            info!(
                target: "audit",
                event = "tunnel_blocked",
                kind = "transparent",
                host = %name,
                orig_dst = %orig_dst,
                category,
                attempt_count = attempts,
                verdict,
                "blocked snitch (transparent)"
            );
            events::emit_serializable(
                &state,
                "block",
                name,
                peer_ip.clone(),
                0,
                0,
                None,
                true,
                None,
                TransparentBlockExtra {
                    category,
                    fingerprint: TransparentFingerprint {
                        tls_ver: tls.tls_ver.clone(),
                        alpn: tls.alpn.clone(),
                        cipher_suites_count: tls.cipher_suites_count,
                        ja3_lite: tls.ja3_lite.clone(),
                    },
                    metrics: TransparentMetrics {
                        attempt_count: attempts,
                        total_blocked_bytes_approx: blocked_bytes,
                        frequency_hz: (freq_hz * 100.0).round() / 100.0,
                        risk_score: risk,
                        iat_ms,
                        consecutive_blocks: streak,
                    },
                    verdict,
                },
            );
            #[cfg(feature = "oracle-db")]
            {
                if let Some(ref ja3) = tls.ja3_lite {
                    crate::db::upsert_tls_fingerprint_event(
                        state.db.clone(),
                        crate::db::TlsFingerprintEvent {
                            ja3_lite: ja3.clone(),
                            tls_ver: tls.tls_ver.clone(),
                            alpn: tls.alpn.clone(),
                            cipher_count: tls.cipher_suites_count.map(i32::from),
                            verdict_hint: Some(verdict.to_string()),
                        },
                    );
                }
                db_session_open(
                    &state,
                    &blocked_session_id,
                    name,
                    peer_ip.clone(),
                    "transparent",
                    true,
                    verdict == "TARPIT",
                    Some(verdict.to_string()),
                    Some(category.to_string()),
                    None,
                    tls.tls_ver.clone(),
                    tls.alpn.clone(),
                    tls.ja3_lite.clone(),
                    None,
                    None,
                );
            }
            if verdict == "TARPIT" {
                if let Ok(_permit) = state.tarpit_sem.clone().try_acquire_owned() {
                    let tarpit_start = Instant::now();
                    let _ = tokio::time::timeout(
                        tokio::time::Duration::from_millis(MAX_TARPIT_MS),
                        tokio::io::copy(&mut stream, &mut tokio::io::sink()),
                    )
                    .await;
                    let held_ms = tarpit_start.elapsed().as_millis() as u64;
                    state.record_tarpit_held(name, held_ms);
                    #[cfg(feature = "oracle-db")]
                    db_session_close(
                        &state,
                        &blocked_session_id,
                        Some(held_ms as i64),
                        0,
                        0,
                        true,
                        true,
                        Some(held_ms as i64),
                        Some(verdict.to_string()),
                        Some(category.to_string()),
                        None,
                        tls.tls_ver.clone(),
                        tls.alpn.clone(),
                        tls.ja3_lite.clone(),
                        None,
                        None,
                    );
                } else {
                    #[cfg(feature = "oracle-db")]
                    db_session_close(
                        &state,
                        &blocked_session_id,
                        Some(0),
                        0,
                        0,
                        true,
                        false,
                        None,
                        Some(verdict.to_string()),
                        Some(category.to_string()),
                        None,
                        tls.tls_ver.clone(),
                        tls.alpn.clone(),
                        tls.ja3_lite.clone(),
                        None,
                        None,
                    );
                }
                return;
            }
            #[cfg(feature = "oracle-db")]
            db_session_close(
                &state,
                &blocked_session_id,
                Some(0),
                0,
                0,
                true,
                false,
                None,
                Some(verdict.to_string()),
                Some(category.to_string()),
                None,
                tls.tls_ver.clone(),
                tls.alpn.clone(),
                tls.ja3_lite.clone(),
                None,
                None,
            );
        }
    }

    #[cfg(feature = "oracle-db")]
    if let Some(ref ja3) = tls.ja3_lite {
        crate::db::upsert_tls_fingerprint_event(
            state.db.clone(),
            crate::db::TlsFingerprintEvent {
                ja3_lite: ja3.clone(),
                tls_ver: tls.tls_ver.clone(),
                alpn: tls.alpn.clone(),
                cipher_count: tls.cipher_suites_count.map(i32::from),
                verdict_hint: Some("ALLOWED".to_string()),
            },
        );
    }

    if let Some(ref name) = hostname {
        if is_cert_pinned_host(name) {
            info!(
                target: "audit",
                event = "tunnel_bypass",
                host = %name,
                "Certificate pinned domain detected, bypassing interception"
            );

            if let Ok(Ok(mut upstream)) = tokio::time::timeout(
                tokio::time::Duration::from_secs(10),
                tokio::net::TcpStream::connect(orig_dst),
            )
            .await
            {
                set_keepalive(&upstream);
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
            }
            return;
        }
    }

    let profile = if let Some(ref name) = hostname {
        obfuscation::classify_obfuscation(name, &state.config.obfuscation)
    } else {
        obfuscation::Profile::None
    };

    if let Some(ref name) = hostname {
        state.record_host_allow(name);
    }
    run_transparent(
        stream, orig_dst, host, state, category, tls, peer_ip, profile,
    )
    .await;
}

/// Retrieve the original destination address from `SO_ORIGINAL_DST`.
pub(crate) fn original_dst(stream: &tokio::net::TcpStream) -> std::io::Result<SocketAddr> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let v6: Result<SocketAddr, _> = unsafe {
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let ret = libc::getsockopt(
            fd,
            41,
            80,
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

    let addr: libc::sockaddr_in = unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let ret = libc::getsockopt(
            fd,
            0,
            80,
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

/// Proxy the transparent stream to its original destination.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_transparent(
    client: tokio::net::TcpStream,
    orig_dst: SocketAddr,
    host: String,
    state: SharedState,
    category: &'static str,
    tls: TlsInfo,
    peer_ip: Option<String>,
    profile: crate::obfuscation::Profile,
) {
    set_keepalive(&client);

    match tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(orig_dst),
    )
    .await
    {
        Ok(Ok(upstream)) => {
            let start = Instant::now();
            #[cfg(feature = "oracle-db")]
            let session_id = uuid::Uuid::new_v4().to_string();
            info!(
                target: "audit",
                event = "tunnel_open",
                kind = "transparent",
                host = %host,
                category,
                "transparent tunnel established"
            );
            if !matches!(profile, crate::obfuscation::Profile::None) {
                state.obfuscated_count.fetch_add(1, Ordering::Relaxed);
                info!(
                    target: "audit",
                    event = "tunnel_obfuscated",
                    kind = "transparent",
                    host = %host,
                    profile = profile.as_str(),
                    category,
                    "transparent tunnel obfuscated"
                );
            }

            events::emit(
                &state,
                "tunnel_open",
                &host,
                EmitPayload {
                    peer_ip: peer_ip.clone(),
                    bytes_up: 0,
                    bytes_down: 0,
                    status_code: None,
                    blocked: false,
                    obfuscation_profile: if matches!(profile, crate::obfuscation::Profile::None) {
                        None
                    } else {
                        Some(profile.as_str().to_string())
                    },
                    extra: serde_json::json!({
                        "kind":             "transparent",
                        "category":         category,
                        "alpn":             tls.alpn,
                        "tls_ver":          tls.tls_ver,
                        "obfuscation_profile": profile.as_str(),
                    }),
                },
            );
            #[cfg(feature = "oracle-db")]
            db_session_open(
                &state,
                &session_id,
                &host,
                peer_ip.clone(),
                "transparent",
                false,
                false,
                Some("ALLOWED".to_string()),
                Some(category.to_string()),
                if matches!(profile, crate::obfuscation::Profile::None) {
                    None
                } else {
                    Some(profile.as_str().to_string())
                },
                tls.tls_ver.clone(),
                tls.alpn.clone(),
                tls.ja3_lite.clone(),
                None,
                None,
            );
            state.record_tunnel_open();

            const PAYLOAD_PREVIEW_LIMIT: usize = 4096;

            let (mut client_read, mut client_write) = tokio::io::split(client);
            let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

            let mut up_buf = Vec::with_capacity(PAYLOAD_PREVIEW_LIMIT);
            let mut down_buf = Vec::with_capacity(PAYLOAD_PREVIEW_LIMIT);

            let up_task = async {
                let mut buf = [0u8; 8192];
                let mut total = 0u64;
                loop {
                    let n = client_read.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    upstream_write.write_all(&buf[..n]).await?;
                    total += n as u64;

                    if up_buf.len() < PAYLOAD_PREVIEW_LIMIT {
                        let take = (PAYLOAD_PREVIEW_LIMIT - up_buf.len()).min(n);
                        up_buf.extend_from_slice(&buf[..take]);
                    }
                }
                Ok::<u64, std::io::Error>(total)
            };

            let down_task = async {
                let mut buf = [0u8; 8192];
                let mut total = 0u64;
                loop {
                    let n = upstream_read.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    client_write.write_all(&buf[..n]).await?;
                    total += n as u64;

                    if down_buf.len() < PAYLOAD_PREVIEW_LIMIT {
                        let take = (PAYLOAD_PREVIEW_LIMIT - down_buf.len()).min(n);
                        down_buf.extend_from_slice(&buf[..take]);
                    }
                }
                Ok::<u64, std::io::Error>(total)
            };

            match tokio::try_join!(up_task, down_task) {
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
                        category,
                        "transparent tunnel closed"
                    );

                    let payload_preview = serde_json::json!({
                        "up": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &up_buf),
                        "down": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &down_buf),
                        "truncated_up": up > PAYLOAD_PREVIEW_LIMIT as u64,
                        "truncated_down": down > PAYLOAD_PREVIEW_LIMIT as u64,
                    });

                    events::emit(
                        &state,
                        "tunnel_close",
                        &host,
                        EmitPayload {
                            peer_ip: peer_ip.clone(),
                            bytes_up: up,
                            bytes_down: down,
                            status_code: None,
                            blocked: false,
                            obfuscation_profile: if matches!(
                                profile,
                                crate::obfuscation::Profile::None
                            ) {
                                None
                            } else {
                                Some(profile.as_str().to_string())
                            },
                            extra: serde_json::json!({
                                "kind":        "transparent",
                                "category":    category,
                                "bytes_up":    up,
                                "bytes_down":  down,
                                "duration_ms": start.elapsed().as_millis(),
                                "payload_preview": payload_preview,
                            }),
                        },
                    );
                    #[cfg(feature = "oracle-db")]
                    {
                        db_session_close(
                            &state,
                            &session_id,
                            Some(start.elapsed().as_millis() as i64),
                            up,
                            down,
                            false,
                            false,
                            None,
                            Some("ALLOWED".to_string()),
                            Some(category.to_string()),
                            if matches!(profile, crate::obfuscation::Profile::None) {
                                None
                            } else {
                                Some(profile.as_str().to_string())
                            },
                            tls.tls_ver.clone(),
                            tls.alpn.clone(),
                            tls.ja3_lite.clone(),
                            None,
                            None,
                        );
                        let up_b64 = base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &up_buf,
                        );
                        crate::db::insert_payload_audit_event(
                            state.db.clone(),
                            crate::db::PayloadAuditEvent {
                                correlation_id: session_id.clone(),
                                host: host.clone(),
                                direction: "UP".to_string(),
                                byte_offset: 0,
                                payload_bytes: up_buf.clone(),
                                payload_b64: Some(up_b64),
                                content_type: None,
                                http_method: None,
                                http_status: None,
                                http_path: None,
                                is_encrypted: true,
                                truncated: up > PAYLOAD_PREVIEW_LIMIT as u64,
                                peer_ip: peer_ip.clone(),
                                notes: Some("transparent tunnel preview".to_string()),
                            },
                        );
                        let down_b64 = base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &down_buf,
                        );
                        crate::db::insert_payload_audit_event(
                            state.db.clone(),
                            crate::db::PayloadAuditEvent {
                                correlation_id: session_id.clone(),
                                host: host.clone(),
                                direction: "DOWN".to_string(),
                                byte_offset: 0,
                                payload_bytes: down_buf.clone(),
                                payload_b64: Some(down_b64),
                                content_type: None,
                                http_method: None,
                                http_status: None,
                                http_path: None,
                                is_encrypted: true,
                                truncated: down > PAYLOAD_PREVIEW_LIMIT as u64,
                                peer_ip: peer_ip.clone(),
                                notes: Some("transparent tunnel preview".to_string()),
                            },
                        );
                    }
                }
                Err(e) => {
                    state.record_tunnel_close(0, 0);
                    debug!(%host, %e, "transparent tunnel closed by peer");
                    #[cfg(feature = "oracle-db")]
                    db_session_close(
                        &state,
                        &session_id,
                        Some(start.elapsed().as_millis() as i64),
                        0,
                        0,
                        false,
                        false,
                        None,
                        Some("ALLOWED".to_string()),
                        Some(category.to_string()),
                        if matches!(profile, crate::obfuscation::Profile::None) {
                            None
                        } else {
                            Some(profile.as_str().to_string())
                        },
                        tls.tls_ver.clone(),
                        tls.alpn.clone(),
                        tls.ja3_lite.clone(),
                        None,
                        None,
                    );
                }
            }
        }
        Ok(Err(e)) => error!(%host, %e, "transparent tunnel connect failed"),
        Err(_) => error!(%host, "transparent tunnel connect timed out"),
    }
}

fn set_keepalive(stream: &tokio::net::TcpStream) {
    use std::time::Duration;

    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(5));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
}
