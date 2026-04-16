//! Explicit HTTP CONNECT tunnel flow.
//!
//! This module owns CONNECT handshake processing, block decisions, bypass
//! handling for certificate-pinned destinations, and the steady-state tunnel
//! copy loop. It does not handle transparent-proxy sockets.

use std::sync::atomic::Ordering;
use std::time::Instant;

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
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
use super::dial::{dial_upstream_with_resolver, parse_host_port};
use super::tarpit::run_tarpit;

/// Handle an explicit HTTP CONNECT request.
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
                .expect("CONNECT bad request response must build"));
        }
    };

    let connect_ua: Option<String> = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(512).collect());

    let (hostname_owned, port) = parse_host_port(&host);
    let category = classify(&hostname_owned, port, None);

    let upgrade_fut = hyper::upgrade::on(&mut req);
    let hostname = hostname_owned.as_str();

    if blocklist::is_blocked(hostname, &state).await {
        #[derive(Serialize)]
        struct ConnectBlockMetrics {
            attempt_count: u64,
            total_blocked_bytes_approx: u64,
            frequency_hz: f64,
            risk_score: f64,
            iat_ms: Option<u64>,
            consecutive_blocks: u32,
        }

        #[derive(Serialize)]
        struct ConnectBlockExtra {
            category: &'static str,
            user_agent: Option<String>,
            metrics: ConnectBlockMetrics,
            verdict: &'static str,
        }

        #[cfg(feature = "oracle-db")]
        let blocked_session_id = uuid::Uuid::new_v4().to_string();
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
        if let Some((prev, next)) = verdict_change {
            let vc = serde_json::json!({
                "type": "verdict_change", "host": hostname,
                "prev_verdict": prev, "next_verdict": next,
                "attempt_count": attempts, "frequency_hz": (freq_hz * 100.0).round() / 100.0,
                "time": chrono::Utc::now().to_rfc3339(),
            });
            let _ = state.events_tx.send(vc.to_string());
        }
        {
            let state2 = state.clone();
            let hostname2 = hostname.to_string();
            if state2.config.proxy.enable_dns_lookups {
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
                                    resolved_at: std::time::Instant::now(),
                                },
                            );
                            state2.record_resolved(&hostname2, ip_str, None);
                        }
                    }
                });
            }
        }
        info!(
            target: "audit",
            event = "tunnel_blocked",
            kind = "connect",
            host = %host,
            category,
            attempt_count = attempts,
            verdict,
            "blocked snitch"
        );
        events::emit_serializable(
            &state,
            "block",
            hostname,
            peer_ip.clone(),
            0,
            0,
            None,
            true,
            None,
            ConnectBlockExtra {
                category,
                user_agent: connect_ua.clone(),
                metrics: ConnectBlockMetrics {
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
            db_session_open(
                &state,
                &blocked_session_id,
                hostname,
                peer_ip.clone(),
                "connect",
                true,
                verdict == "TARPIT",
                Some(verdict.to_string()),
                Some(category.to_string()),
                None,
                None,
                None,
                None,
                None,
                None,
            );
        }

        if verdict == "TARPIT" {
            if let Ok(permit) = state.tarpit_sem.clone().try_acquire_owned() {
                let host_owned = hostname.to_string();
                let state_clone = state.clone();
                #[cfg(feature = "oracle-db")]
                let blocked_session_id = blocked_session_id.clone();
                tokio::spawn(async move {
                    #[cfg(feature = "oracle-db")]
                    let held_ms = run_tarpit(upgrade_fut, host_owned, state_clone.clone()).await;
                    #[cfg(not(feature = "oracle-db"))]
                    run_tarpit(upgrade_fut, host_owned, state_clone.clone()).await;
                    drop(permit);
                    #[cfg(feature = "oracle-db")]
                    {
                        let held_ms = held_ms.map(|value| value as i64);
                        db_session_close(
                            &state_clone,
                            &blocked_session_id,
                            Some(held_ms.unwrap_or(0)),
                            0,
                            0,
                            true,
                            held_ms.is_some(),
                            held_ms,
                            Some(verdict.to_string()),
                            Some(category.to_string()),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        );
                    }
                });
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
                    None,
                    None,
                    None,
                    None,
                    None,
                );
                tokio::spawn(async move {
                    if let Ok(upgraded) = upgrade_fut.await {
                        drop(TokioIo::new(upgraded));
                    }
                });
            }

            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "text/plain; charset=utf-8")
                .body(Body::from("Access denied"))
                .expect("CONNECT tarpit denial response must build"));
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
            None,
            None,
            None,
            None,
            None,
        );
        tokio::spawn(async move {
            if let Ok(upgraded) = upgrade_fut.await {
                let mut stream = TokioIo::new(upgraded);
                let _ = tokio::time::timeout(
                    tokio::time::Duration::from_millis(200),
                    tokio::io::copy(&mut stream, &mut tokio::io::sink()),
                )
                .await;
            }
        });

        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(Body::from("Access denied"))
            .expect("CONNECT denial response must build"));
    }

    let is_pinned_app = is_cert_pinned_host(hostname);

    if is_pinned_app {
        let start = Instant::now();
        info!(
            target: "audit",
            event = "tunnel_bypass",
            kind = "connect",
            host = %host,
            category,
            reason = "certificate_pinning",
            "certificate-pinned domain bypass enabled"
        );

        tokio::spawn(async move {
            let upgraded = match upgrade_fut.await {
                Ok(u) => u,
                Err(_) => return,
            };

            let mut client_io = TokioIo::new(upgraded);

            match dial_upstream_with_resolver(&state, &host).await {
                Ok((mut upstream, resolved_ips, selected_ip)) => {
                    #[cfg(feature = "oracle-db")]
                    let session_id = uuid::Uuid::new_v4().to_string();
                    set_keepalive(&upstream);
                    state.record_tunnel_open();
                    info!(
                        target: "audit",
                        event = "tunnel_open",
                        kind = "bypass",
                        host = %host,
                        category,
                        resolved_ips = ?resolved_ips,
                        selected_ip = %selected_ip,
                        obfuscation_profile = "none",
                        reason = "certificate_pinning",
                        "bypass tunnel established"
                    );
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
                            obfuscation_profile: Some("none".to_string()),
                            extra: serde_json::json!({
                                "kind":                "bypass",
                                "category":            category,
                                "resolved_ips":        resolved_ips,
                                "selected_ip":         selected_ip,
                                "obfuscation_profile": "none",
                                "bypass_reason":       "certificate_pinning",
                            }),
                        },
                    );
                    #[cfg(feature = "oracle-db")]
                    db_session_open(
                        &state,
                        &session_id,
                        &host,
                        peer_ip.clone(),
                        "bypass",
                        false,
                        false,
                        Some("ALLOWED".to_string()),
                        Some(category.to_string()),
                        Some("none".to_string()),
                        None,
                        None,
                        None,
                        Some(selected_ip.clone()),
                        None,
                    );

                    let (bytes_up, bytes_down) =
                        tokio::io::copy_bidirectional(&mut client_io, &mut upstream)
                            .await
                            .unwrap_or((0, 0));
                    state.record_tunnel_close(bytes_up, bytes_down);

                    info!(
                        target: "audit",
                        event = "tunnel_close",
                        kind = "bypass",
                        host = %host,
                        bytes_up,
                        bytes_down,
                        duration_ms = start.elapsed().as_millis(),
                        category,
                        obfuscation_profile = "none",
                        reason = "certificate_pinning",
                        "bypass tunnel closed"
                    );
                    events::emit(
                        &state,
                        "tunnel_close",
                        &host,
                        EmitPayload {
                            peer_ip,
                            bytes_up,
                            bytes_down,
                            status_code: None,
                            blocked: false,
                            obfuscation_profile: Some("none".to_string()),
                            extra: serde_json::json!({
                                "kind":                "bypass",
                                "category":            category,
                                "bytes_up":            bytes_up,
                                "bytes_down":          bytes_down,
                                "duration_ms":         start.elapsed().as_millis(),
                                "selected_ip":         selected_ip,
                                "obfuscation_profile": "none",
                                "bypass_reason":       "certificate_pinning",
                            }),
                        },
                    );
                    #[cfg(feature = "oracle-db")]
                    db_session_close(
                        &state,
                        &session_id,
                        Some(start.elapsed().as_millis() as i64),
                        bytes_up,
                        bytes_down,
                        false,
                        false,
                        None,
                        Some("ALLOWED".to_string()),
                        Some(category.to_string()),
                        Some("none".to_string()),
                        None,
                        None,
                        None,
                        Some(selected_ip),
                        None,
                    );
                }
                Err(e) => {
                    error!(
                        %host,
                        failure_class = e.class(),
                        error = %e.detail(),
                        "bypass tunnel connect failed"
                    );
                    let _ = client_io.shutdown().await;
                }
            }
        });

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .expect("CONNECT bypass response must build"));
    }

    let profile = obfuscation::classify_obfuscation(hostname, &state.config.obfuscation);
    state.record_host_allow(hostname);

    tokio::spawn(async move {
        match upgrade_fut.await {
            Ok(upgraded) => {
                let stream = TokioIo::new(upgraded);
                run_tunnel(stream.into_inner(), host, state, category, peer_ip, profile).await;
            }
            Err(e) => {
                let error_kind = if e.is_canceled() {
                    "client_disconnected"
                } else {
                    "unknown"
                };

                error!(
                    %host,
                    peer_ip = %peer_ip.as_deref().unwrap_or("-"),
                    user_agent = %connect_ua.as_deref().unwrap_or("-"),
                    %category,
                    error_kind,
                    %e,
                    "CONNECT upgrade failed"
                );
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .expect("CONNECT success response must build"))
}

/// Run a CONNECT tunnel after the upgrade succeeds.
pub(crate) async fn run_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    host: String,
    state: SharedState,
    category: &'static str,
    peer_ip: Option<String>,
    profile: crate::obfuscation::Profile,
) {
    let mut client = TokioIo::new(upgraded);
    match dial_upstream_with_resolver(&state, &host).await {
        Ok((mut upstream, resolved_ips, selected_ip)) => {
            let start = Instant::now();
            #[cfg(feature = "oracle-db")]
            let session_id = uuid::Uuid::new_v4().to_string();
            info!(
                target: "audit",
                event = "tunnel_open",
                kind = "connect",
                host = %host,
                category,
                resolved_ips = ?resolved_ips,
                selected_ip = %selected_ip,
                "tunnel established"
            );

            if !matches!(profile, crate::obfuscation::Profile::None) {
                state.obfuscated_count.fetch_add(1, Ordering::Relaxed);
                info!(
                    target: "audit",
                    event = "tunnel_obfuscated",
                    kind = "connect",
                    host = %host,
                    profile = profile.as_str(),
                    category,
                    "connect tunnel obfuscated"
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
                        "kind":             "connect",
                        "category":         category,
                        "resolved_ips":     resolved_ips,
                        "selected_ip":      selected_ip,
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
                "connect",
                false,
                false,
                Some("ALLOWED".to_string()),
                Some(category.to_string()),
                if matches!(profile, crate::obfuscation::Profile::None) {
                    None
                } else {
                    Some(profile.as_str().to_string())
                },
                None,
                None,
                None,
                Some(selected_ip.clone()),
                None,
            );
            state.record_tunnel_open();
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
                        category,
                        "tunnel closed"
                    );
                    events::emit(
                        &state,
                        "tunnel_close",
                        &host,
                        EmitPayload {
                            peer_ip,
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
                                "kind":        "connect",
                                "category":    category,
                                "bytes_up":    up,
                                "bytes_down":  down,
                                "duration_ms": start.elapsed().as_millis(),
                            }),
                        },
                    );
                    #[cfg(feature = "oracle-db")]
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
                        None,
                        None,
                        None,
                        Some(selected_ip.clone()),
                        None,
                    );
                }
                Err(e) => {
                    state.record_tunnel_close(0, 0);
                    debug!(%host, %e, "tunnel closed by peer");
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
                        None,
                        None,
                        None,
                        Some(selected_ip),
                        None,
                    );
                }
            }
        }
        Err(e) => {
            error!(
                %host,
                failure_class = e.class(),
                error = %e.detail(),
                "failed to connect to tunnel target"
            );
            let _ = client.shutdown().await;
        }
    }
}

fn set_keepalive(stream: &tokio::net::TcpStream) {
    use std::time::Duration;

    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(5));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
}
