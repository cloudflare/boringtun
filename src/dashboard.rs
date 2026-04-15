use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use std::sync::atomic::Ordering;
use tokio::sync::broadcast;
use tracing::{error, info, trace, warn};

use crate::state::SharedState;

/// Serializable snapshot of one host's heuristic stats.
#[derive(Serialize)]
pub struct HostSnapshot {
    pub host: String,
    pub blocked_attempts: u64,
    pub blocked_bytes_approx: u64,
    pub frequency_hz: f64,
    pub risk_score: f64,
    pub verdict: &'static str,
    pub tarpit_held_ms: u64,
    pub battery_saved_mwh: f64,
    pub category: &'static str,
    pub consecutive_blocks: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suites_count: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3_lite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_org: Option<String>,
}

/// GET /health — liveness probe for the admin surface.
pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok").into_response()
}

/// GET /ready — readiness probe for optional dependencies such as Oracle.
pub async fn ready(State(_state): State<SharedState>) -> impl IntoResponse {
    #[cfg(feature = "oracle-db")]
    {
        let state = _state;
        if let crate::db::OracleStatus::Misconfigured(_) = &state.oracle_startup_status {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                state.oracle_startup_status.readiness_body(),
            )
                .into_response();
        }

        let status =
            crate::db::oracle_readiness(&state.config, tokio::time::Duration::from_secs(5)).await;
        let code = if matches!(status, crate::db::OracleStatus::Ready) {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        return (code, status.readiness_body()).into_response();
    }
    #[cfg(not(feature = "oracle-db"))]
    (StatusCode::OK, "ok").into_response()
}

/// Spawns a background task that flushes host_stats to Oracle every 60 seconds.
/// Compiled only when the `oracle-db` feature is enabled.
#[cfg(feature = "oracle-db")]
pub fn spawn_oracle_flusher(state: SharedState, token: tokio_util::sync::CancellationToken) {
    tokio::spawn(async move {
        let conn_str = state.config.oracle_conn.clone();
        let user = state.config.oracle_user.clone();
        let pass = match crate::db::oracle_connect_args(&state.config) {
            Ok(args) => args.pass,
            Err(_) => return,
        };
        loop {
            tokio::select! {
                _ = token.cancelled() => { info!("oracle flusher shutting down"); return; }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(60)) => {}
            }
            let rows: Vec<_> = state
                .host_stats
                .iter()
                .map(|e| {
                    (
                        e.key().clone(),
                        e.blocked_attempts,
                        e.blocked_bytes_approx,
                        (e.frequency_hz() * 100.0).round() / 100.0,
                        e.verdict(),
                        e.category,
                        (e.risk_score() * 100.0).round() / 100.0,
                        e.tarpit_held_ms,
                        e.iat_ms,
                        e.consecutive_blocks,
                        e.last_verdict,
                        e.tls_ver.clone(),
                        e.alpn.clone(),
                        e.ja3_lite.clone(),
                        e.resolved_ip.clone(),
                        e.asn_org.clone(),
                    )
                })
                .collect();
            if rows.is_empty() {
                continue;
            }
            let (cs, u, p) = (conn_str.clone(), user.clone(), pass.clone());
            let flush = tokio::task::spawn_blocking(move || {
                let conn = oracle::Connection::connect(&u, &p, &cs)?;
                // Bind order: :1 host :2 blocked_attempts :3 blocked_bytes :4 frequency_hz
                // :5 verdict :6 category :7 risk_score :8 tarpit_held_ms :9 iat_ms
                // :10 consecutive_blocks :11 last_verdict :12 tls_ver :13 alpn
                // :14 ja3_lite :15 resolved_ip :16 asn_org
                let sql = "MERGE INTO blocked_events t \
                           USING (SELECT :1 host, :2 blocked_attempts, :3 blocked_bytes, \
                                         :4 frequency_hz, :5 verdict, :6 category, \
                                         :7 risk_score, :8 tarpit_held_ms, :9 iat_ms, \
                                         :10 consecutive_blocks, :11 last_verdict, \
                                         :12 tls_ver, :13 alpn, :14 ja3_lite, \
                                         :15 resolved_ip, :16 asn_org FROM DUAL) s \
                           ON (t.host = s.host) \
                           WHEN MATCHED THEN UPDATE SET \
                               t.blocked_attempts  = s.blocked_attempts, \
                               t.blocked_bytes     = s.blocked_bytes, \
                               t.frequency_hz      = s.frequency_hz, \
                               t.verdict           = s.verdict, \
                               t.category          = s.category, \
                               t.risk_score        = s.risk_score, \
                               t.tarpit_held_ms    = s.tarpit_held_ms, \
                               t.iat_ms            = s.iat_ms, \
                               t.consecutive_blocks = s.consecutive_blocks, \
                               t.last_verdict      = s.last_verdict, \
                               t.tls_ver           = s.tls_ver, \
                               t.alpn              = s.alpn, \
                               t.ja3_lite          = s.ja3_lite, \
                               t.resolved_ip       = s.resolved_ip, \
                               t.asn_org           = s.asn_org, \
                               t.updated_at        = SYSTIMESTAMP \
                           WHEN NOT MATCHED THEN INSERT \
                               (host, blocked_attempts, blocked_bytes, frequency_hz, verdict, \
                                category, risk_score, tarpit_held_ms, iat_ms, consecutive_blocks, \
                                last_verdict, tls_ver, alpn, ja3_lite, resolved_ip, asn_org) \
                           VALUES (s.host, s.blocked_attempts, s.blocked_bytes, s.frequency_hz, \
                                   s.verdict, s.category, s.risk_score, s.tarpit_held_ms, \
                                   s.iat_ms, s.consecutive_blocks, s.last_verdict, \
                                   s.tls_ver, s.alpn, s.ja3_lite, s.resolved_ip, s.asn_org)";
                let mut stmt = conn.statement(sql).build()?;
                let mut flushed = 0usize;
                for (
                    host,
                    attempts,
                    bytes,
                    hz,
                    verdict,
                    cat,
                    risk,
                    tarpit,
                    iat,
                    streak,
                    lv,
                    tv,
                    alpn,
                    ja3,
                    ip,
                    asn,
                ) in &rows
                {
                    match stmt.execute(&[
                        host, attempts, bytes, hz, verdict, cat, risk, tarpit, iat, streak, lv, tv,
                        alpn, ja3, ip, asn,
                    ]) {
                        Ok(_) => flushed += 1,
                        Err(e) => tracing::warn!(host = %host, %e, "failed to flush row"),
                    }
                }
                conn.commit()?;
                Ok::<usize, oracle::Error>(flushed)
            });
            match tokio::time::timeout(tokio::time::Duration::from_secs(30), flush).await {
                Ok(Ok(Ok(n))) => info!(flushed = n, "oracle flush complete"),
                Ok(Ok(Err(e))) => error!(%e, "oracle flush failed"),
                _ => error!("oracle flush timed out or panicked"),
            }
        }
    });
}

fn to_snapshot(host: String, e: &crate::state::HostStats) -> HostSnapshot {
    HostSnapshot {
        host,
        blocked_attempts: e.blocked_attempts,
        blocked_bytes_approx: e.blocked_bytes_approx,
        frequency_hz: (e.frequency_hz() * 100.0).round() / 100.0,
        risk_score: e.risk_score().round(),
        verdict: e.verdict(),
        tarpit_held_ms: e.tarpit_held_ms,
        battery_saved_mwh: (e.battery_saved_approx() * 1_000_000.0).round() / 1_000_000.0,
        category: e.category,
        consecutive_blocks: e.consecutive_blocks,
        iat_ms: e.iat_ms,
        tls_ver: e.tls_ver.clone(),
        alpn: e.alpn.clone(),
        cipher_suites_count: e.cipher_suites_count,
        ja3_lite: e.ja3_lite.clone(),
        resolved_ip: e.resolved_ip.clone(),
        asn_org: e.asn_org.clone(),
    }
}

/// GET /hosts — returns a JSON array of all tracked hosts sorted by risk score.
pub async fn hosts_snapshot(State(state): State<SharedState>) -> Json<Vec<HostSnapshot>> {
    let mut rows: Vec<HostSnapshot> = state
        .host_stats
        .iter()
        .map(|e| to_snapshot(e.key().clone(), e.value()))
        .collect();
    rows.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Json(rows)
}

/// GET /hosts/{hostname} — single host detail or 404 (Epic 6.2).
pub async fn host_detail(
    State(state): State<SharedState>,
    Path(hostname): Path<String>,
) -> Result<Json<HostSnapshot>, StatusCode> {
    state
        .host_stats
        .get(&hostname)
        .map(|e| Json(to_snapshot(hostname.clone(), e.value())))
        .ok_or(StatusCode::NOT_FOUND)
}

/// GET /stats/summary — aggregate overview (Epic 6.4).
#[derive(Serialize)]
pub struct StatsSummary {
    total_hosts: usize,
    tarpit_count: usize,
    top_category: Option<String>,
    highest_risk_host: Option<String>,
}

pub async fn stats_summary(State(state): State<SharedState>) -> Json<StatsSummary> {
    let mut cat_counts: std::collections::HashMap<&'static str, usize> =
        std::collections::HashMap::new();
    let mut tarpit_count = 0usize;
    let mut highest_risk: Option<(String, f64)> = None;
    for e in state.host_stats.iter() {
        let v = e.verdict();
        if v == "TARPIT" {
            tarpit_count += 1;
        }
        *cat_counts.entry(e.category).or_insert(0) += 1;
        let rs = e.risk_score();
        if highest_risk.as_ref().map(|(_, r)| rs > *r).unwrap_or(true) {
            highest_risk = Some((e.key().clone(), rs));
        }
    }
    let top_category = cat_counts
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(k, _)| k.to_string());
    Json(StatsSummary {
        total_hosts: state.host_stats.len(),
        tarpit_count,
        top_category,
        highest_risk_host: highest_risk.map(|(h, _)| h),
    })
}

pub async fn ws_stats(
    ws: WebSocketUpgrade,
    State(state): State<SharedState>,
) -> impl axum::response::IntoResponse {
    info!("stats WebSocket client connecting");
    ws.on_upgrade(move |socket| stream(socket, state.stats_tx.subscribe()))
}

pub async fn ws_events(
    ws: WebSocketUpgrade,
    State(state): State<SharedState>,
) -> impl axum::response::IntoResponse {
    info!("events WebSocket client connecting");
    ws.on_upgrade(move |socket| stream(socket, state.events_tx.subscribe()))
}

async fn stream(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    info!("dashboard WebSocket client connected");
    loop {
        match rx.recv().await {
            Ok(msg) => {
                if socket.send(Message::Text(msg)).await.is_err() {
                    info!("dashboard WebSocket client disconnected");
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "WebSocket client lagged behind broadcast");
            }
            Err(broadcast::error::RecvError::Closed) => {
                error!("broadcast channel closed — poller task may have crashed");
                break;
            }
        }
    }
}

/// Spawns a task that broadcasts live stats to /ws every second.
pub fn spawn_stats_poller(state: SharedState, token: tokio_util::sync::CancellationToken) {
    tokio::spawn(async move {
        info!("stats poller started");
        let mut prev_up: u64 = 0;
        let mut prev_down: u64 = 0;
        let mut ticks: u64 = 0;
        loop {
            let bytes_up = state.bytes_up.load(Ordering::Relaxed);
            let bytes_down = state.bytes_down.load(Ordering::Relaxed);
            let up_kb_s = bytes_up.saturating_sub(prev_up) / 1024;
            let down_kb_s = bytes_down.saturating_sub(prev_down) / 1024;
            prev_up = bytes_up;
            prev_down = bytes_down;

            // Evict hosts silent for >10 minutes, checked once per minute.
            ticks += 1;
            if ticks % 60 == 0 {
                state.evict_stale_hosts(600);
            }

            let stats = serde_json::json!({
                "active_tunnels": state.active_tunnels.load(Ordering::Relaxed),
                "tunnels_opened": state.tunnels_opened.load(Ordering::Relaxed),
                "up_kBps":        up_kb_s,
                "down_kBps":      down_kb_s,
                "bytes_up":       bytes_up,
                "bytes_down":     bytes_down,
                "blocked":        state.blocked_count.load(Ordering::Relaxed),
                "obfuscated":     state.obfuscated_count.load(Ordering::Relaxed),
            });

            match state.stats_tx.send(stats.to_string()) {
                Ok(n) => trace!(subscribers = n, "stats broadcast sent"),
                Err(_) => trace!("stats broadcast: no active subscribers"),
            }
            tokio::select! {
                _ = token.cancelled() => { info!("stats poller shutting down"); return; }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {}
            }
        }
    });
}
