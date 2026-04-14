#![cfg(feature = "oracle-db")]

/// Oracle DB integration — compiled only with `--features oracle-db`.
///
/// All proxy_events inserts are serialised through a single background writer
/// task (one persistent connection, one blocking thread).  The hot path just
/// sends to an mpsc channel and returns immediately — no pool, no contention.
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

const CHANNEL_CAP: usize = 4_096;

pub struct ProxyEvent {
    pub event_type: String,
    pub host: String,
    pub peer_ip: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub status_code: Option<u16>,
    pub blocked: bool,
    pub obfuscation_profile: Option<String>,
    pub raw_json: String,
}

/// Cheap sender handle cloned into every request handler.
#[derive(Clone)]
pub struct EventSender(mpsc::Sender<ProxyEvent>);

impl EventSender {
    /// Non-blocking enqueue.  Drops the event and logs a warning if the
    /// channel is full — the hot path must never block.
    pub fn send(&self, ev: ProxyEvent) {
        if let Err(e) = self.0.try_send(ev) {
            warn!(
                host = e.into_inner().host,
                "db: event channel full, dropping row"
            );
        }
    }
}

/// Spawn the single writer task.  Returns the sender handle to store in AppState.
/// The task reconnects automatically on error with a 2-second back-off.
pub fn spawn_writer(
    conn_str: String,
    user: String,
    pass: String,
    token: tokio_util::sync::CancellationToken,
) -> EventSender {
    let (tx, mut rx) = mpsc::channel::<ProxyEvent>(CHANNEL_CAP);

    tokio::spawn(async move {
        loop {
            // ── connect (blocking) ──────────────────────────────────────────
            let (cs, u, p) = (conn_str.clone(), user.clone(), pass.clone());
            let conn_result =
                tokio::task::spawn_blocking(move || oracle::Connection::connect(&u, &p, &cs)).await;

            let conn = match conn_result {
                Ok(Ok(c)) => {
                    info!("db: writer connected");
                    c
                }
                Ok(Err(e)) => {
                    error!(%e, "db: connect failed, retrying in 2s");
                    tokio::select! {
                        _ = token.cancelled() => return,
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {}
                    }
                    continue;
                }
                Err(e) => {
                    error!(%e, "db: spawn_blocking panicked on connect");
                    tokio::select! {
                        _ = token.cancelled() => return,
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {}
                    }
                    continue;
                }
            };

            // ── drain loop (blocking thread owns the connection) ────────────
            // Collect a batch of up to 64 events, then hand them to a blocking
            // task.  The blocking task returns the connection when done so we
            // can reuse it for the next batch.
            let mut conn = conn;
            loop {
                // Wait for at least one event (or shutdown).
                let first = tokio::select! {
                    _ = token.cancelled() => {
                        info!("db: writer shutting down");
                        return;
                    }
                    msg = rx.recv() => match msg {
                        Some(ev) => ev,
                        None     => return, // sender side dropped
                    }
                };

                // Drain up to 63 more without blocking.
                let mut batch = vec![first];
                while batch.len() < 64 {
                    match rx.try_recv() {
                        Ok(ev) => batch.push(ev),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(_) => return,
                    }
                }

                let batch_size = batch.len();
                let result = tokio::task::spawn_blocking(move || {
                    insert_batch(&conn, &batch)?;
                    Ok::<oracle::Connection, oracle::Error>(conn)
                })
                .await;

                match result {
                    Ok(Ok(c)) => conn = c,
                    Ok(Err(e)) => {
                        error!(%e, batch_size, "db: batch insert failed, reconnecting");
                        tokio::select! {
                            _ = token.cancelled() => return,
                            _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {}
                        }
                        break;
                    }
                    Err(e) => {
                        error!(%e, batch_size, "db: spawn_blocking panicked on insert");
                        tokio::select! {
                            _ = token.cancelled() => return,
                            _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {}
                        }
                        break;
                    }
                }
            }
        }
    });

    EventSender(tx)
}

fn insert_batch(conn: &oracle::Connection, batch: &[ProxyEvent]) -> Result<(), oracle::Error> {
    let sql = "INSERT INTO proxy_events \
               (event_type, host, peer_ip, bytes_up, bytes_down, status_code, blocked, obfuscation_profile, raw_json) \
               VALUES (:1, :2, :3, :4, :5, :6, :7, :8, :9)";
    let mut stmt = conn.statement(sql).build()?;
    for ev in batch {
        let blocked_i: i32 = if ev.blocked { 1 } else { 0 };
        stmt.execute(&[
            &ev.event_type,
            &ev.host,
            &ev.peer_ip,
            &ev.bytes_up,
            &ev.bytes_down,
            &ev.status_code,
            &blocked_i,
            &ev.obfuscation_profile,
            &ev.raw_json,
        ])?;
    }
    conn.commit()
}

/// Convenience wrapper kept for call-site compatibility.
/// Callers that previously held an `Arc<Pool>` now hold an `Arc<EventSender>`.
pub fn insert_proxy_event(sender: Arc<EventSender>, ev: ProxyEvent) {
    sender.send(ev);
}
