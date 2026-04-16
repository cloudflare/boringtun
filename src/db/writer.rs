//! Oracle writer task and queue-facing helper APIs.
//!
//! This module owns the single writer task, batching logic, reconnect policy,
//! and the cheap sender handle cloned into request handlers. It does not own
//! configuration parsing or SQL statement text.

use std::{sync::Arc, time::Duration};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use super::audit::insert_blocklist_audit_with_fallback;
use super::inserts::{
    insert_connection_session_open_with_fallback, insert_payload_audit_with_fallback,
    insert_proxy_events_with_fallback, update_connection_session_close_with_fallback,
    upsert_tls_fingerprints_with_fallback,
};
use super::types::{
    ConnectionSessionCloseEvent, ConnectionSessionOpenEvent, DbEvent, PayloadAuditEvent,
    ProxyEvent, TlsFingerprintEvent,
};
use super::CHANNEL_CAP;

/// Hold one failed row retry result for DLQ logging.
#[derive(Debug)]
pub(super) struct ProcessingError {
    pub(super) table: &'static str,
    pub(super) row_index: usize,
    pub(super) error: String,
}

const MAX_BATCH_RETRIES: u8 = 5;

#[derive(Clone)]
struct PendingBatch {
    events: Vec<DbEvent>,
    retry_count: u8,
    last_error: String,
}

impl PendingBatch {
    fn new(events: Vec<DbEvent>) -> Self {
        Self {
            events,
            retry_count: 0,
            last_error: String::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BatchDlqEntry {
    event_kind: &'static str,
    row_index: usize,
    retry_count: u8,
    error: String,
}

enum BatchFailureAction {
    Retry(PendingBatch),
    Drop(Vec<BatchDlqEntry>),
}

/// Describe a queueing failure when enqueuing DB work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueError {
    Disabled,
    Full,
    Closed,
}

/// Cheap sender handle cloned into every request handler.
#[derive(Clone)]
pub struct EventSender(Option<mpsc::Sender<DbEvent>>);

impl EventSender {
    /// Construct a disabled sender used when Oracle integration is unavailable.
    pub fn disabled() -> Self {
        Self(None)
    }

    /// Try to enqueue one event without blocking the hot path.
    pub fn try_send(&self, ev: DbEvent) -> Result<(), EnqueueError> {
        let Some(sender) = &self.0 else {
            return Err(EnqueueError::Disabled);
        };

        match sender.try_send(ev) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(EnqueueError::Full),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(EnqueueError::Closed),
        }
    }

    /// Enqueue one event without blocking the hot path.
    pub fn send(&self, ev: DbEvent) {
        let event = event_kind(&ev);
        match self.try_send(ev) {
            Ok(()) | Err(EnqueueError::Disabled) => {}
            Err(err) => {
                warn!(
                    ?err,
                    ev = event,
                    "db: failed to enqueue event, dropping row"
                );
            }
        }
    }
}

/// Spawn the single Oracle writer task and return the sender handle.
pub fn spawn_writer(
    conn_str: String,
    user: String,
    pass: String,
    token: CancellationToken,
) -> EventSender {
    let (tx, mut rx) = mpsc::channel::<DbEvent>(CHANNEL_CAP);

    tokio::spawn(async move {
        let mut pending_batch: Option<PendingBatch> = None;
        loop {
            let (cs, u, p) = (conn_str.clone(), user.clone(), pass.clone());
            let conn_result =
                tokio::task::spawn_blocking(move || oracle::Connection::connect(&u, &p, &cs)).await;

            let conn = match conn_result {
                Ok(Ok(c)) => {
                    info!("db: writer connected");
                    c
                }
                Ok(Err(e)) => {
                    error!(%e, "db: connect failed, retrying with jitter");
                    if !wait_for_retry(&token).await {
                        return;
                    }
                    continue;
                }
                Err(e) => {
                    error!(%e, "db: spawn_blocking panicked on connect");
                    if !wait_for_retry(&token).await {
                        return;
                    }
                    continue;
                }
            };

            let mut conn = conn;
            loop {
                let batch = if let Some(batch) = pending_batch.take() {
                    batch
                } else {
                    let first = tokio::select! {
                        _ = token.cancelled() => {
                            info!("db: writer shutting down");
                            return;
                        }
                        msg = rx.recv() => match msg {
                            Some(ev) => ev,
                            None => return,
                        }
                    };

                    let mut events = vec![first];
                    while events.len() < 64 {
                        match rx.try_recv() {
                            Ok(ev) => events.push(ev),
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(_) => return,
                        }
                    }
                    PendingBatch::new(events)
                };

                let batch_size = batch.events.len();
                let retry_batch = batch.clone();
                let result = tokio::task::spawn_blocking(move || {
                    insert_batch(&conn, &batch.events)?;
                    Ok::<oracle::Connection, oracle::Error>(conn)
                })
                .await;

                match result {
                    Ok(Ok(c)) => conn = c,
                    Ok(Err(e)) => {
                        let error_text = e.to_string();
                        match classify_batch_failure(retry_batch, error_text.clone()) {
                            BatchFailureAction::Retry(next_batch) => {
                                error!(
                                    error = %error_text,
                                    batch_size,
                                    retry_count = next_batch.retry_count,
                                    "db: batch insert failed, reconnecting"
                                );
                                pending_batch = Some(next_batch);
                                if !wait_for_retry(&token).await {
                                    return;
                                }
                            }
                            BatchFailureAction::Drop(entries) => {
                                error!(
                                    error = %error_text,
                                    batch_size,
                                    retry_count = MAX_BATCH_RETRIES + 1,
                                    "db: batch retry budget exhausted, moving rows to DLQ"
                                );
                                for entry in &entries {
                                    emit_exhausted_batch_dlq(entry);
                                }
                            }
                        }
                        break;
                    }
                    Err(e) => {
                        let error_text = e.to_string();
                        match classify_batch_failure(retry_batch, error_text.clone()) {
                            BatchFailureAction::Retry(next_batch) => {
                                error!(
                                    error = %error_text,
                                    batch_size,
                                    retry_count = next_batch.retry_count,
                                    "db: spawn_blocking panicked on insert"
                                );
                                pending_batch = Some(next_batch);
                                if !wait_for_retry(&token).await {
                                    return;
                                }
                            }
                            BatchFailureAction::Drop(entries) => {
                                error!(
                                    error = %error_text,
                                    batch_size,
                                    retry_count = MAX_BATCH_RETRIES + 1,
                                    "db: batch retry budget exhausted, moving rows to DLQ"
                                );
                                for entry in &entries {
                                    emit_exhausted_batch_dlq(entry);
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
    });

    EventSender(Some(tx))
}

fn event_kind(ev: &DbEvent) -> &'static str {
    match ev {
        DbEvent::Proxy(_) => "proxy_events",
        DbEvent::PayloadAudit(_) => "payload_audit",
        DbEvent::TlsFingerprint(_) => "tls_fingerprints",
        DbEvent::ConnectionSessionOpen(_) => "connection_sessions_open",
        DbEvent::ConnectionSessionClose(_) => "connection_sessions_close",
        DbEvent::BlocklistAudit(_) => "blocklist_audit",
    }
}

fn retry_delay() -> Duration {
    Duration::from_millis(1500 + (uuid::Uuid::new_v4().as_u128() % 1000) as u64)
}

async fn wait_for_retry(token: &CancellationToken) -> bool {
    tokio::select! {
        _ = token.cancelled() => false,
        _ = tokio::time::sleep(retry_delay()) => true,
    }
}

fn classify_batch_failure(mut batch: PendingBatch, error: String) -> BatchFailureAction {
    batch.retry_count = batch.retry_count.saturating_add(1);
    batch.last_error = error;
    if batch.retry_count > MAX_BATCH_RETRIES {
        BatchFailureAction::Drop(batch_dlq_entries(&batch))
    } else {
        BatchFailureAction::Retry(batch)
    }
}

fn batch_dlq_entries(batch: &PendingBatch) -> Vec<BatchDlqEntry> {
    batch
        .events
        .iter()
        .enumerate()
        .map(|(row_index, event)| BatchDlqEntry {
            event_kind: event_kind(event),
            row_index,
            retry_count: batch.retry_count,
            error: batch.last_error.clone(),
        })
        .collect()
}

fn insert_batch(conn: &oracle::Connection, batch: &[DbEvent]) -> Result<(), oracle::Error> {
    let mut proxy_events: Vec<&ProxyEvent> = Vec::new();
    let mut payload_events: Vec<&PayloadAuditEvent> = Vec::new();
    let mut tls_events: Vec<&TlsFingerprintEvent> = Vec::new();
    let mut session_open_events: Vec<&ConnectionSessionOpenEvent> = Vec::new();
    let mut session_close_events: Vec<&ConnectionSessionCloseEvent> = Vec::new();
    let mut blocklist_events: Vec<&super::types::BlocklistAuditEvent> = Vec::new();
    let mut processing_errors: Vec<ProcessingError> = Vec::new();

    for ev in batch {
        match ev {
            DbEvent::Proxy(v) => proxy_events.push(v),
            DbEvent::PayloadAudit(v) => payload_events.push(v),
            DbEvent::TlsFingerprint(v) => tls_events.push(v),
            DbEvent::ConnectionSessionOpen(v) => session_open_events.push(v),
            DbEvent::ConnectionSessionClose(v) => session_close_events.push(v),
            DbEvent::BlocklistAudit(v) => blocklist_events.push(v),
        }
    }

    if !proxy_events.is_empty() {
        insert_proxy_events_with_fallback(conn, &proxy_events, &mut processing_errors)?;
    }
    if !payload_events.is_empty() {
        insert_payload_audit_with_fallback(conn, &payload_events, &mut processing_errors)?;
    }
    if !tls_events.is_empty() {
        upsert_tls_fingerprints_with_fallback(conn, &tls_events, &mut processing_errors)?;
    }
    if !session_open_events.is_empty() {
        insert_connection_session_open_with_fallback(
            conn,
            &session_open_events,
            &mut processing_errors,
        )?;
    }
    if !session_close_events.is_empty() {
        update_connection_session_close_with_fallback(
            conn,
            &session_close_events,
            &mut processing_errors,
        )?;
    }
    if !blocklist_events.is_empty() {
        insert_blocklist_audit_with_fallback(conn, &blocklist_events, &mut processing_errors)?;
    }

    for err in &processing_errors {
        emit_processing_error_dlq(err);
    }

    conn.commit()
}

fn emit_processing_error_dlq(err: &ProcessingError) {
    error!(
        target: "db_dlq",
        table = err.table,
        row_index = err.row_index,
        error = %err.error,
        "db row moved to processing DLQ"
    );
}

fn emit_exhausted_batch_dlq(entry: &BatchDlqEntry) {
    error!(
        target: "db_dlq",
        ev = entry.event_kind,
        row_index = entry.row_index,
        retry_count = entry.retry_count,
        error = %entry.error,
        "db batch moved to processing DLQ after retry exhaustion"
    );
}

/// Enqueue one proxy event for Oracle persistence.
pub fn insert_proxy_event(sender: Arc<EventSender>, ev: ProxyEvent) {
    sender.send(DbEvent::Proxy(ev));
}

/// Enqueue one payload audit event for Oracle persistence.
pub fn insert_payload_audit_event(sender: Arc<EventSender>, ev: PayloadAuditEvent) {
    sender.send(DbEvent::PayloadAudit(ev));
}

/// Enqueue one TLS fingerprint update for Oracle persistence.
pub fn upsert_tls_fingerprint_event(sender: Arc<EventSender>, ev: TlsFingerprintEvent) {
    sender.send(DbEvent::TlsFingerprint(ev));
}

/// Enqueue one connection-session open event.
pub fn insert_connection_session_open_event(
    sender: Arc<EventSender>,
    ev: ConnectionSessionOpenEvent,
) {
    sender.send(DbEvent::ConnectionSessionOpen(ev));
}

/// Enqueue one connection-session close event.
pub fn update_connection_session_close_event(
    sender: Arc<EventSender>,
    ev: ConnectionSessionCloseEvent,
) {
    sender.send(DbEvent::ConnectionSessionClose(ev));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ProxyEvent;

    fn sample_proxy_event() -> DbEvent {
        DbEvent::Proxy(ProxyEvent {
            event_type: "tunnel_open".to_string(),
            host: "example.com".to_string(),
            peer_ip: None,
            bytes_up: 0,
            bytes_down: 0,
            status_code: None,
            blocked: false,
            obfuscation_profile: None,
            correlation_id: None,
            parent_event_id: None,
            event_sequence: None,
            duration_ms: None,
            raw_json: "{}".to_string(),
        })
    }

    #[test]
    fn retry_delay_uses_expected_jitter_range() {
        for _ in 0..128 {
            let delay_ms = retry_delay().as_millis();
            assert!((1500..=2499).contains(&delay_ms));
        }
    }

    #[test]
    fn batch_failure_drops_rows_after_sixth_failure() {
        let mut batch = PendingBatch::new(vec![sample_proxy_event()]);

        for expected_retry_count in 1..=MAX_BATCH_RETRIES {
            match classify_batch_failure(batch, "boom".to_string()) {
                BatchFailureAction::Retry(next_batch) => {
                    assert_eq!(next_batch.retry_count, expected_retry_count);
                    batch = next_batch;
                }
                BatchFailureAction::Drop(_) => panic!("batch should still be retried"),
            }
        }

        match classify_batch_failure(batch, "boom".to_string()) {
            BatchFailureAction::Retry(_) => {
                panic!("batch should be dropped after retry exhaustion")
            }
            BatchFailureAction::Drop(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].event_kind, "proxy_events");
                assert_eq!(entries[0].row_index, 0);
                assert_eq!(entries[0].retry_count, MAX_BATCH_RETRIES + 1);
                assert_eq!(entries[0].error, "boom");
                emit_exhausted_batch_dlq(&entries[0]);
            }
        }
    }
}
