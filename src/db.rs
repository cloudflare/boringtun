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

#[derive(Clone)]
pub struct ProxyEvent {
    pub event_type: String,
    pub host: String,
    pub peer_ip: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub status_code: Option<u16>,
    pub blocked: bool,
    pub obfuscation_profile: Option<String>,
    pub correlation_id: Option<uuid::Uuid>,
    pub parent_event_id: Option<uuid::Uuid>,
    pub event_sequence: Option<i32>,
    pub duration_ms: Option<i64>,
    pub raw_json: String,
}

#[derive(Clone)]
pub struct PayloadAuditEvent {
    pub correlation_id: String,
    pub host: String,
    pub direction: String,
    pub byte_offset: i64,
    pub payload_bytes: Vec<u8>,
    pub payload_b64: Option<String>,
    pub content_type: Option<String>,
    pub http_method: Option<String>,
    pub http_status: Option<i32>,
    pub http_path: Option<String>,
    pub is_encrypted: bool,
    pub truncated: bool,
    pub peer_ip: Option<String>,
    pub notes: Option<String>,
}

#[derive(Clone)]
pub struct TlsFingerprintEvent {
    pub ja3_lite: String,
    pub tls_ver: Option<String>,
    pub alpn: Option<String>,
    pub cipher_count: Option<i32>,
    pub verdict_hint: Option<String>,
}

#[derive(Clone)]
pub struct ConnectionSessionOpenEvent {
    pub session_id: String,
    pub correlation_id: Option<String>,
    pub host: String,
    pub peer_ip: Option<String>,
    pub tunnel_kind: String,
    pub blocked: bool,
    pub tarpitted: bool,
    pub verdict: Option<String>,
    pub category: Option<String>,
    pub obfuscation_profile: Option<String>,
    pub tls_ver: Option<String>,
    pub alpn: Option<String>,
    pub ja3_lite: Option<String>,
    pub resolved_ip: Option<String>,
    pub asn_org: Option<String>,
}

#[derive(Clone)]
pub struct ConnectionSessionCloseEvent {
    pub session_id: String,
    pub duration_ms: Option<i64>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub blocked: bool,
    pub tarpitted: bool,
    pub tarpit_held_ms: Option<i64>,
    pub verdict: Option<String>,
    pub category: Option<String>,
    pub obfuscation_profile: Option<String>,
    pub tls_ver: Option<String>,
    pub alpn: Option<String>,
    pub ja3_lite: Option<String>,
    pub resolved_ip: Option<String>,
    pub asn_org: Option<String>,
}

#[derive(Clone)]
pub struct BlocklistAuditEvent {
    pub source_url: Option<String>,
    pub entries_loaded: Option<i64>,
    pub seed_entries: Option<i64>,
    pub success: bool,
    pub error_msg: Option<String>,
    pub duration_ms: Option<i64>,
}

#[derive(Clone)]
pub enum DbEvent {
    Proxy(ProxyEvent),
    PayloadAudit(PayloadAuditEvent),
    TlsFingerprint(TlsFingerprintEvent),
    ConnectionSessionOpen(ConnectionSessionOpenEvent),
    ConnectionSessionClose(ConnectionSessionCloseEvent),
    BlocklistAudit(BlocklistAuditEvent),
}

#[derive(Debug)]
struct ProcessingError {
    table: &'static str,
    row_index: usize,
    error: String,
}

/// Cheap sender handle cloned into every request handler.
#[derive(Clone)]
pub struct EventSender(mpsc::Sender<DbEvent>);

impl EventSender {
    /// Non-blocking enqueue.  Drops the event and logs a warning if the
    /// channel is full — the hot path must never block.
    pub fn send(&self, ev: DbEvent) {
        if let Err(e) = self.0.try_send(ev) {
            warn!(
                ev = ?event_kind(&e.into_inner()),
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
    let (tx, mut rx) = mpsc::channel::<DbEvent>(CHANNEL_CAP);

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

fn insert_batch(conn: &oracle::Connection, batch: &[DbEvent]) -> Result<(), oracle::Error> {
    let mut proxy_events: Vec<&ProxyEvent> = Vec::new();
    let mut payload_events: Vec<&PayloadAuditEvent> = Vec::new();
    let mut tls_events: Vec<&TlsFingerprintEvent> = Vec::new();
    let mut session_open_events: Vec<&ConnectionSessionOpenEvent> = Vec::new();
    let mut session_close_events: Vec<&ConnectionSessionCloseEvent> = Vec::new();
    let mut blocklist_events: Vec<&BlocklistAuditEvent> = Vec::new();
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
        insert_connection_session_open_with_fallback(conn, &session_open_events, &mut processing_errors)?;
    }
    if !session_close_events.is_empty() {
        update_connection_session_close_with_fallback(conn, &session_close_events, &mut processing_errors)?;
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

fn insert_proxy_events(conn: &oracle::Connection, batch: &[&ProxyEvent]) -> Result<(), oracle::Error> {
    let sql = "INSERT INTO proxy_events \
               (event_type, host, peer_ip, bytes_up, bytes_down, status_code, blocked, obfuscation_profile, correlation_id, parent_event_id, event_sequence, duration_ms, raw_json) \
               VALUES (:1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11, :12, :13)";
    let mut stmt = conn.statement(sql).build()?;
    for ev in batch {
        let blocked_i: i32 = if ev.blocked { 1 } else { 0 };
        let correlation_id_str = ev.correlation_id.map(|id| id.to_string());
        let parent_event_id_str = ev.parent_event_id.map(|id| id.to_string());
        stmt.execute(&[
            &ev.event_type,
            &ev.host,
            &ev.peer_ip,
            &ev.bytes_up,
            &ev.bytes_down,
            &ev.status_code,
            &blocked_i,
            &ev.obfuscation_profile,
            &correlation_id_str,
            &parent_event_id_str,
            &ev.event_sequence,
            &ev.duration_ms,
            &ev.raw_json,
        ])?;
    }
    Ok(())
}

fn insert_payload_audit(conn: &oracle::Connection, batch: &[&PayloadAuditEvent]) -> Result<(), oracle::Error> {
    let sql = "INSERT INTO payload_audit \
               (correlation_id, host, direction, byte_offset, payload_bytes, payload_b64, content_type, http_method, http_status, http_path, is_encrypted, truncated, peer_ip, notes) \
               VALUES (:1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11, :12, :13, :14)";
    let mut stmt = conn.statement(sql).build()?;
    for ev in batch {
        let encrypted_i: i32 = if ev.is_encrypted { 1 } else { 0 };
        let truncated_i: i32 = if ev.truncated { 1 } else { 0 };
        stmt.execute(&[
            &ev.correlation_id,
            &ev.host,
            &ev.direction,
            &ev.byte_offset,
            &ev.payload_bytes,
            &ev.payload_b64,
            &ev.content_type,
            &ev.http_method,
            &ev.http_status,
            &ev.http_path,
            &encrypted_i,
            &truncated_i,
            &ev.peer_ip,
            &ev.notes,
        ])?;
    }
    Ok(())
}

fn upsert_tls_fingerprints(
    conn: &oracle::Connection,
    batch: &[&TlsFingerprintEvent],
) -> Result<(), oracle::Error> {
    let sql = "MERGE INTO tls_fingerprints t \
               USING (SELECT :1 ja3_lite, :2 tls_ver, :3 alpn, :4 cipher_count, :5 verdict_hint FROM DUAL) s \
               ON (t.ja3_lite = s.ja3_lite) \
               WHEN MATCHED THEN UPDATE SET \
                 t.last_seen = SYSTIMESTAMP, \
                 t.seen_count = t.seen_count + 1, \
                 t.tls_ver = COALESCE(s.tls_ver, t.tls_ver), \
                 t.alpn = COALESCE(s.alpn, t.alpn), \
                 t.cipher_count = COALESCE(s.cipher_count, t.cipher_count), \
                 t.verdict_hint = COALESCE(s.verdict_hint, t.verdict_hint) \
               WHEN NOT MATCHED THEN INSERT \
                 (ja3_lite, first_seen, last_seen, seen_count, tls_ver, alpn, cipher_count, verdict_hint) \
                 VALUES (s.ja3_lite, SYSTIMESTAMP, SYSTIMESTAMP, 1, s.tls_ver, s.alpn, s.cipher_count, s.verdict_hint)";
    let mut stmt = conn.statement(sql).build()?;
    for ev in batch {
        stmt.execute(&[
            &ev.ja3_lite,
            &ev.tls_ver,
            &ev.alpn,
            &ev.cipher_count,
            &ev.verdict_hint,
        ])?;
    }
    Ok(())
}

fn insert_connection_session_open(
    conn: &oracle::Connection,
    batch: &[&ConnectionSessionOpenEvent],
) -> Result<(), oracle::Error> {
    let sql = "INSERT INTO connection_sessions \
               (session_id, correlation_id, host, peer_ip, tunnel_kind, opened_at, blocked, tarpitted, verdict, category, obfuscation_profile, tls_ver, alpn, ja3_lite, resolved_ip, asn_org, created_at) \
               VALUES (:1, :2, :3, :4, :5, SYSTIMESTAMP, :6, :7, :8, :9, :10, :11, :12, :13, :14, :15, SYSTIMESTAMP)";
    let mut stmt = conn.statement(sql).build()?;
    for ev in batch {
        let blocked_i: i32 = if ev.blocked { 1 } else { 0 };
        let tarpitted_i: i32 = if ev.tarpitted { 1 } else { 0 };
        stmt.execute(&[
            &ev.session_id,
            &ev.correlation_id,
            &ev.host,
            &ev.peer_ip,
            &ev.tunnel_kind,
            &blocked_i,
            &tarpitted_i,
            &ev.verdict,
            &ev.category,
            &ev.obfuscation_profile,
            &ev.tls_ver,
            &ev.alpn,
            &ev.ja3_lite,
            &ev.resolved_ip,
            &ev.asn_org,
        ])?;
    }
    Ok(())
}

fn update_connection_session_close(
    conn: &oracle::Connection,
    batch: &[&ConnectionSessionCloseEvent],
) -> Result<(), oracle::Error> {
    let sql = "UPDATE connection_sessions SET \
               closed_at = SYSTIMESTAMP, duration_ms = :2, bytes_up = :3, bytes_down = :4, \
               blocked = :5, tarpitted = :6, tarpit_held_ms = :7, verdict = :8, category = :9, \
               obfuscation_profile = :10, tls_ver = COALESCE(:11, tls_ver), \
               alpn = COALESCE(:12, alpn), ja3_lite = COALESCE(:13, ja3_lite), \
               resolved_ip = COALESCE(:14, resolved_ip), asn_org = COALESCE(:15, asn_org) \
               WHERE session_id = :1";
    let mut stmt = conn.statement(sql).build()?;
    for ev in batch {
        let blocked_i: i32 = if ev.blocked { 1 } else { 0 };
        let tarpitted_i: i32 = if ev.tarpitted { 1 } else { 0 };
        stmt.execute(&[
            &ev.session_id,
            &ev.duration_ms,
            &ev.bytes_up,
            &ev.bytes_down,
            &blocked_i,
            &tarpitted_i,
            &ev.tarpit_held_ms,
            &ev.verdict,
            &ev.category,
            &ev.obfuscation_profile,
            &ev.tls_ver,
            &ev.alpn,
            &ev.ja3_lite,
            &ev.resolved_ip,
            &ev.asn_org,
        ])?;
    }
    Ok(())
}

fn insert_blocklist_audit(
    conn: &oracle::Connection,
    batch: &[&BlocklistAuditEvent],
) -> Result<(), oracle::Error> {
    let sql = "INSERT INTO blocklist_audit \
               (source_url, entries_loaded, seed_entries, success, error_msg, duration_ms) \
               VALUES (:1, :2, :3, :4, :5, :6)";
    let mut stmt = conn.statement(sql).build()?;
    for ev in batch {
        let success_i: i32 = if ev.success { 1 } else { 0 };
        stmt.execute(&[
            &ev.source_url,
            &ev.entries_loaded,
            &ev.seed_entries,
            &success_i,
            &ev.error_msg,
            &ev.duration_ms,
        ])?;
    }
    Ok(())
}

fn insert_proxy_events_with_fallback(
    conn: &oracle::Connection,
    batch: &[&ProxyEvent],
    processing_errors: &mut Vec<ProcessingError>,
) -> Result<(), oracle::Error> {
    if let Err(bulk_err) = insert_proxy_events(conn, batch) {
        warn!(%bulk_err, rows = batch.len(), "bulk proxy_events insert failed, retrying row-by-row");
        for (idx, ev) in batch.iter().enumerate() {
            if let Err(e) = insert_proxy_events(conn, &[*ev]) {
                processing_errors.push(ProcessingError {
                    table: "proxy_events",
                    row_index: idx,
                    error: e.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn insert_payload_audit_with_fallback(
    conn: &oracle::Connection,
    batch: &[&PayloadAuditEvent],
    processing_errors: &mut Vec<ProcessingError>,
) -> Result<(), oracle::Error> {
    if let Err(bulk_err) = insert_payload_audit(conn, batch) {
        warn!(%bulk_err, rows = batch.len(), "bulk payload_audit insert failed, retrying row-by-row");
        for (idx, ev) in batch.iter().enumerate() {
            if let Err(e) = insert_payload_audit(conn, &[*ev]) {
                processing_errors.push(ProcessingError {
                    table: "payload_audit",
                    row_index: idx,
                    error: e.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn upsert_tls_fingerprints_with_fallback(
    conn: &oracle::Connection,
    batch: &[&TlsFingerprintEvent],
    processing_errors: &mut Vec<ProcessingError>,
) -> Result<(), oracle::Error> {
    if let Err(bulk_err) = upsert_tls_fingerprints(conn, batch) {
        warn!(%bulk_err, rows = batch.len(), "bulk tls_fingerprints upsert failed, retrying row-by-row");
        for (idx, ev) in batch.iter().enumerate() {
            if let Err(e) = upsert_tls_fingerprints(conn, &[*ev]) {
                processing_errors.push(ProcessingError {
                    table: "tls_fingerprints",
                    row_index: idx,
                    error: e.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn insert_connection_session_open_with_fallback(
    conn: &oracle::Connection,
    batch: &[&ConnectionSessionOpenEvent],
    processing_errors: &mut Vec<ProcessingError>,
) -> Result<(), oracle::Error> {
    if let Err(bulk_err) = insert_connection_session_open(conn, batch) {
        warn!(%bulk_err, rows = batch.len(), "bulk connection_sessions open failed, retrying row-by-row");
        for (idx, ev) in batch.iter().enumerate() {
            if let Err(e) = insert_connection_session_open(conn, &[*ev]) {
                processing_errors.push(ProcessingError {
                    table: "connection_sessions",
                    row_index: idx,
                    error: e.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn update_connection_session_close_with_fallback(
    conn: &oracle::Connection,
    batch: &[&ConnectionSessionCloseEvent],
    processing_errors: &mut Vec<ProcessingError>,
) -> Result<(), oracle::Error> {
    if let Err(bulk_err) = update_connection_session_close(conn, batch) {
        warn!(%bulk_err, rows = batch.len(), "bulk connection_sessions close failed, retrying row-by-row");
        for (idx, ev) in batch.iter().enumerate() {
            if let Err(e) = update_connection_session_close(conn, &[*ev]) {
                processing_errors.push(ProcessingError {
                    table: "connection_sessions",
                    row_index: idx,
                    error: e.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn insert_blocklist_audit_with_fallback(
    conn: &oracle::Connection,
    batch: &[&BlocklistAuditEvent],
    processing_errors: &mut Vec<ProcessingError>,
) -> Result<(), oracle::Error> {
    if let Err(bulk_err) = insert_blocklist_audit(conn, batch) {
        warn!(%bulk_err, rows = batch.len(), "bulk blocklist_audit insert failed, retrying row-by-row");
        for (idx, ev) in batch.iter().enumerate() {
            if let Err(e) = insert_blocklist_audit(conn, &[*ev]) {
                processing_errors.push(ProcessingError {
                    table: "blocklist_audit",
                    row_index: idx,
                    error: e.to_string(),
                });
            }
        }
    }
    Ok(())
}

/// Convenience wrapper kept for call-site compatibility.
/// Callers that previously held an `Arc<Pool>` now hold an `Arc<EventSender>`.
pub fn insert_proxy_event(sender: Arc<EventSender>, ev: ProxyEvent) {
    sender.send(DbEvent::Proxy(ev));
}

pub fn insert_payload_audit_event(sender: Arc<EventSender>, ev: PayloadAuditEvent) {
    sender.send(DbEvent::PayloadAudit(ev));
}

pub fn upsert_tls_fingerprint_event(sender: Arc<EventSender>, ev: TlsFingerprintEvent) {
    sender.send(DbEvent::TlsFingerprint(ev));
}

pub fn insert_connection_session_open_event(sender: Arc<EventSender>, ev: ConnectionSessionOpenEvent) {
    sender.send(DbEvent::ConnectionSessionOpen(ev));
}

pub fn update_connection_session_close_event(
    sender: Arc<EventSender>,
    ev: ConnectionSessionCloseEvent,
) {
    sender.send(DbEvent::ConnectionSessionClose(ev));
}

pub fn insert_blocklist_audit_event(sender: Arc<EventSender>, ev: BlocklistAuditEvent) {
    sender.send(DbEvent::BlocklistAudit(ev));
}
