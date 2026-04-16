//! Oracle insert and upsert helpers for typed DB event batches.
//!
//! These helpers convert queued event structs into SQL statements and fallback
//! row-by-row retries. They do not manage connections or channels.

use tracing::warn;

use super::types::{
    ConnectionSessionCloseEvent, ConnectionSessionOpenEvent, PayloadAuditEvent, ProxyEvent,
    TlsFingerprintEvent,
};
use super::writer::ProcessingError;

pub(super) fn insert_proxy_events(
    conn: &oracle::Connection,
    batch: &[&ProxyEvent],
) -> Result<(), oracle::Error> {
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

pub(super) fn insert_payload_audit(
    conn: &oracle::Connection,
    batch: &[&PayloadAuditEvent],
) -> Result<(), oracle::Error> {
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

pub(super) fn upsert_tls_fingerprints(
    conn: &oracle::Connection,
    batch: &[&TlsFingerprintEvent],
) -> Result<(), oracle::Error> {
    use oracle::sql_type::OracleType;

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
    let ja3_lite_type = OracleType::Varchar2(512);
    let tls_ver_type = OracleType::Varchar2(16);
    let alpn_type = OracleType::Varchar2(64);
    let verdict_hint_type = OracleType::Varchar2(32);
    for ev in batch {
        stmt.execute(&[
            &(&ev.ja3_lite, &ja3_lite_type),
            &(&ev.tls_ver, &tls_ver_type),
            &(&ev.alpn, &alpn_type),
            &ev.cipher_count,
            &(&ev.verdict_hint, &verdict_hint_type),
        ])?;
    }
    Ok(())
}

pub(super) fn insert_connection_session_open(
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

pub(super) fn update_connection_session_close(
    conn: &oracle::Connection,
    batch: &[&ConnectionSessionCloseEvent],
) -> Result<(), oracle::Error> {
    let sql = "UPDATE connection_sessions SET \
               closed_at = SYSTIMESTAMP, duration_ms = :2, bytes_up = :3, bytes_down = :4, \
               blocked = :5, tarpitted = :6, tarpit_held_ms = :7, verdict = :8, category = :9, \
               obfuscation_profile = :10, tls_ver = :11, \
               alpn = :12, ja3_lite = :13, \
               resolved_ip = :14, asn_org = :15 \
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

pub(super) fn insert_proxy_events_with_fallback(
    conn: &oracle::Connection,
    batch: &[&ProxyEvent],
    processing_errors: &mut Vec<ProcessingError>,
) -> Result<(), oracle::Error> {
    if let Err(bulk_err) = insert_proxy_events(conn, batch) {
        warn!(%bulk_err, rows = batch.len(), "bulk proxy_events insert failed, retrying row-by-row");
        conn.rollback()?;
        let mut any_row_succeeded = false;
        for (idx, ev) in batch.iter().enumerate() {
            if let Err(e) = insert_proxy_events(conn, &[*ev]) {
                processing_errors.push(ProcessingError {
                    table: "proxy_events",
                    row_index: idx,
                    error: e.to_string(),
                });
            } else {
                any_row_succeeded = true;
            }
        }
        if !any_row_succeeded {
            return Err(bulk_err);
        }
    }
    Ok(())
}

pub(super) fn insert_payload_audit_with_fallback(
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

pub(super) fn upsert_tls_fingerprints_with_fallback(
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

pub(super) fn insert_connection_session_open_with_fallback(
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

pub(super) fn update_connection_session_close_with_fallback(
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
