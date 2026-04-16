//! Blocklist-specific audit insert helpers.
//!
//! These helpers own the blocklist refresh audit write path and the queueing
//! wrapper used by the rest of the application. They do not manage the writer
//! lifecycle.

use std::sync::Arc;

use tracing::warn;

use super::types::{BlocklistAuditEvent, DbEvent};
use super::writer::{EnqueueError, EventSender, ProcessingError};

pub(super) fn insert_blocklist_audit(
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

pub(super) fn insert_blocklist_audit_with_fallback(
    conn: &oracle::Connection,
    batch: &[&BlocklistAuditEvent],
    processing_errors: &mut Vec<ProcessingError>,
) -> Result<(), oracle::Error> {
    if let Err(bulk_err) = insert_blocklist_audit(conn, batch) {
        warn!(%bulk_err, rows = batch.len(), "bulk blocklist_audit insert failed, retrying row-by-row");
        conn.rollback()?;
        let mut any_row_succeeded = false;
        for (idx, ev) in batch.iter().enumerate() {
            if let Err(e) = insert_blocklist_audit(conn, &[*ev]) {
                processing_errors.push(ProcessingError {
                    table: "blocklist_audit",
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

/// Enqueue one blocklist audit event for the Oracle writer.
pub fn insert_blocklist_audit_event(sender: Arc<EventSender>, ev: BlocklistAuditEvent) {
    if let Err(err) = sender.try_send(DbEvent::BlocklistAudit(ev)) {
        match err {
            EnqueueError::Disabled | EnqueueError::Full | EnqueueError::Closed => {
                warn!(?err, "failed to enqueue blocklist audit event");
            }
        }
    }
}
