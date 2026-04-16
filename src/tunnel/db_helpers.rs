//! Tunnel-side Oracle session bridge helpers.
//!
//! This module keeps the tunnel split mechanical while DB session writes still
//! flow through the existing `crate::db` API. Shared event emission now lives
//! in `events.rs`.

#[cfg(feature = "oracle-db")]
use crate::state::SharedState;

/// Record that a connection session opened.
#[cfg(feature = "oracle-db")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn db_session_open(
    state: &SharedState,
    session_id: &str,
    host: &str,
    peer_ip: Option<String>,
    tunnel_kind: &str,
    blocked: bool,
    tarpitted: bool,
    verdict: Option<String>,
    category: Option<String>,
    obfuscation_profile: Option<String>,
    tls_ver: Option<String>,
    alpn: Option<String>,
    ja3_lite: Option<String>,
    resolved_ip: Option<String>,
    asn_org: Option<String>,
) {
    crate::db::insert_connection_session_open_event(
        state.db.clone(),
        crate::db::ConnectionSessionOpenEvent {
            session_id: session_id.to_string(),
            correlation_id: None,
            host: host.to_string(),
            peer_ip,
            tunnel_kind: tunnel_kind.to_string(),
            blocked,
            tarpitted,
            verdict,
            category,
            obfuscation_profile,
            tls_ver,
            alpn,
            ja3_lite,
            resolved_ip,
            asn_org,
        },
    );
}

/// Record that a connection session closed.
#[cfg(feature = "oracle-db")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn db_session_close(
    state: &SharedState,
    session_id: &str,
    duration_ms: Option<i64>,
    bytes_up: u64,
    bytes_down: u64,
    blocked: bool,
    tarpitted: bool,
    tarpit_held_ms: Option<i64>,
    verdict: Option<String>,
    category: Option<String>,
    obfuscation_profile: Option<String>,
    tls_ver: Option<String>,
    alpn: Option<String>,
    ja3_lite: Option<String>,
    resolved_ip: Option<String>,
    asn_org: Option<String>,
) {
    crate::db::update_connection_session_close_event(
        state.db.clone(),
        crate::db::ConnectionSessionCloseEvent {
            session_id: session_id.to_string(),
            duration_ms,
            bytes_up,
            bytes_down,
            blocked,
            tarpitted,
            tarpit_held_ms,
            verdict,
            category,
            obfuscation_profile,
            tls_ver,
            alpn,
            ja3_lite,
            resolved_ip,
            asn_org,
        },
    );
}
