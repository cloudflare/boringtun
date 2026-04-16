//! Oracle DB integration compiled only with `--features oracle-db`.
//!
//! All writes funnel through a single background writer task that owns one
//! persistent Oracle connection. Request handlers enqueue typed events and
//! return immediately; this module does not expose connection pooling or
//! blocking DB work to the hot path.

mod audit;
mod inserts;
mod oracle;
mod types;
mod writer;

pub const CHANNEL_CAP: usize = 4_096;

#[allow(unused_imports)]
pub use audit::insert_blocklist_audit_event;
#[allow(unused_imports)]
pub use oracle::{oracle_connect_args, oracle_readiness, OracleConnectArgs, OracleStatus};
#[allow(unused_imports)]
pub use types::{
    BlocklistAuditEvent, ConnectionSessionCloseEvent, ConnectionSessionOpenEvent, DbEvent,
    PayloadAuditEvent, ProxyEvent, TlsFingerprintEvent,
};
#[allow(unused_imports)]
pub use writer::{
    insert_connection_session_open_event, insert_payload_audit_event, insert_proxy_event,
    spawn_writer, update_connection_session_close_event, upsert_tls_fingerprint_event, EventSender,
};
