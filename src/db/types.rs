//! Typed DB event payloads for the Oracle writer queue.
//!
//! These types own the row data enqueued from request handlers and background
//! tasks. They do not perform serialization or database I/O themselves.

/// Represent one proxy event row queued for insertion.
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

/// Represent one payload preview audit row.
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

/// Represent one TLS fingerprint upsert request.
#[derive(Clone)]
pub struct TlsFingerprintEvent {
    pub ja3_lite: String,
    pub tls_ver: Option<String>,
    pub alpn: Option<String>,
    pub cipher_count: Option<i32>,
    pub verdict_hint: Option<String>,
}

/// Represent one connection-session open event.
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

/// Represent one connection-session close event.
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

/// Represent one blocklist refresh audit row.
#[derive(Clone)]
pub struct BlocklistAuditEvent {
    pub source_url: Option<String>,
    pub entries_loaded: Option<i64>,
    pub seed_entries: Option<i64>,
    pub success: bool,
    pub error_msg: Option<String>,
    pub duration_ms: Option<i64>,
}

/// Represent one queued write for the Oracle writer task.
#[derive(Clone)]
pub enum DbEvent {
    Proxy(ProxyEvent),
    PayloadAudit(PayloadAuditEvent),
    TlsFingerprint(TlsFingerprintEvent),
    ConnectionSessionOpen(ConnectionSessionOpenEvent),
    ConnectionSessionClose(ConnectionSessionCloseEvent),
    BlocklistAudit(BlocklistAuditEvent),
}
