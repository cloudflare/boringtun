-- V003: Reporting views
-- All CREATE OR REPLACE — idempotent, no ALTER needed for views.

-- ── 1. V_BLOCKED_SUMMARY ────────────────────────────────────────────────────
-- Per-host rollup of blocking activity. Used by the /hosts API equivalent
-- in Oracle reporting. Joins blocked_events with tls_fingerprints.
CREATE OR REPLACE VIEW v_blocked_summary AS
SELECT
    be.host,
    be.blocked_attempts,
    be.blocked_bytes,
    be.frequency_hz,
    be.verdict,
    be.category,
    be.risk_score,
    be.tarpit_held_ms,
    be.iat_ms,
    be.consecutive_blocks,
    be.last_verdict,
    be.tls_ver,
    be.alpn,
    be.ja3_lite,
    be.resolved_ip,
    be.asn_org,
    be.updated_at,
    -- Derived: estimated battery saved in mWh (mirrors Rust logic)
    ROUND((be.tarpit_held_ms / 1000.0) * 0.5 / 3600.0, 6) AS battery_saved_mwh,
    -- Derived: days since first record (approximated from updated_at window)
    ROUND(be.blocked_attempts / NULLIF(be.frequency_hz, 0) / 86400, 2) AS est_active_days,
    -- Risk tier for easy filtering
    CASE
        WHEN be.risk_score >= 1000000 THEN 'CRITICAL'
        WHEN be.risk_score >= 100000  THEN 'HIGH'
        WHEN be.risk_score >= 10000   THEN 'MEDIUM'
        ELSE 'LOW'
    END AS risk_tier
FROM blocked_events be
/

COMMENT ON TABLE v_blocked_summary IS
    'Per-host blocking summary with derived risk tier. Use for dashboards and compliance exports.';

-- ── 2. V_SESSION_TIMELINE ────────────────────────────────────────────────────
-- Joins connection_sessions with proxy_events to give a complete timeline
-- per correlation_id. Used for incident investigation.
CREATE OR REPLACE VIEW v_session_timeline AS
SELECT
    cs.session_id,
    cs.correlation_id,
    cs.host,
    cs.peer_ip,
    cs.tunnel_kind,
    cs.opened_at,
    cs.closed_at,
    cs.duration_ms,
    cs.bytes_up,
    cs.bytes_down,
    cs.blocked,
    cs.tarpitted,
    cs.tarpit_held_ms,
    cs.verdict,
    cs.category,
    cs.obfuscation_profile,
    cs.tls_ver,
    cs.alpn,
    cs.ja3_lite,
    cs.resolved_ip,
    cs.asn_org,
    -- Aggregate child events from proxy_events
    (SELECT COUNT(*) FROM proxy_events pe
     WHERE pe.correlation_id = cs.correlation_id) AS event_count,
    (SELECT MAX(pe.bytes_up) FROM proxy_events pe
     WHERE pe.correlation_id = cs.correlation_id) AS max_event_bytes_up,
    -- Latest status code seen in this session
    (SELECT MAX(pe.status_code) FROM proxy_events pe
     WHERE pe.correlation_id = cs.correlation_id
     AND pe.status_code IS NOT NULL) AS last_status_code
FROM connection_sessions cs
/

-- ── 3. V_PAYLOAD_AUDIT_READABLE ─────────────────────────────────────────────
-- Joins payload_audit with connection_sessions for human-readable export.
-- Strips raw bytes; exposes only base64 and metadata.
CREATE OR REPLACE VIEW v_payload_audit_readable AS
SELECT
    pa.id,
    pa.correlation_id,
    pa.host,
    pa.direction,
    pa.captured_at,
    pa.content_type,
    pa.http_method,
    pa.http_status,
    pa.http_path,
    pa.is_encrypted,
    pa.truncated,
    pa.peer_ip,
    pa.notes,
    pa.payload_b64,
    -- Session context
    cs.tunnel_kind,
    cs.verdict,
    cs.category,
    cs.obfuscation_profile,
    cs.opened_at AS session_opened_at,
    cs.bytes_up  AS session_bytes_up,
    cs.bytes_down AS session_bytes_down
FROM payload_audit pa
LEFT JOIN connection_sessions cs ON cs.correlation_id = pa.correlation_id
/

-- ── 4. V_TOP_RISK_HOSTS ──────────────────────────────────────────────────────
-- Top 100 hosts by risk score with enrichment. Intended for SOC dashboard.
CREATE OR REPLACE VIEW v_top_risk_hosts AS
SELECT * FROM (
    SELECT
        host,
        risk_score,
        verdict,
        category,
        blocked_attempts,
        frequency_hz,
        tarpit_held_ms,
        consecutive_blocks,
        tls_ver,
        alpn,
        resolved_ip,
        asn_org,
        updated_at,
        RANK() OVER (ORDER BY risk_score DESC NULLS LAST) AS risk_rank
    FROM blocked_events
    WHERE updated_at >= SYSTIMESTAMP - INTERVAL '24' HOUR
)
WHERE risk_rank <= 100
/

-- ── 5. V_HOURLY_TRAFFIC ──────────────────────────────────────────────────────
-- Hourly rollup of all proxy traffic. Used for capacity and anomaly detection.
CREATE OR REPLACE VIEW v_hourly_traffic AS
SELECT
    TRUNC(event_time, 'HH') AS hour_bucket,
    COUNT(*)                 AS total_events,
    SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) AS blocked_count,
    SUM(CASE WHEN blocked = 0 THEN 1 ELSE 0 END) AS allowed_count,
    SUM(bytes_up)            AS total_bytes_up,
    SUM(bytes_down)          AS total_bytes_down,
    COUNT(DISTINCT host)     AS distinct_hosts,
    COUNT(DISTINCT peer_ip)  AS distinct_clients,
    -- Top category by count in this hour (scalar subquery approach)
    (SELECT category FROM (
        SELECT pe2.category, COUNT(*) cnt,
               RANK() OVER (ORDER BY COUNT(*) DESC) rk
        FROM proxy_events pe2
        WHERE TRUNC(pe2.event_time, 'HH') = TRUNC(pe.event_time, 'HH')
        GROUP BY pe2.category
     ) WHERE rk = 1 AND ROWNUM = 1
    ) AS top_category
FROM proxy_events pe
GROUP BY TRUNC(event_time, 'HH')
/

-- ── 6. V_TLS_FINGERPRINT_STATS ───────────────────────────────────────────────
-- Aggregated view of JA3-lite fingerprints seen, useful for detecting
-- non-browser clients (e.g. malware, scrapers).
CREATE OR REPLACE VIEW v_tls_fingerprint_stats AS
SELECT
    tf.ja3_lite,
    tf.tls_ver,
    tf.alpn,
    tf.cipher_count,
    tf.seen_count,
    tf.first_seen,
    tf.last_seen,
    tf.verdict_hint,
    -- How many distinct hosts used this fingerprint
    (SELECT COUNT(DISTINCT be.host) FROM blocked_events be
     WHERE be.ja3_lite = tf.ja3_lite) AS distinct_blocked_hosts,
    (SELECT COUNT(DISTINCT cs.host) FROM connection_sessions cs
     WHERE cs.ja3_lite = tf.ja3_lite) AS distinct_session_hosts,
    -- Days since last seen
    ROUND(SYSDATE - CAST(tf.last_seen AS DATE), 1) AS days_since_last_seen
FROM tls_fingerprints tf
/

COMMIT;
