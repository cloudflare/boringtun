-- =============================================================================
-- Views — correlated network + database activity for Kibana / Grafana panels
-- =============================================================================

-- ---------------------------------------------------------------------------
-- V_HOST_THREAT_SCORE  — 7-day rolling risk score per host
-- Combines block frequency, total bytes attempted, and recency decay.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_host_threat_score AS
SELECT
    pe.host,
    COUNT(*)                                                    AS total_blocks_7d,
    SUM(pe.bytes_up + pe.bytes_down)                            AS total_bytes_7d,
    ROUND(
        COUNT(*) * AVG(pe.bytes_up + pe.bytes_down + 1)
        -- recency weight: events in the last 24 h count 3x
        * (1 + 2 * SUM(CASE WHEN pe.event_time >= SYSTIMESTAMP - INTERVAL '1' DAY THEN 1 ELSE 0 END)
                   / NULLIF(COUNT(*), 0)),
    2)                                                          AS threat_score,
    MAX(pe.event_time)                                          AS last_seen
FROM proxy_events pe
WHERE pe.blocked = 1
  AND pe.event_time >= SYSTIMESTAMP - INTERVAL '7' DAY
GROUP BY pe.host
ORDER BY threat_score DESC;

-- ---------------------------------------------------------------------------
-- V_MALICIOUS_ACTORS  — auto-flagging view for alerting and dashboard
-- Joins the 7-day rolling threat score with the live Rust-flushed verdict.
-- Labels are intentionally coarse: consumers filter on intelligence_label.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_malicious_actors AS
SELECT
    ts.host,
    ts.total_blocks_7d,
    ts.total_bytes_7d,
    ts.threat_score,
    ts.last_seen,
    be.frequency_hz,
    be.verdict                                          AS live_verdict,
    be.blocked_attempts                                 AS lifetime_attempts,
    CASE
        WHEN ts.threat_score >= 1000 AND be.frequency_hz > 8 THEN 'MALICIOUS_AGGRESSIVE'
        WHEN ts.threat_score >= 500                          THEN 'SUSPICIOUS_HIGH_VOLUME'
        ELSE                                                      'MONITORED'
    END                                                 AS intelligence_label
FROM v_host_threat_score ts
JOIN blocked_events be ON be.host = ts.host
WHERE ts.total_blocks_7d > 1
ORDER BY ts.threat_score DESC;

CREATE OR REPLACE VIEW v_blocked_hosts_24h AS
SELECT
    host,
    COUNT(*)                                        AS block_count,
    MIN(event_time)                                 AS first_seen,
    MAX(event_time)                                 AS last_seen
FROM proxy_events
WHERE blocked = 1
  AND event_time >= SYSTIMESTAMP - INTERVAL '24' HOUR
GROUP BY host
ORDER BY block_count DESC;

-- ---------------------------------------------------------------------------
-- V_TUNNEL_THROUGHPUT  — per-minute bandwidth (last hour)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_tunnel_throughput AS
SELECT
    TRUNC(event_time, 'MI')                         AS minute,
    SUM(bytes_up)                                   AS total_bytes_up,
    SUM(bytes_down)                                 AS total_bytes_down,
    COUNT(*)                                        AS tunnel_count
FROM proxy_events
WHERE event_type = 'tunnel_close'
  AND event_time >= SYSTIMESTAMP - INTERVAL '1' HOUR
GROUP BY TRUNC(event_time, 'MI')
ORDER BY minute;

-- ---------------------------------------------------------------------------
-- V_WG_PEER_TIMELINE  — WireGuard handshake + traffic per peer (last 24 h)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_wg_peer_timeline AS
SELECT
    peer_pubkey,
    COUNT(CASE WHEN event_type LIKE 'handshake%' THEN 1 END) AS handshakes,
    SUM(rx_bytes)                                             AS total_rx,
    SUM(tx_bytes)                                             AS total_tx,
    AVG(latency_ms)                                           AS avg_latency_ms,
    MAX(event_time)                                           AS last_seen
FROM wg_events
WHERE event_time >= SYSTIMESTAMP - INTERVAL '24' HOUR
GROUP BY peer_pubkey;

-- ---------------------------------------------------------------------------
-- V_CORRELATED_ACTIVITY  — join proxy blocks with concurrent WG handshakes
-- (±5 s window) to surface suspicious correlation
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_correlated_activity AS
SELECT
    pe.event_time                                   AS proxy_time,
    pe.host                                         AS blocked_host,
    pe.peer_ip                                      AS client_ip,
    we.event_time                                   AS wg_time,
    we.peer_pubkey,
    we.endpoint_ip,
    ABS(
        EXTRACT(DAY    FROM (pe.event_time - we.event_time)) * 86400
      + EXTRACT(HOUR   FROM (pe.event_time - we.event_time)) * 3600
      + EXTRACT(MINUTE FROM (pe.event_time - we.event_time)) * 60
      + EXTRACT(SECOND FROM (pe.event_time - we.event_time))
    ) AS delta_seconds
FROM proxy_events pe
JOIN wg_events we
  ON we.event_time BETWEEN pe.event_time - INTERVAL '5' SECOND
                       AND pe.event_time + INTERVAL '5' SECOND
 AND pe.peer_ip = we.endpoint_ip
WHERE pe.blocked = 1
  AND pe.event_time >= SYSTIMESTAMP - INTERVAL '1' HOUR;

-- ---------------------------------------------------------------------------
-- V_SLOW_QUERIES  — top 50 slowest queries in the last hour
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_slow_queries AS
SELECT *
FROM (
    SELECT
        captured_at,
        client_ip,
        db_user,
        elapsed_ms,
        rows_examined,
        rows_returned,
        SUBSTR(sql_text, 1, 200)                    AS sql_preview
    FROM db_query_log
    WHERE captured_at >= SYSTIMESTAMP - INTERVAL '1' HOUR
    ORDER BY elapsed_ms DESC
)
WHERE ROWNUM <= 50;

-- ---------------------------------------------------------------------------
-- V_PIPELINE_HEALTH  — shipper lag summary for ops alerting
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_pipeline_health AS
SELECT
    agent_name,
    host_fqdn,
    MAX(reported_at)                                AS last_heartbeat,
    AVG(lag_seconds)                                AS avg_lag_s,
    MAX(lag_seconds)                                AS max_lag_s,
    SUM(events_sent)                                AS total_events_sent,
    CASE
        WHEN MAX(reported_at) < SYSTIMESTAMP - INTERVAL '5' MINUTE THEN 'STALE'
        WHEN MAX(lag_seconds) > 30                                  THEN 'LAGGING'
        ELSE 'OK'
    END                                             AS health_status
FROM shipper_heartbeats
WHERE reported_at >= SYSTIMESTAMP - INTERVAL '1' HOUR
GROUP BY agent_name, host_fqdn;
