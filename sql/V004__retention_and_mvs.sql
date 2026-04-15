-- V004: Retention, partitioning helpers, and materialized views
-- Run after V002 and V003. All idempotent.

-- ── 1. PROXY_EVENTS — add event_time if missing (used by V_HOURLY_TRAFFIC) ──
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_tab_columns
  WHERE table_name = 'PROXY_EVENTS' AND column_name = 'EVENT_TIME';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE
      'ALTER TABLE proxy_events ADD (event_time TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL)';
  END IF;
END;
/

-- ── 2. PROXY_EVENTS — index on event_time for range scans ───────────────────
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_indexes
  WHERE index_name = 'PE_EVENT_TIME_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE
      'CREATE INDEX pe_event_time_idx ON proxy_events(event_time)';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_indexes
  WHERE index_name = 'PE_HOST_TIME_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE
      'CREATE INDEX pe_host_time_idx ON proxy_events(host, event_time)';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_indexes
  WHERE index_name = 'PE_BLOCKED_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE
      'CREATE INDEX pe_blocked_idx ON proxy_events(blocked, event_time)';
  END IF;
END;
/

-- ── 3. DATA_RETENTION_POLICY ─────────────────────────────────────────────────
-- Configuration table so retention periods are data-driven, not hardcoded.
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tables WHERE table_name = 'DATA_RETENTION_POLICY';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE '
      CREATE TABLE data_retention_policy (
        table_name        VARCHAR2(128)  NOT NULL,
        retention_days    NUMBER(6,0)    NOT NULL,
        date_column       VARCHAR2(128)  NOT NULL,
        enabled           NUMBER(1,0)    DEFAULT 1 NOT NULL,
        last_purge_at     TIMESTAMP,
        last_purge_rows   NUMBER(12,0),
        notes             VARCHAR2(512),
        CONSTRAINT drp_pk PRIMARY KEY (table_name)
      )
    ';
    -- Seed default retention rules
    EXECUTE IMMEDIATE q'[
      INSERT ALL
        INTO data_retention_policy(table_name, retention_days, date_column, notes)
          VALUES('PROXY_EVENTS',       90,  'EVENT_TIME',   '90-day rolling window')
        INTO data_retention_policy(table_name, retention_days, date_column, notes)
          VALUES('PAYLOAD_AUDIT',      30,  'CAPTURED_AT',  '30-day compliance window')
        INTO data_retention_policy(table_name, retention_days, date_column, notes)
          VALUES('CONNECTION_SESSIONS',90,  'OPENED_AT',    '90-day rolling window')
        INTO data_retention_policy(table_name, retention_days, date_column, notes)
          VALUES('BLOCKLIST_AUDIT',   365,  'REFRESHED_AT', '1-year audit trail')
      SELECT 1 FROM DUAL
    ]';
  END IF;
END;
/

-- ── 4. PURGE_OLD_EVENTS procedure ────────────────────────────────────────────
-- Call from a DBMS_SCHEDULER job (or manually) to enforce retention policy.
CREATE OR REPLACE PROCEDURE purge_old_events AS
  v_sql    VARCHAR2(512);
  v_rows   NUMBER;
  v_cutoff TIMESTAMP;
BEGIN
  FOR rec IN (
    SELECT table_name, retention_days, date_column
    FROM data_retention_policy
    WHERE enabled = 1
  ) LOOP
    v_cutoff := SYSTIMESTAMP - rec.retention_days;
    v_sql := 'DELETE FROM ' || rec.table_name
          || ' WHERE ' || rec.date_column || ' < :1';
    EXECUTE IMMEDIATE v_sql USING v_cutoff;
    v_rows := SQL%ROWCOUNT;
    UPDATE data_retention_policy
    SET last_purge_at   = SYSTIMESTAMP,
        last_purge_rows = v_rows
    WHERE table_name = rec.table_name;
    COMMIT;
  END LOOP;
END;
/

-- ── 5. MATERIALIZED VIEW: MV_DAILY_BLOCKED ───────────────────────────────────
-- Pre-aggregated daily blocking stats. Refresh nightly via scheduler.
-- Dropped and recreated only if not present (no ALTER MV needed for schema).
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_objects WHERE object_type = 'MATERIALIZED VIEW'
  AND object_name = 'MV_DAILY_BLOCKED';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE MATERIALIZED VIEW mv_daily_blocked
      BUILD DEFERRED
      REFRESH COMPLETE ON DEMAND
      ENABLE QUERY REWRITE
      AS
      SELECT
        TRUNC(updated_at) AS day_dt,
        category,
        verdict,
        COUNT(*)          AS host_count,
        SUM(blocked_attempts) AS total_blocks,
        SUM(blocked_bytes)    AS total_bytes,
        SUM(tarpit_held_ms)   AS total_tarpit_ms,
        AVG(risk_score)       AS avg_risk_score,
        MAX(risk_score)       AS max_risk_score
      FROM blocked_events
      GROUP BY TRUNC(updated_at), category, verdict
    ]';
  END IF;
END;
/

-- ── 6. MATERIALIZED VIEW: MV_PEER_IP_SUMMARY ────────────────────────────────
-- Per-client-IP session summary. Useful for detecting compromised devices.
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_objects WHERE object_type = 'MATERIALIZED VIEW'
  AND object_name = 'MV_PEER_IP_SUMMARY';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE q'[
      CREATE MATERIALIZED VIEW mv_peer_ip_summary
      BUILD DEFERRED
      REFRESH COMPLETE ON DEMAND
      AS
      SELECT
        peer_ip,
        COUNT(*)                                    AS total_sessions,
        SUM(CASE WHEN blocked   = 1 THEN 1 ELSE 0 END) AS blocked_sessions,
        SUM(CASE WHEN tarpitted = 1 THEN 1 ELSE 0 END) AS tarpitted_sessions,
        SUM(bytes_up)                               AS total_bytes_up,
        SUM(bytes_down)                             AS total_bytes_down,
        COUNT(DISTINCT host)                        AS distinct_hosts,
        MIN(opened_at)                              AS first_seen,
        MAX(opened_at)                              AS last_seen,
        -- Most-used tunnel kind
        STATS_MODE(tunnel_kind)                     AS primary_tunnel_kind
      FROM connection_sessions
      WHERE peer_ip IS NOT NULL
      GROUP BY peer_ip
    ]';
  END IF;
END;
/

-- ── 7. DBMS_SCHEDULER job for nightly purge ──────────────────────────────────
-- Only created if it doesn't exist already.
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_scheduler_jobs
  WHERE job_name = 'JOB_PURGE_OLD_EVENTS';
  IF v_count = 0 THEN
    DBMS_SCHEDULER.CREATE_JOB(
      job_name        => 'JOB_PURGE_OLD_EVENTS',
      job_type        => 'STORED_PROCEDURE',
      job_action      => 'PURGE_OLD_EVENTS',
      start_date      => SYSTIMESTAMP,
      repeat_interval => 'FREQ=DAILY;BYHOUR=2;BYMINUTE=0',
      enabled         => TRUE,
      comments        => 'Nightly data retention purge per DATA_RETENTION_POLICY table'
    );
  END IF;
END;
/

-- ── 8. DBMS_SCHEDULER job for MV refresh ─────────────────────────────────────
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_scheduler_jobs
  WHERE job_name = 'JOB_REFRESH_MVS';
  IF v_count = 0 THEN
    DBMS_SCHEDULER.CREATE_JOB(
      job_name        => 'JOB_REFRESH_MVS',
      job_type        => 'PLSQL_BLOCK',
      job_action      => q'[BEGIN
        DBMS_MVIEW.REFRESH('MV_DAILY_BLOCKED',   'C');
        DBMS_MVIEW.REFRESH('MV_PEER_IP_SUMMARY', 'C');
      END;]',
      start_date      => SYSTIMESTAMP,
      repeat_interval => 'FREQ=DAILY;BYHOUR=3;BYMINUTE=0',
      enabled         => TRUE,
      comments        => 'Nightly refresh of pre-aggregated materialized views'
    );
  END IF;
END;
/

COMMIT;
