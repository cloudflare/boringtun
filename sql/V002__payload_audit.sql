-- V002: Payload audit table and supporting schema
-- Safe to run multiple times: all DDL is guarded by existence checks
-- via PL/SQL anonymous blocks. Only ALTER used if objects exist.

-- ── 1. PAYLOAD_AUDIT ────────────────────────────────────────────────────────
-- Stores the first N bytes of each proxied stream (plain HTTP only unless
-- TLS MITM is in place). Keyed back to PROXY_EVENTS via correlation_id.
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tables WHERE table_name = 'PAYLOAD_AUDIT';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE '
      CREATE TABLE payload_audit (
        id               NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        correlation_id   VARCHAR2(36)      NOT NULL,
        host             VARCHAR2(255)     NOT NULL,
        direction        VARCHAR2(4)       NOT NULL CHECK (direction IN (''UP'',''DOWN'')),
        captured_at      TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL,
        byte_offset      NUMBER(10,0)      DEFAULT 0 NOT NULL,
        payload_bytes    RAW(8192),        -- first 4-8 KB, binary-safe
        payload_b64      CLOB,             -- base64 of payload_bytes for JSON export
        content_type     VARCHAR2(128),
        http_method      VARCHAR2(16),
        http_status      NUMBER(5,0),
        http_path        VARCHAR2(1024),
        is_encrypted     NUMBER(1,0)       DEFAULT 0 NOT NULL,
        truncated        NUMBER(1,0)       DEFAULT 0 NOT NULL,
        peer_ip          VARCHAR2(45),
        notes            VARCHAR2(512)
      )
    ';
    EXECUTE IMMEDIATE 'COMMENT ON TABLE payload_audit IS
      ''Partial payload capture (first N bytes) for compliance auditing.
        Encrypted TLS tunnels store metadata only; is_encrypted=1.''';
  END IF;
END;
/

-- Indexes for payload_audit
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_indexes
  WHERE index_name = 'PA_CORR_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX pa_corr_idx ON payload_audit(correlation_id)';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_indexes
  WHERE index_name = 'PA_HOST_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX pa_host_idx ON payload_audit(host, captured_at)';
  END IF;
END;
/

-- ── 2. TLS_FINGERPRINTS ──────────────────────────────────────────────────────
-- Normalised store of JA3/TLS metadata. One row per unique JA3-lite hash.
-- BLOCKED_EVENTS stores the raw strings; this table deduplicates them.
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tables WHERE table_name = 'TLS_FINGERPRINTS';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE '
      CREATE TABLE tls_fingerprints (
        ja3_lite         VARCHAR2(512)  NOT NULL,
        first_seen       TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
        last_seen        TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
        seen_count       NUMBER(10,0)   DEFAULT 1 NOT NULL,
        tls_ver          VARCHAR2(16),
        alpn             VARCHAR2(64),
        cipher_count     NUMBER(3,0),
        verdict_hint     VARCHAR2(32),   -- ALLOWED / BLOCKED / TARPIT
        CONSTRAINT tls_fp_pk PRIMARY KEY (ja3_lite)
      )
    ';
  END IF;
END;
/

-- ── 3. CONNECTION_SESSIONS ───────────────────────────────────────────────────
-- One row per CONNECT tunnel / transparent tunnel session. Richer than
-- proxy_events (which is per-event); this is the session summary.
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tables WHERE table_name = 'CONNECTION_SESSIONS';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE '
      CREATE TABLE connection_sessions (
        session_id       VARCHAR2(36)   DEFAULT SYS_GUID() PRIMARY KEY,
        correlation_id   VARCHAR2(36),
        host             VARCHAR2(255)  NOT NULL,
        peer_ip          VARCHAR2(45),
        tunnel_kind      VARCHAR2(16)   NOT NULL, -- connect / transparent / quic-h3 / bypass
        opened_at        TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL,
        closed_at        TIMESTAMP,
        duration_ms      NUMBER(12,0),
        bytes_up         NUMBER(18,0)   DEFAULT 0,
        bytes_down       NUMBER(18,0)   DEFAULT 0,
        blocked          NUMBER(1,0)    DEFAULT 0 NOT NULL,
        tarpitted        NUMBER(1,0)    DEFAULT 0 NOT NULL,
        tarpit_held_ms   NUMBER(10,0),
        verdict          VARCHAR2(32),
        category         VARCHAR2(64),
        obfuscation_profile VARCHAR2(32),
        tls_ver          VARCHAR2(16),
        alpn             VARCHAR2(64),
        ja3_lite         VARCHAR2(512),
        resolved_ip      VARCHAR2(45),
        asn_org          VARCHAR2(128),
        created_at       TIMESTAMP      DEFAULT SYSTIMESTAMP NOT NULL
      )
    ';
  END IF;
END;
/

DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_indexes WHERE index_name = 'CS_HOST_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX cs_host_idx ON connection_sessions(host, opened_at)';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_indexes WHERE index_name = 'CS_PEER_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX cs_peer_idx ON connection_sessions(peer_ip, opened_at)';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_indexes WHERE index_name = 'CS_CORR_IDX';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'CREATE INDEX cs_corr_idx ON connection_sessions(correlation_id)';
  END IF;
END;
/

-- ── 4. BLOCKLIST_AUDIT ───────────────────────────────────────────────────────
-- Tracks every blocklist refresh: how many entries loaded, from which source.
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count
  FROM user_tables WHERE table_name = 'BLOCKLIST_AUDIT';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE '
      CREATE TABLE blocklist_audit (
        id               NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        refreshed_at     TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL,
        source_url       VARCHAR2(1024),
        entries_loaded   NUMBER(10,0),
        seed_entries     NUMBER(10,0),
        success          NUMBER(1,0) DEFAULT 1 NOT NULL,
        error_msg        VARCHAR2(512),
        duration_ms      NUMBER(10,0)
      )
    ';
  END IF;
END;
/

-- ── 5. ALTER existing PROXY_EVENTS to add missing columns ───────────────────
-- Add columns that db.rs already writes but may not be in the original DDL.
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_tab_columns
  WHERE table_name = 'PROXY_EVENTS' AND column_name = 'DURATION_MS';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events ADD (duration_ms NUMBER(12,0))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_columns
  WHERE table_name = 'PROXY_EVENTS' AND column_name = 'EVENT_SEQUENCE';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events ADD (event_sequence NUMBER(10,0))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_columns
  WHERE table_name = 'PROXY_EVENTS' AND column_name = 'PARENT_EVENT_ID';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events ADD (parent_event_id VARCHAR2(36))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_columns
  WHERE table_name = 'PROXY_EVENTS' AND column_name = 'OBFUSCATION_PROFILE';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE proxy_events ADD (obfuscation_profile VARCHAR2(32))';
  END IF;
END;
/

-- ── 6. ALTER existing BLOCKED_EVENTS to add enrichment columns ─────────────
DECLARE
  v_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO v_count FROM user_tab_columns
  WHERE table_name = 'BLOCKED_EVENTS' AND column_name = 'CONSECUTIVE_BLOCKS';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE blocked_events ADD (consecutive_blocks NUMBER(6,0))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_columns
  WHERE table_name = 'BLOCKED_EVENTS' AND column_name = 'LAST_VERDICT';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE blocked_events ADD (last_verdict VARCHAR2(32))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_columns
  WHERE table_name = 'BLOCKED_EVENTS' AND column_name = 'TLS_VER';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE blocked_events ADD (tls_ver VARCHAR2(16))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_columns
  WHERE table_name = 'BLOCKED_EVENTS' AND column_name = 'ALPN';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE blocked_events ADD (alpn VARCHAR2(64))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_columns
  WHERE table_name = 'BLOCKED_EVENTS' AND column_name = 'JA3_LITE';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE blocked_events ADD (ja3_lite VARCHAR2(512))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_columns
  WHERE table_name = 'BLOCKED_EVENTS' AND column_name = 'RESOLVED_IP';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE blocked_events ADD (resolved_ip VARCHAR2(45))';
  END IF;

  SELECT COUNT(*) INTO v_count FROM user_tab_columns
  WHERE table_name = 'BLOCKED_EVENTS' AND column_name = 'ASN_ORG';
  IF v_count = 0 THEN
    EXECUTE IMMEDIATE 'ALTER TABLE blocked_events ADD (asn_org VARCHAR2(128))';
  END IF;
END;
/

COMMIT;
