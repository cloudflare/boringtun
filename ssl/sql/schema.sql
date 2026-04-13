-- =============================================================================
-- ssl-proxy observability schema  (Oracle ADB, wallet auth)
-- Run as the schema owner after connecting via wallet (see connect.sql)
-- =============================================================================

-- Proxy tunnel / block / HTTP events  (matches tunnel.rs + proxy.rs JSON shapes)
CREATE TABLE proxy_events (
    id           NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_time   TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    event_type   VARCHAR2(16)  NOT NULL,   -- 'tunnel_open' | 'tunnel_close' | 'block' | 'http'
    host         VARCHAR2(253) NOT NULL,
    peer_ip      VARCHAR2(45),
    bytes_up     NUMBER(20) DEFAULT 0,
    bytes_down   NUMBER(20) DEFAULT 0,
    status_code  NUMBER(5),
    blocked      NUMBER(1)  DEFAULT 0 CHECK (blocked IN (0,1)),
    raw_json     CLOB       CHECK (raw_json IS JSON)
);

CREATE INDEX ix_pe_time    ON proxy_events (event_time DESC);
CREATE INDEX ix_pe_host    ON proxy_events (host);
CREATE INDEX ix_pe_blocked ON proxy_events (blocked, event_time DESC);

-- WireGuard kernel events  (from dynamic debug / wg show polling)
CREATE TABLE wg_events (
    id            NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_time    TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    event_type    VARCHAR2(32)  NOT NULL,  -- 'handshake_init' | 'handshake_resp' | 'peer_change' | 'keepalive'
    interface     VARCHAR2(16)  NOT NULL,
    peer_pubkey   VARCHAR2(64)  NOT NULL,
    endpoint_ip   VARCHAR2(45),
    endpoint_port NUMBER(5),
    rx_bytes      NUMBER(20) DEFAULT 0,
    tx_bytes      NUMBER(20) DEFAULT 0,
    latency_ms    NUMBER(10,3),
    raw_json      CLOB       CHECK (raw_json IS JSON)
);

CREATE INDEX ix_wg_time ON wg_events (event_time DESC);
CREATE INDEX ix_wg_peer ON wg_events (peer_pubkey, event_time DESC);

-- Slow / captured SQL queries  (Hoop.dev proxy or slow-query log)
CREATE TABLE db_query_log (
    id            NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    captured_at   TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    session_id    VARCHAR2(64),
    client_ip     VARCHAR2(45),
    db_user       VARCHAR2(128),
    sql_text      CLOB NOT NULL,
    elapsed_ms    NUMBER(12,3),
    rows_examined NUMBER(20),
    rows_returned NUMBER(20),
    plan_hash     VARCHAR2(64),
    raw_json      CLOB CHECK (raw_json IS JSON)
);

CREATE INDEX ix_dql_time    ON db_query_log (captured_at DESC);
CREATE INDEX ix_dql_elapsed ON db_query_log (elapsed_ms DESC);

-- blocked_events: per-host heuristic summary flushed from Rust every 60 s
CREATE TABLE blocked_events (
    id               NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host             VARCHAR2(253) NOT NULL,
    blocked_attempts NUMBER(20)    DEFAULT 0 NOT NULL,
    blocked_bytes    NUMBER(20)    DEFAULT 0 NOT NULL,
    frequency_hz     NUMBER(10,4)  DEFAULT 0 NOT NULL,
    verdict          VARCHAR2(32)  NOT NULL,
    updated_at       TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    first_seen       TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX ix_be_host      ON blocked_events (host);
CREATE INDEX        ix_be_timestamp ON blocked_events (updated_at DESC);

CREATE TABLE shipper_heartbeats (
    id           NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    reported_at  TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP NOT NULL,
    agent_name   VARCHAR2(64)  NOT NULL,
    host_fqdn    VARCHAR2(253) NOT NULL,
    version      VARCHAR2(32),
    events_sent  NUMBER(20) DEFAULT 0,
    lag_seconds  NUMBER(10,3),
    raw_json     CLOB CHECK (raw_json IS JSON)
);
