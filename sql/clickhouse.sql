-- ClickHouse schema for ssl-proxy audit events
-- Columns match the exact field names emitted by proxy.rs and tunnel.rs

CREATE TABLE proxy_events
(
    -- tracing metadata (always present)
    timestamp   DateTime64(3)                                    CODEC(Delta, ZSTD),
    level       LowCardinality(String),
    target      LowCardinality(String),

    -- audit fields (present on target = 'audit' rows)
    event       LowCardinality(String)  DEFAULT '',  -- http_proxied | http_blocked | http_error | tunnel_open | tunnel_close | tunnel_blocked
    kind        LowCardinality(String)  DEFAULT '',  -- connect | transparent  (tunnels only)
    host        String                  DEFAULT '',
    method      LowCardinality(String)  DEFAULT '',  -- HTTP only
    uri         String                  DEFAULT '',  -- HTTP only
    status      UInt16                  DEFAULT 0,   -- HTTP only
    bytes_up    UInt64                  DEFAULT 0,   -- tunnel_close only
    bytes_down  UInt64                  DEFAULT 0,   -- tunnel_close only
    duration_ms UInt32                  DEFAULT 0,
    orig_dst    String                  DEFAULT '',  -- transparent only
    error       String                  DEFAULT '',  -- http_error only

    -- catch-all for any future fields Vector forwards
    message     String                  DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, event, host)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
