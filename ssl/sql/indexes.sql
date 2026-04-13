-- =============================================================================
-- Indexes — optimised for the query patterns used by Kibana / Grafana
-- =============================================================================

-- proxy_events: time-range scans (most dashboards), host lookups, block audits
CREATE INDEX ix_pe_time       ON proxy_events (event_time DESC)    LOCAL;
CREATE INDEX ix_pe_host       ON proxy_events (host, event_time)   LOCAL;
CREATE INDEX ix_pe_blocked    ON proxy_events (blocked, event_time) LOCAL;
CREATE INDEX ix_pe_type_time  ON proxy_events (event_type, event_time DESC) LOCAL;

-- wg_events: peer timeline, endpoint correlation
CREATE INDEX ix_wg_time       ON wg_events (event_time DESC)              LOCAL;
CREATE INDEX ix_wg_peer       ON wg_events (peer_pubkey, event_time DESC) LOCAL;
CREATE INDEX ix_wg_endpoint   ON wg_events (endpoint_ip, event_time)      LOCAL;

-- db_query_log: slow-query hunting, per-user audits
CREATE INDEX ix_dql_time      ON db_query_log (captured_at DESC)          LOCAL;
CREATE INDEX ix_dql_elapsed   ON db_query_log (elapsed_ms DESC, captured_at) LOCAL;
CREATE INDEX ix_dql_user      ON db_query_log (db_user, captured_at)      LOCAL;
CREATE INDEX ix_dql_client    ON db_query_log (client_ip, captured_at)    LOCAL;

-- JSON search index on raw_json columns (Oracle 21c+)
CREATE SEARCH INDEX ix_pe_json  ON proxy_events  (raw_json) FOR JSON;
CREATE SEARCH INDEX ix_wg_json  ON wg_events     (raw_json) FOR JSON;
CREATE SEARCH INDEX ix_dql_json ON db_query_log  (raw_json) FOR JSON;
