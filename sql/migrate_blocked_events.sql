-- Migration: add columns missing from the original blocked_events schema
-- Run as schema owner:  sql <DB_USER>/<DB_PASS>@<DB_TNS> @migrate_blocked_events.sql

ALTER TABLE blocked_events ADD (
    category          VARCHAR2(64),
    risk_score        NUMBER(10,4)  DEFAULT 0 CHECK (risk_score >= 0),
    tarpit_held_ms    NUMBER(20)    DEFAULT 0 CHECK (tarpit_held_ms >= 0),
    iat_ms            NUMBER(20),
    consecutive_blocks NUMBER(10)   DEFAULT 0 CHECK (consecutive_blocks >= 0),
    last_verdict      VARCHAR2(32),
    tls_ver           VARCHAR2(16),
    alpn              VARCHAR2(64),
    ja3_lite          VARCHAR2(512),
    resolved_ip       VARCHAR2(45),
    asn_org           VARCHAR2(128)
);
