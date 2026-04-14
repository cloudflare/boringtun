# Operator Runbook

## Operational Procedures

---

### 1. Adding a New Obfuscation Profile

#### Steps:
1.  **Edit `src/obfuscation.rs`:**
    -   Add new domain patterns to the `FOX_DOMAINS` array
    -   Add new variant to the `Profile` enum
    -   Update `as_str()` conversion method
    -   Extend match statement in `classify_obfuscation()`

2.  **Update configuration struct:**
    -   Add profile enable flag in `src/config.rs`
    -   Add environment variable mapping

3.  **Verify implementation:**
    ```bash
    cargo test obfuscation::tests
    ```

4.  **Rebuild container:**
    ```bash
    docker compose build ssl-proxy
    docker compose up -d
    ```

---

### 2. Updating Blocklist URL

Set the environment variable in your compose override or shell:
```bash
BLOCKLIST_URL=https://example.com/blocklist.txt
```

Blocklist is automatically refreshed on service startup and every 24 hours.

Manual refresh trigger:
```bash
curl -X POST http://localhost:3000/admin/refresh-blocklist
```

---

### 3. Rotate WireGuard Key Pair

1.  **Generate new server keys:**
    ```bash
    wg genkey | tee server.key | wg pubkey > server.pub
    ```

2.  **Update server configuration:**
    -   Replace private key in `config/wg_confs/wg0.conf`
    -   Distribute new public key to all peers

3.  **Restart service:**
    ```bash
    docker compose restart ssl-proxy
    ```

> **Important:** All connected clients will require updated configuration with the new server public key.

---

### 4. Oracle ADB Connection & Views

1.  **Place Oracle wallet files in `./wallet/` directory**

2.  **Connect using SQL*Plus:**
    ```bash
    sqlplus USCIS_APP@mainerc_tp
    ```

3.  **Available Audit Views:**
    ```sql
    -- Session traffic summary
    SELECT * FROM v_proxy_session_stats;
    
    -- Obfuscation events
    SELECT * FROM v_obfuscation_log;
    
    -- Blocked requests
    SELECT * FROM v_blocked_requests;
    
    -- Daily bandwidth usage
    SELECT * FROM v_daily_bandwidth;
    ```

All views are optimized for ADB columnar storage.

---

### 5. Prometheus / Vector Pipeline Setup

1.  **Start pipeline:**
    ```bash
    LOG_FORMAT=json ./ssl-proxy | vector --config vector.toml
    ```

2.  **Configuration:**
    -   `vector.toml` filters audit events
    -   Normalizes timestamps for ClickHouse
    -   Batches inserts for optimal warehouse performance

3.  **Environment Variables:**
    ```
    CLICKHOUSE_URL=http://clickhouse:8123
    CLICKHOUSE_USER=default
    CLICKHOUSE_PASSWORD=yourpassword
    ```

4.  **Prometheus metrics are available at:**
    ```
    http://localhost:3000/metrics
