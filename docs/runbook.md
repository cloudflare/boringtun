# Operator Runbook

## Operational Procedures

---

### 1. Adding a New Obfuscation Profile

#### Steps

1. **Edit `src/obfuscation.rs`:**
   - Add new domain patterns to the `FOX_DOMAINS` array
   - Add new variant to the `Profile` enum
   - Update `as_str()` conversion method
   - Extend match statement in `classify_obfuscation()`

2. **Update configuration struct:**
   - Add profile enable flag in `src/config.rs`
   - Add environment variable mapping

3. **Verify implementation:**
   ```bash
   cargo test obfuscation::tests
   ```

4. **Rebuild container:**
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

Apply changes by restarting the service:

```bash
docker compose restart ssl-proxy
```

---

### 3. Rotate WireGuard Key Pair

1. **Generate new server keys:**
   ```bash
   wg genkey | tee config/server/privatekey-server | wg pubkey > config/server/publickey-server
   ```

2. **Update server configuration:**
   - Keep the private key in `config/server/privatekey-server`
   - The container will render `/run/wireguard/wg0.conf` from `config/templates/server.conf`
   - Distribute the updated public key to all peers

3. **Restart service:**
   ```bash
   docker compose restart ssl-proxy
   ```

> **Important:** All connected clients will require updated configuration with the new server public key.

---

### 4. Verify Container Provenance for WireGuard Startup

1. **Force a fresh build with explicit metadata:**
   ```bash
   export VCS_REF="$(git rev-parse --short HEAD)"
   export BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
   docker compose down --remove-orphans
   docker compose up -d --build
   ```

2. **Compare the built image and compose input:**
   ```bash
   docker images boringtun-ssl-proxy
   docker compose config | sed -n '20,55p'
   ```

3. **Verify the runtime fingerprint and rendered config:**
   ```bash
   docker compose logs ssl-proxy | grep '\[startup-fingerprint\]'
   docker compose exec -T ssl-proxy sed -n '1,12p' /run/wireguard/wg0.conf
   ```

   If a mounted template drifted and duplicated `Address = ...` lines, startup now canonicalizes them back to one line before bringing `wg0` up.

4. **If logs contradict the repo:**
   - Remove the old container with `docker compose down --remove-orphans`
   - Rebuild with `docker compose up -d --build`
   - Re-check the `[startup-fingerprint]` lines before debugging WireGuard behavior

---

### 5. Oracle ADB Connection & Views

1. **Place Oracle wallet files in `./wallet/` directory**
   - Restart the container after adding the wallet so the startup preflight can enable Oracle persistence.
   - `GET /ready` on `http://127.0.0.1:3002/ready` stays `503` until the wallet contains the `mainerc_tp` alias and the required wallet artifacts.

2. **Connect using SQL*Plus:**
   ```bash
   sqlplus USCIS_APP@mainerc_tp
   ```

3. **Available Audit Views:**
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

### 6. Prometheus / Vector Pipeline Setup

1. **Start pipeline:**
   ```bash
   LOG_FORMAT=json ./ssl-proxy | vector --config vector.toml
   ```

2. **Configuration:**
   - `vector.toml` filters audit events
   - Normalizes timestamps for ClickHouse
   - Batches inserts for optimal warehouse performance

3. **Environment Variables:**
   ```text
   CLICKHOUSE_URL=http://clickhouse:8123
   CLICKHOUSE_USER=default
   CLICKHOUSE_PASSWORD=yourpassword
   ```

4. **Operational health and dashboard are available at:**
   ```text
   http://127.0.0.1:3002/health
   http://127.0.0.1:3002/dashboard
   ```
