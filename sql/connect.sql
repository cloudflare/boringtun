-- =============================================================================
-- connect.sql  —  connect to Oracle ADB using a wallet directory
--
-- Setup (one-time):
--   1. Download wallet_<dbname>.zip from OCI Console → ADB → DB Connection
--   2. Unzip to a local directory, e.g. /opt/oracle/wallet/mainerc
--   3. Edit sqlnet.ora inside that directory:
--        WALLET_LOCATION = (SOURCE=(METHOD=FILE)(METHOD_DATA=(DIRECTORY=/opt/oracle/wallet/mainerc)))
--        SSL_SERVER_DN_MATCH=yes
--   4. Export TNS_ADMIN before running SQL*Plus / SQLcl:
--        export TNS_ADMIN=/opt/oracle/wallet/mainerc
--
-- TNS aliases (from tnsnames.ora inside the wallet):
--   mainerc_high   — highest priority, lowest concurrency  (analytics)
--   mainerc_medium — balanced
--   mainerc_low    — highest concurrency, lowest priority  (bulk inserts)
-- =============================================================================

-- Connect via SQLcl / SQL*Plus (TNS_ADMIN must be set in the shell):
--   sql <db_user>/<db_password>@mainerc_medium

-- Or inline with the full connect descriptor:
-- NOTE: SSL/TLS still requires access to the Oracle wallet even with an inline
-- descriptor. Provide it via one of:
--   a) Set TNS_ADMIN to the wallet directory before connecting
--   b) Place sqlnet.ora in the current working directory
--   c) Set ORACLE_HOME and put sqlnet.ora in $ORACLE_HOME/network/admin
--   d) Use SQLcl's -W flag: sql -W /path/to/wallet <user>/<pass>@"(description=...)"
-- A wallet is required for certificate validation (ssl_server_dn_match=yes).
CONNECT <db_user>/<db_password>@"(description=
  (retry_count=20)(retry_delay=3)
  (address=(protocol=tcps)(port=1522)(host=<adb_host>))
  (connect_data=(service_name=<adb_service_name>))
  (security=(ssl_server_dn_match=yes)))"

-- Verify
SELECT SYS_CONTEXT('USERENV','DB_NAME')    AS db_name,
       SYS_CONTEXT('USERENV','SERVER_HOST') AS host,
       SYS_CONTEXT('USERENV','SESSION_USER') AS session_user
FROM DUAL;
