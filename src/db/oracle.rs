//! Oracle connection argument construction and readiness checks.
//!
//! This module validates environment-derived Oracle configuration, reads
//! credentials, and performs readiness checks. It does not enqueue writer
//! events or execute application row inserts.

use std::{path::Path, time::Duration};

use crate::config::Config;

/// Describe the startup or readiness state of Oracle integration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OracleStatus {
    Ready,
    Misconfigured(String),
    Unreachable(String),
    Timeout,
}

impl OracleStatus {
    /// Return the HTTP response body used by readiness endpoints.
    pub fn readiness_body(&self) -> &'static str {
        match self {
            Self::Ready => "ok",
            Self::Misconfigured(_) => "oracle misconfigured",
            Self::Unreachable(_) => "db unreachable",
            Self::Timeout => "db timeout",
        }
    }
}

/// Hold fully resolved Oracle connection parameters.
pub struct OracleConnectArgs {
    pub conn_str: String,
    pub user: String,
    pub pass: String,
}

impl std::fmt::Debug for OracleConnectArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleConnectArgs")
            .field("conn_str", &self.conn_str)
            .field("user", &self.user)
            .field("pass", &"[REDACTED]")
            .finish()
    }
}

/// Build validated Oracle connection arguments from runtime config.
pub fn oracle_connect_args(config: &Config) -> Result<OracleConnectArgs, OracleStatus> {
    let conn_str = config.oracle.conn.trim().to_string();
    let user = config.oracle.user.trim().to_string();

    if conn_str.is_empty() {
        return Err(OracleStatus::Misconfigured(
            "ORACLE_CONN is empty".to_string(),
        ));
    }
    if user.is_empty() {
        return Err(OracleStatus::Misconfigured(
            "ORACLE_USER is empty".to_string(),
        ));
    }

    let pass = read_oracle_password(config).map_err(OracleStatus::Misconfigured)?;
    validate_wallet(config, &conn_str)?;

    Ok(OracleConnectArgs {
        conn_str,
        user,
        pass,
    })
}

/// Probe Oracle readiness within the configured timeout.
pub async fn oracle_readiness(config: &Config, timeout: Duration) -> OracleStatus {
    let args = match oracle_connect_args(config) {
        Ok(args) => args,
        Err(status) => return status,
    };

    let OracleConnectArgs {
        conn_str,
        user,
        pass,
    } = args;

    match tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || {
            oracle::Connection::connect(&user, &pass, &conn_str).and_then(|conn| {
                conn.query_row_as::<u32>("SELECT 1 FROM DUAL", &[])
                    .map(|_| ())
            })
        }),
    )
    .await
    {
        Ok(Ok(Ok(()))) => OracleStatus::Ready,
        Ok(Ok(Err(e))) => OracleStatus::Unreachable(e.to_string()),
        Ok(Err(e)) => OracleStatus::Unreachable(format!("oracle readiness task failed: {e}")),
        Err(_) => OracleStatus::Timeout,
    }
}

fn read_oracle_password(config: &Config) -> Result<String, String> {
    if let Some(pass) = config.oracle.pass.clone().filter(|s| !s.trim().is_empty()) {
        return Ok(pass);
    }

    if config.oracle.pass_file.trim().is_empty() {
        return Err("ORACLE_PASS/ORACLE_PASS_FILE not set".to_string());
    }

    let path = Path::new(&config.oracle.pass_file);
    let password = std::fs::read_to_string(path)
        .map_err(|e| format!("unable to read ORACLE_PASS_FILE {}: {}", path.display(), e))?;
    let password = password.trim_end_matches(&['\n', '\r'][..]).to_string();
    if password.is_empty() {
        return Err(format!("ORACLE_PASS_FILE {} is empty", path.display()));
    }
    Ok(password)
}

fn validate_wallet(config: &Config, conn_str: &str) -> Result<(), OracleStatus> {
    let Some(tns_admin) = config.oracle.tns_admin.as_ref() else {
        return Err(OracleStatus::Misconfigured(
            "TNS_ADMIN is not set".to_string(),
        ));
    };

    let tns_admin = Path::new(tns_admin);
    if !tns_admin.is_dir() {
        return Err(OracleStatus::Misconfigured(format!(
            "TNS_ADMIN directory not found: {}",
            tns_admin.display()
        )));
    }

    let tnsnames = tns_admin.join("tnsnames.ora");
    if !tnsnames.is_file() {
        return Err(OracleStatus::Misconfigured(format!(
            "missing tnsnames.ora in {}",
            tns_admin.display()
        )));
    }

    if !wallet_artifacts_present(tns_admin) {
        return Err(OracleStatus::Misconfigured(format!(
            "missing Oracle wallet artifacts in {}",
            tns_admin.display()
        )));
    }

    if is_tns_alias(conn_str) {
        let tnsnames_contents = std::fs::read_to_string(&tnsnames).map_err(|e| {
            OracleStatus::Misconfigured(format!("unable to read {}: {}", tnsnames.display(), e))
        })?;
        if !tns_alias_exists(&tnsnames_contents, conn_str) {
            return Err(OracleStatus::Misconfigured(format!(
                "TNS alias {} not found in {}",
                conn_str,
                tnsnames.display()
            )));
        }
    }

    Ok(())
}

fn wallet_artifacts_present(tns_admin: &Path) -> bool {
    [
        "cwallet.sso",
        "ewallet.p12",
        "keystore.jks",
        "truststore.jks",
    ]
    .iter()
    .any(|name| tns_admin.join(name).is_file())
}

fn is_tns_alias(conn_str: &str) -> bool {
    !conn_str.is_empty()
        && conn_str
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn tns_alias_exists(tnsnames_contents: &str, alias: &str) -> bool {
    tnsnames_contents.lines().any(|line| {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            return false;
        }

        let Some((candidate, _)) = trimmed.split_once('=') else {
            return false;
        };
        candidate.trim().eq_ignore_ascii_case(alias)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::{Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn temp_wallet_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "boringtun-oracle-wallet-{}-{}-{}",
            name,
            std::process::id(),
            unique
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn test_config(tns_admin: Option<String>) -> Config {
        let mut config = Config::for_tests();
        config.oracle.conn = "mainerc_tp".to_string();
        config.oracle.user = "USCIS_APP".to_string();
        config.oracle.pass = Some("secret".to_string());
        config.oracle.tns_admin = tns_admin;
        config
    }

    #[test]
    fn tns_alias_match_is_case_insensitive() {
        let contents = "MAINERC_TP =\n  (DESCRIPTION=...)";
        assert!(tns_alias_exists(contents, "mainerc_tp"));
        assert!(!tns_alias_exists(contents, "other_alias"));
    }

    #[test]
    fn oracle_connect_args_requires_tns_admin() {
        let _guard = env_lock();
        let config = test_config(None);

        let status = oracle_connect_args(&config).unwrap_err();
        assert_eq!(
            status,
            OracleStatus::Misconfigured("TNS_ADMIN is not set".to_string())
        );
    }

    #[test]
    fn oracle_connect_args_requires_alias_in_wallet() {
        let _guard = env_lock();
        let wallet_dir = temp_wallet_dir("missing-alias");
        fs::write(
            wallet_dir.join("tnsnames.ora"),
            "OTHER_ALIAS = (DESCRIPTION=...)",
        )
        .unwrap();
        fs::write(wallet_dir.join("cwallet.sso"), "placeholder").unwrap();

        let config = test_config(Some(wallet_dir.display().to_string()));
        let status = oracle_connect_args(&config).unwrap_err();

        match status {
            OracleStatus::Misconfigured(reason) => {
                assert!(reason.contains("TNS alias mainerc_tp not found"));
            }
            other => panic!("unexpected oracle status: {other:?}"),
        }

        fs::remove_dir_all(wallet_dir).unwrap();
    }

    #[test]
    fn oracle_connect_args_accepts_valid_wallet_alias() {
        let _guard = env_lock();
        let wallet_dir = temp_wallet_dir("valid");
        fs::write(
            wallet_dir.join("tnsnames.ora"),
            "mainerc_tp = (DESCRIPTION=...)",
        )
        .unwrap();
        fs::write(wallet_dir.join("cwallet.sso"), "placeholder").unwrap();

        let config = test_config(Some(wallet_dir.display().to_string()));
        let args = oracle_connect_args(&config).unwrap();

        assert_eq!(args.conn_str, "mainerc_tp");
        assert_eq!(args.user, "USCIS_APP");
        assert_eq!(args.pass, "secret");

        fs::remove_dir_all(wallet_dir).unwrap();
    }

    #[test]
    fn oracle_connect_args_debug_redacts_password() {
        let args = OracleConnectArgs {
            conn_str: "mainerc_tp".to_string(),
            user: "USCIS_APP".to_string(),
            pass: "secret".to_string(),
        };

        let rendered = format!("{args:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("secret"));
    }

    #[test]
    fn oracle_connect_args_rejects_sqlnet_only_wallet() {
        let _guard = env_lock();
        let wallet_dir = temp_wallet_dir("sqlnet-only");
        fs::write(
            wallet_dir.join("tnsnames.ora"),
            "mainerc_tp = (DESCRIPTION=...)",
        )
        .unwrap();
        fs::write(wallet_dir.join("sqlnet.ora"), "WALLET_LOCATION = /tmp").unwrap();

        let config = test_config(Some(wallet_dir.display().to_string()));
        let status = oracle_connect_args(&config).unwrap_err();

        assert_eq!(
            status,
            OracleStatus::Misconfigured(format!(
                "missing Oracle wallet artifacts in {}",
                wallet_dir.display()
            ))
        );

        fs::remove_dir_all(wallet_dir).unwrap();
    }
}
