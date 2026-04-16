//! Runtime configuration loaded from environment variables.
//!
//! Call `Config::from_env()` once at startup. All fields are validated before
//! `Ok` is returned; invalid configurations produce `ConfigError` instead of
//! panicking. Sensitive fields remain redacted in `Debug`.

use std::collections::HashMap;

use thiserror::Error;

use crate::obfuscation::{Profile, FOX_DOMAINS};

/// Runtime configuration grouped by subsystem.
#[derive(Clone)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub admin: AdminConfig,
    pub oracle: OracleConfig,
    pub obfuscation: ObfuscationConfig,
    pub tls: TlsConfig,
    pub wireguard: WireGuardConfig,
    pub runtime: RuntimeConfig,
}

/// Explicit proxy credentials loaded from environment or files.
#[derive(Clone)]
pub struct ProxyCredentials {
    pub username: String,
    pub password: String,
}

/// Proxy listener and tunnel runtime settings.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub port: u16,
    pub transparent_port: u16,
    pub explicit_enabled: bool,
    pub max_connections: usize,
    pub tarpit_max_connections: usize,
    pub credentials: Option<ProxyCredentials>,
    pub upstream_proxy: Option<String>,
    pub tunnel_endpoint: Option<String>,
    pub enable_dns_lookups: bool,
}

/// Admin API settings.
#[derive(Clone)]
pub struct AdminConfig {
    pub port: u16,
    pub api_key: String,
    pub cors_allowed_origins: Vec<String>,
}

/// Oracle connectivity settings.
#[derive(Clone)]
pub struct OracleConfig {
    pub conn: String,
    pub user: String,
    #[cfg_attr(not(feature = "oracle-db"), allow(dead_code))]
    pub pass: Option<String>,
    pub pass_file: String,
    pub tns_admin: Option<String>,
}

/// Traffic obfuscation settings and prebuilt domain map.
#[derive(Clone, Debug)]
pub struct ObfuscationConfig {
    pub enabled: bool,
    pub enabled_profiles: Vec<String>,
    pub fox_ua_override: String,
    pub domain_map: HashMap<String, Profile>,
}

/// TLS listener certificate settings.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

/// WireGuard ingress settings.
#[derive(Clone, Debug)]
pub struct WireGuardConfig {
    pub port: u16,
    pub interface: Option<String>,
}

/// Runtime-only logging settings.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub log_format: String,
}

/// Typed configuration loading errors returned by `Config::from_env()`.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("PROXY_PORT must not equal WG_PORT")]
    PortConflict,
    #[error("ORACLE_CONN is required when oracle-db feature is enabled")]
    MissingOracleConn,
    #[error("ORACLE_USER is required when oracle-db feature is enabled")]
    MissingOracleUser,
    #[error("ADMIN_API_KEY is required and must not be empty")]
    MissingAdminApiKey,
    #[error(
        "PROXY_USERNAME is set but PROXY_PASSWORD is missing (both are required for proxy auth)"
    )]
    MissingProxyPassword,
    #[error(
        "PROXY_PASSWORD is set but PROXY_USERNAME is missing (both are required for proxy auth)"
    )]
    MissingProxyUsername,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("proxy", &self.proxy)
            .field("admin", &self.admin)
            .field("oracle", &self.oracle)
            .field("obfuscation", &self.obfuscation)
            .field("tls", &self.tls)
            .field("wireguard", &self.wireguard)
            .field("runtime", &self.runtime)
            .finish()
    }
}

impl std::fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for AdminConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminConfig")
            .field("port", &self.port)
            .field("api_key", &"[REDACTED]")
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .finish()
    }
}

impl std::fmt::Debug for OracleConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleConfig")
            .field("conn", &self.conn)
            .field("user", &self.user)
            .field("pass", &"[REDACTED]")
            .field("pass_file", &self.pass_file)
            .field("tns_admin", &self.tns_admin)
            .finish()
    }
}

impl Config {
    /// Load and validate configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let proxy = ProxyConfig::from_env()?;
        let admin = AdminConfig::from_env()?;
        let oracle = OracleConfig::from_env()?;
        let obfuscation = ObfuscationConfig::from_env();
        let tls = TlsConfig::from_env();
        let wireguard = WireGuardConfig::from_env();
        let runtime = RuntimeConfig::from_env();

        if proxy.port == proxy.transparent_port
            || proxy.transparent_port == wireguard.port
            || proxy.port == wireguard.port
            || admin.port == proxy.port
            || admin.port == proxy.transparent_port
            || admin.port == wireguard.port
        {
            return Err(ConfigError::PortConflict);
        }

        oracle.validate()?;

        Ok(Self {
            proxy,
            admin,
            oracle,
            obfuscation,
            tls,
            wireguard,
            runtime,
        })
    }

    /// Load config from environment and panic on failure.
    pub fn from_env_or_panic() -> Self {
        match Config::from_env() {
            Ok(cfg) => cfg,
            Err(e) => panic!("Configuration error: {e}"),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        let mut config = Self::default();
        config.admin.api_key = "test-key".to_string();
        config
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut config = Self {
            proxy: ProxyConfig {
                port: 3000,
                transparent_port: 3001,
                explicit_enabled: false,
                max_connections: 4096,
                tarpit_max_connections: 64,
                credentials: None,
                upstream_proxy: None,
                tunnel_endpoint: None,
                enable_dns_lookups: false,
            },
            admin: AdminConfig {
                port: 3002,
                api_key: String::new(),
                cors_allowed_origins: vec![],
            },
            oracle: OracleConfig {
                conn: String::new(),
                user: String::new(),
                pass: None,
                pass_file: String::new(),
                tns_admin: None,
            },
            obfuscation: ObfuscationConfig {
                enabled: true,
                enabled_profiles: vec![
                    "fox-news".to_string(),
                    "fox-sports".to_string(),
                    "fox-general".to_string(),
                    "fox-cdn".to_string(),
                    "fx-network".to_string(),
                ],
                fox_ua_override: "Mozilla/5.0 (Test UA)".to_string(),
                domain_map: HashMap::new(),
            },
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            wireguard: WireGuardConfig {
                port: 51820,
                interface: None,
            },
            runtime: RuntimeConfig {
                log_format: "human".to_string(),
            },
        };
        config.obfuscation.domain_map = build_domain_map(&config.obfuscation.enabled_profiles);
        config
    }
}

impl ProxyConfig {
    fn from_env() -> Result<Self, ConfigError> {
        let username = std::env::var("PROXY_USERNAME")
            .ok()
            .filter(|s| !s.is_empty());
        let password = read_secret("PROXY_PASSWORD", "PROXY_PASSWORD_FILE");

        let credentials = match (username, password) {
            (Some(username), Some(password)) => Some(ProxyCredentials { username, password }),
            (Some(_), None) => return Err(ConfigError::MissingProxyPassword),
            (None, Some(_)) => return Err(ConfigError::MissingProxyUsername),
            (None, None) => None,
        };

        Ok(Self {
            port: read_port("PROXY_PORT", 3000),
            transparent_port: read_port("TPROXY_PORT", 3001),
            explicit_enabled: read_bool("EXPLICIT_PROXY_ENABLED", false),
            max_connections: read_usize("MAX_CONNECTIONS", 4096),
            tarpit_max_connections: read_usize("TARPIT_MAX_CONNECTIONS", 64),
            credentials,
            upstream_proxy: std::env::var("UPSTREAM_PROXY")
                .ok()
                .filter(|s| !s.is_empty()),
            tunnel_endpoint: std::env::var("TUNNEL_ENDPOINT")
                .ok()
                .filter(|s| !s.is_empty()),
            enable_dns_lookups: read_bool("ENABLE_DNS_LOOKUPS", false),
        })
    }
}

impl AdminConfig {
    fn from_env() -> Result<Self, ConfigError> {
        let api_key = read_secret("ADMIN_API_KEY", "ADMIN_API_KEY_FILE")
            .ok_or(ConfigError::MissingAdminApiKey)?;
        Ok(Self {
            port: read_port("ADMIN_PORT", 3002),
            api_key,
            cors_allowed_origins: std::env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }
}

impl OracleConfig {
    fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            conn: std::env::var("ORACLE_CONN").unwrap_or_default(),
            user: std::env::var("ORACLE_USER").unwrap_or_default(),
            pass: read_secret("ORACLE_PASS", "ORACLE_PASS_FILE"),
            pass_file: std::env::var("ORACLE_PASS_FILE").unwrap_or_default(),
            tns_admin: std::env::var("TNS_ADMIN").ok().filter(|s| !s.is_empty()),
        })
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.conn.is_empty() && cfg!(feature = "oracle-db") {
            return Err(ConfigError::MissingOracleConn);
        }
        if self.user.is_empty() && cfg!(feature = "oracle-db") {
            return Err(ConfigError::MissingOracleUser);
        }
        Ok(())
    }
}

impl ObfuscationConfig {
    fn from_env() -> Self {
        let enabled_profiles: Vec<String> = std::env::var("OBFUSCATION_PROFILE")
            .unwrap_or_else(|_| "fox-news,fox-sports".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            enabled: read_bool("OBFUSCATION_ENABLED", true),
            fox_ua_override: std::env::var("FOX_UA_OVERRIDE").unwrap_or_else(|_| {
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
                    .to_string()
            }),
            domain_map: build_domain_map(&enabled_profiles),
            enabled_profiles,
        }
    }
}

impl TlsConfig {
    fn from_env() -> Self {
        Self {
            cert_path: std::env::var("TLS_CERT_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            key_path: std::env::var("TLS_KEY_PATH").ok().filter(|s| !s.is_empty()),
        }
    }
}

impl WireGuardConfig {
    fn from_env() -> Self {
        Self {
            port: read_port("WG_PORT", 51820),
            interface: std::env::var("WG_INTERFACE").ok().filter(|s| !s.is_empty()),
        }
    }
}

impl RuntimeConfig {
    fn from_env() -> Self {
        Self {
            log_format: std::env::var("LOG_FORMAT").unwrap_or_else(|_| "human".to_string()),
        }
    }
}

fn build_domain_map(enabled_profiles: &[String]) -> HashMap<String, Profile> {
    let mut map = HashMap::new();
    for (pattern, profile_name) in FOX_DOMAINS {
        let Some(profile) = Profile::from_name(profile_name) else {
            continue;
        };
        if !enabled_profiles
            .iter()
            .any(|enabled| enabled == profile.as_str())
        {
            continue;
        }
        if let Some(stripped) = pattern.strip_prefix("*.") {
            map.insert(format!(".{}", stripped), profile);
        } else {
            map.insert((*pattern).to_string(), profile);
        }
    }
    map
}

fn read_port(var: &str, default: u16) -> u16 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn read_usize(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn read_bool(var: &str, default: bool) -> bool {
    std::env::var(var)
        .map(|v| match v.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => true,
            "false" | "0" | "no" | "off" => false,
            _ => default,
        })
        .unwrap_or(default)
}

fn read_secret(var: &str, file_var: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let file = std::env::var(file_var).unwrap_or_default();
            if file.is_empty() {
                return None;
            }
            std::fs::read_to_string(file)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn clear_env() {
        for key in [
            "PROXY_PORT",
            "TPROXY_PORT",
            "WG_PORT",
            "ADMIN_PORT",
            "EXPLICIT_PROXY_ENABLED",
            "WG_INTERFACE",
            "MAX_CONNECTIONS",
            "TARPIT_MAX_CONNECTIONS",
            "ADMIN_API_KEY",
            "ADMIN_API_KEY_FILE",
            "CORS_ALLOWED_ORIGINS",
            "LOG_FORMAT",
            "ORACLE_CONN",
            "ORACLE_USER",
            "ORACLE_PASS",
            "ORACLE_PASS_FILE",
            "TNS_ADMIN",
            "OBFUSCATION_ENABLED",
            "OBFUSCATION_PROFILE",
            "FOX_UA_OVERRIDE",
            "TLS_CERT_PATH",
            "TLS_KEY_PATH",
            "PROXY_USERNAME",
            "PROXY_PASSWORD",
            "PROXY_PASSWORD_FILE",
            "TUNNEL_ENDPOINT",
            "UPSTREAM_PROXY",
            "ENABLE_DNS_LOOKUPS",
        ] {
            std::env::remove_var(key);
        }
    }

    fn set_oracle_env_defaults() {
        if cfg!(feature = "oracle-db") {
            std::env::set_var("ORACLE_CONN", "test_conn");
            std::env::set_var("ORACLE_USER", "test_user");
        }
    }

    #[test]
    fn config_port_conflict_error() {
        let _guard = env_lock();
        clear_env();
        set_oracle_env_defaults();
        std::env::set_var("PROXY_PORT", "51820");
        std::env::set_var("WG_PORT", "51820");
        std::env::set_var("ADMIN_API_KEY", "test-key");

        let result = Config::from_env();
        assert!(matches!(result, Err(ConfigError::PortConflict)));
    }

    #[test]
    #[cfg(feature = "oracle-db")]
    fn config_missing_oracle_conn_error() {
        let _guard = env_lock();
        clear_env();
        std::env::remove_var("ORACLE_CONN");
        std::env::set_var("ORACLE_USER", "test_user");
        std::env::set_var("ADMIN_API_KEY", "test-key");

        let result = Config::from_env();
        assert!(matches!(result, Err(ConfigError::MissingOracleConn)));
    }

    #[test]
    #[cfg(feature = "oracle-db")]
    fn config_missing_oracle_user_error() {
        let _guard = env_lock();
        clear_env();
        std::env::set_var("ORACLE_CONN", "test_conn");
        std::env::remove_var("ORACLE_USER");
        std::env::set_var("ADMIN_API_KEY", "test-key");

        let result = Config::from_env();
        assert!(matches!(result, Err(ConfigError::MissingOracleUser)));
    }

    #[test]
    fn explicit_proxy_disabled_by_default() {
        let _guard = env_lock();
        clear_env();
        set_oracle_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-key");

        let result = Config::from_env().unwrap();

        assert!(!result.proxy.explicit_enabled);
    }

    #[test]
    fn explicit_proxy_enabled_when_requested() {
        let _guard = env_lock();
        clear_env();
        set_oracle_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-key");
        std::env::set_var("EXPLICIT_PROXY_ENABLED", "true");

        let result = Config::from_env().unwrap();

        assert!(result.proxy.explicit_enabled);
    }

    #[test]
    fn admin_config_debug_redacts_api_key() {
        let config = AdminConfig {
            port: 3002,
            api_key: "super-secret".to_string(),
            cors_allowed_origins: vec!["https://example.com".to_string()],
        };

        let rendered = format!("{config:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("super-secret"));
    }

    #[test]
    fn oracle_config_reads_password_from_file() {
        let _guard = env_lock();
        clear_env();
        let path = std::env::temp_dir().join(format!(
            "boringtun-oracle-pass-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(&path, "file-secret\n").unwrap();
        std::env::set_var("ORACLE_PASS_FILE", &path);

        let oracle = OracleConfig::from_env().unwrap();

        assert_eq!(oracle.pass.as_deref(), Some("file-secret"));
        assert_eq!(oracle.pass_file, path.display().to_string());

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn config_default_uses_empty_admin_api_key() {
        assert!(Config::default().admin.api_key.is_empty());
    }

    #[test]
    fn config_for_tests_uses_test_admin_api_key() {
        assert_eq!(Config::for_tests().admin.api_key, "test-key");
    }
}
