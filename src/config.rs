/// Configuration loaded from environment variables at startup.
#[derive(Clone)]
pub struct Config {
    pub proxy_port: u16,
    pub tproxy_port: u16,
    pub wg_port: u16,
    pub wg_interface: Option<String>,
    pub max_connections: usize,
    pub tarpit_max_connections: usize,
    pub admin_api_key: Option<String>,
    pub cors_allowed_origins: Vec<String>,
    pub log_format: String,
    pub oracle_conn: String,
    pub oracle_user: String,
    pub oracle_pass: Option<String>,
    pub oracle_pass_file: String,
    pub obfuscation_profiles: String,
    pub obfuscation_enabled: bool,
    pub obfuscation_profile: Vec<String>,
    pub fox_ua_override: String,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,
    pub proxy_password_file: String,
    pub tunnel_endpoint: Option<String>,
    pub upstream_proxy: Option<String>,
    pub enable_dns_lookups: bool,
}

use thiserror::Error;

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

#[cfg(test)]
mod tests {
    use super::*;

#[test]
fn test_config_port_conflict_error() {
    std::env::set_var("PROXY_PORT", "51820");
    std::env::set_var("WG_PORT", "51820");
    std::env::set_var("ADMIN_API_KEY", "test-key");

    let result = Config::from_env();
    assert!(matches!(result, Err(ConfigError::PortConflict)));
}

#[test]
#[cfg(feature = "oracle-db")]
fn test_config_missing_oracle_conn_error() {
    std::env::remove_var("ORACLE_CONN");
    std::env::set_var("ORACLE_USER", "test_user");
    std::env::set_var("ADMIN_API_KEY", "test-key");

    let result = Config::from_env();
    assert!(matches!(result, Err(ConfigError::MissingOracleConn)));
}

#[test]
#[cfg(feature = "oracle-db")]
fn test_config_missing_oracle_user_error() {
    std::env::set_var("ORACLE_CONN", "test_conn");
    std::env::remove_var("ORACLE_USER");
    std::env::set_var("ADMIN_API_KEY", "test-key");

    let result = Config::from_env();
    assert!(matches!(result, Err(ConfigError::MissingOracleUser)));
}
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("proxy_port", &self.proxy_port)
            .field("tproxy_port", &self.tproxy_port)
            .field("wg_port", &self.wg_port)
            .field("wg_interface", &self.wg_interface)
            .field("max_connections", &self.max_connections)
            .field("tarpit_max_connections", &self.tarpit_max_connections)
            .field("admin_api_key", &"[REDACTED]")
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field("log_format", &self.log_format)
            .field("oracle_conn", &self.oracle_conn)
            .field("oracle_user", &self.oracle_user)
            .field("oracle_pass", &"[REDACTED]")
            .field("oracle_pass_file", &self.oracle_pass_file)
            .field("obfuscation_profiles", &self.obfuscation_profiles)
            .field("obfuscation_enabled", &self.obfuscation_enabled)
            .field("obfuscation_profile", &self.obfuscation_profile)
            .field("fox_ua_override", &self.fox_ua_override)
            .field("tls_cert_path", &self.tls_cert_path)
            .field("tls_key_path", &self.tls_key_path)
            .field("proxy_username", &self.proxy_username)
            .field("proxy_password", &"[REDACTED]")
            .field("proxy_password_file", &self.proxy_password_file)
            .field("tunnel_endpoint", &self.tunnel_endpoint)
            .finish()
    }
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let proxy_port = std::env::var("PROXY_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3000);
        let tproxy_port = std::env::var("TPROXY_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3001);
        let wg_port = std::env::var("WG_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(51820);
        let wg_interface = std::env::var("WG_INTERFACE").ok();
        let max_connections = std::env::var("MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4096);
        let tarpit_max_connections = std::env::var("TARPIT_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(64);
        let admin_api_key_file = std::env::var("ADMIN_API_KEY_FILE").unwrap_or_default();
        let admin_api_key = std::env::var("ADMIN_API_KEY")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                if !admin_api_key_file.is_empty() {
                    std::fs::read_to_string(&admin_api_key_file)
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                } else {
                    None
                }
            });
        let cors_allowed_origins = std::env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let log_format = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "human".to_string());
        let oracle_conn = std::env::var("ORACLE_CONN").unwrap_or_default();
        let oracle_user = std::env::var("ORACLE_USER").unwrap_or_default();
        let oracle_pass = std::env::var("ORACLE_PASS").ok().filter(|s| !s.is_empty());
        let oracle_pass_file = std::env::var("ORACLE_PASS_FILE").unwrap_or_default();
        let obfuscation_profiles = std::env::var("OBFUSCATION_PROFILES").unwrap_or_default();
        let obfuscation_enabled = std::env::var("OBFUSCATION_ENABLED")
            .map(|v| match v.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => true,
                "false" | "0" | "no" | "off" => false,
                _ => true, // default
            })
            .unwrap_or(true);
        let obfuscation_profile = std::env::var("OBFUSCATION_PROFILE")
            .unwrap_or_else(|_| "fox-news,fox-sports".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let fox_ua_override = std::env::var("FOX_UA_OVERRIDE").unwrap_or_else(|_| {
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
                .to_string()
        });
        let tls_cert_path = std::env::var("TLS_CERT_PATH")
            .ok()
            .filter(|s| !s.is_empty());
        let tls_key_path = std::env::var("TLS_KEY_PATH").ok().filter(|s| !s.is_empty());
        let proxy_username = std::env::var("PROXY_USERNAME")
            .ok()
            .filter(|s| !s.is_empty());
        let proxy_password_file = std::env::var("PROXY_PASSWORD_FILE").unwrap_or_default();
        let proxy_password = std::env::var("PROXY_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                if !proxy_password_file.is_empty() {
                    std::fs::read_to_string(&proxy_password_file)
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                } else {
                    None
                }
            });

        let tunnel_endpoint = std::env::var("TUNNEL_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty());

        let upstream_proxy = std::env::var("UPSTREAM_PROXY")
            .ok()
            .filter(|s| !s.is_empty());
            
        let enable_dns_lookups = std::env::var("ENABLE_DNS_LOOKUPS")
            .map(|v| match v.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => true,
                "false" | "0" | "no" | "off" => false,
                _ => false, // Default OFF - no DNS leaks
            })
            .unwrap_or(false);

        // Validate required fields
        if proxy_port == tproxy_port || tproxy_port == wg_port || proxy_port == wg_port {
            return Err(ConfigError::PortConflict);
        }
        if oracle_conn.is_empty() && cfg!(feature = "oracle-db") {
            return Err(ConfigError::MissingOracleConn);
        }
        if oracle_user.is_empty() && cfg!(feature = "oracle-db") {
            return Err(ConfigError::MissingOracleUser);
        }
        if proxy_username.is_some() && proxy_password.is_none() {
            return Err(ConfigError::MissingProxyPassword);
        }
        if proxy_password.is_some() && proxy_username.is_none() {
            return Err(ConfigError::MissingProxyUsername);
        }
        if admin_api_key.is_none() {
            return Err(ConfigError::MissingAdminApiKey);
        }

        Ok(Self {
            proxy_port,
            tproxy_port,
            wg_port,
            wg_interface,
            max_connections,
            tarpit_max_connections,
            admin_api_key,
            cors_allowed_origins,
            log_format,
            oracle_conn,
            oracle_user,
            oracle_pass,
            oracle_pass_file,
            obfuscation_profiles,
            obfuscation_enabled,
            obfuscation_profile,
            fox_ua_override,
            tls_cert_path,
            tls_key_path,
            proxy_username,
            proxy_password,
            proxy_password_file,
            tunnel_endpoint,
            upstream_proxy,
            enable_dns_lookups,
        })
    }

    /// Load config from environment and exit process on failure (for tests and main)
    pub fn from_env_or_panic() -> Self {
        match Config::from_env() {
            Ok(cfg) => cfg,
            Err(e) => {
                panic!("Configuration error: {}", e);
            }
        }
    }
}
