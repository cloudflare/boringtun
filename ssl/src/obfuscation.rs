use std::collections::HashMap;

/// Hardcoded seed domains for obfuscation profiles.
/// These domains will have their traffic normalized to avoid fingerprinting.
pub const FOX_DOMAINS: &[(&str, &str)] = &[
    // fox-news
    ("foxnews.com", "fox-news"),
    ("*.foxnews.com", "fox-news"),
    // fox-sports
    ("foxsports.com", "fox-sports"),
    ("*.foxsports.com", "fox-sports"),
    // fox-general
    ("fox.com", "fox-general"),
    ("*.fox.com", "fox-general"),
    ("foxbusiness.com", "fox-general"),
    ("*.foxbusiness.com", "fox-general"),
    // fox-cdn
    ("fox-cdn.com", "fox-cdn"),
    ("*.akamaized.net", "fox-cdn"),
    // fx-network
    ("fxnetworks.com", "fx-network"),
    ("*.fxnetworks.com", "fx-network"),
];

/// Obfuscation profile for traffic normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    FoxNews,
    FoxSports,
    FoxGeneral,
    FoxCdn,
    FxNetwork,
    None,
}

impl Profile {
    /// Convert profile to string for logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Profile::FoxNews => "fox-news",
            Profile::FoxSports => "fox-sports",
            Profile::FoxGeneral => "fox-general",
            Profile::FoxCdn => "fox-cdn",
            Profile::FxNetwork => "fx-network",
            Profile::None => "none",
        }
    }
}

/// Classify a hostname into an obfuscation profile by walking the domain hierarchy.
/// Similar to `is_blocked` but returns the matching profile instead of a boolean.
pub fn classify_obfuscation(hostname: &str, config: &crate::config::Config) -> Profile {
    // Early exit if obfuscation is globally disabled
    if !config.obfuscation_enabled {
        return Profile::None;
    }

    let normalized = hostname.to_ascii_lowercase();
    let normalized = normalized.trim_end_matches('.');
    let mut domain = normalized;

    // Build a lookup map for efficient matching
    let mut profile_map = HashMap::new();
    for (pattern, profile_str) in FOX_DOMAINS {
        let profile = match *profile_str {
            "fox-news" => Profile::FoxNews,
            "fox-sports" => Profile::FoxSports,
            "fox-general" => Profile::FoxGeneral,
            "fox-cdn" => Profile::FoxCdn,
            "fx-network" => Profile::FxNetwork,
            _ => continue,
        };

        // Only include profiles that are enabled in configuration
        if !config
            .obfuscation_profile
            .contains(&profile.as_str().to_string())
        {
            continue;
        }

        if pattern.starts_with("*.") {
            // Wildcard pattern: *.example.com matches sub.example.com but NOT example.com itself
            let base = &pattern[2..]; // Remove *.
            profile_map.insert(format!(".{}", base), profile);
        } else {
            // Exact match
            profile_map.insert(pattern.to_string(), profile);
        }
    }

    // Walk up the domain hierarchy
    loop {
        // Check for exact match first
        if let Some(profile) = profile_map.get(domain) {
            return *profile;
        }

        // Check for wildcard subdomain match (with leading dot)
        let wildcard_key = format!(".{}", domain);
        if let Some(profile) = profile_map.get(&wildcard_key) {
            return *profile;
        }

        // Move to parent domain
        match domain.find('.') {
            Some(idx) => domain = &domain[idx + 1..],
            None => return Profile::None,
        }
    }
}

/// Apply request header obfuscation for Fox profiles.
/// Strips proxy-related headers and normalizes User-Agent.
pub fn apply_request_headers(
    headers: &mut axum::http::HeaderMap,
    profile: &Profile,
    config: &crate::config::Config,
) {
    if matches!(profile, Profile::None) {
        return;
    }

    // Strip proxy-forwarding headers that could leak client information
    headers.remove("x-forwarded-for");
    headers.remove("via");
    headers.remove("forwarded");

    // Remove privacy-signal headers that could cause server-side fingerprint deviation
    headers.remove("dnt");
    headers.remove("sec-gpc");

    // Normalize User-Agent to configured override string
    if !config.fox_ua_override.is_empty() {
        headers.insert(
            "user-agent",
            axum::http::HeaderValue::from_str(&config.fox_ua_override).unwrap_or_else(|_| {
                axum::http::HeaderValue::from_static("Mozilla/5.0 (compatible; Generic/1.0)")
            }),
        );
    }
}

/// Apply response header obfuscation for Fox profiles.
/// Strips CDN leak headers while preserving security headers.
pub fn apply_response_headers(headers: &mut axum::http::HeaderMap, profile: &Profile) {
    if matches!(profile, Profile::None) {
        return;
    }

    // Strip CDN leak headers
    headers.remove("x-cache");
    headers.remove("x-edge-ip");
    headers.remove("x-served-by");

    // Note: Content-Security-Policy is intentionally preserved as it's a security header
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::http::{HeaderMap, HeaderValue};

    fn test_config() -> Config {
        Config {
            proxy_port: 3000,
            tproxy_port: 3001,
            wg_port: 51820,
            wg_interface: None,
            max_connections: 4096,
            tarpit_max_connections: 64,
            admin_api_key: "test-key".to_string(),
            cors_allowed_origins: vec![],
            log_format: "human".to_string(),
            oracle_conn: "".to_string(),
            oracle_user: "".to_string(),
            oracle_pass_file: "".to_string(),
            obfuscation_profiles: "".to_string(),
            obfuscation_enabled: true,
            obfuscation_profile: vec![
                "fox-news".to_string(),
                "fox-sports".to_string(),
                "fox-general".to_string(),
                "fox-cdn".to_string(),
                "fx-network".to_string(),
            ],
            fox_ua_override: "Mozilla/5.0 (Test UA)".to_string(),
            tls_cert_path: None,
            tls_key_path: None,
        }
    }

    #[test]
    fn test_classify_obfuscation_fox_news() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("foxnews.com", &config),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("www.foxnews.com", &config),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("api.foxnews.com", &config),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("sub.api.foxnews.com", &config),
            Profile::FoxNews
        );
    }

    #[test]
    fn test_classify_obfuscation_fox_sports() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("foxsports.com", &config),
            Profile::FoxSports
        );
        assert_eq!(
            classify_obfuscation("www.foxsports.com", &config),
            Profile::FoxSports
        );
        assert_eq!(
            classify_obfuscation("api.foxsports.com", &config),
            Profile::FoxSports
        );
        assert_eq!(
            classify_obfuscation("sub.api.foxsports.com", &config),
            Profile::FoxSports
        );
    }

    #[test]
    fn test_classify_obfuscation_none() {
        let config = test_config();
        assert_eq!(classify_obfuscation("google.com", &config), Profile::None);
        assert_eq!(classify_obfuscation("example.com", &config), Profile::None);
        assert_eq!(classify_obfuscation("notfox.com", &config), Profile::None);
    }

    #[test]
    fn test_classify_obfuscation_case_insensitive() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("FOXNEWS.COM", &config),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("FoxSports.Com", &config),
            Profile::FoxSports
        );
    }

    #[test]
    fn test_classify_obfuscation_trailing_dot() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("foxnews.com.", &config),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("www.foxnews.com.", &config),
            Profile::FoxNews
        );
    }

    #[test]
    fn test_apply_request_headers_fox_profile() {
        let config = test_config();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.1"));
        headers.insert("via", HeaderValue::from_static("proxy.example.com"));
        headers.insert("forwarded", HeaderValue::from_static("for=192.168.1.1"));
        headers.insert("dnt", HeaderValue::from_static("1"));
        headers.insert("sec-gpc", HeaderValue::from_static("1"));
        headers.insert("user-agent", HeaderValue::from_static("Custom/1.0"));

        apply_request_headers(&mut headers, &Profile::FoxNews, &config);

        assert!(!headers.contains_key("x-forwarded-for"));
        assert!(!headers.contains_key("via"));
        assert!(!headers.contains_key("forwarded"));
        assert!(!headers.contains_key("dnt"));
        assert!(!headers.contains_key("sec-gpc"));
        assert!(headers.contains_key("user-agent"));
    }

    #[test]
    fn test_apply_request_headers_none_profile() {
        let config = test_config();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.1"));
        headers.insert("user-agent", HeaderValue::from_static("Custom/1.0"));

        apply_request_headers(&mut headers, &Profile::None, &config);

        assert!(headers.contains_key("x-forwarded-for"));
        assert!(headers.contains_key("user-agent"));
    }

    #[test]
    fn test_apply_request_headers_ua_override() {
        let mut config = test_config();
        config.fox_ua_override = "TestUA/1.0".to_string();

        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("Original/1.0"));

        apply_request_headers(&mut headers, &Profile::FoxNews, &config);

        assert_eq!(headers.get("user-agent").unwrap(), "TestUA/1.0");
    }

    #[test]
    fn test_apply_response_headers_fox_profile() {
        let mut headers = HeaderMap::new();
        headers.insert("x-cache", HeaderValue::from_static("HIT"));
        headers.insert("x-edge-ip", HeaderValue::from_static("1.2.3.4"));
        headers.insert("x-served-by", HeaderValue::from_static("cdn.example.com"));
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static("default-src 'self'"),
        );

        apply_response_headers(&mut headers, &Profile::FoxNews);

        assert!(!headers.contains_key("x-cache"));
        assert!(!headers.contains_key("x-edge-ip"));
        assert!(!headers.contains_key("x-served-by"));
        // CSP should be preserved
        assert!(headers.contains_key("content-security-policy"));
    }

    #[test]
    fn test_apply_response_headers_none_profile() {
        let mut headers = HeaderMap::new();
        headers.insert("x-cache", HeaderValue::from_static("HIT"));
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static("default-src 'self'"),
        );

        apply_response_headers(&mut headers, &Profile::None);

        // Headers should be unchanged
        assert!(headers.contains_key("x-cache"));
        assert!(headers.contains_key("content-security-policy"));
    }
}
