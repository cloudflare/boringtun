//! Traffic obfuscation for Fox-family domains.
//!
//! This module classifies outbound hostnames into a `Profile` and normalizes
//! request and response headers to reduce proxy fingerprinting. It does not
//! modify request bodies or TLS payloads.

use crate::config::ObfuscationConfig;

/// Hardcoded seed domains for obfuscation profiles.
pub const FOX_DOMAINS: &[(&str, &str)] = &[
    ("foxnews.com", "fox-news"),
    ("*.foxnews.com", "fox-news"),
    ("foxsports.com", "fox-sports"),
    ("*.foxsports.com", "fox-sports"),
    ("fox.com", "fox-general"),
    ("*.fox.com", "fox-general"),
    ("foxbusiness.com", "fox-general"),
    ("*.foxbusiness.com", "fox-general"),
    ("fox-cdn.com", "fox-cdn"),
    ("*.akamaized.net", "fox-cdn"),
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
    /// Convert the profile to its configured string form.
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

    /// Convert a configured profile name into the enum variant.
    pub(crate) fn from_name(value: &str) -> Option<Self> {
        match value {
            "fox-news" => Some(Profile::FoxNews),
            "fox-sports" => Some(Profile::FoxSports),
            "fox-general" => Some(Profile::FoxGeneral),
            "fox-cdn" => Some(Profile::FoxCdn),
            "fx-network" => Some(Profile::FxNetwork),
            _ => None,
        }
    }
}

/// Classify a hostname into an obfuscation profile.
pub fn classify_obfuscation(hostname: &str, config: &ObfuscationConfig) -> Profile {
    if !config.enabled {
        return Profile::None;
    }

    let normalized = hostname.to_ascii_lowercase();
    let normalized = normalized.trim_end_matches('.');
    let mut domain = normalized;

    loop {
        if let Some(profile) = config.domain_map.get(domain) {
            return *profile;
        }

        let wildcard_key = format!(".{}", domain);
        if let Some(profile) = config.domain_map.get(&wildcard_key) {
            return *profile;
        }

        match domain.find('.') {
            Some(idx) => domain = &domain[idx + 1..],
            None => return Profile::None,
        }
    }
}

/// Apply request header obfuscation for Fox profiles.
pub fn apply_request_headers(
    headers: &mut axum::http::HeaderMap,
    profile: &Profile,
    config: &ObfuscationConfig,
) {
    if matches!(profile, Profile::None) {
        return;
    }

    headers.remove("x-forwarded-for");
    headers.remove("via");
    headers.remove("forwarded");
    headers.remove("dnt");
    headers.remove("sec-gpc");

    let ua = if config.fox_ua_override.is_empty() {
        axum::http::HeaderValue::from_static("Mozilla/5.0 (compatible; Generic/1.0)")
    } else {
        axum::http::HeaderValue::from_str(&config.fox_ua_override).unwrap_or_else(|_| {
            axum::http::HeaderValue::from_static("Mozilla/5.0 (compatible; Generic/1.0)")
        })
    };
    headers.insert("user-agent", ua);
}

/// Apply response header obfuscation for Fox profiles.
pub fn apply_response_headers(headers: &mut axum::http::HeaderMap, profile: &Profile) {
    if matches!(profile, Profile::None) {
        return;
    }

    headers.remove("x-cache");
    headers.remove("x-edge-ip");
    headers.remove("x-served-by");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn test_config() -> crate::config::Config {
        crate::config::Config::for_tests()
    }

    #[test]
    fn classify_obfuscation_fox_news() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("foxnews.com", &config.obfuscation),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("www.foxnews.com", &config.obfuscation),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("api.foxnews.com", &config.obfuscation),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("sub.api.foxnews.com", &config.obfuscation),
            Profile::FoxNews
        );
    }

    #[test]
    fn classify_obfuscation_fox_sports() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("foxsports.com", &config.obfuscation),
            Profile::FoxSports
        );
        assert_eq!(
            classify_obfuscation("www.foxsports.com", &config.obfuscation),
            Profile::FoxSports
        );
        assert_eq!(
            classify_obfuscation("api.foxsports.com", &config.obfuscation),
            Profile::FoxSports
        );
        assert_eq!(
            classify_obfuscation("sub.api.foxsports.com", &config.obfuscation),
            Profile::FoxSports
        );
    }

    #[test]
    fn classify_obfuscation_none() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("google.com", &config.obfuscation),
            Profile::None
        );
        assert_eq!(
            classify_obfuscation("example.com", &config.obfuscation),
            Profile::None
        );
        assert_eq!(
            classify_obfuscation("notfox.com", &config.obfuscation),
            Profile::None
        );
    }

    #[test]
    fn classify_obfuscation_case_insensitive() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("FOXNEWS.COM", &config.obfuscation),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("FoxSports.Com", &config.obfuscation),
            Profile::FoxSports
        );
    }

    #[test]
    fn classify_obfuscation_trailing_dot() {
        let config = test_config();
        assert_eq!(
            classify_obfuscation("foxnews.com.", &config.obfuscation),
            Profile::FoxNews
        );
        assert_eq!(
            classify_obfuscation("www.foxnews.com.", &config.obfuscation),
            Profile::FoxNews
        );
    }

    #[test]
    fn apply_request_headers_fox_profile() {
        let config = test_config();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.1"));
        headers.insert("via", HeaderValue::from_static("proxy.example.com"));
        headers.insert("forwarded", HeaderValue::from_static("for=192.168.1.1"));
        headers.insert("dnt", HeaderValue::from_static("1"));
        headers.insert("sec-gpc", HeaderValue::from_static("1"));
        headers.insert("user-agent", HeaderValue::from_static("Custom/1.0"));

        apply_request_headers(&mut headers, &Profile::FoxNews, &config.obfuscation);

        assert!(!headers.contains_key("x-forwarded-for"));
        assert!(!headers.contains_key("via"));
        assert!(!headers.contains_key("forwarded"));
        assert!(!headers.contains_key("dnt"));
        assert!(!headers.contains_key("sec-gpc"));
        assert!(headers.contains_key("user-agent"));
    }

    #[test]
    fn apply_request_headers_none_profile() {
        let config = test_config();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.1"));
        headers.insert("user-agent", HeaderValue::from_static("Custom/1.0"));

        apply_request_headers(&mut headers, &Profile::None, &config.obfuscation);

        assert!(headers.contains_key("x-forwarded-for"));
        assert!(headers.contains_key("user-agent"));
    }

    #[test]
    fn apply_request_headers_ua_override() {
        let mut config = test_config();
        config.obfuscation.fox_ua_override = "TestUA/1.0".to_string();

        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("Original/1.0"));

        apply_request_headers(&mut headers, &Profile::FoxNews, &config.obfuscation);

        assert_eq!(headers.get("user-agent").unwrap(), "TestUA/1.0");
    }

    #[test]
    fn apply_response_headers_fox_profile() {
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
        assert!(headers.contains_key("content-security-policy"));
    }

    #[test]
    fn apply_response_headers_none_profile() {
        let mut headers = HeaderMap::new();
        headers.insert("x-cache", HeaderValue::from_static("HIT"));
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static("default-src 'self'"),
        );

        apply_response_headers(&mut headers, &Profile::None);

        assert!(headers.contains_key("x-cache"));
        assert!(headers.contains_key("content-security-policy"));
    }
}
