// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Integration test for obfuscation UA override behavior.

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};
    use ssl_proxy::config::Config;
    use ssl_proxy::obfuscation;

    #[tokio::test]
    #[ignore]
    async fn test_obfuscation_ua_override_on_foxnews_connect() {
        let mut config = Config::default();
        config.obfuscation.fox_ua_override = "Mozilla/5.0 (Test Override)".to_string();

        let profile = obfuscation::classify_obfuscation("foxnews.com", &config.obfuscation);
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("boringtun/1.0"));

        obfuscation::apply_request_headers(&mut headers, &profile, &config.obfuscation);

        let ua = headers
            .get("user-agent")
            .expect("user-agent should be present")
            .to_str()
            .expect("user-agent should be valid UTF-8");
        assert_ne!(ua, "boringtun/1.0");
        assert!(ua.contains("Mozilla/5.0"));

        let normal_profile = obfuscation::classify_obfuscation("example.com", &config.obfuscation);
        let mut normal_headers = HeaderMap::new();
        obfuscation::apply_request_headers(
            &mut normal_headers,
            &normal_profile,
            &config.obfuscation,
        );

        assert_eq!(normal_headers.get("user-agent"), None);
    }
}
