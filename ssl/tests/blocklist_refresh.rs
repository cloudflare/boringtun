// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Integration test for blocklist refresh mechanism
//! Verifies refresh task updates in-memory set and seed fallback works

#[cfg(test)]
mod tests {
    use ssl_proxy::blocklist;
    use ssl_proxy::config::Config;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    #[ignore]
    async fn test_blocklist_refresh_and_seed_fallback() {
        // Start mock CDN server
        let mock_server = MockServer::start().await;

        // Mock successful blocklist response
        Mock::given(method("GET"))
            .and(path("/blocklist.txt"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("example.com\nblocked.net\ntest.org"),
            )
            .mount(&mock_server)
            .await;

        // Create config pointing to mock server
        let mut config = Config::default();
        config.blocklist_url = format!("{}/blocklist.txt", mock_server.uri());
        config.blocklist_refresh_interval = Duration::from_millis(100);

        // Initialize blocklist
        let blocklist = blocklist::Blocklist::new(&config).await;

        // Start refresh task
        let refresh_handle = blocklist.start_refresh_task();

        // Wait for first refresh with bounded polling
        let mut attempts = 0;
        loop {
            if blocklist.contains("example.com") {
                break;
            }
            attempts += 1;
            if attempts > 20 {
                panic!("Timeout waiting for blocklist to refresh");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Verify blocklist was populated
        assert!(
            blocklist.contains("example.com"),
            "example.com should be blocked"
        );
        assert!(
            blocklist.contains("blocked.net"),
            "blocked.net should be blocked"
        );
        assert!(blocklist.contains("test.org"), "test.org should be blocked");
        assert!(
            !blocklist.contains("allowed.com"),
            "allowed.com should not be blocked"
        );

        // Stop mock server to simulate CDN failure
        drop(mock_server);

        // Wait for refresh failure with bounded polling
        let mut attempts = 0;
        loop {
            if blocklist.contains("seed-domain-1.com") {
                break;
            }
            attempts += 1;
            if attempts > 20 {
                panic!("Timeout waiting for blocklist fallback to activate");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Verify seed fallback activates - seed list should be present
        assert!(
            blocklist.contains("seed-domain-1.com"),
            "Seed domain should be present after fetch failure"
        );
        assert!(
            blocklist.contains("seed-domain-2.net"),
            "Seed domain should be present after fetch failure"
        );

        // Verify existing domains still work during fallback
        assert!(
            blocklist.contains("example.com"),
            "Existing domains should remain after fetch failure"
        );

        // Cleanup
        refresh_handle.abort();
    }
}
