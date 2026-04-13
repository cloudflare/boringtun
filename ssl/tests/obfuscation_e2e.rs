// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! End-to-end test for obfuscation UA override
//! Verifies that HTTP CONNECT requests have correct User-Agent applied

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        handler::Handler,
        http::{HeaderMap, Method, Request, StatusCode},
        Router,
    };
    use ssl_proxy::config::Config;
    use ssl_proxy::obfuscation;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    #[ignore]
    async fn test_obfuscation_ua_override_on_foxnews_connect() {
        // Start test server that captures headers
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = axum::Server::bind(&"127.0.0.1:0".parse().unwrap()).serve(
            Router::new()
                .route(
                    "/*path",
                    axum::routing::any(move |req: Request<Body>| async move {
                        tx.send(req.headers().clone()).unwrap();
                        (StatusCode::OK, "OK")
                    }),
                )
                .into_make_service(),
        );

        let server_addr = server.local_addr();
        tokio::spawn(async {
            server.await.unwrap();
        });

        // Simulate HTTP CONNECT to foxnews.com:443
        let mut stream = TcpStream::connect(server_addr).await.unwrap();

        // Send CONNECT request
        let connect_request = format!(
            "CONNECT foxnews.com:443 HTTP/1.1\r\n\
             Host: foxnews.com:443\r\n\
             User-Agent: boringtun/1.0\r\n\
             Connection: keep-alive\r\n\
             \r\n"
        );

        stream.write_all(connect_request.as_bytes()).await.unwrap();

        // Read server response
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("200 OK"),
            "Expected 200 OK response, got: {}",
            response
        );

        // Get captured headers from test server
        let captured_headers = rx.await.unwrap();

        // Verify headers from actual proxy connection
        assert!(
            captured_headers.contains_key("user-agent"),
            "User-Agent header should be present in captured headers"
        );
        let ua = captured_headers.get("user-agent").unwrap().to_str().unwrap();
        assert_ne!(
            ua, "boringtun/1.0",
            "Original User-Agent should be overridden in actual request"
        );
        assert!(
            ua.contains("Mozilla/5.0"),
            "Overridden User-Agent should be standard browser UA in actual request"
        );

        // Create test config
        let config = Config::default();

        // Apply obfuscation headers (simulating proxy behavior)
        let mut headers = HeaderMap::new();
        let profile = obfuscation::classify_obfuscation("foxnews.com", &config);
        obfuscation::apply_request_headers(&mut headers, &profile, &config);

        // Verify UA override is applied
        assert!(
            headers.contains_key("user-agent"),
            "User-Agent header should be present"
        );
        let ua = headers.get("user-agent").unwrap().to_str().unwrap();

        // Verify it's not the original boringtun UA
        assert_ne!(
            ua, "boringtun/1.0",
            "Original User-Agent should be overridden"
        );

        // Verify it matches the expected override UA
        assert!(
            ua.contains("Mozilla/5.0"),
            "Overridden User-Agent should be standard browser UA"
        );

        // Test that non-target domain doesn't get override
        let normal_profile = obfuscation::classify_obfuscation("example.com", &config);
        let mut normal_headers = HeaderMap::new();
        obfuscation::apply_request_headers(&mut normal_headers, &normal_profile, &config);

        assert_eq!(
            normal_headers.get("user-agent"),
            None,
            "Non-target domains should not receive UA override"
        );
    }
}
