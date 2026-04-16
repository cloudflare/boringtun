// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Integration test for blocklist snapshot replacement behavior.

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use hickory_resolver::TokioAsyncResolver;
    use ssl_proxy::blocklist;
    use ssl_proxy::config::Config;
    use ssl_proxy::state::AppState;
    use tokio::sync::broadcast;

    async fn create_state() -> ssl_proxy::state::SharedState {
        let (stats_tx, _) = broadcast::channel(16);
        let (events_tx, _) = broadcast::channel(16);
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .expect("system resolver should initialize");

        AppState::new(
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(hyper_util::client::legacy::connect::HttpConnector::new()),
            resolver,
            stats_tx,
            events_tx,
            Config::default(),
            #[cfg(feature = "oracle-db")]
            tokio_util::sync::CancellationToken::new(),
        )
    }

    #[tokio::test]
    #[ignore]
    async fn test_blocklist_snapshot_replacement() {
        let state = create_state().await;

        state
            .blocklist
            .store(Arc::new(HashSet::from(["example.com".to_string()])));

        assert!(blocklist::is_blocked("example.com", &state).await);
        assert!(blocklist::is_blocked("sub.example.com", &state).await);
        assert!(!blocklist::is_blocked("allowed.com", &state).await);

        state
            .blocklist
            .store(Arc::new(HashSet::from(["blocked.net".to_string()])));

        assert!(!blocklist::is_blocked("example.com", &state).await);
        assert!(blocklist::is_blocked("blocked.net", &state).await);
    }
}
