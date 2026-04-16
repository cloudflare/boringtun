//! DNS blocklist loading and hot-path membership checks.
//!
//! This module owns the in-memory set of blocked domains, seeded at startup and
//! refreshed from a remote list in the background. It does not decide how a
//! blocked connection is handled after a match is found.

use std::collections::HashSet;
use std::sync::Arc;
use tracing::{error, info};

use crate::state::SharedState;

/// Remote source of the periodically refreshed domain blocklist.
pub const BLOCKLIST_URL: &str =
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/ultimate.txt";

/// Hardcoded seed — active immediately on startup before the remote fetch completes.
pub const SEED: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "adtrafficquality.google",
    "adnxs.com",
    "amazon-adsystem.com",
    "pubmatic.com",
    "rubiconproject.com",
    "smartadserver.com",
    "criteo.com",
    "criteo.net",
    "scorecardresearch.com",
    "crwdcntrl.net",
    "permutive.app",
    "permutive.com",
    "chartbeat.com",
    "chartbeat.net",
    "id5-sync.com",
    "im-apps.net",
    "seedtag.com",
    "rtbhouse.com",
    "mgaru.dev",
    "mygaru.com",
    "cxense.com",
    // Grammarly telemetry
    "f-log-mobile-ios.grammarly.io",
    "ios.femetrics.grammarly.io",
    "o565714.ingest.sentry.io",
];

/// Spawns a task that fetches the remote blocklist immediately then refreshes
/// every 24 hours.
///
/// The seed entries remain active while the download is in progress and are
/// re-applied on every successful refresh. On fetch failure the current list is
/// preserved; if the set is empty, the seed list is restored.
pub fn spawn_refresh_task(state: SharedState, token: tokio_util::sync::CancellationToken) {
    tokio::spawn(async move {
        loop {
            #[cfg(feature = "oracle-db")]
            let started = std::time::Instant::now();
            match fetch().await {
                Ok(remote) => {
                    let old_len = state.blocklist.load().len();
                    let mut merged: HashSet<String> = SEED.iter().map(|s| s.to_string()).collect();
                    merged.extend(remote);
                    #[cfg(feature = "oracle-db")]
                    let loaded = merged.len() as i64;
                    state.blocklist.store(Arc::new(merged));
                    info!(
                        entries = state.blocklist.load().len(),
                        previous = old_len,
                        "blocklist refreshed"
                    );
                    #[cfg(feature = "oracle-db")]
                    crate::db::insert_blocklist_audit_event(
                        state.db.clone(),
                        crate::db::BlocklistAuditEvent {
                            source_url: Some(BLOCKLIST_URL.to_string()),
                            entries_loaded: Some(loaded),
                            seed_entries: Some(SEED.len() as i64),
                            success: true,
                            error_msg: None,
                            duration_ms: Some(started.elapsed().as_millis() as i64),
                        },
                    );
                }
                Err(e) => {
                    error!(%e, "blocklist fetch failed, keeping existing list");
                    if state.blocklist.load().is_empty() {
                        let seed: HashSet<String> = SEED.iter().map(|s| s.to_string()).collect();
                        let entries = seed.len();
                        state.blocklist.store(Arc::new(seed));
                        info!(entries, "loaded seed blocklist as fallback");
                    }
                    #[cfg(feature = "oracle-db")]
                    crate::db::insert_blocklist_audit_event(
                        state.db.clone(),
                        crate::db::BlocklistAuditEvent {
                            source_url: Some(BLOCKLIST_URL.to_string()),
                            entries_loaded: None,
                            seed_entries: Some(SEED.len() as i64),
                            success: false,
                            error_msg: Some(e.to_string().chars().take(512).collect()),
                            duration_ms: Some(started.elapsed().as_millis() as i64),
                        },
                    );
                }
            }
            tokio::select! {
                _ = token.cancelled() => { info!("blocklist task shutting down"); return; }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(86_400)) => {}
            }
        }
    });
}

/// Returns true if `hostname` (no port) matches any entry in the blocklist,
/// walking up through parent domains so `sub.tracker.com` matches `tracker.com`.
///
/// # Cancellation safety
/// This function performs only an atomic snapshot load plus in-memory lookups,
/// so cancelling it does not leave shared state in a partial state.
pub async fn is_blocked(hostname: &str, state: &SharedState) -> bool {
    let normalized = hostname.to_ascii_lowercase();
    let normalized = normalized.trim_end_matches('.');
    let bl = state.blocklist.load();
    let mut domain = normalized;
    loop {
        if bl.contains(domain) {
            return true;
        }
        match domain.find('.') {
            Some(idx) => domain = &domain[idx + 1..],
            None => return false,
        }
    }
}

async fn fetch() -> Result<HashSet<String>, reqwest::Error> {
    info!(url = BLOCKLIST_URL, "fetching remote blocklist");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let text = client
        .get(BLOCKLIST_URL)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let set = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| l.trim().to_lowercase())
        .collect::<HashSet<String>>();
    info!(entries = set.len(), "remote blocklist parsed");
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AppState, SharedState};
    use hickory_resolver::TokioAsyncResolver;
    use tokio::sync::broadcast;

    async fn create_test_state() -> SharedState {
        let (stats_tx, _) = broadcast::channel(16);
        let (events_tx, _) = broadcast::channel(16);
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();

        let mut config = crate::config::Config::for_tests();
        config.obfuscation.enabled = true;

        AppState::new(
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(hyper_util::client::legacy::connect::HttpConnector::new()),
            resolver,
            stats_tx,
            events_tx,
            config,
            #[cfg(feature = "oracle-db")]
            tokio_util::sync::CancellationToken::new(),
        )
    }

    #[tokio::test]
    async fn test_is_blocked_parent_domain_walking() {
        let state = create_test_state().await;

        // Add test domain to blocklist
        state
            .blocklist
            .store(Arc::new(HashSet::from(["tracker.com".to_string()])));

        // Test that subdomains correctly match parent domain
        assert!(is_blocked("tracker.com", &state).await);
        assert!(is_blocked("sub.tracker.com", &state).await);
        assert!(is_blocked("sub.sub.tracker.com", &state).await);
        assert!(is_blocked("deep.sub.sub.tracker.com", &state).await);

        // Test non-matching domains
        assert!(!is_blocked("example.com", &state).await);
        assert!(!is_blocked("com", &state).await);
        assert!(!is_blocked("tracker.co", &state).await);
    }

    #[tokio::test]
    async fn test_is_blocked_case_insensitive_and_trailing_dot() {
        let state = create_test_state().await;

        state
            .blocklist
            .store(Arc::new(HashSet::from(["tracker.com".to_string()])));

        // Case insensitivity
        assert!(is_blocked("TRACKER.COM", &state).await);
        assert!(is_blocked("Sub.Tracker.Com", &state).await);

        // Trailing dot handling
        assert!(is_blocked("tracker.com.", &state).await);
        assert!(is_blocked("sub.tracker.com.", &state).await);
    }
}
