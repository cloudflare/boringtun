use std::collections::HashSet;
use tracing::{error, info};

use crate::state::SharedState;

pub const BLOCKLIST_URL: &str =
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/pro.plus.txt";

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
/// every 24 hours. The seed stays active while the download is in progress.
pub fn spawn_refresh_task(state: SharedState, token: tokio_util::sync::CancellationToken) {
    tokio::spawn(async move {
        loop {
            match fetch().await {
                Ok(remote) => {
                    let mut bl = state.blocklist.write().await;
                    let old_len = bl.len();
                    bl.clear();
                    bl.extend(SEED.iter().map(|s| s.to_string()));
                    bl.extend(remote);
                    info!(
                        entries = bl.len(),
                        previous = old_len,
                        "blocklist refreshed"
                    );
                }
                Err(e) => {
                    error!(%e, "blocklist fetch failed, keeping existing list");
                    let mut bl = state.blocklist.write().await;
                    if bl.is_empty() {
                        bl.extend(SEED.iter().map(|s| s.to_string()));
                        info!(entries = bl.len(), "loaded seed blocklist as fallback");
                    }
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
pub async fn is_blocked(hostname: &str, state: &SharedState) -> bool {
    let normalized = hostname.to_ascii_lowercase();
    let normalized = normalized.trim_end_matches('.');
    let bl = state.blocklist.read().await;
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

        let mut config = crate::config::Config::from_env_or_panic();
        config.obfuscation_enabled = true;

        AppState::new(
            crate::proxy::ProxyClient::builder(hyper_util::rt::TokioExecutor::new())
                .build(hyper_util::client::legacy::connect::HttpConnector::new()),
            resolver,
            stats_tx,
            events_tx,
            None,
            64,
            config,
            #[cfg(feature = "oracle-db")]
            tokio_util::sync::CancellationToken::new(),
        )
    }

    #[tokio::test]
    async fn test_is_blocked_parent_domain_walking() {
        let state = create_test_state().await;

        // Add test domain to blocklist
        {
            let mut bl = state.blocklist.write().await;
            bl.clear();
            bl.insert("tracker.com".to_string());
        }

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

        {
            let mut bl = state.blocklist.write().await;
            bl.clear();
            bl.insert("tracker.com".to_string());
        }

        // Case insensitivity
        assert!(is_blocked("TRACKER.COM", &state).await);
        assert!(is_blocked("Sub.Tracker.Com", &state).await);

        // Trailing dot handling
        assert!(is_blocked("tracker.com.", &state).await);
        assert!(is_blocked("sub.tracker.com.", &state).await);
    }
}
