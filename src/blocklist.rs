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
            let started = std::time::Instant::now();
            match fetch().await {
                Ok(remote) => {
                    let mut bl = state.blocklist.write().await;
                    let old_len = bl.len();
                    bl.clear();
                    bl.extend(SEED.iter().map(|s| s.to_string()));
                    bl.extend(remote);
                    let loaded = bl.len() as i64;
                    info!(
                        entries = bl.len(),
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
                    let mut bl = state.blocklist.write().await;
                    if bl.is_empty() {
                        bl.extend(SEED.iter().map(|s| s.to_string()));
                        info!(entries = bl.len(), "loaded seed blocklist as fallback");
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

        let mut config = crate::config::Config {
            proxy_port: 3000,
            tproxy_port: 3001,
            wg_port: 51820,
            admin_port: 3002,
            explicit_proxy_enabled: false,
            wg_interface: None,
            max_connections: 4096,
            tarpit_max_connections: 64,
            admin_api_key: Some("test-key".to_string()),
            cors_allowed_origins: vec![],
            log_format: "human".to_string(),
            oracle_conn: String::new(),
            oracle_user: String::new(),
            oracle_pass: None,
            oracle_pass_file: String::new(),
            tns_admin: None,
            obfuscation_profiles: String::new(),
            obfuscation_enabled: true,
            obfuscation_profile: vec![],
            fox_ua_override: "Mozilla/5.0 (Test UA)".to_string(),
            tls_cert_path: None,
            tls_key_path: None,
            proxy_username: None,
            proxy_password: None,
            proxy_password_file: String::new(),
            tunnel_endpoint: None,
            upstream_proxy: None,
            enable_dns_lookups: false,
        };
        config.obfuscation_enabled = true;

        AppState::new(
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
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
