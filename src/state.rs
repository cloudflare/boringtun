use dashmap::DashMap;
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio::sync::{broadcast, RwLock};

use crate::blocklist::SEED;

/// Metadata cached from a DNS resolution (Epic 2.1).
#[derive(Clone)]
pub struct ResolvedMeta {
    pub ip: String,
    pub resolved_at: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::TokioAsyncResolver;
    use std::time::Duration;
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
    async fn test_record_host_block_verdict_transition() {
        let state = create_test_state().await;
        let host = "test.telemetry.host";

        // First block
        let verdict_change = state.record_host_block(host, 100, "telemetry");
        assert!(verdict_change.is_none());
        assert_eq!(state.host_stats.get(host).unwrap().verdict(), "BLOCKED");

        // Simulate high frequency by manually modifying stats
        {
            let mut stats = state.host_stats.get_mut(host).unwrap();
            stats.blocked_attempts = 100;
            // Manually set first_seen to 10 seconds ago to get 10 Hz frequency
            stats.first_seen = Instant::now() - Duration::from_secs(10);
        }

        // Next block should trigger verdict change
        let verdict_change = state.record_host_block(host, 100, "telemetry");
        assert!(verdict_change.is_some());
        assert_eq!(verdict_change.unwrap(), ("BLOCKED", "TARPIT"));

        // Increase frequency further to trigger TARPIT
        {
            let mut stats = state.host_stats.get_mut(host).unwrap();
            stats.blocked_attempts = 100;
            stats.first_seen = Instant::now() - Duration::from_secs(1); // 100 Hz
        }

        let verdict_change = state.record_host_block(host, 100, "telemetry");
        assert!(verdict_change.is_some());
        assert_eq!(verdict_change.unwrap(), ("AGGRESSIVE_POLLING", "TARPIT"));
    }

    #[tokio::test]
    async fn test_evict_stale_hosts() {
        let state = create_test_state().await;

        // Add active host
        state.record_host_block("active.host", 100, "test");

        // Add stale host (manually set last_seen to old time)
        state.record_host_block("stale.host", 100, "test");
        {
            let mut stats = state.host_stats.get_mut("stale.host").unwrap();
            stats.last_seen = Instant::now() - Duration::from_secs(3600); // 1 hour old
        }

        assert_eq!(state.host_stats.len(), 2);

        // Evict hosts older than 10 minutes
        state.evict_stale_hosts(600);

        // Only active host remains
        assert_eq!(state.host_stats.len(), 1);
        assert!(state.host_stats.contains_key("active.host"));
        assert!(!state.host_stats.contains_key("stale.host"));
    }
}

pub type SharedState = Arc<AppState>;

/// Per-host heuristic counters — kept in RAM only, never written to disk.
pub struct HostStats {
    pub blocked_attempts: u64,
    pub blocked_bytes_approx: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub tarpit_held_ms: u64,
    pub category: &'static str,
    // Epic 3.2 — inter-arrival time
    pub iat_ms: Option<u64>,
    // Epic 3.3 — verdict transition
    pub last_verdict: &'static str,
    // Epic 3.4 — consecutive block streak
    pub consecutive_blocks: u32,
    // Epic 4.1 — TLS fingerprint
    pub tls_ver: Option<String>,
    pub alpn: Option<String>,
    pub cipher_suites_count: Option<u8>,
    pub ja3_lite: Option<String>,
    // Epic 2.1 — last resolved IP
    pub resolved_ip: Option<String>,
    // Epic 2.2 — ASN enrichment
    pub asn_org: Option<String>,
}

impl HostStats {
    fn new(bytes: u64, category: &'static str) -> Self {
        let now = Instant::now();
        Self {
            blocked_attempts: 1,
            blocked_bytes_approx: bytes,
            first_seen: now,
            last_seen: now,
            tarpit_held_ms: 0,
            category,
            iat_ms: None,
            last_verdict: "BLOCKED",
            consecutive_blocks: 1,
            tls_ver: None,
            alpn: None,
            cipher_suites_count: None,
            ja3_lite: None,
            resolved_ip: None,
            asn_org: None,
        }
    }

    /// Attempts per second since first seen (frequency in Hz).
    pub fn frequency_hz(&self) -> f64 {
        let secs = self.first_seen.elapsed().as_secs_f64();
        if secs < 0.001 {
            return 0.0;
        }
        self.blocked_attempts as f64 / secs
    }

    /// Risk score: blocked_bytes_approx * frequency_hz.
    pub fn risk_score(&self) -> f64 {
        self.blocked_bytes_approx as f64 * self.frequency_hz()
    }

    /// Heuristic verdict. TARPIT takes priority when the host is a high-frequency
    /// telemetry poller (the classic "retry storm" battery drain pattern).
    pub fn verdict(&self) -> &'static str {
        let hz = self.frequency_hz();
        if hz > 8.0 && self.category == "telemetry" {
            return "TARPIT";
        }
        if hz > 1.0 {
            return "AGGRESSIVE_POLLING";
        }
        if self.risk_score() > 100_000.0 {
            return "HEURISTIC_FLAG_DATA_EXFIL";
        }
        if self.blocked_attempts > 10 {
            return "PERSISTENT_RECONNECT";
        }
        "BLOCKED"
    }

    /// Approximate mWh saved by tarpitting vs. letting the app retry freely.
    /// Model: each retry attempt at 13 req/s costs ~0.5 mW of radio wake time;
    /// holding the connection in a tarpit suppresses those retries.
    pub fn battery_saved_approx(&self) -> f64 {
        // 0.5 mW * held_seconds = mWh saved (rough order-of-magnitude estimate)
        let held_secs = self.tarpit_held_ms as f64 / 1000.0;
        0.5 * held_secs / 3600.0
    }
}

pub struct AppState {
    pub client: crate::proxy::ProxyClient,
    pub resolver: hickory_resolver::TokioAsyncResolver,
    pub stats_tx: broadcast::Sender<String>,
    pub events_tx: broadcast::Sender<String>,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub active_tunnels: AtomicU64,
    pub tunnels_opened: AtomicU64,
    pub blocked_count: AtomicU64,
    pub obfuscated_count: AtomicU64,
    pub blocklist: RwLock<HashSet<String>>,
    pub host_stats: DashMap<String, HostStats>,
    pub tarpit_sem: std::sync::Arc<tokio::sync::Semaphore>,
    /// DNS resolution cache with 5-minute TTL (Epic 2.1).
    pub dns_cache: DashMap<String, ResolvedMeta>,
    /// WireGuard TUN device name for diagnostics (optional).
    pub wg_interface: Option<String>,
    pub config: crate::config::Config,
    #[cfg(feature = "oracle-db")]
    pub db: std::sync::Arc<crate::db::EventSender>,
}

impl AppState {
    pub fn new(
        client: crate::proxy::ProxyClient,
        resolver: hickory_resolver::TokioAsyncResolver,
        stats_tx: broadcast::Sender<String>,
        events_tx: broadcast::Sender<String>,
        wg_interface: Option<String>,
        max_tarpit: usize,
        config: crate::config::Config,
        #[cfg(feature = "oracle-db")] shutdown: tokio_util::sync::CancellationToken,
    ) -> SharedState {
        let seed = SEED.iter().map(|s| s.to_string()).collect();
        #[cfg(feature = "oracle-db")]
        let db = {
            let conn_str = config.oracle_conn.clone();
            let user = config.oracle_user.clone();
            let pass = config.oracle_pass.clone().unwrap_or_else(|| {
                std::fs::read_to_string(&config.oracle_pass_file)
                    .unwrap_or_default()
                    .trim_end_matches(&['\n', '\r'][..])
                    .to_string()
            });
            if conn_str.is_empty() || user.is_empty() {
                tracing::warn!(
                    "oracle-db feature enabled but ORACLE_CONN/ORACLE_USER not set; \
                     DB events will not be persisted"
                );
            }
            std::sync::Arc::new(crate::db::spawn_writer(conn_str, user, pass, shutdown))
        };
        Arc::new(Self {
            client,
            resolver,
            stats_tx,
            events_tx,
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            active_tunnels: AtomicU64::new(0),
            tunnels_opened: AtomicU64::new(0),
            blocked_count: AtomicU64::new(0),
            obfuscated_count: AtomicU64::new(0),
            blocklist: RwLock::new(seed),
            host_stats: DashMap::new(),
            tarpit_sem: crate::tunnel::tarpit_semaphore(max_tarpit),
            dns_cache: DashMap::new(),
            wg_interface,
            config,
            #[cfg(feature = "oracle-db")]
            db,
        })
    }

    pub fn record_tunnel_open(&self) {
        self.active_tunnels.fetch_add(1, Ordering::Relaxed);
        self.tunnels_opened.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tunnel_close(&self, up: u64, down: u64) {
        self.bytes_up.fetch_add(up, Ordering::Relaxed);
        self.bytes_down.fetch_add(down, Ordering::Relaxed);
        self.active_tunnels
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                debug_assert!(
                    v > 0,
                    "record_tunnel_close called with active_tunnels already zero"
                );
                Some(v.saturating_sub(1))
            })
            .ok();
    }

    pub fn record_blocked(&self) {
        self.blocked_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Update per-host heuristic counters for a blocked connection.
    /// Returns `(prev_verdict, next_verdict)` if the verdict changed.
    pub fn record_host_block(
        &self,
        host: &str,
        connect_header_bytes: u64,
        category: &'static str,
    ) -> Option<(&'static str, &'static str)> {
        const MAX_TRACKED_HOSTS: usize = 100_000;
        let now = Instant::now();
        if let Some(mut s) = self.host_stats.get_mut(host) {
            let iat = now.duration_since(s.last_seen).as_millis() as u64;
            s.iat_ms = Some(iat);
            s.blocked_attempts += 1;
            s.blocked_bytes_approx += connect_header_bytes;
            s.last_seen = now;
            s.category = category;
            s.consecutive_blocks = s.consecutive_blocks.saturating_add(1);
            let prev = s.last_verdict;
            let next = s.verdict();
            if prev != next {
                s.last_verdict = next;
                return Some((prev, next));
            }
            None
        } else if self.host_stats.len() < MAX_TRACKED_HOSTS {
            self.host_stats
                .entry(host.to_string())
                .or_insert_with(|| HostStats::new(connect_header_bytes, category));
            None
        } else {
            None
        }
    }

    /// Reset the consecutive-block streak when a host is allowed through (Epic 3.4).
    pub fn record_host_allow(&self, host: &str) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.consecutive_blocks = 0;
        }
    }

    /// Store TLS fingerprint fields into HostStats (Epic 4.1).
    pub fn record_tls_fingerprint(
        &self,
        host: &str,
        tls_ver: Option<String>,
        alpn: Option<String>,
        cipher_suites_count: Option<u8>,
        ja3_lite: Option<String>,
    ) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.tls_ver = tls_ver;
            s.alpn = alpn;
            s.cipher_suites_count = cipher_suites_count;
            s.ja3_lite = ja3_lite;
        }
    }

    /// Store resolved IP (and optionally ASN org) into HostStats (Epic 2.1/2.2).
    pub fn record_resolved(&self, host: &str, ip: String, asn_org: Option<String>) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.resolved_ip = Some(ip);
            s.asn_org = asn_org;
        }
    }

    /// Record milliseconds a tarpit connection was held open for a host.
    pub fn record_tarpit_held(&self, host: &str, held_ms: u64) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.tarpit_held_ms = s.tarpit_held_ms.saturating_add(held_ms);
        }
    }

    /// Drop hosts that haven't been seen in `ttl_secs` seconds.
    /// Called periodically by the stats poller — never from a request handler.
    pub fn evict_stale_hosts(&self, ttl_secs: u64) {
        self.host_stats
            .retain(|_, v| v.last_seen.elapsed().as_secs() < ttl_secs);
    }
}
