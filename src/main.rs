#![warn(clippy::unwrap_used)]

mod blocklist;
mod config;
mod dashboard;
#[cfg(feature = "oracle-db")]
mod db;
mod events;
mod obfuscation;
mod proxy;
mod quic;
mod state;
mod tunnel;

use axum::http::Method;
use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{any, get},
    Router,
};
use base64::Engine;
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use hyper::service::service_fn;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ServerBuilder,
};
use std::net::SocketAddr;
use tokio::{sync::broadcast, task::JoinSet};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::Service;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use tracing::{debug, error, info, warn};

pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn admin_api_key_matches(provided: &str, key: &str) -> bool {
    !key.is_empty() && constant_time_eq(provided, key)
}

/// Validate the Proxy-Authorization header (RFC 7235 / RFC 7617 Basic scheme).
/// Returns `true` when the header carries valid credentials.
/// Generic over the body type so it works for both hyper and h3 requests.
pub(crate) fn check_proxy_auth<B>(req: &Request<B>, username: &str, password: &str) -> bool {
    let header = match req
        .headers()
        .get("proxy-authorization")
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h,
        None => return false,
    };
    // RFC 7235 §2.1: auth-scheme comparison is case-insensitive.
    let encoded = if header.len() >= 6 && header[..6].eq_ignore_ascii_case("basic ") {
        &header[6..]
    } else {
        return false;
    };
    let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let decoded_str = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let (user, pass) = match decoded_str.split_once(':') {
        Some(pair) => pair,
        None => return false,
    };
    let user_ok = constant_time_eq(user, username);
    let pass_ok = constant_time_eq(pass, password);
    user_ok & pass_ok
}

#[tokio::main]
async fn main() {
    // Install rustls crypto provider FIRST before ANY other code
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive(
            "ssl_proxy=info"
                .parse()
                .expect("static directive must parse"),
        )
        .add_directive(
            "tower_http=info"
                .parse()
                .expect("static directive must parse"),
        );

    let mut opts = ResolverOpts::default();
    opts.cache_size = 1024;
    // Prefer IPv4 first to avoid "Network unreachable" errors when IPv6 is not configured
    opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4thenIpv6;

    let cloudflare_ips = [
        "1.1.1.1"
            .parse()
            .expect("static Cloudflare resolver address must parse"),
        "1.0.0.1"
            .parse()
            .expect("static Cloudflare resolver address must parse"),
    ];
    let resolver_config = ResolverConfig::from_parts(
        None,
        Vec::new(),
        NameServerConfigGroup::from_ips_https(
            &cloudflare_ips,
            443,
            "cloudflare-dns.com".to_string(),
            true,
        ),
    );
    let resolver = TokioAsyncResolver::tokio(resolver_config, opts);

    let (stats_tx, _) = broadcast::channel(64);
    let (events_tx, _) = broadcast::channel(256);

    let shutdown = CancellationToken::new();

    let config = config::Config::from_env_or_panic();

    let client = Client::builder(TokioExecutor::new()).build(HttpConnector::new());

    // LOG_FORMAT=json  →  newline-delimited JSON (pipe to Vector/Filebeat)
    // anything else    →  human-readable (default for dev)
    if config.runtime.log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    let state = state::AppState::new(
        client,
        resolver,
        stats_tx,
        events_tx,
        config.clone(),
        #[cfg(feature = "oracle-db")]
        shutdown.clone(),
    );

    // Semaphore to limit concurrent connections
    let connection_semaphore =
        std::sync::Arc::new(tokio::sync::Semaphore::new(config.proxy.max_connections));

    blocklist::spawn_refresh_task(state.clone(), shutdown.clone());
    dashboard::spawn_stats_poller(state.clone(), shutdown.clone());
    dashboard::spawn_host_eviction_task(state.clone(), shutdown.clone());

    let cors = if !config.admin.cors_allowed_origins.is_empty() {
        let parsed: Vec<axum::http::HeaderValue> = config
            .admin
            .cors_allowed_origins
            .iter()
            .filter_map(|origin| match origin.parse() {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!(origin = %origin, %e, "invalid CORS origin, skipping");
                    None
                }
            })
            .collect();
        if parsed.is_empty() {
            warn!("CORS_ALLOWED_ORIGINS set but no valid origins parsed — no origins allowed");
        }
        CorsLayer::new()
            .allow_origin(parsed)
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    } else if cfg!(debug_assertions) {
        info!("CORS_ALLOWED_ORIGINS not set, using permissive CORS (dev mode)");
        CorsLayer::permissive()
    } else {
        warn!("CORS_ALLOWED_ORIGINS not set in release build, defaulting to restrictive CORS");
        CorsLayer::new()
    };
    let admin_api_key = config.admin.api_key.clone();
    let admin_routes = Router::new()
        .route("/hosts", get(dashboard::hosts_snapshot))
        .route("/hosts/:hostname", get(dashboard::host_detail))
        .route("/stats/summary", get(dashboard::stats_summary))
        .layer(middleware::from_fn(
            move |req: Request<Body>, next: Next| {
                let key = admin_api_key.clone();
                async move {
                    // If no admin API key configured, deny all access to admin endpoints
                    let provided = req
                        .headers()
                        .get("x-api-key")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");

                    if !admin_api_key_matches(provided, &key) {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }

                    next.run(req).await
                }
            },
        ))
        .with_state(state.clone());

    // Admin / dashboard listener — plaintext, internal only
    let admin_router = Router::new()
        .route("/ws", get(dashboard::ws_stats))
        .route("/events", get(dashboard::ws_events))
        .route("/health", get(dashboard::health))
        .route("/ready", get(dashboard::ready))
        .merge(admin_routes)
        .nest_service("/dashboard", ServeDir::new("static"))
        .layer(TraceLayer::new_for_http())
        .layer(cors.clone())
        .with_state(state.clone());

    let admin_addr = SocketAddr::from(([0, 0, 0, 0], config.admin.port));
    let admin_listener = tokio::net::TcpListener::bind(admin_addr)
        .await
        .unwrap_or_else(|e| {
            error!(%admin_addr, %e, "failed to bind admin listener");
            std::process::exit(1)
        });
    info!(%admin_addr, "admin/dashboard listener active (plaintext)");

    let admin_shutdown = shutdown.clone();
    tokio::spawn(async move {
        axum::serve(admin_listener, admin_router)
            .with_graceful_shutdown(async move { admin_shutdown.cancelled().await })
            .await
            .ok();
    });

    #[cfg(feature = "oracle-db")]
    dashboard::spawn_oracle_flusher(state.clone(), shutdown.clone());

    info!(
        proxy_port = config.proxy.port,
        tproxy_port = config.proxy.transparent_port,
        wg_port = config.wireguard.port,
        admin_port = config.admin.port,
        explicit_proxy_enabled = config.proxy.explicit_enabled,
        wg_interface = ?config.wireguard.interface,
        upstream_proxy = ?config.proxy.upstream_proxy,
        tunnel_endpoint = ?config.proxy.tunnel_endpoint,
        obfuscation_profiles = ?config.obfuscation.enabled_profiles,
        "port assignment"
    );

    // Transparent proxy listener — receives connections redirected by iptables REDIRECT
    let tproxy_addr = SocketAddr::from(([0, 0, 0, 0], config.proxy.transparent_port));
    let tproxy_listener = tokio::net::TcpListener::bind(tproxy_addr)
        .await
        .unwrap_or_else(|e| {
            error!(%tproxy_addr, %e, "failed to bind transparent proxy listener");
            std::process::exit(1)
        });
    info!(%tproxy_addr, "transparent proxy listener active");

    let tproxy_state = state.clone();
    let tproxy_shutdown = shutdown.clone();
    let tproxy_connection_semaphore = connection_semaphore.clone();
    let tproxy_handle = tokio::spawn(async move {
        let mut tproxy_tasks: JoinSet<()> = JoinSet::new();
        loop {
            tokio::select! {
                _ = tproxy_shutdown.cancelled() => break,
                result = tproxy_listener.accept() => {
                    match result {
                        Ok((stream, _peer)) => {
                            let permit = match tproxy_connection_semaphore.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    warn!("max connections reached, dropping transparent connection");
                                    continue;
                                }
                            };
                            let s = tproxy_state.clone();
                            tproxy_tasks.spawn(async move {
                                let _permit = permit; // hold until task completes
                                tunnel::handle_transparent(stream, s).await;
                            });
                        }
                        Err(e) => error!(%e, "tproxy accept failed"),
                    }
                }
            }
        }
        while tproxy_tasks.join_next().await.is_some() {}
    });

    let mut tasks: JoinSet<()> = JoinSet::new();

    if config.proxy.explicit_enabled {
        warn!(
            "EXPLICIT_PROXY_ENABLED=true — legacy explicit proxy listeners are active; plaintext HTTP CONNECT leaks target hostnames on the client-to-proxy leg"
        );

        let router = Router::new()
            .fallback(any(proxy::handler))
            .layer(TraceLayer::new_for_http())
            .layer(cors)
            .with_state(state.clone());

        let proxy_creds: Option<std::sync::Arc<(String, String)>> =
            config.proxy.credentials.as_ref().map(|creds| {
                info!(username = %creds.username, "explicit proxy authentication enabled");
                std::sync::Arc::new((creds.username.clone(), creds.password.clone()))
            });
        if proxy_creds.is_none() {
            warn!("PROXY_USERNAME / PROXY_PASSWORD not set — explicit proxy has NO authentication");
        }

        let addr = SocketAddr::from(([0, 0, 0, 0], config.proxy.port));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .unwrap_or_else(|e| {
                error!(%addr, %e, "failed to bind explicit proxy listener");
                std::process::exit(1)
            });
        info!(%addr, "explicit proxy listener active");

        let tls_acceptor: Option<TlsAcceptor> = if let (Some(cert_path), Some(key_path)) =
            (&config.tls.cert_path, &config.tls.key_path)
        {
            let cert_pem = std::fs::read(cert_path).expect("failed to read TLS cert");
            let key_pem = std::fs::read(key_path).expect("failed to read TLS key");
            let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
                .collect::<Result<_, _>>()
                .expect("invalid cert PEM");
            let key = rustls_pemfile::private_key(&mut &key_pem[..])
                .expect("failed to parse key PEM")
                .expect("no private key found");
            let tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .expect("invalid TLS config");
            info!("TLS enabled on explicit proxy listener");
            Some(TlsAcceptor::from(std::sync::Arc::new(tls_config)))
        } else {
            warn!("TLS_CERT_PATH / TLS_KEY_PATH not set — explicit proxy listener is PLAINTEXT");
            None
        };

        if tls_acceptor.is_some() {
            let quic_state = state.clone();
            let quic_config = config.clone();
            let quic_shutdown = shutdown.clone();
            let quic_creds = proxy_creds.clone();
            tasks.spawn(async move {
                quic::run_quic_listener(quic_state, quic_config, quic_shutdown, quic_creds).await;
            });
        }

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("shutdown signal received, stopping explicit proxy accept loop");
                    shutdown.cancel();
                    break;
                }
                result = tokio::signal::ctrl_c() => {
                    if let Err(e) = result {
                        error!(%e, "ctrl_c signal handler failed");
                    }
                    info!("shutdown signal received, stopping explicit proxy accept loop");
                    shutdown.cancel();
                    break;
                }
                result = listener.accept() => {
                    let (stream, peer) = match result {
                        Ok(c) => c,
                        Err(e) => {
                            error!(%e, "accept failed");
                            continue;
                        }
                    };

                    let permit = match connection_semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            warn!("max connections reached, dropping connection");
                            continue;
                        }
                    };

                    let state = state.clone();
                    let router = router.clone();
                    let token = shutdown.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let proxy_creds = proxy_creds.clone();

                    tasks.spawn(async move {
                        let _permit = permit; // hold until task completes

                        // Serve either plain TCP explicit-proxy traffic or TLS-wrapped
                        // explicit-proxy traffic on the same request handling path.
                        macro_rules! serve_io {
                            ($io:expr) => {{
                                let io = $io;
                                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                                    let state = state.clone();
                                    let router = router.clone();
                                    let creds = proxy_creds.clone();
                                    async move {
                                        let req: Request<Body> = req.map(Body::new);

                                        let is_proxy_request = req.method() == Method::CONNECT
                                            || req.uri().scheme().is_some();

                                        if is_proxy_request {
                                            if let Some(ref c) = creds {
                                                if !check_proxy_auth(&req, &c.0, &c.1) {
                                                    return Ok(Response::builder()
                                                        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                                                        .header(
                                                            "Proxy-Authenticate",
                                                            "Basic realm=\"Proxy Access\"",
                                                        )
                                                        .body(Body::empty())
                                                        .unwrap());
                                                }
                                            }
                                        }

                                        if req.method() == Method::CONNECT {
                                            tunnel::handle(req, state, Some(peer.ip().to_string())).await
                                        } else {
                                            let mut router = router.clone();
                                            router.call(req).await.map_err(|e| match e {})
                                        }
                                    }
                                });

                                let builder = ServerBuilder::new(TokioExecutor::new());
                                let conn = builder.serve_connection_with_upgrades(io, svc);
                                tokio::select! {
                                    result = conn => {
                                        if let Err(e) = result {
                                            debug!(%peer, %e, "connection error");
                                        }
                                    }
                                    _ = token.cancelled() => {
                                        debug!(%peer, "connection dropped due to shutdown");
                                    }
                                }
                            }};
                        }

                        if let Some(ref acceptor) = tls_acceptor {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    serve_io!(TokioIo::new(tls_stream));
                                }
                                Err(e) => {
                                    debug!(%peer, %e, "TLS handshake failed");
                                }
                            }
                        } else {
                            serve_io!(TokioIo::new(stream));
                        }
                    });
                }
            }
        }
    } else {
        info!(
            proxy_port = config.proxy.port,
            "explicit proxy listener disabled; WireGuard is the supported client ingress"
        );
        if config.tls.cert_path.is_some() || config.tls.key_path.is_some() {
            warn!(
                "TLS_CERT_PATH / TLS_KEY_PATH set while EXPLICIT_PROXY_ENABLED=false — skipping HTTPS and QUIC explicit-proxy listeners"
            );
        }
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("shutdown signal received, stopping background listeners");
            }
            result = tokio::signal::ctrl_c() => {
                if let Err(e) = result {
                    error!(%e, "ctrl_c signal handler failed");
                }
                info!("shutdown signal received, stopping background listeners");
                shutdown.cancel();
            }
        }
        shutdown.cancel();
    }

    info!("draining in-flight connections (5s timeout)");
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(5), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(2), tproxy_handle).await;
    info!("shutdown complete");
}

#[cfg(test)]
mod tests {
    use super::{admin_api_key_matches, constant_time_eq};

    #[test]
    fn constant_time_eq_rejects_same_prefix_with_different_lengths() {
        assert!(!constant_time_eq("prefix", "prefix-suffix"));
    }

    #[test]
    fn constant_time_eq_handles_long_inputs() {
        let a = "a".repeat(300);
        let b = "a".repeat(300);

        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn admin_api_key_matches_rejects_empty_keys() {
        assert!(!admin_api_key_matches("", ""));
        assert!(!admin_api_key_matches("test-key", ""));
        assert!(admin_api_key_matches("test-key", "test-key"));
    }
}
