mod blocklist;
mod config;
mod dashboard;
#[cfg(feature = "oracle-db")]
mod db;
mod obfuscation;
mod proxy;
mod state;
mod tunnel;

use axum::http::Method;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{any, get},
    Router,
};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
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
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use tracing::{debug, error, info, warn};

fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    const MAX_LEN: usize = 256;
    let mut a_buf = [0u8; MAX_LEN];
    let mut b_buf = [0u8; MAX_LEN];
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    a_buf[..a_bytes.len().min(MAX_LEN)].copy_from_slice(&a_bytes[..a_bytes.len().min(MAX_LEN)]);
    b_buf[..b_bytes.len().min(MAX_LEN)].copy_from_slice(&b_bytes[..b_bytes.len().min(MAX_LEN)]);
    a_buf.ct_eq(&b_buf).into()
}

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive("ssl_proxy=info".parse().unwrap())
        .add_directive("tower_http=info".parse().unwrap());

    let client = Client::builder(TokioExecutor::new()).build(HttpConnector::new());

    let mut opts = ResolverOpts::default();
    opts.cache_size = 1024;
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare_https(), opts);

    let (stats_tx, _) = broadcast::channel(64);
    let (events_tx, _) = broadcast::channel(256);

    let shutdown = CancellationToken::new();

    let config = config::Config::from_env_or_panic();

    // LOG_FORMAT=json  →  newline-delimited JSON (pipe to Vector/Filebeat)
    // anything else    →  human-readable (default for dev)
    if config.log_format == "json" {
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
        config.wg_interface.clone(),
        config.tarpit_max_connections,
        config.clone(),
        #[cfg(feature = "oracle-db")]
        shutdown.clone(),
    );

    // Semaphore to limit concurrent connections
    let connection_semaphore =
        std::sync::Arc::new(tokio::sync::Semaphore::new(config.max_connections));

    blocklist::spawn_refresh_task(state.clone(), shutdown.clone());
    dashboard::spawn_stats_poller(state.clone(), shutdown.clone());

    let cors = if !config.cors_allowed_origins.is_empty() {
        let parsed: Vec<axum::http::HeaderValue> = config
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
    } else {
        if cfg!(debug_assertions) {
            info!("CORS_ALLOWED_ORIGINS not set, using permissive CORS (dev mode)");
            CorsLayer::permissive()
        } else {
            warn!("CORS_ALLOWED_ORIGINS not set in release build, defaulting to restrictive CORS");
            CorsLayer::new()
        }
    };
    let admin_routes = Router::new()
        .route("/hosts", get(dashboard::hosts_snapshot))
        .route("/hosts/:hostname", get(dashboard::host_detail))
        .route("/stats/summary", get(dashboard::stats_summary))
        .layer(middleware::from_fn(
            move |req: Request<Body>, next: Next| {
                let key = config.admin_api_key.clone();
                async move {
                    // If no admin API key configured, deny all access to admin endpoints
                    let Some(ref valid_key) = key else {
                        return StatusCode::NOT_FOUND.into_response();
                    };

                    let provided = req
                        .headers()
                        .get("x-api-key")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");

                    if !constant_time_eq(provided, valid_key) {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }

                    next.run(req).await
                }
            },
        ))
        .with_state(state.clone());

    let router = Router::new()
        .route("/ws", get(dashboard::ws_stats))
        .route("/events", get(dashboard::ws_events))
        .route("/health", get(dashboard::health))
        .merge(admin_routes)
        .fallback(any(proxy::handler))
        .nest_service("/dashboard", ServeDir::new("static"))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state.clone());

    #[cfg(feature = "oracle-db")]
    dashboard::spawn_oracle_flusher(state.clone(), shutdown.clone());

    info!(
        proxy_port = config.proxy_port,
        tproxy_port = config.tproxy_port,
        wg_port = config.wg_port,
        "port assignment"
    );

    let addr = SocketAddr::from(([0, 0, 0, 0], config.proxy_port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            error!(%addr, %e, "failed to bind listener");
            std::process::exit(1)
        });
    info!(%addr, "proxy + dashboard active");

    // Transparent proxy listener — receives connections redirected by iptables REDIRECT
    let tproxy_addr = SocketAddr::from(([0, 0, 0, 0], config.tproxy_port));
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

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received, stopping accept loop");
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

                tasks.spawn(async move {
                    let _permit = permit; // hold until task completes
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let state = state.clone();
                        let router = router.clone();
                        async move {
                            let req: Request<Body> = req.map(Body::new);
                            if req.method() == Method::CONNECT {
                                tunnel::handle(req, state, Some(peer.ip().to_string())).await
                            } else {
                                router.oneshot(req).await.map_err(|e| match e {})
                            }
                        }
                    });

                    let builder = ServerBuilder::new(TokioExecutor::new());
                    let conn = builder
                        .serve_connection_with_upgrades(TokioIo::new(stream), svc);
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
                });
            }
        }
    }

    info!("draining in-flight connections (5s timeout)");
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(5), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(2), tproxy_handle).await;
    info!("shutdown complete");
}
