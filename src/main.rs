mod blocklist;
mod config;
mod dashboard;
#[cfg(feature = "oracle-db")]
mod db;
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
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use tracing::{debug, error, info, warn};

pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
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
    let admin_api_key = config.admin_api_key.clone();
    let admin_routes = Router::new()
        .route("/hosts", get(dashboard::hosts_snapshot))
        .route("/hosts/:hostname", get(dashboard::host_detail))
        .route("/stats/summary", get(dashboard::stats_summary))
        .layer(middleware::from_fn(
            move |req: Request<Body>, next: Next| {
                let key = admin_api_key.clone();
                async move {
                    // If no admin API key configured, deny all access to admin endpoints
                    let Some(valid_key) = key.as_ref() else {
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

    // Build proxy credentials for WAN authentication (RFC 7235 Basic).
    let proxy_creds: Option<std::sync::Arc<(String, String)>> =
        match (&config.proxy_username, &config.proxy_password) {
            (Some(u), Some(p)) => {
                info!(username = %u, "proxy authentication enabled");
                Some(std::sync::Arc::new((u.clone(), p.clone())))
            }
            _ => {
                warn!(
                    "PROXY_USERNAME / PROXY_PASSWORD not set \u{2014} proxy has NO authentication"
                );
                None
            }
        };

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

    // Build TLS acceptor if cert/key paths are configured
    let tls_acceptor: Option<TlsAcceptor> =
        if let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) {
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
            info!("TLS enabled on proxy listener");
            Some(TlsAcceptor::from(std::sync::Arc::new(tls_config)))
        } else {
            warn!("TLS_CERT_PATH / TLS_KEY_PATH not set \u{2014} proxy listener is PLAINTEXT");
            None
        };

    // Spawn QUIC/H3 listener if TLS is configured
    if config.tls_cert_path.is_some() && config.tls_key_path.is_some() {
        let quic_state = state.clone();
        let quic_config = config.clone();
        let quic_shutdown = shutdown.clone();
        let quic_creds = proxy_creds.clone();
        tokio::spawn(async move {
            quic::run_quic_listener(quic_state, quic_config, quic_shutdown, quic_creds).await;
        });
    }

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
                let tls_acceptor = tls_acceptor.clone();
                let proxy_creds = proxy_creds.clone();

                tasks.spawn(async move {
                    let _permit = permit; // hold until task completes

                    // Macro-like closure to build the service and serve a connection
                    // on an arbitrary AsyncRead + AsyncWrite stream.
                    macro_rules! serve_io {
                        ($io:expr) => {{
                            let io = $io;
                            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                                let state = state.clone();
                                let router = router.clone();
                                let creds = proxy_creds.clone();
                                async move {
                                    let req: Request<Body> = req.map(Body::new);

                                    // Proxy requests (CONNECT or absolute-URI forwards)
                                    // require Proxy-Authorization when credentials are
                                    // configured. Internal management routes (relative
                                    // URIs such as /health, /dashboard) pass through.
                                    let is_proxy_request = req.method() == Method::CONNECT
                                        || req.uri().scheme().is_some();

                                    if is_proxy_request {
                                        if let Some(ref c) = creds {
                                            if !check_proxy_auth(&req, &c.0, &c.1) {
                                                return Ok(Response::builder()
                                                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                                                    .header(
                                                        "Proxy-Authenticate",
                                                        "Basic realm=\"proxy\"",
                                                    )
                                                    .body(Body::empty())
                                                    .unwrap());
                                            }
                                        }
                                    }

                                    if req.method() == Method::CONNECT {
                                        tunnel::handle(req, state, Some(peer.ip().to_string())).await
                                    } else {
                                        router.oneshot(req).await.map_err(|e| match e {})
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
                                return;
                            }
                        }
                    } else {
                        serve_io!(TokioIo::new(stream));
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
