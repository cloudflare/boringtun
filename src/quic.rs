use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::blocklist;
use crate::check_proxy_auth;
use crate::config::Config;
use crate::obfuscation;
use crate::state::SharedState;

/// Build a `rustls::ServerConfig` from the TLS cert/key paths in `Config`.
/// Panics if the files are missing or malformed — caller must ensure paths are set.
fn build_rustls_config(config: &Config) -> Arc<rustls::ServerConfig> {
    let cert_path = config
        .tls_cert_path
        .as_ref()
        .expect("tls_cert_path must be set for QUIC");
    let key_path = config
        .tls_key_path
        .as_ref()
        .expect("tls_key_path must be set for QUIC");

    let cert_pem = std::fs::read(cert_path).expect("failed to read TLS cert for QUIC");
    let key_pem = std::fs::read(key_path).expect("failed to read TLS key for QUIC");
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .expect("invalid cert PEM for QUIC");
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("failed to parse key PEM for QUIC")
        .expect("no private key found for QUIC");

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("invalid TLS config for QUIC");

    // Enable HTTP/3 ALPN
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    Arc::new(tls_config)
}

/// Run the QUIC/HTTP3 listener on `0.0.0.0:443` (UDP).
///
/// For each incoming QUIC connection, spawns a task that processes HTTP/3
/// requests. CONNECT requests are handled with the same blocklist/policy
/// logic as the TCP proxy, then bidirectional-copied to the upstream.
pub async fn run_quic_listener(
    state: SharedState,
    config: Config,
    shutdown: CancellationToken,
    proxy_creds: Option<Arc<(String, String)>>,
) {
    let rustls_config = build_rustls_config(&config);

    let quinn_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config);
    let quinn_config = match quinn_config {
        Ok(c) => c,
        Err(e) => {
            error!(%e, "failed to build QUIC server config");
            return;
        }
    };
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quinn_config));

    let addr: SocketAddr = "0.0.0.0:443".parse().unwrap();
    let endpoint = match quinn::Endpoint::server(server_config, addr) {
        Ok(ep) => ep,
        Err(e) => {
            error!(%addr, %e, "failed to bind QUIC endpoint");
            return;
        }
    };
    info!(%addr, "QUIC/H3 listener active");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("QUIC listener shutting down");
                endpoint.close(0u32.into(), b"shutdown");
                break;
            }
            incoming = endpoint.accept() => {
                let incoming = match incoming {
                    Some(i) => i,
                    None => {
                        info!("QUIC endpoint closed");
                        break;
                    }
                };
                let state = state.clone();
                let config = config.clone();
                let creds = proxy_creds.clone();
                tokio::spawn(async move {
                    handle_quic_connection(incoming, state, config, creds).await;
                });
            }
        }
    }
}

/// Handle a single QUIC connection: accept it, then process HTTP/3 requests.
async fn handle_quic_connection(
    incoming: quinn::Incoming,
    state: SharedState,
    config: Config,
    proxy_creds: Option<Arc<(String, String)>>,
) {
    let connection = match incoming.await {
        Ok(c) => c,
        Err(e) => {
            debug!(%e, "QUIC connection failed");
            return;
        }
    };
    let peer = connection.remote_address();
    debug!(%peer, "QUIC connection established");

    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
        match h3::server::Connection::new(h3_quinn::Connection::new(connection)).await {
            Ok(c) => c,
            Err(e) => {
                debug!(%peer, %e, "H3 connection setup failed");
                return;
            }
        };

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let state = state.clone();
                let config = config.clone();
                let creds = proxy_creds.clone();
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            handle_h3_request(req, stream, state, config, peer, creds).await;
                        }
                        Err(e) => {
                            debug!(%peer, %e, "H3 request resolve failed");
                        }
                    }
                });
            }
            Ok(None) => {
                debug!(%peer, "H3 connection closed");
                break;
            }
            Err(e) => {
                debug!(%peer, %e, "H3 accept error");
                break;
            }
        }
    }
}

/// Handle a single HTTP/3 request.
///
/// - CONNECT: extract host from `:authority`, run blocklist check, then
///   bidirectional copy to the upstream target (same as `tunnel::handle`).
/// - Other methods: return 405 for now (can be extended later).
async fn handle_h3_request(
    req: axum::http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: SharedState,
    config: Config,
    peer: SocketAddr,
    proxy_creds: Option<Arc<(String, String)>>,
) {
    let method = req.method().clone();
    let uri = req.uri().clone();

    // Proxy authentication check — all H3 requests are proxy requests
    // (QUIC/H3 is only used for CONNECT tunnels, not internal management).
    if let Some(ref creds) = proxy_creds {
        if !check_proxy_auth(&req, &creds.0, &creds.1) {
            let resp = axum::http::Response::builder()
                .status(axum::http::StatusCode::from_u16(407).unwrap())
                .header("Proxy-Authenticate", "Basic realm=\"proxy\"")
                .body(())
                .unwrap();
            stream.send_response(resp).await.ok();
            stream.finish().await.ok();
            return;
        }
    }

    if method != axum::http::Method::CONNECT {
        // Non-CONNECT: return 405 Method Not Allowed
        let resp = axum::http::Response::builder()
            .status(axum::http::StatusCode::METHOD_NOT_ALLOWED)
            .body(())
            .unwrap();
        if let Err(e) = stream.send_response(resp).await {
            debug!(%peer, %e, "failed to send H3 405 response");
        }
        stream.finish().await.ok();
        return;
    }

    // Extract host from :authority pseudo-header
    let host = match uri.authority().map(|a| a.to_string()) {
        Some(h) => h,
        None => {
            error!(%peer, uri = %uri, "H3 CONNECT missing :authority");
            let resp = axum::http::Response::builder()
                .status(axum::http::StatusCode::BAD_REQUEST)
                .body(())
                .unwrap();
            stream.send_response(resp).await.ok();
            stream.finish().await.ok();
            return;
        }
    };

    let hostname: String = host
        .rsplit_once(':')
        .and_then(|(h, p)| {
            p.parse::<u16>()
                .ok()
                .map(|_| h.trim_start_matches('[').trim_end_matches(']').to_string())
        })
        .unwrap_or_else(|| {
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .to_string()
        });
    let port: u16 = host
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(443);

    // Blocklist check — same logic as tunnel::handle (lines 801-935)
    if blocklist::is_blocked(&hostname, &state).await {
        state.record_blocked();
        let approx_bytes = (50 + hostname.len()) as u64;
        state.record_host_block(&hostname, approx_bytes, "quic");
        info!(
            target: "audit",
            event = "tunnel_blocked",
            kind = "quic-h3",
            host = %host,
            "blocked snitch (QUIC/H3)"
        );
        let event = serde_json::json!({
            "type":     "block",
            "host":     hostname,
            "kind":     "quic-h3",
            "time":     chrono::Utc::now().to_rfc3339(),
        });
        let _ = state.events_tx.send(event.to_string());

        // Return 200 OK then immediately close (fast drop)
        let resp = axum::http::Response::builder()
            .status(axum::http::StatusCode::OK)
            .body(())
            .unwrap();
        stream.send_response(resp).await.ok();
        stream.finish().await.ok();
        return;
    }

    // Classify obfuscation profile after blocklist check
    let _profile = obfuscation::classify_obfuscation(&hostname, &config);

    // Record allow for streak reset
    state.record_host_allow(&hostname);

    // Send 200 OK to acknowledge the CONNECT
    let resp = axum::http::Response::builder()
        .status(axum::http::StatusCode::OK)
        .body(())
        .unwrap();
    if let Err(e) = stream.send_response(resp).await {
        debug!(%peer, %e, "failed to send H3 200 response");
        return;
    }

    // Connect to the upstream target
    let connect = async {
        let addrs = state.resolver.lookup_ip(hostname.as_str()).await?;
        let mut last_err =
            std::io::Error::new(std::io::ErrorKind::NotFound, "DoH returned no addresses");
        for ip in addrs.iter() {
            match tokio::net::TcpStream::connect((ip, port)).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    };

    let mut upstream =
        match tokio::time::timeout(tokio::time::Duration::from_secs(10), connect).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                error!(%host, %e, "QUIC: failed to connect to tunnel target");
                stream.finish().await.ok();
                return;
            }
            Err(_) => {
                error!(%host, "QUIC: tunnel connect timed out");
                stream.finish().await.ok();
                return;
            }
        };

    let start = Instant::now();
    info!(
        target: "audit",
        event = "tunnel_open",
        kind = "quic-h3",
        host = %host,
        "QUIC tunnel established"
    );
    state.record_tunnel_open();

    // Bidirectional copy between H3 stream and upstream TCP.
    // Split the H3 bidi stream into send/recv halves and the upstream TCP stream.
    let (mut h3_send, mut h3_recv) = stream.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();

    // H3 → upstream: read H3 data chunks and write to TCP
    let h3_to_upstream = async {
        let mut total: u64 = 0;
        loop {
            match h3_recv.recv_data().await {
                Ok(Some(mut buf)) => {
                    while bytes::Buf::has_remaining(&buf) {
                        let chunk: &[u8] = bytes::Buf::chunk(&buf);
                        let len = chunk.len();
                        if let Err(e) = upstream_write.write_all(chunk).await {
                            debug!(%host, %e, "QUIC: upstream write failed");
                            return total;
                        }
                        total += len as u64;
                        bytes::Buf::advance(&mut buf, len);
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    debug!(%host, %e, "QUIC: H3 recv failed");
                    break;
                }
            }
        }
        total
    };

    // upstream → H3: read TCP and send as H3 data
    let upstream_to_h3 = async {
        let mut total: u64 = 0;
        let mut buf = vec![0u8; 16384];
        loop {
            match upstream_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let data = Bytes::copy_from_slice(&buf[..n]);
                    if let Err(e) = h3_send.send_data(data).await {
                        debug!(%host, %e, "QUIC: H3 send failed");
                        break;
                    }
                    total += n as u64;
                }
                Err(e) => {
                    debug!(%host, %e, "QUIC: upstream read failed");
                    break;
                }
            }
        }
        h3_send.finish().await.ok();
        total
    };

    let (up, down) = tokio::join!(h3_to_upstream, upstream_to_h3);
    state.record_tunnel_close(up, down);

    info!(
        target: "audit",
        event = "tunnel_close",
        kind = "quic-h3",
        host = %host,
        bytes_up = up,
        bytes_down = down,
        duration_ms = start.elapsed().as_millis(),
        "QUIC tunnel closed"
    );
}
