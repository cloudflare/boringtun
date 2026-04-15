use axum::{
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode},
};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use std::{sync::atomic::Ordering, time::Instant};
use tracing::{error, info};

use crate::{blocklist, obfuscation, state::SharedState};

pub type ProxyClient = Client<HttpConnector, Body>;

/// Return a URI string with the query component replaced by `[REDACTED]`.
fn scrub_uri(uri: &axum::http::Uri) -> String {
    if uri.query().is_some() {
        format!("{}?[REDACTED]", uri.path())
    } else {
        uri.path().to_string()
    }
}

/// Epic 1.4 — extract path and query-parameter names only (no values).
fn decompose_uri(uri: &axum::http::Uri) -> (String, Vec<String>) {
    let path = uri.path().to_string();
    let keys = uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter_map(|pair| {
            pair.split('=')
                .next()
                .filter(|k| !k.is_empty())
                .map(str::to_string)
        })
        .collect();
    (path, keys)
}
fn emit_full(
    state: &SharedState,
    event: &str,
    host: &str,
    peer_ip: Option<String>,
    bytes_up: u64,
    bytes_down: u64,
    status_code: Option<u16>,
    blocked: bool,
    obfuscation_profile: Option<String>,
    extra: serde_json::Value,
) {
    let mut v = serde_json::json!({
        "type": event,
        "host": host,
        "time": chrono::Utc::now().to_rfc3339(),
    });
    if let (Some(obj), Some(ext)) = (v.as_object_mut(), extra.as_object()) {
        obj.extend(ext.clone());
    }
    let raw = v.to_string();
    
    // Send to broadcast channel (non-blocking for broadcast senders)
    if let Err(e) = state.events_tx.send(raw.clone()) {
        tracing::warn!(target: "audit", error = %e, "failed to send audit event to channel");
    }
    
    #[cfg(feature = "oracle-db")]
    {
        let db = state.db.clone();
        let event = crate::db::ProxyEvent {
            obfuscation_profile,
            event_type: event.to_string(),
            host: host.to_string(),
            peer_ip,
            bytes_up,
            bytes_down,
            status_code,
            blocked,
            correlation_id: None,
            parent_event_id: None,
            event_sequence: None,
            duration_ms: None,
            raw_json: raw,
        };
        
        // Offload blocking DB operation to blocking thread pool
        let handle = tokio::task::spawn_blocking(move || {
            if let Err(e) = crate::db::insert_proxy_event(db, event) {
                error!(%e, "failed to insert proxy event into database");
            }
        });
        
        // Detach handle but log join errors
        tokio::spawn(async move {
            if let Err(e) = handle.await {
                error!(%e, "proxy event database task failed");
            }
        });
    }
}
pub async fn handler(
    State(state): State<SharedState>,
    mut req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let start = Instant::now();

    // Check blocklist using the host from the URI or Host header.
    let hostname = req
        .uri()
        .host()
        .or_else(|| req.headers().get("host").and_then(|v| v.to_str().ok()))
        .unwrap_or("");
    let hostname = if hostname.starts_with('[') {
        hostname
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("")
    } else {
        hostname.split(':').next().unwrap_or("")
    }
    .to_string();
    if hostname.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if blocklist::is_blocked(&hostname, &state).await {
        state.record_blocked();
        let scrubbed = scrub_uri(req.uri());
        // Epic 1.1 — Content-Length header value (no body buffering)
        let req_content_length: Option<u64> = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        // Epic 1.2a — interesting header inventory
        let interesting = [
            "content-type",
            "user-agent",
            "x-client-data",
            "x-amz-target",
        ];
        let req_headers_present: Vec<String> = interesting
            .iter()
            .filter(|&&h| req.headers().contains_key(h))
            .map(|&h| h.to_string())
            .collect();
        // Epic 1.2b — auth/cookie presence flags (names only, zero value leakage)
        let req_has_auth = req.headers().contains_key("authorization");
        let req_has_cookie = req.headers().contains_key("cookie");
        // Epic 1.4 — URI decomposition
        let (req_path, req_query_keys) = decompose_uri(req.uri());
        info!(
            target: "audit",
            event = "http_blocked",
            host = %hostname,
            method = %req.method(),
            uri = %scrubbed,
            duration_ms = start.elapsed().as_millis(),
            "blocked snitch (http)"
        );
        emit_full(
            &state,
            "http_blocked",
            &hostname,
            None,
            0,
            0,
            None,
            true,
            None,
            serde_json::json!({
                "method":              req.method().as_str(),
                "uri":                 scrubbed,
                "duration_ms":         start.elapsed().as_millis(),
                "req_content_length_bytes": req_content_length,
                "req_headers_present": req_headers_present,
                "req_has_auth":        req_has_auth,
                "req_has_cookie":      req_has_cookie,
                "req_path":            req_path,
                "req_query_keys":      req_query_keys,
            }),
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Classify obfuscation profile after blocklist check
    let profile = obfuscation::classify_obfuscation(&hostname, &state.config);

    // Rewrite absolute URI to origin form and forward to the correct host.
    if req.uri().scheme().is_some() {
        let host = req
            .uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let new_uri = format!("http://{}{}", host, path_and_query);
        *req.uri_mut() = new_uri.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    }

    // Capture display values before req is consumed by the upstream call.
    let method = req.method().clone();
    let scrubbed_uri = scrub_uri(req.uri());

    req.headers_mut().remove("connection");
    req.headers_mut().remove("keep-alive");
    req.headers_mut().remove("proxy-authorization");
    req.headers_mut().remove("te");
    req.headers_mut().remove("trailers");
    req.headers_mut().remove("transfer-encoding");
    req.headers_mut().remove("upgrade");

    // Full global header scrubbing - remove ALL identifying headers
    {
        let headers = req.headers_mut();
        
        // Explicitly remove known leak headers
        headers.remove("forwarded");
        headers.remove("x-real-ip");
        headers.remove("x-client-ip");
        headers.remove("x-forwarded-host");
        headers.remove("x-forwarded-proto");
        headers.remove("x-forwarded-port");
        headers.remove("x-forwarded-for");
        headers.remove("x-forwarded-server");
        headers.remove("x-forwarded-proto");
        headers.remove("x-original-url");
        headers.remove("x-original-uri");
        headers.remove("x-request-id");
        headers.remove("x-request-id");
        headers.remove("x-amzn-trace-id");
        headers.remove("x-cloud-trace-context");
        headers.remove("via");
        
        // Remove ANY header starting with x- that is not explicitly whitelisted
        let x_headers: Vec<_> = headers.keys()
            .filter(|k| {
                let name = k.as_str();
                name.starts_with("x-") && 
                // Whitelist only safe headers here
                !name.eq("x-amz-target") &&
                !name.eq("x-client-data")
            })
            .map(|k| k.clone())
            .collect();
            
        for name in x_headers {
            headers.remove(name);
        }
        
        // Replace User-Agent with generic value
        headers.insert("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".parse().unwrap());
    }

    // Apply request header obfuscation for Fox profiles
    if !matches!(profile, obfuscation::Profile::None) {
        obfuscation::apply_request_headers(req.headers_mut(), &profile, &state.config);
        state.obfuscated_count.fetch_add(1, Ordering::Relaxed);
    }

    match state.client.request(req).await {
        Ok(mut res) => {
            let status = res.status().as_u16();
            info!(
                target: "audit",
                event = "http_proxied",
                host = %hostname,
                method = %method,
                uri = %scrubbed_uri,
                status = status,
                duration_ms = start.elapsed().as_millis(),
                "proxy response received"
            );
            // Apply response header obfuscation for Fox profiles
            if !matches!(profile, obfuscation::Profile::None) {
                obfuscation::apply_response_headers(res.headers_mut(), &profile);
            }

            // Emit obfuscated event if profile is not None
            if !matches!(profile, obfuscation::Profile::None) {
                info!(
                    target: "audit",
                    event = "http_obfuscated",
                    host = %hostname,
                    profile = profile.as_str(),
                    method = %method,
                    uri = %scrubbed_uri,
                    status = status,
                    duration_ms = start.elapsed().as_millis(),
                    "http traffic obfuscated"
                );
            }

            emit_full(
                &state,
                "http_proxied",
                &hostname,
                None,
                0,
                0,
                Some(status),
                false,
                if matches!(profile, obfuscation::Profile::None) { None } else { Some(profile.as_str().to_string()) },
                serde_json::json!({
                    "method": method.as_str(),
                    "uri":    scrubbed_uri,
                    "status": status,
                    "duration_ms": start.elapsed().as_millis(),
                    "obfuscation_profile": profile.as_str(),
                }),
            );
            let mut res = res.map(Body::new);
            // Collect any header names listed in the Connection header value.
            let conn_headers: Vec<String> = res
                .headers()
                .get_all("connection")
                .iter()
                .flat_map(|v| v.to_str().unwrap_or("").split(','))
                .map(|s| s.trim().to_lowercase())
                .collect();
            for name in &conn_headers {
                res.headers_mut().remove(name.as_str());
            }
            for h in &[
                "connection",
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "proxy-connection",
                "te",
                "trailer",
                "trailers",
                "transfer-encoding",
                "upgrade",
            ] {
                res.headers_mut().remove(*h);
            }
            Ok(res)
        }
        Err(e) => {
            error!(
                target: "audit",
                event = "http_error",
                host = %hostname,
                method = %method,
                uri = %scrubbed_uri,
                duration_ms = start.elapsed().as_millis(),
                error = %e,
                "upstream request failed"
            );
            emit_full(
                &state,
                "http_error",
                &hostname,
                None,
                0,
                0,
                None,
                false,
                None,
                serde_json::json!({
                    "method": method.as_str(),
                    "uri":    scrubbed_uri,
                    "error_kind": if e.is_connect() { "connect" }
                                  else if e.to_string().contains("timed out") { "timeout" }
                                  else { "other" },
                    "duration_ms": start.elapsed().as_millis(),
                }),
            );
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}
