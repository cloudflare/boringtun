//! Library exports for integration tests and shared module access.
//!
//! The production binary lives in `main.rs`, but integration tests import the
//! same modules through this library target.

use base64::Engine;

pub mod blocklist;
pub mod config;
pub mod dashboard;
#[cfg(feature = "oracle-db")]
pub mod db;
pub mod events;
pub mod obfuscation;
pub mod proxy;
pub mod quic;
pub mod state;
pub mod tunnel;

/// Compare two strings in constant time up to the fixed maximum length.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Validate the `Proxy-Authorization` header for proxy requests.
pub fn check_proxy_auth<B>(req: &axum::http::Request<B>, username: &str, password: &str) -> bool {
    let header = match req
        .headers()
        .get("proxy-authorization")
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h,
        None => return false,
    };
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

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn constant_time_eq_matches_equal_strings() {
        assert!(constant_time_eq("same-value", "same-value"));
    }

    #[test]
    fn constant_time_eq_rejects_same_prefix_with_different_lengths() {
        assert!(!constant_time_eq("prefix", "prefix-suffix"));
    }

    #[test]
    fn constant_time_eq_handles_long_inputs() {
        let a = "a".repeat(300);
        let b = "a".repeat(300);
        let c = format!("{}b", "a".repeat(299));

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }
}
