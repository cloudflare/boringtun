//! Upstream authority parsing and resolver-backed dialing helpers.
//!
//! This module owns host/port parsing and the timeout-wrapped DNS + TCP dial
//! flow used by CONNECT and bypass paths. It does not emit audit events or
//! mutate application state beyond DNS lookups.

use std::io;

use crate::state::SharedState;

const DNS_RESOLVE_TIMEOUT_SECS: u64 = 5;
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Describe a failure while resolving or connecting to an upstream target.
#[derive(Debug)]
pub(crate) enum UpstreamDialError {
    ResolveTimeout,
    ResolveFailed(String),
    NoAddresses,
    ConnectTimeout,
    ConnectFailed(io::Error),
}

impl UpstreamDialError {
    /// Return the low-cardinality error class for logging.
    pub(crate) fn class(&self) -> &'static str {
        match self {
            Self::ResolveTimeout => "resolve_timeout",
            Self::ResolveFailed(_) => "resolve_failed",
            Self::NoAddresses => "resolve_empty",
            Self::ConnectTimeout => "connect_timeout",
            Self::ConnectFailed(_) => "connect_failed",
        }
    }

    /// Render the detailed error string for logs.
    pub(crate) fn detail(&self) -> String {
        match self {
            Self::ResolveTimeout => "resolver timeout".to_string(),
            Self::ResolveFailed(err) => format!("resolver error: {err}"),
            Self::NoAddresses => "resolver returned no addresses".to_string(),
            Self::ConnectTimeout => "upstream connect timeout".to_string(),
            Self::ConnectFailed(err) => format!("upstream connect error: {err}"),
        }
    }
}

/// Parse an authority string into `(hostname, port)`.
pub(crate) fn parse_host_port(authority: &str) -> (String, u16) {
    if authority.starts_with('[') {
        let Some(bracket_end) = authority.find(']') else {
            return (authority.to_string(), 443);
        };
        let remainder = &authority[bracket_end + 1..];
        if !remainder.is_empty() && !remainder.starts_with(':') {
            return (authority.to_string(), 443);
        }

        let hostname = authority[1..bracket_end].to_string();
        let port = remainder
            .strip_prefix(':')
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(443);
        return (hostname, port);
    }
    if authority.contains(']') {
        return (authority.to_string(), 443);
    }
    if authority.chars().filter(|&c| c == ':').count() > 1 {
        return (authority.to_string(), 443);
    }
    authority
        .rsplit_once(':')
        .and_then(|(h, p)| p.parse::<u16>().ok().map(|port| (h.to_string(), port)))
        .unwrap_or_else(|| (authority.to_string(), 443))
}

/// Dial the upstream target after resolving it through the configured resolver.
pub(crate) async fn dial_upstream_with_resolver(
    state: &SharedState,
    authority: &str,
) -> Result<(tokio::net::TcpStream, Vec<String>, String), UpstreamDialError> {
    let (hostname, port) = parse_host_port(authority);

    let addrs = tokio::time::timeout(
        tokio::time::Duration::from_secs(DNS_RESOLVE_TIMEOUT_SECS),
        state.resolver.lookup_ip(hostname.as_str()),
    )
    .await
    .map_err(|_| UpstreamDialError::ResolveTimeout)?
    .map_err(|e| UpstreamDialError::ResolveFailed(e.to_string()))?;

    let ips: Vec<std::net::IpAddr> = addrs.iter().collect();
    let resolved_ips: Vec<String> = ips.iter().map(ToString::to_string).collect();
    if ips.is_empty() {
        return Err(UpstreamDialError::NoAddresses);
    }

    let connect = async {
        let mut last_err = io::Error::new(io::ErrorKind::NotFound, "No connect candidates");
        for ip in &ips {
            match tokio::net::TcpStream::connect((*ip, port)).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    };

    let upstream = tokio::time::timeout(
        tokio::time::Duration::from_secs(CONNECT_TIMEOUT_SECS),
        connect,
    )
    .await
    .map_err(|_| UpstreamDialError::ConnectTimeout)?
    .map_err(UpstreamDialError::ConnectFailed)?;

    let selected_ip = upstream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "-".to_string());

    Ok((upstream, resolved_ips, selected_ip))
}

#[cfg(test)]
mod tests {
    use super::parse_host_port;

    #[test]
    fn parses_ipv4_and_hostname_authorities() {
        assert_eq!(
            parse_host_port("example.com"),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("example.com:8443"),
            ("example.com".to_string(), 8443)
        );
        assert_eq!(parse_host_port("1.2.3.4:80"), ("1.2.3.4".to_string(), 80));
    }

    #[test]
    fn parses_ipv6_authorities() {
        assert_eq!(parse_host_port("[::1]"), ("::1".to_string(), 443));
        assert_eq!(parse_host_port("[::1]:8443"), ("::1".to_string(), 8443));
        assert_eq!(
            parse_host_port("2001:db8::1"),
            ("2001:db8::1".to_string(), 443)
        );
    }

    #[test]
    fn falls_back_for_malformed_bracketed_authorities() {
        assert_eq!(
            parse_host_port("foo[::1]:8443"),
            ("foo[::1]:8443".to_string(), 443)
        );
        assert_eq!(parse_host_port("[::1"), ("[::1".to_string(), 443));
        assert_eq!(
            parse_host_port("[::1]extra"),
            ("[::1]extra".to_string(), 443)
        );
    }
}
