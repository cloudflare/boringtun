//! Tunnel-side traffic classification helpers.
//!
//! These helpers map destinations into coarse traffic categories and identify
//! certificate-pinned domains that must bypass interception. They do not
//! perform I/O or state mutation.

/// Map the destination into a human-readable traffic category.
pub(crate) fn classify(host: &str, port: u16, alpn: Option<&str>) -> &'static str {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h.contains("firebaselogging")
        || h.contains("firebase-settings")
        || h.contains("app-measurement")
        || h.contains("crashlytics")
        || h.contains("sentry.io")
        || h.contains("analytics")
        || h.contains("telemetry")
        || h.contains("metrics")
        || h.contains("datadog")
        || h.contains("newrelic")
        || h.contains("segment.io")
    {
        return "telemetry";
    }
    if h.contains("doubleclick")
        || h.contains("googlesyndication")
        || h.contains("adnxs")
        || h.contains("criteo")
        || h.contains("pubmatic")
        || h.contains("rubiconproject")
        || h.contains("scorecardresearch")
    {
        return "ads/tracking";
    }
    if h.contains("push.apple.com")
        || h.contains("push.googleapis")
        || h.contains("fcm.googleapis")
        || h.contains("notify.windows")
    {
        return "push-notifications";
    }
    if h.contains("accounts.google")
        || h.contains("oauth")
        || h.contains("auth0.com")
        || h.contains("okta")
        || h.contains("login.microsoft")
        || h.contains("appleid.apple")
    {
        return "auth";
    }
    if h.contains("akamai")
        || h.contains("cloudfront")
        || h.contains("fastly.net")
        || h.contains(".cdn.")
        || h.contains("static.")
        || h.contains("assets.")
    {
        return "cdn/media";
    }
    if h.contains("apple.com") {
        return "apple-services";
    }
    if h.contains("icloud.com") {
        return "icloud";
    }
    if h.contains("googleapis.com") {
        return "google-services";
    }
    if h.contains("whatsapp") {
        return "whatsapp";
    }
    if h.contains("instagram") {
        return "instagram";
    }
    if h.contains("facebook") {
        return "facebook";
    }
    if h.contains("twitter") || h.contains("twimg") {
        return "twitter/x";
    }
    if h.contains("netflix") {
        return "netflix";
    }
    if h.contains("spotify") {
        return "spotify";
    }
    match (port, alpn) {
        (443, Some("h2")) => "https/h2",
        (443, Some("http/1.1")) => "https/h1",
        (443, _) => "https",
        (80, _) => "http",
        (22, _) => "ssh",
        (5228, _) => "google-push",
        _ => "unknown",
    }
}

/// Return whether the hostname is known to require certificate pinning bypass.
pub(crate) fn is_cert_pinned_host(hostname: &str) -> bool {
    let normalized = hostname.trim_end_matches('.').to_ascii_lowercase();
    let pinned_suffixes = [
        "facebook.com",
        "fbcdn.net",
        "instagram.com",
        "cdninstagram.com",
        "instagramstatic.com",
        "youtube.com",
        "googlevideo.com",
        "ytimg.com",
        "ggpht.com",
        "gvt1.com",
        "apple.com",
    ];
    pinned_suffixes
        .iter()
        .any(|suffix| normalized == *suffix || normalized.ends_with(&format!(".{suffix}")))
}

#[cfg(test)]
mod tests {
    use super::{classify, is_cert_pinned_host};

    #[test]
    fn classify_normalizes_case_and_trailing_dot() {
        assert_eq!(classify("SENTRY.IO.", 443, None), "telemetry");
    }

    #[test]
    fn pinned_host_normalization_handles_trailing_dot() {
        assert!(is_cert_pinned_host("APPLE.COM."));
    }
}
