use hyper::header::{HeaderMap, HeaderName, HeaderValue};

/// The primary 11 sensitive headers scrubbed by platform ingress to prevent spoofing,
/// augmented by mesh identity and transport headers.
pub static SENSITIVE_HEADER_NAMES: &[&str] = &[
    // The canonical 11 headers from platform/ingress/runtime/Caddyfile.common
    "forwarded",
    "x-auth-request-user",
    "x-auth-request-email",
    "x-auth-request-groups",
    "x-forwarded-user",
    "x-forwarded-email",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-platform-auth",
    "x-internal-auth-token",
    // Auxiliary spoofable headers
    "x-real-ip",
    "x-scheme",
    "tailscale-user-login",
    "tailscale-user-name",
    "tailscale-headers-info",
    "x-edge-broker-client-signature",
    "x-edge-broker-client-fingerprint",
    "x-edge-broker-caller",
];

/// Remove all sensitive and spoofable headers from the provided request headers.
/// Returns a list of headers that were actually removed (for structured audit logging).
pub fn scrub_sensitive_headers(headers: &mut HeaderMap) -> Vec<String> {
    let mut removed = Vec::new();

    for &name in SENSITIVE_HEADER_NAMES {
        if let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) {
            // HeaderMap::remove removes all values associated with the header name
            if headers.remove(&header_name).is_some() {
                removed.push(name.to_string());
            }
        }
    }

    // Also check for dynamic patterns like tailscale-user-* if present
    let keys_to_remove: Vec<HeaderName> = headers
        .keys()
        .filter(|key| {
            let s = key.as_str().to_lowercase();
            s.starts_with("tailscale-user-") || s.starts_with("x-auth-request-")
        })
        .cloned()
        .collect();

    for key in keys_to_remove {
        if headers.remove(&key).is_some() {
            removed.push(key.as_str().to_string());
        }
    }

    removed
}

/// Check if a given header name is in the sensitive/prohibited list.
pub fn is_sensitive_header(name: &str) -> bool {
    let lower = name.trim().to_lowercase();
    SENSITIVE_HEADER_NAMES.contains(&lower.as_str())
        || lower.starts_with("tailscale-user-")
        || lower.starts_with("x-auth-request-")
}

/// Safely inject canonical forwarding headers into an upstream request.
pub fn inject_canonical_forwarded_headers(
    headers: &mut HeaderMap,
    remote_addr: &str,
    host: &str,
    proto: &str,
) {
    if let Ok(val) = HeaderValue::from_str(remote_addr) {
        headers.insert(HeaderName::from_static("x-forwarded-for"), val);
    }
    if let Ok(val) = HeaderValue::from_str(host) {
        headers.insert(HeaderName::from_static("x-forwarded-host"), val);
    }
    if let Ok(val) = HeaderValue::from_str(proto) {
        headers.insert(HeaderName::from_static("x-forwarded-proto"), val);
    }
}
