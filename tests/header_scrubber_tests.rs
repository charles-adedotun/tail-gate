use hyper::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use tail_gate::proxy::headers::{
    inject_canonical_forwarded_headers, is_sensitive_header, scrub_sensitive_headers,
    SENSITIVE_HEADER_NAMES,
};

#[test]
fn test_all_11_sensitive_headers_are_stripped() {
    let mut headers = HeaderMap::new();

    // Populate every single one of the canonical 11 sensitive headers
    headers.insert(
        HeaderName::from_static("forwarded"),
        HeaderValue::from_static("for=1.2.3.4;proto=http"),
    );
    headers.insert(
        HeaderName::from_static("x-auth-request-user"),
        HeaderValue::from_static("attacker"),
    );
    headers.insert(
        HeaderName::from_static("x-auth-request-email"),
        HeaderValue::from_static("attacker@evil.com"),
    );
    headers.insert(
        HeaderName::from_static("x-auth-request-groups"),
        HeaderValue::from_static("admin"),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-user"),
        HeaderValue::from_static("impersonated_user"),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-email"),
        HeaderValue::from_static("spoofed@example.com"),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_static("8.8.8.8"),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-host"),
        HeaderValue::from_static("fake.internal"),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("http"),
    );
    headers.insert(
        HeaderName::from_static("x-platform-auth"),
        HeaderValue::from_static("stolen-token-123"),
    );
    headers.insert(
        HeaderName::from_static("x-internal-auth-token"),
        HeaderValue::from_static("spoofed-internal-token"),
    );

    // Also populate auxiliary headers
    headers.insert(
        HeaderName::from_static("x-real-ip"),
        HeaderValue::from_static("192.168.1.1"),
    );
    headers.insert(
        HeaderName::from_static("tailscale-user-login"),
        HeaderValue::from_static("fake-tailscale-user"),
    );

    // Add safe headers that MUST be preserved
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("TailGateTestClient/1.0"),
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer legitimate-session-token"),
    );

    let scrubbed = scrub_sensitive_headers(&mut headers);

    // Verify all 11 canonical headers plus auxiliaries were removed
    assert!(scrubbed.len() >= 11);

    for &name in SENSITIVE_HEADER_NAMES {
        let hn = HeaderName::from_bytes(name.as_bytes()).unwrap();
        assert!(
            headers.get(&hn).is_none(),
            "Header '{name}' was NOT scrubbed from HeaderMap!"
        );
    }

    // Verify safe headers were NOT touched
    assert_eq!(headers.get(USER_AGENT).unwrap(), "TailGateTestClient/1.0");
    assert_eq!(headers.get(CONTENT_TYPE).unwrap(), "application/json");
    assert_eq!(
        headers.get(AUTHORIZATION).unwrap(),
        "Bearer legitimate-session-token"
    );
}

#[test]
fn test_case_insensitive_header_scrubbing() {
    let mut headers = HeaderMap::new();

    // Mixed-case headers
    headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_static("1.1.1.1"),
    );
    headers.insert(
        HeaderName::from_static("x-platform-auth"),
        HeaderValue::from_static("val"),
    );

    let scrubbed = scrub_sensitive_headers(&mut headers);
    assert_eq!(scrubbed.len(), 2);
    assert!(headers.get("x-forwarded-for").is_none());
    assert!(headers.get("x-platform-auth").is_none());
}

#[test]
fn test_is_sensitive_header_helper() {
    assert!(is_sensitive_header("Forwarded"));
    assert!(is_sensitive_header("X-Forwarded-For"));
    assert!(is_sensitive_header("X-Auth-Request-User"));
    assert!(is_sensitive_header("X-Platform-Auth"));
    assert!(is_sensitive_header("X-Internal-Auth-Token"));
    assert!(is_sensitive_header("Tailscale-User-Login"));
    assert!(is_sensitive_header("x-real-ip"));

    assert!(!is_sensitive_header("Content-Type"));
    assert!(!is_sensitive_header("Authorization"));
    assert!(!is_sensitive_header("User-Agent"));
    assert!(!is_sensitive_header("Accept"));
}

#[test]
fn test_canonical_header_injection() {
    let mut headers = HeaderMap::new();

    inject_canonical_forwarded_headers(&mut headers, "100.64.0.1", "app.tail.example.com", "https");

    assert_eq!(headers.get("x-forwarded-for").unwrap(), "100.64.0.1");
    assert_eq!(
        headers.get("x-forwarded-host").unwrap(),
        "app.tail.example.com"
    );
    assert_eq!(headers.get("x-forwarded-proto").unwrap(), "https");
}
