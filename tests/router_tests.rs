use hyper::header::HOST;
use hyper::{Request, StatusCode};
use tail_gate::config::{BackendTarget, Config, RouteRule};
use tail_gate::proxy::extract_host;
use tail_gate::router::{misdirected_request_response, RouteTable};

fn test_config() -> Config {
    Config {
        listen_addr: "127.0.0.1:9443".parse().unwrap(),
        tailscale_socket_path: "/var/run/tailscale/tailscaled.sock".into(),
        routes: vec![
            RouteRule {
                host: "app.tail.example.com".into(),
                backend: BackendTarget::Tcp("127.0.0.1:8000".into()),
                strip_headers: true,
                require_tailscale_users: None,
                require_tailscale_tags: None,
            },
            RouteRule {
                host: "service.tail.example.com".into(),
                backend: BackendTarget::UnixSocket("/run/service/edge.sock".into()),
                strip_headers: true,
                require_tailscale_users: None,
                require_tailscale_tags: None,
            },
            RouteRule {
                host: "tail.example.com".into(),
                backend: BackendTarget::Static {
                    status: 200,
                    body: "platform landing".into(),
                    content_type: Some("text/html".into()),
                },
                strip_headers: true,
                require_tailscale_users: None,
                require_tailscale_tags: None,
            },
        ],
    }
}

#[test]
fn test_exact_host_lookup_success() {
    let cfg = test_config();
    let table = RouteTable::new(&cfg);

    // Exact matches
    assert!(table.find_route("app.tail.example.com").is_some());
    assert!(table.find_route("service.tail.example.com").is_some());
    assert!(table.find_route("tail.example.com").is_some());

    // Case-insensitivity
    assert!(table.find_route("APP.TAIL.EXAMPLE.COM").is_some());
    assert!(table.find_route("Service.Tail.Example.Com").is_some());

    // Matches with port attached
    assert!(table.find_route("app.tail.example.com:9443").is_some());
    assert!(table.find_route("app.tail.example.com:443").is_some());

    // Matches with trailing FQDN dot
    assert!(table.find_route("app.tail.example.com.").is_some());
}

#[test]
fn test_unmapped_host_fails_closed() {
    let cfg = test_config();
    let table = RouteTable::new(&cfg);

    // Unmapped domains must return None
    assert!(table.find_route("unknown.tail.example.com").is_none());
    assert!(table.find_route("attacker.org").is_none());
    assert!(table.find_route("google.com").is_none());
    assert!(table.find_route("evil-app.tail.example.com").is_none());
    assert!(table.find_route("sub.app.tail.example.com").is_none());
}

#[test]
fn test_rfc9110_421_response_generation() {
    let resp = misdirected_request_response("unmapped host 'evil.tail.example.com'");

    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(resp.status().as_u16(), 421);

    let headers = resp.headers();
    assert_eq!(
        headers.get("content-type").unwrap(),
        "text/plain; charset=utf-8"
    );
    assert_eq!(headers.get("connection").unwrap(), "close");
}

#[test]
fn test_host_extraction() {
    // 1. From Host header
    let req1 = Request::builder()
        .header(HOST, "app.tail.example.com")
        .uri("/healthz")
        .body(())
        .unwrap();
    assert_eq!(
        extract_host(&req1),
        Some("app.tail.example.com".to_string())
    );

    // 2. From URI authority (HTTP/2 :authority)
    let req2 = Request::builder()
        .uri("https://service.tail.example.com/api/status")
        .body(())
        .unwrap();
    assert_eq!(
        extract_host(&req2),
        Some("service.tail.example.com".to_string())
    );

    // 3. Missing host
    let req3 = Request::builder().uri("/").body(()).unwrap();
    assert_eq!(extract_host(&req3), None);
}

#[test]
fn test_wildcard_forbidden_in_config() {
    let mut cfg = test_config();
    cfg.routes.push(RouteRule {
        host: "*.tail.example.com".into(),
        backend: BackendTarget::Tcp("127.0.0.1:9000".into()),
        strip_headers: true,
        require_tailscale_users: None,
        require_tailscale_tags: None,
    });

    assert!(cfg.validate().is_err());
}
