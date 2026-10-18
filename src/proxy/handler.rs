use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::HOST;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpStream, UnixStream};
use tracing::{info, warn};

use crate::config::BackendTarget;
use crate::proxy::headers::{inject_canonical_forwarded_headers, scrub_sensitive_headers};
use crate::router::{misdirected_request_response, status_response, ResponseBody, RouteTable};
use crate::tailscale::TailscaleClient;

pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;

/// Extract the destination host from the request's `Host` header or `:authority` pseudo-header.
pub fn extract_host<B>(req: &Request<B>) -> Option<String> {
    if let Some(host_hdr) = req.headers().get(HOST) {
        if let Ok(host_str) = host_hdr.to_str() {
            return Some(host_str.to_string());
        }
    }
    if let Some(auth) = req.uri().authority() {
        return Some(auth.as_str().to_string());
    }
    None
}

/// The core reverse proxy request handler.
pub async fn handle_proxy_request(
    mut req: Request<Incoming>,
    remote_addr: SocketAddr,
    route_table: Arc<RouteTable>,
    tailscale_client: Option<Arc<TailscaleClient>>,
) -> Result<Response<ResponseBody>, std::convert::Infallible> {
    // 1. Extract and validate target host
    let raw_host = match extract_host(&req) {
        Some(h) => h,
        None => {
            warn!("Request rejected: missing Host or :authority header");
            return Ok(misdirected_request_response("missing host header"));
        }
    };

    // 2. Exact match route table lookup
    let rule = match route_table.find_route(&raw_host) {
        Some(r) => r,
        None => {
            warn!(
                "Request rejected: host '{}' not mapped in route table",
                raw_host
            );
            return Ok(misdirected_request_response(&format!(
                "unmapped host '{raw_host}'"
            )));
        }
    };

    // 3. Tailscale LocalAPI zero-trust identity verification
    if rule.require_tailscale_users.is_some() || rule.require_tailscale_tags.is_some() {
        if let Some(client) = &tailscale_client {
            match client.query_whois(remote_addr).await {
                Ok(whois) => {
                    if let Some(required_users) = &rule.require_tailscale_users {
                        let user_login = whois
                            .user_profile
                            .as_ref()
                            .map(|u| u.login_name.as_str())
                            .unwrap_or("");
                        if !required_users
                            .iter()
                            .any(|u| u.eq_ignore_ascii_case(user_login))
                        {
                            warn!(
                                "Access denied: Tailscale user '{}' does not match required users for host '{}'",
                                user_login, raw_host
                            );
                            return Ok(status_response(
                                StatusCode::FORBIDDEN,
                                "Access Denied: Tailscale user not authorized",
                            ));
                        }
                    }

                    if let Some(required_tags) = &rule.require_tailscale_tags {
                        let peer_tags = whois
                            .node
                            .as_ref()
                            .map(|n| n.tags.as_slice())
                            .unwrap_or(&[]);
                        let has_tag = required_tags
                            .iter()
                            .any(|req_tag| peer_tags.iter().any(|t| t == req_tag));
                        if !has_tag {
                            warn!(
                                "Access denied: Tailscale node tags do not match required tags for host '{}'",
                                raw_host
                            );
                            return Ok(status_response(
                                StatusCode::FORBIDDEN,
                                "Access Denied: Tailscale node tags not authorized",
                            ));
                        }
                    }
                }
                Err(err) => {
                    warn!("Tailscale LocalAPI query error: {}", err);
                    return Ok(status_response(
                        StatusCode::FORBIDDEN,
                        "Access Denied: Tailscale peer identity verification failed",
                    ));
                }
            }
        }
    }

    // 4. Automated 11-header scrubbing
    if rule.strip_headers {
        let scrubbed = scrub_sensitive_headers(req.headers_mut());
        if !scrubbed.is_empty() {
            info!(
                "Scrubbed {} sensitive headers from request to '{}': {:?}",
                scrubbed.len(),
                raw_host,
                scrubbed
            );
        }
    }

    // 5. Inject canonical forwarding headers
    inject_canonical_forwarded_headers(
        req.headers_mut(),
        &remote_addr.ip().to_string(),
        &raw_host,
        "https",
    );

    // 6. Upstream dispatching
    match &rule.backend {
        BackendTarget::Static {
            status,
            body,
            content_type,
        } => {
            let status_code = StatusCode::from_u16(*status).unwrap_or(StatusCode::OK);
            let body_bytes = Bytes::from(body.clone());
            let ct = content_type
                .as_deref()
                .unwrap_or("text/plain; charset=utf-8");

            let resp = Response::builder()
                .status(status_code)
                .header(hyper::header::CONTENT_TYPE, ct)
                .header(hyper::header::CONTENT_LENGTH, body_bytes.len().to_string())
                .body(crate::router::boxed_body(body_bytes))
                .unwrap_or_else(|_| {
                    status_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal error building static response",
                    )
                });
            Ok(resp)
        }

        BackendTarget::Tcp(addr) => {
            let stream = match TcpStream::connect(addr).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to connect to TCP backend '{}': {}", addr, e);
                    return Ok(status_response(
                        StatusCode::BAD_GATEWAY,
                        &format!("Bad Gateway: failed to connect to upstream TCP {addr}"),
                    ));
                }
            };

            let io = TokioIo::new(stream);
            let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
                Ok(res) => res,
                Err(e) => {
                    warn!(
                        "HTTP/1.1 handshake failed with TCP backend '{}': {}",
                        addr, e
                    );
                    return Ok(status_response(
                        StatusCode::BAD_GATEWAY,
                        "Bad Gateway: upstream HTTP handshake failed",
                    ));
                }
            };

            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    warn!("TCP backend connection error: {:?}", err);
                }
            });

            // Map incoming request body to BoxBody
            let (parts, body) = req.into_parts();
            let boxed_body = body.map_err(|e| Box::new(e) as BoxedError).boxed();
            let req_upstream = Request::from_parts(parts, boxed_body);

            match sender.send_request(req_upstream).await {
                Ok(upstream_resp) => {
                    let (parts, body) = upstream_resp.into_parts();
                    let boxed = body.map_err(|e| Box::new(e) as BoxedError).boxed();
                    Ok(Response::from_parts(parts, boxed))
                }
                Err(e) => {
                    warn!("Failed to send request to TCP backend '{}': {}", addr, e);
                    Ok(status_response(
                        StatusCode::BAD_GATEWAY,
                        "Bad Gateway: error forwarding request to upstream",
                    ))
                }
            }
        }

        BackendTarget::UnixSocket(socket_path) => {
            let stream = match UnixStream::connect(socket_path).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "Failed to connect to Unix socket backend '{}': {}",
                        socket_path.display(),
                        e
                    );
                    return Ok(status_response(
                        StatusCode::BAD_GATEWAY,
                        &format!(
                            "Bad Gateway: failed to connect to upstream socket {}",
                            socket_path.display()
                        ),
                    ));
                }
            };

            let io = TokioIo::new(stream);
            let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
                Ok(res) => res,
                Err(e) => {
                    warn!(
                        "HTTP/1.1 handshake failed with Unix socket '{}': {}",
                        socket_path.display(),
                        e
                    );
                    return Ok(status_response(
                        StatusCode::BAD_GATEWAY,
                        "Bad Gateway: upstream Unix socket HTTP handshake failed",
                    ));
                }
            };

            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    warn!("Unix socket backend connection error: {:?}", err);
                }
            });

            let (parts, body) = req.into_parts();
            let boxed_body = body.map_err(|e| Box::new(e) as BoxedError).boxed();
            let req_upstream = Request::from_parts(parts, boxed_body);

            match sender.send_request(req_upstream).await {
                Ok(upstream_resp) => {
                    let (parts, body) = upstream_resp.into_parts();
                    let boxed = body.map_err(|e| Box::new(e) as BoxedError).boxed();
                    Ok(Response::from_parts(parts, boxed))
                }
                Err(e) => {
                    warn!(
                        "Failed to send request to Unix socket '{}': {}",
                        socket_path.display(),
                        e
                    );
                    Ok(status_response(
                        StatusCode::BAD_GATEWAY,
                        "Bad Gateway: error forwarding request to upstream socket",
                    ))
                }
            }
        }
    }
}
