use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Response, StatusCode};

pub type ResponseBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Helper to create a boxed response body from static or owned bytes.
pub fn boxed_body<B: Into<Bytes>>(bytes: B) -> ResponseBody {
    Full::new(bytes.into())
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed()
}

/// Generate a strict RFC 9110 §15.5.22 HTTP 421 Misdirected Request response.
///
/// This fail-closed response is returned whenever an incoming request targets an
/// unmapped Host or `:authority`, or when an HTTP/2 client attempts to coalesce
/// a connection onto an unauthorized host.
pub fn misdirected_request_response(reason: &str) -> Response<ResponseBody> {
    let body_text = format!("RFC 9110 §15.5.22 Misdirected Request: {reason}\n");
    let body_bytes = Bytes::from(body_text);
    let body_len = body_bytes.len().to_string();

    Response::builder()
        .status(StatusCode::MISDIRECTED_REQUEST)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, body_len)
        .header(CONNECTION, "close")
        .body(boxed_body(body_bytes))
        .expect("static response builder must not fail")
}

/// Helper to create a custom error response (e.g. 403 Forbidden, 413 Payload Too Large, 502 Bad Gateway).
pub fn status_response(status: StatusCode, message: &str) -> Response<ResponseBody> {
    let body_text = format!("{message}\n");
    let body_bytes = Bytes::from(body_text);
    let body_len = body_bytes.len().to_string();

    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, body_len)
        .body(boxed_body(body_bytes))
        .expect("static response builder must not fail")
}
