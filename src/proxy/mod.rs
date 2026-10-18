pub mod handler;
pub mod headers;

pub use handler::{extract_host, handle_proxy_request};
pub use headers::{
    inject_canonical_forwarded_headers, is_sensitive_header, scrub_sensitive_headers,
    SENSITIVE_HEADER_NAMES,
};
