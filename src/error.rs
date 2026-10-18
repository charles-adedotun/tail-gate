use thiserror::Error;

/// Domain errors for `tail-gate`.
#[derive(Error, Debug)]
pub enum TailGateError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] hyper::http::Error),

    #[error("JSON deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML deserialization error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Tailscale LocalAPI error: {0}")]
    TailscaleLocalApi(String),

    #[error("RFC 9110 §15.5.22 Misdirected Request: {0}")]
    MisdirectedRequest(String),

    #[error("Backend unreachable ({target}): {details}")]
    BackendUnreachable { target: String, details: String },

    #[error("Access denied: {0}")]
    AccessDenied(String),
}

pub type Result<T> = std::result::Result<T, TailGateError>;
