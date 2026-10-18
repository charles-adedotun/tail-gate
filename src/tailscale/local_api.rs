use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::error::{Result, TailGateError};

/// Deserialized response from Tailscale's `/localapi/v0/whois` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WhoIsResponse {
    #[serde(rename = "Node", default)]
    pub node: Option<TailscaleNode>,

    #[serde(rename = "UserProfile", default)]
    pub user_profile: Option<TailscaleUserProfile>,

    #[serde(rename = "CapMap", default)]
    pub cap_map: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TailscaleNode {
    #[serde(rename = "ID", default)]
    pub id: u64,

    #[serde(rename = "Name", default)]
    pub name: String,

    #[serde(rename = "Addresses", default)]
    pub addresses: Vec<String>,

    #[serde(rename = "Tags", default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TailscaleUserProfile {
    #[serde(rename = "ID", default)]
    pub id: u64,

    #[serde(rename = "LoginName", default)]
    pub login_name: String,

    #[serde(rename = "DisplayName", default)]
    pub display_name: String,
}

/// Asynchronous client communicating with Tailscale daemon over its Unix Domain Socket.
#[derive(Debug, Clone)]
pub struct TailscaleClient {
    socket_path: PathBuf,
}

impl TailscaleClient {
    /// Create a new Tailscale LocalAPI client pointing to the given socket path.
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Query Tailscale's LocalAPI whois endpoint for identity of a remote socket address.
    pub async fn query_whois(&self, client_addr: SocketAddr) -> Result<WhoIsResponse> {
        let mut stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            TailGateError::TailscaleLocalApi(format!(
                "Failed to connect to tailscaled.sock at {}: {}",
                self.socket_path.display(),
                e
            ))
        })?;

        let request = format!(
            "GET /localapi/v0/whois?addr={client_addr} HTTP/1.1\r\nHost: local-tailscaled.sock\r\nConnection: close\r\n\r\n"
        );

        stream.write_all(request.as_bytes()).await.map_err(|e| {
            TailGateError::TailscaleLocalApi(format!("Failed to write whois request: {e}"))
        })?;

        let mut response_bytes = Vec::new();
        stream.read_to_end(&mut response_bytes).await.map_err(|e| {
            TailGateError::TailscaleLocalApi(format!("Failed to read whois response: {e}"))
        })?;

        Self::parse_http_response(&response_bytes)
    }

    /// Parse raw HTTP/1.1 response bytes into WhoIsResponse.
    fn parse_http_response(bytes: &[u8]) -> Result<WhoIsResponse> {
        let s = String::from_utf8_lossy(bytes);

        // Find header-body boundary
        let body = if let Some(idx) = s.find("\r\n\r\n") {
            &s[idx + 4..]
        } else if let Some(idx) = s.find("\n\n") {
            &s[idx + 2..]
        } else {
            return Err(TailGateError::TailscaleLocalApi(
                "Invalid HTTP response from tailscaled (no body delimiter)".to_string(),
            ));
        };

        // Extract status line
        let first_line = s.lines().next().unwrap_or("");
        if !first_line.contains(" 200 ") && !first_line.contains(" 200 OK") {
            return Err(TailGateError::TailscaleLocalApi(format!(
                "Tailscale LocalAPI returned non-200 status: {first_line}"
            )));
        }

        let parsed: WhoIsResponse = serde_json::from_str(body.trim())?;
        Ok(parsed)
    }
}
