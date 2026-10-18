use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::error::{Result, TailGateError};

/// Default listen address on private port 9443.
pub fn default_listen_addr() -> SocketAddr {
    "127.0.0.1:9443"
        .parse()
        .expect("valid default listen address")
}

/// Default Tailscale LocalAPI Unix Domain Socket path.
pub fn default_tailscale_socket() -> PathBuf {
    PathBuf::from("/var/run/tailscale/tailscaled.sock")
}

fn default_true() -> bool {
    true
}

/// Top-level configuration for the `tail-gate` reverse proxy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,

    #[serde(default = "default_tailscale_socket")]
    pub tailscale_socket_path: PathBuf,

    #[serde(default)]
    pub routes: Vec<RouteRule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            tailscale_socket_path: default_tailscale_socket(),
            routes: Vec::new(),
        }
    }
}

/// A single routing rule mapping an exact hostname to a backend target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteRule {
    /// Exact domain name (e.g. "app.tail.example.com" or "service.tail.example.com").
    pub host: String,

    /// Target backend to proxy to.
    pub backend: BackendTarget,

    /// Whether to strip the 11 sensitive headers (default: true).
    #[serde(default = "default_true")]
    pub strip_headers: bool,

    /// Optional Tailscale login names required to access this route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_tailscale_users: Option<Vec<String>>,

    /// Optional Tailscale ACL tags required to access this route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_tailscale_tags: Option<Vec<String>>,
}

/// The upstream target for a matched route.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "target")]
pub enum BackendTarget {
    /// Upstream TCP endpoint (e.g. "127.0.0.1:8000" or "windmill-server:8000").
    #[serde(rename = "tcp")]
    Tcp(String),

    /// Direct Unix Domain Socket endpoint (e.g. "/run/owobe/edge.sock").
    #[serde(rename = "unix")]
    UnixSocket(PathBuf),

    /// Static HTTP response (useful for health checks and static platform landing).
    #[serde(rename = "static")]
    Static {
        status: u16,
        body: String,
        content_type: Option<String>,
    },
}

impl Config {
    /// Load and deserialize configuration from a file (TOML or JSON).
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        let content = std::fs::read_to_string(path_ref).map_err(|e| {
            TailGateError::Config(format!(
                "Failed to read config file {}: {}",
                path_ref.display(),
                e
            ))
        })?;

        let extension = path_ref
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("toml");

        let config: Self = match extension {
            "json" => serde_json::from_str(&content)?,
            _ => toml::from_str(&content)?,
        };

        config.validate()?;
        Ok(config)
    }

    /// Load and deserialize configuration from a TOML string.
    pub fn from_toml(content: &str) -> Result<Self> {
        let config: Self = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    /// Load and deserialize configuration from a JSON string.
    pub fn from_json(content: &str) -> Result<Self> {
        let config: Self = serde_json::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate routing rules and enforce invariants.
    pub fn validate(&self) -> Result<()> {
        let mut seen_hosts = std::collections::HashSet::new();

        for (idx, route) in self.routes.iter().enumerate() {
            let host_trimmed = route.host.trim().to_lowercase();
            if host_trimmed.is_empty() {
                return Err(TailGateError::Config(format!(
                    "Route at index {idx} has an empty host"
                )));
            }

            // In accordance with fail-closed invariants, wildcards are forbidden in route declarations.
            // All unmapped domains fall back to the RFC 9110 HTTP 421 engine.
            if host_trimmed.contains('*') {
                return Err(TailGateError::Config(format!(
                    "Route '{}' contains wildcard. Wildcards are forbidden; use exact hostnames.",
                    route.host
                )));
            }

            if !seen_hosts.insert(host_trimmed.clone()) {
                return Err(TailGateError::Config(format!(
                    "Duplicate route definition for host '{}'",
                    route.host
                )));
            }

            match &route.backend {
                BackendTarget::Tcp(addr) => {
                    if addr.trim().is_empty() {
                        return Err(TailGateError::Config(format!(
                            "Route '{}' has an empty TCP backend address",
                            route.host
                        )));
                    }
                }
                BackendTarget::UnixSocket(path) => {
                    if path.as_os_str().is_empty() {
                        return Err(TailGateError::Config(format!(
                            "Route '{}' has an empty Unix socket path",
                            route.host
                        )));
                    }
                }
                BackendTarget::Static { status, .. } => {
                    if *status < 100 || *status > 599 {
                        return Err(TailGateError::Config(format!(
                            "Route '{}' has invalid static HTTP status code {}",
                            route.host, status
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}
