#![forbid(unsafe_code)]
//! # `tail-gate`
//!
//! An RFC 9110 HTTP 421 fail-closed edge ingress proxy and Unix Domain Socket
//! zero-trust gateway for Tailscale meshes in Safe Rust.
//!
//! Replaces legacy Caddy ingress (50.9 MB RSS, 1.27 GB VSZ) with a lightweight static binary
//! running under < 6.0 MB RSS with sub-millisecond p99 latency overhead.

pub mod config;
pub mod error;
pub mod proxy;
pub mod router;
pub mod tailscale;

pub use config::{BackendTarget, Config, RouteRule};
pub use error::{Result, TailGateError};
pub use router::{misdirected_request_response, status_response, RouteTable};
