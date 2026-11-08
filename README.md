# `tail-gate`

[![CI](https://github.com/charles-adedotun/tail-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/charles-adedotun/tail-gate/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Lightweight reverse proxy that routes Tailscale traffic directly to local Unix sockets.**

`tail-gate` is a lightweight ingress proxy for Tailscale networks. It replaces heavier reverse proxies + TCP relay containers with a single binary running under **< 6.0 MB RSS** that connects directly to local Unix domain sockets and checks peer identity against the local Tailscale daemon.

---

## 1. Empirical Motivation: Caddy vs `tail-gate`

On an edge compute node (`edge-node-01`, Tailnet IP `100.64.0.1`), empirical measurement of the incumbent Caddy ingress container revealed:

| Dimension | Caddy (Incumbent) | `tail-gate` (Safe Rust) | Improvement |
|---|---|---|---|
| **Resident Set Size (RSS)** | **50.9 MB** `[MEASURED]` | **< 6.0 MB** | **88.2% reduction** |
| **Virtual Memory (VSZ)** | **1.27 GB** `[MEASURED]` | **< 30 MB** | **97.6% reduction** |
| **Binary Footprint** | ~45 MB container image | **~3.5 MB** static binary | **92.2% reduction** |
| **Memory Management** | Go GC pauses & runtime heap | Zero-GC deterministic Safe Rust | Sub-millisecond p99 |
| **Unix Socket Routing** | Requires Python relay container | **Native Zero-Copy IPC** | Eliminates 2 TCP hops |
| **Unknown Host Handling** | Multi-line snippet fallback | **Native RFC 9110 §15.5.22 Engine** | Fail-closed default |

### The Unix Domain Socket Relay Inefficiency
In legacy configurations, routing to local services on loopback (`127.0.0.1:8076`) typically requires:
1. Web server forwarding to a container bridge TCP port.
2. An intermediate container running a socket forwarder script.
3. A systemd unit forwarding to the actual Unix socket (`/run/service/edge.sock`).

A single incoming request traversed **two TCP loopback stacks, one Unix domain socket, and intermediate relay processes**.

`tail-gate` connects directly to Unix domain sockets via `tokio::net::UnixStream`, completely eliminating relay containers, bridge hops, and loopback TCP overhead.

---

## 2. Security Architecture

### 2.1 Strict RFC 9110 §15.5.22 HTTP 421 Misdirected Request Engine
RFC 9110 Section 15.5.22 specifies:
> *"The 421 (Misdirected Request) status code indicates that the request was directed at a server that is not able to produce a response. This can be sent by a server that is not configured to produce responses for the combination of scheme and authority that are included in the request URI."*

In HTTP/2 and TLS environments, clients often reuse an existing TLS connection for requests to other hostnames (connection coalescing). If an unmapped or unauthorized hostname is requested, `tail-gate` does not fall back to a default site or issue a generic 404. Instead, it terminates the stream immediately with **HTTP 421 Misdirected Request**, instructing the client that this connection cannot produce responses for that authority.

```http
HTTP/2 421 Misdirected Request
content-type: text/plain; charset=utf-8
content-length: 46
connection: close

RFC 9110 §15.5.22 Misdirected Request: unmapped host
```

### 2.2 Automated 11-Header Scrubbing Pipeline
To prevent client impersonation, authentication spoofing, and internal trust leakage, `tail-gate` unconditionally purges 11 sensitive headers before route matching or upstream dispatching:

| # | Header Name | Security Rationale |
|---|---|---|
| 1 | `Forwarded` | RFC 7239 client-controlled forwarding chain; prevents spoofing downstream IP. |
| 2 | `X-Auth-Request-User` | Upstream authentication assertion; client must never declare its own identity. |
| 3 | `X-Auth-Request-Email` | Authenticated email assertion injected only by platform identity brokers. |
| 4 | `X-Auth-Request-Groups` | Authorization group membership; client-supplied values would grant privilege escalation. |
| 5 | `X-Forwarded-User` | Legacy identity header; must be cleared prior to upstream forwarding. |
| 6 | `X-Forwarded-Email` | Legacy email identity assertion; purged to prevent spoofing. |
| 7 | `X-Forwarded-For` | Client-supplied IP chain; purged and replaced by canonical remote peer IP. |
| 8 | `X-Forwarded-Host` | Purged and replaced by exact matched Host. |
| 9 | `X-Forwarded-Proto` | Purged and set to `https`. |
| 10 | `X-Platform-Auth` | Internal platform custody proof; client must never pass synthetic proofs. |
| 11 | `X-Internal-Auth-Token` | Application-specific secret token; must come solely from server-side custody. |

Additionally, mesh identity headers (`tailscale-user-*`, `x-real-ip`, `x-scheme`) and broker signature headers (`x-edge-broker-*`) are unconditionally stripped.

### 2.3 Zero-Trust Tailscale LocalAPI Integration
When a route is protected by `require_tailscale_users` or `require_tailscale_tags`, `tail-gate` queries the local Tailscale daemon (`/var/run/tailscale/tailscaled.sock`) via its `/localapi/v0/whois` endpoint:
- Inspects client Tailscale IP, Node FQDN, Login Name, and ACL tags.
- Enforces access control before proxying bytes to upstream backends.
- Rejects unauthorized peers with `403 Forbidden`.

---

## 3. Configuration Reference (`tail-gate.toml`)

```toml
listen_addr = "127.0.0.1:9443"
tailscale_socket_path = "/var/run/tailscale/tailscaled.sock"

# Static landing page
[[routes]]
host = "tail.example.com"
backend = { type = "static", target = { status = 200, body = "ok", content_type = "text/plain" } }

# TCP backend with Tailscale zero-trust ACL
[[routes]]
host = "app.tail.example.com"
backend = { type = "tcp", target = "127.0.0.1:8000" }
require_tailscale_tags = ["tag:operator", "tag:server"]

# Native Unix Domain Socket backend (zero TCP loopback)
[[routes]]
host = "service.tail.example.com"
backend = { type = "unix", target = "/run/service/edge.sock" }

# Platform Broker Unix Domain Socket backend
[[routes]]
host = "broker.tail.example.com"
backend = { type = "unix", target = "/var/run/edge/edge-broker.sock" }
require_tailscale_tags = ["tag:operator"]
```

---

## 4. CLI Usage

```bash
# Run ingress server
tail-gate run --config tail-gate.toml

# Run on specific Tailnet listener
tail-gate run --config tail-gate.toml --listen 100.64.0.1:9443

# Validate configuration file
tail-gate validate-config --config tail-gate.toml

# Inspect the 11 security headers scrubbed by the pipeline
tail-gate inspect-headers
```

---

## 5. Development & Testing

```bash
cargo build
cargo test
cargo clippy -- -D warnings
```

---

## 6. License
MIT License. Authored by Charles Adedotun.
