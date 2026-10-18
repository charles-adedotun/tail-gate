use std::collections::HashMap;
use std::sync::Arc;

use crate::config::{Config, RouteRule};

/// Thread-safe in-memory lookup table for exact host routes.
#[derive(Debug, Clone)]
pub struct RouteTable {
    routes: HashMap<String, Arc<RouteRule>>,
}

impl RouteTable {
    /// Build a route table from the parsed configuration.
    pub fn new(config: &Config) -> Self {
        let mut routes = HashMap::with_capacity(config.routes.len());
        for rule in &config.routes {
            let normalized = Self::normalize_host(&rule.host);
            routes.insert(normalized, Arc::new(rule.clone()));
        }
        Self { routes }
    }

    /// Normalize host strings: lowercases, trims whitespace, removes trailing FQDN dot,
    /// and strips standard ingress port if attached.
    pub fn normalize_host(raw_host: &str) -> String {
        let trimmed = raw_host.trim().to_lowercase();
        let without_dot = trimmed.strip_suffix('.').unwrap_or(&trimmed);

        // Strip port (e.g., "app.tail.example.com:9443" or "app.tail.example.com:443")
        if let Some((domain, _port)) = without_dot.rsplit_once(':') {
            // Guard against IPv6 brackets
            if !domain.contains(']') || without_dot.ends_with(']') {
                return domain.to_string();
            }
        }

        without_dot.to_string()
    }

    /// Look up a route rule for an incoming Host or `:authority` header.
    /// Returns `None` if the host is not explicitly mapped.
    pub fn find_route(&self, host_or_authority: &str) -> Option<Arc<RouteRule>> {
        let normalized = Self::normalize_host(host_or_authority);
        self.routes.get(&normalized).cloned()
    }

    /// Number of configured routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether the route table has no rules.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Return all mapped hostnames.
    pub fn all_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self.routes.keys().cloned().collect();
        hosts.sort();
        hosts
    }
}
