//! Small in-process rate limiter.
//!
//! kagi is usually deployed as a single process (or a handful of identical
//! processes behind a load balancer). This is a fixed-window limiter keyed by
//! `scope + client IP`; it protects the credential endpoints from online
//! guessing without adding a network dependency. For multi-region deployments
//! put a shared limiter in front of the OP as well.

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug)]
struct Bucket {
    start: i64,
    count: u32,
}

#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return `true` when the request is allowed. At most `limit` requests are
    /// allowed per `window` seconds for a given key.
    pub fn allow(&self, key: &str, limit: u32, window: i64) -> bool {
        let now = crate::util::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());

        // Keep the map bounded if an attacker rotates keys.
        if buckets.len() > 20_000 {
            buckets.retain(|_, b| now - b.start < window.max(60));
        }

        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            start: now,
            count: 0,
        });
        if now - bucket.start >= window {
            bucket.start = now;
            bucket.count = 0;
        }
        if bucket.count >= limit {
            return false;
        }
        bucket.count += 1;
        true
    }
}

/// Extract the client address recorded by the `harden` middleware.
pub fn client_ip(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("x-kagi-ip")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub fn client_user_agent(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.chars().take(400).collect::<String>())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window() {
        let limiter = RateLimiter::new();
        assert!(limiter.allow("ip:login", 2, 60));
        assert!(limiter.allow("ip:login", 2, 60));
        assert!(!limiter.allow("ip:login", 2, 60));
        assert!(limiter.allow("ip:other", 2, 60));
    }
}
