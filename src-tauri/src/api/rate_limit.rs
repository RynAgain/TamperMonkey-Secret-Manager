//! Simple sliding-window rate limiter for the local HTTP API.
//!
//! Prevents brute-force token guessing and secret enumeration by limiting
//! requests per endpoint to a configurable maximum within a rolling time window.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

/// A sliding-window rate limiter keyed by endpoint path.
///
/// Each endpoint tracks a list of request timestamps. When [`check`] is called,
/// expired entries are pruned and the current count is compared against
/// `max_requests`. If the limit is exceeded the request is denied.
#[derive(Clone)]
pub struct RateLimiter {
    /// Map of endpoint key -> list of request timestamps within the current window.
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    /// Maximum number of requests allowed per endpoint within `window`.
    max_requests: usize,
    /// Rolling time window for rate limiting.
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// * `max_requests` -- maximum requests allowed per endpoint within the window
    /// * `window_secs` -- duration of the sliding window in seconds
    pub fn new(max_requests: usize, window_secs: u64) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Check whether a request to `key` (typically the endpoint path) is allowed.
    ///
    /// Returns `true` if the request is within the rate limit, `false` if it
    /// should be rejected with HTTP 429.
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = self.requests.lock().unwrap_or_else(|e| e.into_inner());

        let timestamps = map.entry(key.to_string()).or_default();

        // Prune entries older than the window
        timestamps.retain(|&t| now.duration_since(t) < self.window);

        if timestamps.len() >= self.max_requests {
            false
        } else {
            timestamps.push(now);
            true
        }
    }
}

/// Axum middleware layer that enforces rate limiting on every request.
///
/// Extracts the request path and checks it against the shared [`RateLimiter`].
/// Returns HTTP 429 Too Many Requests when the limit is exceeded.
pub async fn rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path().to_string();

    if !limiter.check(&path) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(5, 60);

        for _ in 0..5 {
            assert!(limiter.check("test_endpoint"), "should allow up to max_requests");
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(3, 60);

        assert!(limiter.check("ep"));
        assert!(limiter.check("ep"));
        assert!(limiter.check("ep"));
        assert!(!limiter.check("ep"), "4th request should be blocked");
    }

    #[test]
    fn test_rate_limiter_separate_endpoints() {
        let limiter = RateLimiter::new(2, 60);

        assert!(limiter.check("a"));
        assert!(limiter.check("a"));
        assert!(!limiter.check("a"), "endpoint 'a' should be blocked");

        // Different endpoint should still be allowed
        assert!(limiter.check("b"));
        assert!(limiter.check("b"));
        assert!(!limiter.check("b"), "endpoint 'b' should be blocked");
    }

    #[test]
    fn test_rate_limiter_window_expiry() {
        // Use a 0-second window so entries expire immediately
        let limiter = RateLimiter::new(1, 0);

        assert!(limiter.check("ep"));
        // With a 0s window, the previous entry should already be expired
        // (Instant::now() - previous >= 0s is always true, but Duration::from_secs(0)
        // means we keep entries where elapsed < 0s which is never true, so all are pruned)
        assert!(limiter.check("ep"), "expired entries should be pruned");
    }
}
