//! Integration tests for the HTTP API authentication and rate limiting.
//!
//! These tests verify bearer token validation and rate limiter behaviour
//! without spawning a full Axum server. The rate limiter is tested directly
//! and the auth helper is tested via unit-style invocations.

use tampermonkey_secret_manager_lib::api::auth::{constant_time_eq, generate_token};
use tampermonkey_secret_manager_lib::api::rate_limit::RateLimiter;

// ------------------------------------------------------------------
// Bearer token auth tests
// ------------------------------------------------------------------

#[test]
fn test_valid_token_matches() {
    let token = generate_token();
    assert!(
        constant_time_eq(token.as_bytes(), token.as_bytes()),
        "identical tokens must match"
    );
}

#[test]
fn test_invalid_token_rejected() {
    let token = generate_token();
    let wrong = generate_token();
    assert!(
        !constant_time_eq(token.as_bytes(), wrong.as_bytes()),
        "different tokens must not match"
    );
}

#[test]
fn test_missing_prefix_rejected() {
    // Simulates the case where "Bearer " prefix is missing
    let token = generate_token();
    let header_value = format!("Token {}", token);
    let extracted = header_value.strip_prefix("Bearer ");
    assert!(extracted.is_none(), "non-Bearer prefix should fail");
}

#[test]
fn test_malformed_header_rejected() {
    // Empty header
    let header_value = "";
    let extracted = header_value.strip_prefix("Bearer ");
    assert!(extracted.is_none(), "empty header should fail");

    // Just "Bearer" without space
    let header_value = "Bearer";
    let extracted = header_value.strip_prefix("Bearer ");
    assert!(extracted.is_none(), "'Bearer' without space should fail");
}

#[test]
fn test_token_is_43_chars_base64url() {
    let token = generate_token();
    assert_eq!(token.len(), 43);
    // Verify it only contains base64url characters
    assert!(
        token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "token should only contain base64url characters"
    );
}

// ------------------------------------------------------------------
// Rate limiter tests
// ------------------------------------------------------------------

#[test]
fn test_rate_limiter_allows_up_to_limit() {
    let limiter = RateLimiter::new(5, 60);

    for i in 0..5 {
        assert!(
            limiter.check("/api/secrets/test"),
            "request {} should be allowed",
            i + 1
        );
    }
}

#[test]
fn test_rate_limiter_blocks_over_limit() {
    let limiter = RateLimiter::new(3, 60);

    assert!(limiter.check("/api/secrets/test"));
    assert!(limiter.check("/api/secrets/test"));
    assert!(limiter.check("/api/secrets/test"));
    assert!(
        !limiter.check("/api/secrets/test"),
        "4th request should be blocked (429)"
    );
}

#[test]
fn test_rate_limiter_separate_endpoints_independent() {
    let limiter = RateLimiter::new(2, 60);

    // Exhaust endpoint A
    assert!(limiter.check("/api/secrets/a"));
    assert!(limiter.check("/api/secrets/a"));
    assert!(!limiter.check("/api/secrets/a"));

    // Endpoint B should still work
    assert!(limiter.check("/api/register"));
    assert!(limiter.check("/api/register"));
    assert!(!limiter.check("/api/register"));
}

#[test]
fn test_rate_limiter_window_expiry() {
    // 0-second window: entries expire immediately
    let limiter = RateLimiter::new(1, 0);

    assert!(limiter.check("ep"));
    // With a 0s window, elapsed is always >= 0s, so all entries are pruned
    assert!(limiter.check("ep"), "expired entries should be pruned");
}

#[test]
fn test_rate_limiter_high_volume() {
    let limiter = RateLimiter::new(60, 60);

    // Send exactly 60 requests -- all should pass
    for _ in 0..60 {
        assert!(limiter.check("/api/health"));
    }

    // 61st should fail
    assert!(!limiter.check("/api/health"));
}
