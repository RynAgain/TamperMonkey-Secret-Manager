use std::sync::{Arc, RwLock};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::api::auth::constant_time_eq;
use crate::crypto::encryption;
use crate::state::AppState;

/// Shared state passed to every Axum handler.
///
/// The `bearer_token` is wrapped in `Arc<RwLock<..>>` so the token can be
/// rotated at runtime via the `rotate_api_token` IPC command without
/// restarting the HTTP server.
#[derive(Clone)]
pub struct ApiState {
    pub app_state: Arc<AppState>,
    pub bearer_token: Arc<RwLock<String>>,
}

// ------------------------------------------------------------------
// Request / Response types
// ------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SecretRequest {
    pub script_id: String,
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub script_id: String,
    pub script_name: String,
    pub domain: String,
    pub requested_secrets: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub approved: bool,
    pub script_id: String,
}

// ------------------------------------------------------------------
// Secret name validation (shared with commands.rs)
// ------------------------------------------------------------------

/// Validate that a secret name conforms to security constraints.
///
/// Rules:
/// - Only `a-z`, `A-Z`, `0-9`, `_`, `-`, `.` are allowed
/// - Length: 1..=128 characters
/// - Must start with a letter or underscore
pub fn validate_secret_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Secret name cannot be empty".to_string());
    }
    if name.len() > 128 {
        return Err("Secret name must be at most 128 characters".to_string());
    }

    let first = name.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err("Secret name must start with a letter or underscore".to_string());
    }

    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return Err(
            "Secret name must contain only letters, digits, underscores, hyphens, and dots"
                .to_string(),
        );
    }

    Ok(())
}

// ------------------------------------------------------------------
// Bearer-token verification helper
// ------------------------------------------------------------------

/// Extract and verify the bearer token from the `Authorization` header.
/// Returns `Ok(())` when the token matches, or the appropriate `StatusCode` on failure.
fn verify_bearer(headers: &HeaderMap, expected: &str) -> Result<(), StatusCode> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !constant_time_eq(token.as_bytes(), expected.as_bytes()) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(())
}

// ------------------------------------------------------------------
// Route handlers
// ------------------------------------------------------------------

/// `GET /api/health` -- no auth required.
pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

/// `POST /api/secrets/:name` -- bearer auth required.
///
/// Retrieves and decrypts a secret for an approved script.
/// Returns 410 Gone if the secret has expired.
pub async fn get_secret_api(
    Path(name): Path<String>,
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<SecretRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // -- Auth: read the current shared token --
    {
        let token_guard = state
            .bearer_token
            .read()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        verify_bearer(&headers, &token_guard)?;
    }

    // -- Validate secret name in API path --
    validate_secret_name(&name).map_err(|_| StatusCode::BAD_REQUEST)?;

    let app = &state.app_state;

    // -- Check unlocked --
    {
        let unlocked = app.is_unlocked.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if !*unlocked {
            return Err(StatusCode::LOCKED); // 423
        }
    }

    // -- Script approval check + per-secret access --
    {
        let db_guard = app.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let db = db_guard.as_ref().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

        let script = match db.get_script(&body.script_id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)? {
            Some(script) => {
                if !script.approved {
                    return Err(StatusCode::FORBIDDEN);
                }
                script
            }
            None => {
                // Auto-register as unapproved
                let _ = db.register_script(&body.script_id, &body.script_id, &body.domain);
                let _ = db.log_event("script_auto_registered", Some(&body.script_id), Some(&name));
                return Err(StatusCode::FORBIDDEN);
            }
        };

        // Per-secret access check: look up the secret to get its ID
        if let Ok(Some(secret_entry)) = db.get_secret_by_name(&name) {
            // Check expiration before granting access
            if let Some(ref exp) = secret_entry.expires_at {
                if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(exp) {
                    if chrono::Utc::now() > expiry {
                        let _ = db.log_event("secret_expired", Some(&body.script_id), Some(&name));
                        return Err(StatusCode::GONE); // 410 Gone
                    }
                }
            }

            match db.check_script_secret_access(script.id, secret_entry.id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            {
                Some(true) => { /* Access approved -- proceed */ }
                Some(false) => {
                    // Access record exists but denied
                    return Err(StatusCode::FORBIDDEN);
                }
                None => {
                    // No record -- auto-create unapproved request and deny
                    let _ = db.create_access_request(script.id, secret_entry.id);
                    let _ = db.log_event("secret_access_requested", Some(&body.script_id), Some(&name));
                    return Err(StatusCode::FORBIDDEN);
                }
            }
        }
        // If secret not found in DB, we'll check env vars later -- no per-secret access check needed
    }

    // -- Get master key --
    let master_key = {
        let key_guard = app.master_key.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        key_guard.ok_or(StatusCode::LOCKED)?
    };

    // -- Retrieve and decrypt secret --
    // First try the secrets DB, then fall back to env var allowlist
    let mut plaintext = {
        let db_guard = app.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let db = db_guard.as_ref().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

        match db.get_secret_by_name(&name).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)? {
            Some(entry) => {
                // Check expiration again (in case the DB guard was released and re-acquired)
                if let Some(ref exp) = entry.expires_at {
                    if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(exp) {
                        if chrono::Utc::now() > expiry {
                            let _ = db.log_event("secret_expired", Some(&body.script_id), Some(&name));
                            return Err(StatusCode::GONE); // 410 Gone
                        }
                    }
                }

                // Found in secrets DB -- decrypt and return
                let encrypted_data = encryption::EncryptedData::from_bytes(&entry.encrypted_value)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                let decrypted = encryption::decrypt(&encrypted_data, &master_key)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                String::from_utf8(decrypted).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            }
            None => {
                // Not in secrets DB -- check if it's on the env var allowlist
                let env_vars = db.list_env_vars().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                let is_allowed = env_vars.iter().any(|ev| ev.var_name == name);

                if !is_allowed {
                    return Err(StatusCode::NOT_FOUND);
                }

                // Read from system environment -- never persisted
                std::env::var(&name).map_err(|_| StatusCode::NOT_FOUND)?
            }
        }
    };

    // -- Audit log --
    {
        let db_guard = app.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if let Some(db) = db_guard.as_ref() {
            let _ = db.log_event("secret_accessed_via_api", Some(&body.script_id), Some(&name));
        }
    }

    // -- Build response with security headers --
    let mut response_headers = HeaderMap::new();
    response_headers.insert("cache-control", "no-store, no-cache, must-revalidate".parse().unwrap());
    response_headers.insert("pragma", "no-cache".parse().unwrap());
    response_headers.insert("x-content-type-options", "nosniff".parse().unwrap());

    let response_body = plaintext.clone();

    // Security: zeroize the decrypted plaintext after building the response
    plaintext.zeroize();

    Ok((StatusCode::OK, response_headers, response_body))
}

/// `POST /api/register` -- bearer auth required.
///
/// Registers a TamperMonkey script (or returns existing approval status).
pub async fn register_script_api(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // -- Auth: read the current shared token --
    {
        let token_guard = state
            .bearer_token
            .read()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        verify_bearer(&headers, &token_guard)?;
    }

    let app = &state.app_state;

    let db_guard = app.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let db = db_guard.as_ref().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    // Check if already registered
    let approved = match db.get_script(&body.script_id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)? {
        Some(script) => script.approved,
        None => {
            // Register as unapproved
            let reg = db
                .register_script(&body.script_id, &body.script_name, &body.domain)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let _ = db.log_event("script_registered", Some(&body.script_id), None);
            reg.approved
        }
    };

    Ok(Json(RegisterResponse {
        approved,
        script_id: body.script_id,
    }))
}
