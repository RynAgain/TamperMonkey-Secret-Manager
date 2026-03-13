use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

use crate::api::auth;
use crate::api::rate_limit::{self, RateLimiter};
use crate::api::routes::{self, ApiState};
use crate::error::ApiError;
use crate::state::AppState;

/// Start the local HTTP API server on a random port bound to `127.0.0.1`.
///
/// A fresh bearer token is generated on every launch and persisted to
/// `{app_data_dir}/tampermonkey-secrets/api.token` so that TamperMonkey
/// scripts can read it.  The assigned port is likewise written to
/// `api.port`.
///
/// The server is spawned onto the Tokio runtime and runs in the
/// background for the lifetime of the application.
pub async fn start_api_server(
    app_state: Arc<AppState>,
    app_data_dir: PathBuf,
) -> Result<u16, ApiError> {
    // -- Generate and persist bearer token --
    let token = auth::generate_token();
    auth::save_token(&app_data_dir, &token)?;

    // Store token in AppState so the UI can expose it
    {
        let mut guard = app_state
            .api_token
            .lock()
            .map_err(|e| ApiError::ServerError(format!("Lock error: {e}")))?;
        *guard = Some(token.clone());
    }

    // Write to the shared token reference (used by Axum handlers and token rotation)
    {
        let mut shared = app_state
            .shared_api_token
            .write()
            .map_err(|e| ApiError::ServerError(format!("RwLock error: {e}")))?;
        *shared = token;
    }

    // Store app data dir for token rotation
    {
        let mut dir_guard = app_state
            .app_data_dir
            .lock()
            .map_err(|e| ApiError::ServerError(format!("Lock error: {e}")))?;
        *dir_guard = Some(app_data_dir.clone());
    }

    // -- Build shared Axum state --
    let api_state = ApiState {
        app_state: Arc::clone(&app_state),
        bearer_token: Arc::clone(&app_state.shared_api_token),
    };

    // -- Rate limiter: 60 requests per minute per endpoint --
    let limiter = RateLimiter::new(60, 60);

    // -- Build router --
    // The rate limiter is applied as middleware to all routes.
    let app = Router::new()
        .route("/api/health", get(routes::health))
        .route("/api/secrets/{name}", post(routes::get_secret_api))
        .route("/api/register", post(routes::register_script_api))
        .layer(CorsLayer::permissive())
        .with_state(api_state)
        .route_layer(middleware::from_fn_with_state(
            limiter,
            rate_limit::rate_limit_middleware,
        ));

    // -- Bind to 127.0.0.1:0 (OS-assigned random port) --
    let addr = SocketAddr::from(([127, 0, 0, 1], 0u16));
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| ApiError::ServerError(format!("Failed to bind: {e}")))?;

    let local_addr = listener
        .local_addr()
        .map_err(|e| ApiError::ServerError(format!("Failed to get local addr: {e}")))?;
    let port = local_addr.port();

    // -- Persist assigned port --
    auth::save_port(&app_data_dir, port)?;

    // Store port in AppState so the UI can expose it
    {
        let mut guard = app_state
            .api_port
            .lock()
            .map_err(|e| ApiError::ServerError(format!("Lock error: {e}")))?;
        *guard = Some(port);
    }

    // -- Spawn the server as a background task --
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("[API] server error: {e}");
        }
    });

    Ok(port)
}
