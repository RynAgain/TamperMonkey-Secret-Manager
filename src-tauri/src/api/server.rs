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

/// Default port the local API server tries to bind to.
///
/// Using a fixed, memorable port means TamperMonkey scripts only need to
/// configure the bearer token once -- the port stays the same across
/// application restarts.  If the port is already in use (e.g. another
/// instance is running) the server falls back to an OS-assigned random port.
const DEFAULT_PORT: u16 = 17179;

/// Start the local HTTP API server bound to `127.0.0.1`.
///
/// **Token persistence:** If a bearer token already exists on disk (from a
/// previous launch) it is reused so that TamperMonkey scripts do not need
/// to be reconfigured.  A new token is only generated on the very first
/// launch or after an explicit rotation via the `rotate_api_token` command.
///
/// **Port stability:** The server first attempts to bind to the fixed
/// [`DEFAULT_PORT`].  Only if that port is unavailable does it fall back
/// to an OS-assigned random port.  The assigned port is always written to
/// `{app_data_dir}/tampermonkey-secrets/api.port`.
///
/// The server is spawned onto the Tokio runtime and runs in the
/// background for the lifetime of the application.
pub async fn start_api_server(
    app_state: Arc<AppState>,
    app_data_dir: PathBuf,
) -> Result<u16, ApiError> {
    // -- Resolve bearer token: reuse existing or generate fresh ----------
    let token = match auth::load_token(&app_data_dir)? {
        Some(existing) => {
            println!("[API] reusing existing bearer token from disk");
            existing
        }
        None => {
            let fresh = auth::generate_token();
            auth::save_token(&app_data_dir, &fresh)?;
            println!("[API] generated new bearer token");
            fresh
        }
    };

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
        .route("/api/execute/{module_name}", post(routes::execute_code_api))
        .layer(CorsLayer::permissive())
        .with_state(api_state)
        .route_layer(middleware::from_fn_with_state(
            limiter,
            rate_limit::rate_limit_middleware,
        ));

    // -- Bind: try fixed port first, fall back to random -----------------
    let listener = {
        let preferred = SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT));
        match TcpListener::bind(preferred).await {
            Ok(l) => {
                println!("[API] bound to preferred port {DEFAULT_PORT}");
                l
            }
            Err(_) => {
                // Port busy -- fall back to OS-assigned random port
                let fallback = SocketAddr::from(([127, 0, 0, 1], 0u16));
                let l = TcpListener::bind(fallback)
                    .await
                    .map_err(|e| ApiError::ServerError(format!("Failed to bind: {e}")))?;
                println!(
                    "[API] port {DEFAULT_PORT} busy, bound to fallback port {}",
                    l.local_addr().map(|a| a.port()).unwrap_or(0)
                );
                l
            }
        }
    };

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
