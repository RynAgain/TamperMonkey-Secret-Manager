pub mod api;
pub mod commands;
pub mod crypto;
pub mod db;
pub mod error;
pub mod secrets;
pub mod state;

use state::AppState;
use std::fs;
use std::sync::Arc;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // Resolve the app data directory via Tauri v2 path API
            let app_data_dir = app
                .path()
                .app_data_dir()
                .expect("Failed to resolve app data directory");

            let db_dir = app_data_dir.join("tampermonkey-secrets");
            fs::create_dir_all(&db_dir).expect("Failed to create database directory");

            let db_path = db_dir.join("secrets.db");
            let database =
                db::Database::open(&db_path).expect("Failed to open/create the database");

            // Harden database file permissions (Windows: restrict to current user)
            api::auth::harden_db_permissions(&db_path);

            // Build application state with the initialised database, wrapped in Arc
            // so it can be shared between Tauri's managed state and the Axum server.
            let app_state = Arc::new(AppState::new());
            {
                let mut db_guard = app_state.db.lock().expect("Failed to lock db mutex");
                *db_guard = Some(database);
            }

            // Give Tauri a clone of the Arc (commands receive State<'_, Arc<AppState>>)
            app.manage(Arc::clone(&app_state));

            // Start the local HTTP API server in the background
            let state_for_api = Arc::clone(&app_state);
            let data_dir = app_data_dir.clone();
            tauri::async_runtime::spawn(async move {
                match api::server::start_api_server(state_for_api, data_dir).await {
                    Ok(port) => println!("[API] server started on 127.0.0.1:{}", port),
                    Err(e) => eprintln!("[API] failed to start server: {}", e),
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::check_first_run,
            commands::setup_master_password,
            commands::unlock,
            commands::lock,
            commands::get_app_status,
            commands::change_master_password,
            commands::set_auto_lock_minutes,
            commands::get_auto_lock_minutes,
            commands::create_secret,
            commands::get_secret,
            commands::list_secrets,
            commands::update_secret,
            commands::delete_secret,
            commands::get_api_info,
            commands::rotate_api_token,
            commands::add_env_var_to_allowlist,
            commands::remove_env_var_from_allowlist,
            commands::list_env_var_allowlist,
            commands::read_env_var,
            commands::export_vault_file,
            commands::import_vault_file,
            commands::list_scripts_cmd,
            commands::approve_script_cmd,
            commands::revoke_script,
            commands::delete_script_cmd,
            commands::list_script_access,
            commands::set_script_secret_access,
            commands::get_audit_log,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
