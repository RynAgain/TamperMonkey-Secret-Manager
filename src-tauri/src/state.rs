use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use zeroize::Zeroize;

use crate::db::Database;

/// Application state managed by Tauri across all IPC commands.
///
/// The `master_key` is held in memory only while the vault is unlocked
/// and is zeroized on lock.
pub struct AppState {
    pub db: Mutex<Option<Database>>,
    /// Derived AES-256 key, held in memory while unlocked.
    pub master_key: Mutex<Option<[u8; 32]>>,
    pub is_unlocked: Mutex<bool>,
    /// Bearer token for the local HTTP API (regenerated each app launch).
    /// Stored in a Mutex for IPC command access.
    pub api_token: Mutex<Option<String>>,
    /// Port the local HTTP API is listening on.
    pub api_port: Mutex<Option<u16>>,
    /// Shared bearer token reference used by both the Axum server and the
    /// `rotate_api_token` IPC command. Wrapped in `Arc<RwLock<..>>` so the
    /// Axum handlers can read it while `rotate_api_token` writes to it.
    pub shared_api_token: Arc<RwLock<String>>,
    /// Path to app data directory, needed for token rotation file writes.
    pub app_data_dir: Mutex<Option<std::path::PathBuf>>,
    /// Auto-lock inactivity timeout in minutes. 0 = disabled. Default: 15.
    pub auto_lock_minutes: Mutex<u32>,
    /// Timestamp of the last successful IPC activity. Used for auto-lock.
    pub last_activity: Mutex<Option<Instant>>,
    /// Tauri app handle, used to emit events to the frontend from the HTTP
    /// API server (e.g. when a script requests access to an unapproved secret).
    pub app_handle: Mutex<Option<tauri::AppHandle>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            db: Mutex::new(None),
            master_key: Mutex::new(None),
            is_unlocked: Mutex::new(false),
            api_token: Mutex::new(None),
            api_port: Mutex::new(None),
            shared_api_token: Arc::new(RwLock::new(String::new())),
            app_data_dir: Mutex::new(None),
            auto_lock_minutes: Mutex::new(15),
            last_activity: Mutex::new(None),
            app_handle: Mutex::new(None),
        }
    }

    /// Zeroize the master key and mark the app as locked.
    pub fn lock(&self) {
        if let Ok(mut key) = self.master_key.lock() {
            if let Some(ref mut k) = *key {
                // Security: zeroize the 32-byte master key before dropping
                k.zeroize();
            }
            *key = None;
        }
        if let Ok(mut unlocked) = self.is_unlocked.lock() {
            *unlocked = false;
        }
    }

    /// Update the last activity timestamp to now. Called on every successful
    /// secret-accessing IPC command.
    pub fn touch_activity(&self) {
        if let Ok(mut last) = self.last_activity.lock() {
            *last = Some(Instant::now());
        }
    }

    /// Check if the auto-lock timer has expired. Returns `true` if the app
    /// should be locked due to inactivity.
    pub fn check_auto_lock_expired(&self) -> bool {
        let minutes = match self.auto_lock_minutes.lock() {
            Ok(m) => *m,
            Err(_) => return false,
        };
        if minutes == 0 {
            return false; // Disabled
        }
        let last = match self.last_activity.lock() {
            Ok(l) => *l,
            Err(_) => return false,
        };
        match last {
            Some(last_time) => {
                last_time.elapsed() > std::time::Duration::from_secs(u64::from(minutes) * 60)
            }
            None => false,
        }
    }
}
