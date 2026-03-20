use std::sync::Arc;

use rusqlite::params;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::api::auth;
use crate::api::routes::validate_secret_name;
use crate::crypto::{encryption, kdf};
use crate::db::models::SecretType;
use crate::secrets::vault::{self, VaultPayload, VaultSecret};
use crate::state::AppState;

/// Known plaintext used as the verification token.
/// If we can decrypt this successfully, the master password is correct.
const VERIFICATION_PLAINTEXT: &[u8] = b"TAMPERMONKEY_SECRETS_VERIFIED";

/// Minimum PIN length enforced on vault export/import.
const MIN_PIN_LENGTH: usize = 6;

/// Valid auto-lock durations in minutes. 0 = disabled.
const VALID_AUTO_LOCK_MINUTES: &[u32] = &[0, 1, 5, 10, 15, 30, 60];

/// Serializable status returned to the frontend by `get_app_status`.
#[derive(Debug, Clone, Serialize)]
pub struct AppStatus {
    pub is_first_run: bool,
    pub is_unlocked: bool,
}

/// Metadata for a secret entry (never includes the decrypted value).
#[derive(Debug, Clone, Serialize)]
pub struct SecretMetadata {
    pub id: i64,
    pub name: String,
    pub secret_type: String,
    pub blind: bool,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>,
}

/// A secret entry with its optionally-decrypted value.
#[derive(Debug, Clone, Serialize)]
pub struct SecretValue {
    pub id: i64,
    pub name: String,
    pub value: Option<String>,
    pub secret_type: String,
    pub blind: bool,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>,
}

/// Info about an environment variable on the allowlist.
#[derive(Debug, Clone, Serialize)]
pub struct EnvVarInfo {
    pub var_name: String,
    pub is_set: bool,
}

/// Result info for each secret imported from a vault file.
#[derive(Debug, Clone, Serialize)]
pub struct ImportedSecretInfo {
    pub name: String,
    pub blind: bool,
    pub success: bool,
    pub error: Option<String>,
    pub expires_at: Option<String>,
}

/// Connection info for the local HTTP API, returned to the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct ApiInfo {
    pub port: Option<u16>,
    pub token: Option<String>,
}

/// Info about a registered script returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptInfo {
    pub id: i64,
    pub script_id: String,
    pub script_name: String,
    pub domain: String,
    pub approved: bool,
    pub created_at: String,
}

/// Info about a script's access to a specific secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptAccessInfo {
    pub secret_name: String,
    pub approved: bool,
    pub created_at: String,
}

/// An audit log entry returned to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub event_type: String,
    pub script_id: Option<String>,
    pub secret_name: Option<String>,
    pub timestamp: String,
}

/// Validate a vault PIN meets complexity requirements.
///
/// - Minimum 6 characters
/// - Must not be empty
fn validate_pin(pin: &str) -> Result<(), String> {
    if pin.is_empty() {
        return Err("PIN cannot be empty".to_string());
    }
    if pin.len() < MIN_PIN_LENGTH {
        return Err(format!(
            "PIN must be at least {} characters",
            MIN_PIN_LENGTH
        ));
    }
    Ok(())
}

/// Enforce that the app is unlocked AND has not expired the auto-lock timer.
/// If the timer has expired, locks the app and returns an error.
/// Otherwise, updates last_activity to now.
fn enforce_unlocked_or_auto_lock(state: &AppState) -> Result<(), String> {
    // Check if app is unlocked
    {
        let unlocked = state
            .is_unlocked
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        if !*unlocked {
            return Err("App is locked -- unlock first".to_string());
        }
    }

    // Check auto-lock timer
    if state.check_auto_lock_expired() {
        state.lock();
        return Err("App locked due to inactivity".to_string());
    }

    // Update activity timestamp
    state.touch_activity();
    Ok(())
}

/// Check whether this is the first run (no master password configured yet).
#[tauri::command]
pub async fn check_first_run(state: tauri::State<'_, Arc<AppState>>) -> Result<bool, String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    let has_config = db.has_master_config().map_err(|e| format!("DB error: {e}"))?;
    Ok(!has_config)
}

/// First-time master password setup.
///
/// Derives a key via Argon2id, encrypts a verification token with AES-256-GCM,
/// persists the config to the database, and stores the derived key in memory.
#[tauri::command]
pub async fn setup_master_password(
    password: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    // Generate salt and derive key
    let salt = kdf::generate_salt();
    let derived_key = kdf::derive_key(password.as_bytes(), &salt)
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    // Security: zeroize the password string as soon as we no longer need it
    let mut pw = password;
    pw.zeroize();

    // Encrypt the verification token
    let encrypted_token = encryption::encrypt(VERIFICATION_PLAINTEXT, &derived_key)
        .map_err(|e| format!("Encryption failed: {e}"))?;

    let token_bytes = encrypted_token.to_bytes();
    let now = chrono::Utc::now().to_rfc3339();

    // Save to database
    {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        let db = db_guard
            .as_ref()
            .ok_or_else(|| "Database not initialised".to_string())?;

        let config = crate::db::models::MasterConfig {
            id: 0, // ignored on insert
            password_hash: token_bytes,
            salt: salt.to_vec(),
            created_at: now,
        };

        db.save_master_config(&config)
            .map_err(|e| format!("Failed to save master config: {e}"))?;

        // Log audit event
        db.log_event("master_password_created", None, None)
            .map_err(|e| format!("Failed to log event: {e}"))?;
    }

    // Store key in app state and mark as unlocked
    {
        let mut key_guard = state
            .master_key
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        *key_guard = Some(derived_key);
    }
    {
        let mut unlocked = state
            .is_unlocked
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        *unlocked = true;
    }

    // Start activity timer
    state.touch_activity();

    Ok(())
}

/// Unlock the vault with an existing master password.
///
/// Loads the stored config, re-derives the key, and attempts to decrypt the
/// verification token. Returns `true` on success, `false` on wrong password.
#[tauri::command]
pub async fn unlock(password: String, state: tauri::State<'_, Arc<AppState>>) -> Result<bool, String> {
    // Load master config from DB
    let (stored_token_bytes, stored_salt) = {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        let db = db_guard
            .as_ref()
            .ok_or_else(|| "Database not initialised".to_string())?;

        let config = db
            .get_master_config()
            .map_err(|e| format!("DB error: {e}"))?
            .ok_or_else(|| "No master config found -- run setup first".to_string())?;

        (config.password_hash, config.salt)
    };

    // Derive key from password + stored salt
    let derived_key = kdf::derive_key(password.as_bytes(), &stored_salt)
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    // Security: zeroize the password string
    let mut pw = password;
    pw.zeroize();

    // Attempt to decrypt verification token
    let encrypted_data = encryption::EncryptedData::from_bytes(&stored_token_bytes)
        .map_err(|e| format!("Invalid stored token: {e}"))?;

    match encryption::decrypt(&encrypted_data, &derived_key) {
        Ok(plaintext) if plaintext == VERIFICATION_PLAINTEXT => {
            // Correct password -- store key and unlock
            {
                let mut key_guard = state
                    .master_key
                    .lock()
                    .map_err(|e| format!("Lock error: {e}"))?;
                *key_guard = Some(derived_key);
            }
            {
                let mut unlocked = state
                    .is_unlocked
                    .lock()
                    .map_err(|e| format!("Lock error: {e}"))?;
                *unlocked = true;
            }

            // Start activity timer
            state.touch_activity();

            // Load auto-lock setting from DB
            {
                let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
                if let Some(db) = db_guard.as_ref() {
                    if let Ok(Some(val)) = db.get_config("auto_lock_minutes") {
                        if let Ok(mins) = val.parse::<u32>() {
                            if let Ok(mut m) = state.auto_lock_minutes.lock() {
                                *m = mins;
                            }
                        }
                    }
                    let _ = db.log_event("unlock_success", None, None);
                }
            }

            Ok(true)
        }
        _ => {
            // Wrong password or decryption failed -- zeroize the derived key
            let mut bad_key = derived_key;
            bad_key.zeroize();

            let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
            if let Some(db) = db_guard.as_ref() {
                let _ = db.log_event("unlock_failed", None, None);
            }

            Ok(false)
        }
    }
}

/// Lock the app, zeroizing the in-memory master key.
#[tauri::command]
pub async fn lock(state: tauri::State<'_, Arc<AppState>>) -> Result<(), String> {
    state.lock();

    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    if let Some(db) = db_guard.as_ref() {
        let _ = db.log_event("locked", None, None);
    }

    Ok(())
}

/// Return current application status for the frontend.
#[tauri::command]
pub async fn get_app_status(state: tauri::State<'_, Arc<AppState>>) -> Result<AppStatus, String> {
    // Check auto-lock before reporting status
    if state.check_auto_lock_expired() {
        state.lock();
    }

    let is_first_run = {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        match db_guard.as_ref() {
            Some(db) => !db
                .has_master_config()
                .map_err(|e| format!("DB error: {e}"))?,
            None => true,
        }
    };

    let is_unlocked = *state
        .is_unlocked
        .lock()
        .map_err(|e| format!("Lock error: {e}"))?;

    Ok(AppStatus {
        is_first_run,
        is_unlocked,
    })
}

// ======================================================================
// Master Password Change Command
// ======================================================================

/// Change the master password, atomically re-encrypting all secrets.
///
/// 1. Verify current password
/// 2. Derive new key from new password + new salt
/// 3. In a single SQLite transaction: re-encrypt all secrets, update master config
/// 4. Update in-memory master key
/// 5. Zeroize all sensitive intermediates
#[tauri::command]
pub async fn change_master_password(
    current_password: String,
    new_password: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    // Enforce unlocked + auto-lock
    enforce_unlocked_or_auto_lock(&state)?;

    // Load master config from DB
    let master_config = {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        let db = db_guard
            .as_ref()
            .ok_or_else(|| "Database not initialised".to_string())?;
        db.get_master_config()
            .map_err(|e| format!("DB error: {e}"))?
            .ok_or_else(|| "No master config found".to_string())?
    };

    // Derive old key from current_password + stored salt and verify
    let mut old_key = kdf::derive_key(current_password.as_bytes(), &master_config.salt)
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    // Security: zeroize current_password
    let mut cur_pw = current_password;
    cur_pw.zeroize();

    // Verify old key by decrypting the verification token
    let encrypted_token = encryption::EncryptedData::from_bytes(&master_config.password_hash)
        .map_err(|e| format!("Invalid stored token: {e}"))?;
    match encryption::decrypt(&encrypted_token, &old_key) {
        Ok(plaintext) if plaintext == VERIFICATION_PLAINTEXT => { /* OK */ }
        _ => {
            old_key.zeroize();
            let mut new_pw = new_password;
            new_pw.zeroize();
            return Err("Current password is incorrect".to_string());
        }
    }

    // Generate new salt and derive new key
    let new_salt = kdf::generate_salt();
    let new_key = kdf::derive_key(new_password.as_bytes(), &new_salt)
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    // Security: zeroize new_password
    let mut new_pw = new_password;
    new_pw.zeroize();

    // Create new verification token
    let new_token = encryption::encrypt(VERIFICATION_PLAINTEXT, &new_key)
        .map_err(|e| format!("Encryption failed: {e}"))?;
    let new_token_bytes = new_token.to_bytes();

    // Load all secrets from DB for re-encryption
    let secrets = {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        let db = db_guard
            .as_ref()
            .ok_or_else(|| "Database not initialised".to_string())?;
        db.list_secrets().map_err(|e| format!("DB error: {e}"))?
    };

    // Decrypt all secrets with old key, re-encrypt with new key (in memory)
    let mut re_encrypted: Vec<(String, Vec<u8>)> = Vec::with_capacity(secrets.len());
    for secret in &secrets {
        let enc_data = encryption::EncryptedData::from_bytes(&secret.encrypted_value)
            .map_err(|e| format!("Invalid encrypted data for '{}': {e}", secret.name))?;
        let mut plaintext = encryption::decrypt(&enc_data, &old_key)
            .map_err(|e| format!("Decryption failed for '{}': {e}", secret.name))?;
        let new_enc = encryption::encrypt(&plaintext, &new_key)
            .map_err(|e| format!("Re-encryption failed for '{}': {e}", secret.name))?;

        // Zeroize plaintext immediately
        plaintext.zeroize();

        re_encrypted.push((secret.name.clone(), new_enc.to_bytes()));
    }

    // ATOMIC: Execute all DB updates inside a single transaction
    {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        let db = db_guard
            .as_ref()
            .ok_or_else(|| "Database not initialised".to_string())?;
        let conn = db.connection();

        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("Failed to start transaction: {e}"))?;

        // Update each secret's encrypted value
        let now = chrono::Utc::now().to_rfc3339();
        for (name, encrypted_bytes) in &re_encrypted {
            tx.execute(
                "UPDATE secrets SET encrypted_value = ?1, updated_at = ?2 WHERE name = ?3",
                params![encrypted_bytes, now, name],
            )
            .map_err(|e| format!("Failed to update secret '{}': {e}", name))?;
        }

        // Update master config with new salt and verification token
        tx.execute(
            "UPDATE master_config SET password_hash = ?1, salt = ?2 WHERE id = ?3",
            params![new_token_bytes, new_salt.to_vec(), master_config.id],
        )
        .map_err(|e| format!("Failed to update master config: {e}"))?;

        // Log audit event inside the transaction
        let audit_now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO audit_log (event_type, script_id, secret_name, timestamp) VALUES (?1, ?2, ?3, ?4)",
            params!["master_password_changed", Option::<String>::None, Option::<String>::None, audit_now],
        )
        .map_err(|e| format!("Failed to log event: {e}"))?;

        tx.commit()
            .map_err(|e| format!("Transaction commit failed: {e}"))?;
    }

    // Update in-memory master key
    {
        let mut key_guard = state
            .master_key
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        if let Some(ref mut k) = *key_guard {
            k.zeroize();
        }
        *key_guard = Some(new_key);
    }

    // Security: zeroize old key
    old_key.zeroize();

    // Update activity timestamp
    state.touch_activity();

    Ok(())
}

// ======================================================================
// Auto-Lock Settings Commands
// ======================================================================

/// Set the auto-lock inactivity timeout in minutes.
/// Valid values: 0 (disabled), 1, 5, 10, 15, 30, 60.
#[tauri::command]
pub async fn set_auto_lock_minutes(
    minutes: u32,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    if !VALID_AUTO_LOCK_MINUTES.contains(&minutes) {
        return Err(format!(
            "Invalid auto-lock value: {}. Valid options: {:?}",
            minutes, VALID_AUTO_LOCK_MINUTES
        ));
    }

    // Update in-memory state
    {
        let mut guard = state
            .auto_lock_minutes
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        *guard = minutes;
    }

    // Persist to DB
    {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        let db = db_guard
            .as_ref()
            .ok_or_else(|| "Database not initialised".to_string())?;
        db.set_config("auto_lock_minutes", &minutes.to_string())
            .map_err(|e| format!("Failed to save config: {e}"))?;
    }

    // Reset activity timer so the new timeout starts fresh
    state.touch_activity();

    Ok(())
}

/// Get the current auto-lock inactivity timeout in minutes.
#[tauri::command]
pub async fn get_auto_lock_minutes(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<u32, String> {
    let guard = state
        .auto_lock_minutes
        .lock()
        .map_err(|e| format!("Lock error: {e}"))?;
    Ok(*guard)
}

// ======================================================================
// Secret CRUD Commands
// ======================================================================

/// Create a new key-value secret. The value is encrypted before storage.
#[tauri::command]
pub async fn create_secret(
    name: String,
    value: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    enforce_unlocked_or_auto_lock(&state)?;
    validate_secret_name(&name)?;

    // Get the master key
    let master_key = {
        let key_guard = state
            .master_key
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        key_guard
            .ok_or_else(|| "App is locked -- unlock first".to_string())?
    };

    // Encrypt the value
    let encrypted = encryption::encrypt(value.as_bytes(), &master_key)
        .map_err(|e| format!("Encryption failed: {e}"))?;
    let encrypted_bytes = encrypted.to_bytes();

    // Security: zeroize the plaintext value after encryption
    let mut val = value;
    val.zeroize();

    // Store in database
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    db.create_secret(&name, &encrypted_bytes, SecretType::KeyValue, false)
        .map_err(|e| format!("Failed to create secret: {e}"))?;

    // Log audit event
    db.log_event("secret_created", None, Some(&name))
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

/// Retrieve a secret by name. Blind secrets return metadata only (value = None).
/// Expired secrets are rejected with an error and an audit event is logged.
#[tauri::command]
pub async fn get_secret(
    name: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Option<SecretValue>, String> {
    enforce_unlocked_or_auto_lock(&state)?;

    // Get the master key
    let master_key = {
        let key_guard = state
            .master_key
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        key_guard
            .ok_or_else(|| "App is locked -- unlock first".to_string())?
    };

    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    let entry = db
        .get_secret_by_name(&name)
        .map_err(|e| format!("DB error: {e}"))?;

    match entry {
        Some(secret) => {
            // Check expiration
            if let Some(ref exp) = secret.expires_at {
                if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(exp) {
                    if chrono::Utc::now() > expiry {
                        let _ = db.log_event("secret_expired", None, Some(&name));
                        return Err("Secret has expired".to_string());
                    }
                }
            }

            let decrypted_value = if secret.blind {
                // Blind secrets never expose their value to the frontend
                None
            } else {
                let encrypted_data =
                    encryption::EncryptedData::from_bytes(&secret.encrypted_value)
                        .map_err(|e| format!("Invalid encrypted data: {e}"))?;
                let mut plaintext_bytes = encryption::decrypt(&encrypted_data, &master_key)
                    .map_err(|e| format!("Decryption failed: {e}"))?;
                let value = String::from_utf8(plaintext_bytes.clone())
                    .map_err(|e| format!("Invalid UTF-8 in secret value: {e}"))?;

                // Security: zeroize the decrypted bytes buffer
                plaintext_bytes.zeroize();

                Some(value)
            };

            Ok(Some(SecretValue {
                id: secret.id,
                name: secret.name,
                value: decrypted_value,
                secret_type: secret.secret_type.to_string(),
                blind: secret.blind,
                created_at: secret.created_at,
                updated_at: secret.updated_at,
                expires_at: secret.expires_at,
            }))
        }
        None => Ok(None),
    }
}

/// List metadata for all secrets (values are never decrypted in list view).
/// Includes `expires_at` so the frontend can show expiration indicators.
#[tauri::command]
pub async fn list_secrets(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Vec<SecretMetadata>, String> {
    enforce_unlocked_or_auto_lock(&state)?;

    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    let entries = db.list_secrets().map_err(|e| format!("DB error: {e}"))?;

    let metadata: Vec<SecretMetadata> = entries
        .into_iter()
        .map(|e| SecretMetadata {
            id: e.id,
            name: e.name,
            secret_type: e.secret_type.to_string(),
            blind: e.blind,
            created_at: e.created_at,
            updated_at: e.updated_at,
            expires_at: e.expires_at,
        })
        .collect();

    Ok(metadata)
}

/// Update the value of an existing secret (re-encrypts with the master key).
#[tauri::command]
pub async fn update_secret(
    name: String,
    value: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    enforce_unlocked_or_auto_lock(&state)?;

    // Get the master key
    let master_key = {
        let key_guard = state
            .master_key
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        key_guard
            .ok_or_else(|| "App is locked -- unlock first".to_string())?
    };

    // Encrypt the new value
    let encrypted = encryption::encrypt(value.as_bytes(), &master_key)
        .map_err(|e| format!("Encryption failed: {e}"))?;
    let encrypted_bytes = encrypted.to_bytes();

    // Security: zeroize the plaintext value after encryption
    let mut val = value;
    val.zeroize();

    // Update in database
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    db.update_secret(&name, &encrypted_bytes)
        .map_err(|e| format!("Failed to update secret: {e}"))?;

    // Log audit event
    db.log_event("secret_updated", None, Some(&name))
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

/// Delete a secret by name.
#[tauri::command]
pub async fn delete_secret(
    name: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    enforce_unlocked_or_auto_lock(&state)?;

    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    db.delete_secret(&name)
        .map_err(|e| format!("Failed to delete secret: {e}"))?;

    // Log audit event
    db.log_event("secret_deleted", None, Some(&name))
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

// ======================================================================
// Environment Variable Commands
// ======================================================================

/// Add an environment variable name to the allowlist.
#[tauri::command]
pub async fn add_env_var_to_allowlist(
    var_name: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    // Validate name with the same rules as secret names
    validate_secret_name(&var_name)?;

    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    db.add_env_var(&var_name)
        .map_err(|e| format!("Failed to add env var: {e}"))?;

    db.log_event("env_var_added", None, Some(&var_name))
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

/// Remove an environment variable from the allowlist.
#[tauri::command]
pub async fn remove_env_var_from_allowlist(
    var_name: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    db.remove_env_var(&var_name)
        .map_err(|e| format!("Failed to remove env var: {e}"))?;

    db.log_event("env_var_removed", None, Some(&var_name))
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

/// List all configured env vars from the allowlist.
/// For each, checks whether the actual environment variable is set on the system.
/// Never returns actual values.
#[tauri::command]
pub async fn list_env_var_allowlist(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Vec<EnvVarInfo>, String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    let env_vars = db
        .list_env_vars()
        .map_err(|e| format!("DB error: {e}"))?;

    let result: Vec<EnvVarInfo> = env_vars
        .into_iter()
        .map(|ev| {
            let is_set = std::env::var(&ev.var_name).is_ok();
            EnvVarInfo {
                var_name: ev.var_name,
                is_set,
            }
        })
        .collect();

    Ok(result)
}

/// Read the value of an environment variable (if on the allowlist and app is unlocked).
/// This is primarily for the HTTP API to use; the value is never persisted to disk.
#[tauri::command]
pub async fn read_env_var(
    var_name: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Option<String>, String> {
    enforce_unlocked_or_auto_lock(&state)?;

    // Verify var_name is on the allowlist
    {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        let db = db_guard
            .as_ref()
            .ok_or_else(|| "Database not initialised".to_string())?;

        let env_vars = db
            .list_env_vars()
            .map_err(|e| format!("DB error: {e}"))?;

        if !env_vars.iter().any(|ev| ev.var_name == var_name) {
            return Err(format!(
                "Environment variable '{}' is not on the allowlist",
                var_name
            ));
        }

        // Log audit event
        db.log_event("env_var_read", None, Some(&var_name))
            .map_err(|e| format!("Failed to log event: {e}"))?;
    }

    // Read from system environment -- NEVER persist to DB
    match std::env::var(&var_name) {
        Ok(val) => Ok(Some(val)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(format!("Failed to read env var '{}': {}", var_name, e)),
    }
}

// ======================================================================
// Vault Export/Import Commands
// ======================================================================

/// Export selected secrets to a .tmvault file, encrypted with a PIN.
/// Optionally accepts an `expires_at` ISO 8601 UTC timestamp to create
/// a time-limited vault. The expiration is stored inside the encrypted
/// payload (tamper-resistant).
#[tauri::command]
pub async fn export_vault_file(
    secret_names: Vec<String>,
    pin: String,
    file_path: String,
    mark_blind: bool,
    expires_at: Option<String>,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    enforce_unlocked_or_auto_lock(&state)?;
    validate_pin(&pin)?;

    // Get master key
    let master_key = {
        let key_guard = state
            .master_key
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        key_guard
            .ok_or_else(|| "App is locked -- unlock first".to_string())?
    };

    // Retrieve and decrypt each requested secret
    let mut vault_secrets: Vec<VaultSecret> = Vec::new();
    {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        let db = db_guard
            .as_ref()
            .ok_or_else(|| "Database not initialised".to_string())?;

        for name in &secret_names {
            let entry = db
                .get_secret_by_name(name)
                .map_err(|e| format!("DB error: {e}"))?
                .ok_or_else(|| format!("Secret '{}' not found", name))?;

            let encrypted_data =
                encryption::EncryptedData::from_bytes(&entry.encrypted_value)
                    .map_err(|e| format!("Invalid encrypted data for '{}': {e}", name))?;

            let mut decrypted_bytes = encryption::decrypt(&encrypted_data, &master_key)
                .map_err(|e| format!("Decryption failed for '{}': {e}", name))?;

            let mut value = String::from_utf8(decrypted_bytes.clone())
                .map_err(|e| format!("Invalid UTF-8 in secret '{}': {e}", name))?;

            // Security: zeroize the raw decrypted bytes
            decrypted_bytes.zeroize();

            vault_secrets.push(VaultSecret {
                name: name.clone(),
                value: value.clone(),
                blind: mark_blind || entry.blind,
            });

            // Security: zeroize the plaintext value string
            value.zeroize();
        }
    }

    // Export to vault format with optional expiration
    let vault_bytes = vault::export_vault(vault_secrets, &pin, expires_at)
        .map_err(|e| format!("Vault export failed: {e}"))?;

    // Security: zeroize PIN after use
    let mut pin_buf = pin;
    pin_buf.zeroize();

    // Write to file
    std::fs::write(&file_path, &vault_bytes)
        .map_err(|e| format!("Failed to write vault file: {e}"))?;

    // Log audit event
    {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        if let Some(db) = db_guard.as_ref() {
            let _ = db.log_event("vault_exported", None, None);
        }
    }

    Ok(())
}

/// Import secrets from a .tmvault file, re-encrypting with the master key.
/// If the vault payload contains an `expires_at`, it is propagated to each
/// imported secret so runtime expiration checks apply.
#[tauri::command]
pub async fn import_vault_file(
    file_path: String,
    pin: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Vec<ImportedSecretInfo>, String> {
    enforce_unlocked_or_auto_lock(&state)?;
    validate_pin(&pin)?;

    // Get master key
    let master_key = {
        let key_guard = state
            .master_key
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        key_guard
            .ok_or_else(|| "App is locked -- unlock first".to_string())?
    };

    // Read vault file
    let file_data = std::fs::read(&file_path)
        .map_err(|e| format!("Failed to read vault file: {e}"))?;

    // Decrypt vault -- returns VaultPayload with expires_at
    let mut vault_payload: VaultPayload = vault::import_vault(&file_data, &pin)
        .map_err(|e| format!("Vault import failed: {e}"))?;

    // Security: zeroize PIN after use
    let mut pin_buf = pin;
    pin_buf.zeroize();

    // Extract the vault-level expiration for each imported secret
    let vault_expires_at = vault_payload.expires_at.clone();

    // Import each secret into DB
    let mut results: Vec<ImportedSecretInfo> = Vec::new();

    {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        let db = db_guard
            .as_ref()
            .ok_or_else(|| "Database not initialised".to_string())?;

        for secret in &mut vault_payload.secrets {
            let encrypted = match encryption::encrypt(secret.value.as_bytes(), &master_key) {
                Ok(enc) => enc,
                Err(e) => {
                    results.push(ImportedSecretInfo {
                        name: secret.name.clone(),
                        blind: secret.blind,
                        success: false,
                        error: Some(format!("Encryption failed: {e}")),
                        expires_at: vault_expires_at.clone(),
                    });
                    continue;
                }
            };

            let encrypted_bytes = encrypted.to_bytes();

            match db.create_secret_with_expiry(
                &secret.name,
                &encrypted_bytes,
                SecretType::VaultImport,
                secret.blind,
                vault_expires_at.as_deref(),
            ) {
                Ok(_) => {
                    results.push(ImportedSecretInfo {
                        name: secret.name.clone(),
                        blind: secret.blind,
                        success: true,
                        error: None,
                        expires_at: vault_expires_at.clone(),
                    });
                }
                Err(e) => {
                    results.push(ImportedSecretInfo {
                        name: secret.name.clone(),
                        blind: secret.blind,
                        success: false,
                        error: Some(format!("{e}")),
                        expires_at: vault_expires_at.clone(),
                    });
                }
            }

            // Security: zeroize the plaintext secret value after re-encryption
            secret.value.zeroize();
        }

        // Log audit event
        let _ = db.log_event("vault_imported", None, None);
    }

    Ok(results)
}

// ======================================================================
// Script Management Commands
// ======================================================================

/// List all registered scripts with their approval status.
#[tauri::command]
pub async fn list_scripts_cmd(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Vec<ScriptInfo>, String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    let scripts = db.list_scripts().map_err(|e| format!("DB error: {e}"))?;

    let result: Vec<ScriptInfo> = scripts
        .into_iter()
        .map(|s| ScriptInfo {
            id: s.id,
            script_id: s.script_id,
            script_name: s.script_name,
            domain: s.domain,
            approved: s.approved,
            created_at: s.created_at,
        })
        .collect();

    Ok(result)
}

/// Approve a registered script.
#[tauri::command]
pub async fn approve_script_cmd(
    script_id: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    db.approve_script(&script_id)
        .map_err(|e| format!("Failed to approve script: {e}"))?;

    db.log_event("script_approved", Some(&script_id), None)
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

/// Revoke approval for a registered script.
#[tauri::command]
pub async fn revoke_script(
    script_id: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    db.revoke_script(&script_id)
        .map_err(|e| format!("Failed to revoke script: {e}"))?;

    db.log_event("script_revoked", Some(&script_id), None)
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

/// Delete a script registration and all its access records.
#[tauri::command]
pub async fn delete_script_cmd(
    script_id: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    db.delete_script(&script_id)
        .map_err(|e| format!("Failed to delete script: {e}"))?;

    db.log_event("script_deleted", Some(&script_id), None)
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

/// List all secrets a script has requested access to, with approval status.
#[tauri::command]
pub async fn list_script_access(
    script_id: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Vec<ScriptAccessInfo>, String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    let script = db
        .get_script(&script_id)
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| format!("Script '{}' not found", script_id))?;

    let access = db
        .list_script_access(script.id)
        .map_err(|e| format!("DB error: {e}"))?;

    let result: Vec<ScriptAccessInfo> = access
        .into_iter()
        .map(|a| ScriptAccessInfo {
            secret_name: a.secret_name,
            approved: a.approved,
            created_at: a.created_at,
        })
        .collect();

    Ok(result)
}

/// Create or update the access record for a script+secret pair.
#[tauri::command]
pub async fn set_script_secret_access(
    script_id: String,
    secret_name: String,
    approved: bool,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    let script = db
        .get_script(&script_id)
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| format!("Script '{}' not found", script_id))?;

    let secret = db
        .get_secret_by_name(&secret_name)
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| format!("Secret '{}' not found", secret_name))?;

    db.set_script_secret_access(script.id, secret.id, approved)
        .map_err(|e| format!("Failed to set access: {e}"))?;

    db.log_event("script_access_updated", Some(&script_id), Some(&secret_name))
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

/// Return recent audit log entries.
#[tauri::command]
pub async fn get_audit_log(
    limit: Option<u32>,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Vec<AuditEntry>, String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    let entries = db
        .get_recent_events(limit.unwrap_or(50))
        .map_err(|e| format!("DB error: {e}"))?;

    let result: Vec<AuditEntry> = entries
        .into_iter()
        .map(|e| AuditEntry {
            event_type: e.event_type,
            script_id: e.script_id,
            secret_name: e.secret_name,
            timestamp: e.timestamp,
        })
        .collect();

    Ok(result)
}

// ======================================================================
// API Info Command
// ======================================================================

/// Return the local HTTP API connection info (port + bearer token) so the
/// frontend can display it for users to copy into their TamperMonkey scripts.
#[tauri::command]
pub async fn get_api_info(state: tauri::State<'_, Arc<AppState>>) -> Result<ApiInfo, String> {
    let port = {
        let guard = state
            .api_port
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        *guard
    };
    let token = {
        let guard = state
            .api_token
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        guard.clone()
    };

    Ok(ApiInfo { port, token })
}

// ======================================================================
// API Token Rotation Command
// ======================================================================

/// Rotate the API bearer token at runtime.
///
/// Generates a new token, updates it in:
/// 1. The shared `Arc<RwLock<String>>` (so Axum handlers use the new token immediately)
/// 2. The `api_token` Mutex (so `get_api_info` returns the new token)
/// 3. The on-disk `api.token` file
///
/// Logs an audit event and returns the new token to the frontend.
#[tauri::command]
pub async fn rotate_api_token(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<String, String> {
    // Generate a new token
    let new_token = auth::generate_token();

    // 1. Update the shared Axum token (used by HTTP handlers)
    {
        let mut shared = state
            .shared_api_token
            .write()
            .map_err(|e| format!("RwLock error: {e}"))?;

        // Security: zeroize the old token before overwriting
        shared.zeroize();
        *shared = new_token.clone();
    }

    // 2. Update the Mutex-based token (used by get_api_info IPC command)
    {
        let mut guard = state
            .api_token
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;

        // Security: zeroize the old token
        if let Some(ref mut old) = *guard {
            old.zeroize();
        }
        *guard = Some(new_token.clone());
    }

    // 3. Persist to disk
    {
        let dir_guard = state
            .app_data_dir
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        let app_data_dir = dir_guard
            .as_ref()
            .ok_or_else(|| "App data directory not set".to_string())?;

        auth::save_token(app_data_dir, &new_token)
            .map_err(|e| format!("Failed to save token: {e}"))?;
    }

    // 4. Audit log
    {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        if let Some(db) = db_guard.as_ref() {
            let _ = db.log_event("api_token_rotated", None, None);
        }
    }

    Ok(new_token)
}

// ======================================================================
// Blind Code Module Types
// ======================================================================

/// Metadata for a blind code module (never includes the actual code).
#[derive(Debug, Clone, Serialize)]
pub struct BlindCodeModuleMetadata {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub language: String,
    pub required_secrets: Vec<String>,
    pub allowed_params: Vec<String>,
    pub approved: bool,
    pub blind: bool,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>,
}

/// Result info for a blind code module import.
#[derive(Debug, Clone, Serialize)]
pub struct ImportedCodeModuleInfo {
    pub name: String,
    pub description: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Info about a script's access to a code module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptCodeAccessInfo {
    pub module_name: String,
    pub approved: bool,
    pub created_at: String,
}

// ======================================================================
// Blind Code Module Commands
// ======================================================================

/// List all blind code modules (metadata only -- code is never sent to frontend).
#[tauri::command]
pub async fn list_blind_code_modules(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Vec<BlindCodeModuleMetadata>, String> {
    enforce_unlocked_or_auto_lock(&state)?;

    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    let modules = db.list_blind_code_modules().map_err(|e| format!("DB error: {e}"))?;

    let result: Vec<BlindCodeModuleMetadata> = modules
        .into_iter()
        .map(|m| {
            let required_secrets: Vec<String> =
                serde_json::from_str(&m.required_secrets).unwrap_or_default();
            let allowed_params: Vec<String> =
                serde_json::from_str(&m.allowed_params).unwrap_or_default();
            BlindCodeModuleMetadata {
                id: m.id,
                name: m.name,
                description: m.description,
                language: m.language,
                required_secrets,
                allowed_params,
                approved: m.approved,
                blind: m.blind,
                created_at: m.created_at,
                updated_at: m.updated_at,
                expires_at: m.expires_at,
            }
        })
        .collect();

    Ok(result)
}

/// Import a blind code module from a .tmcode file.
#[tauri::command]
pub async fn import_blind_code_file(
    file_path: String,
    pin: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<ImportedCodeModuleInfo, String> {
    enforce_unlocked_or_auto_lock(&state)?;
    validate_pin(&pin)?;

    // Get master key
    let master_key = {
        let key_guard = state
            .master_key
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        key_guard
            .ok_or_else(|| "App is locked -- unlock first".to_string())?
    };

    // Read .tmcode file
    let file_data = std::fs::read(&file_path)
        .map_err(|e| format!("Failed to read code file: {e}"))?;

    // Decrypt
    let mut payload = crate::secrets::blind_code::import_code(&file_data, &pin)
        .map_err(|e| format!("Code import failed: {e}"))?;

    // Security: zeroize PIN
    let mut pin_buf = pin;
    pin_buf.zeroize();

    if payload.modules.is_empty() {
        return Err("Code file contains no modules".to_string());
    }

    let module = &mut payload.modules[0];
    let module_name = module.name.clone();
    let module_desc = module.description.clone();

    // Encrypt the Rhai code with the master key for DB storage
    let encrypted = encryption::encrypt(module.code.as_bytes(), &master_key)
        .map_err(|e| format!("Encryption failed: {e}"))?;
    let encrypted_bytes = encrypted.to_bytes();

    // Security: zeroize the plaintext code
    module.code.zeroize();

    // Serialize required_secrets and allowed_params as JSON
    let required_secrets_json = serde_json::to_string(&module.required_secrets)
        .map_err(|e| format!("JSON error: {e}"))?;
    let allowed_params_json = serde_json::to_string(&module.allowed_params)
        .map_err(|e| format!("JSON error: {e}"))?;

    // Store in DB
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    let module_language = module.language.clone();

    match db.create_blind_code_module(
        &module_name,
        &module_desc,
        &encrypted_bytes,
        &module_language,
        &required_secrets_json,
        &allowed_params_json,
        true, // always blind for imported modules
        payload.expires_at.as_deref(),
    ) {
        Ok(_) => {
            let _ = db.log_event("blind_code_imported", None, Some(&module_name));
            Ok(ImportedCodeModuleInfo {
                name: module_name,
                description: module_desc,
                success: true,
                error: None,
            })
        }
        Err(e) => Ok(ImportedCodeModuleInfo {
            name: module_name,
            description: module_desc,
            success: false,
            error: Some(format!("{e}")),
        }),
    }
}

/// Export a blind code module as a .tmcode file (for code authors).
///
/// If the module is blind, the code is decrypted from storage for export.
/// The exported file is encrypted with the provided PIN.
#[tauri::command]
pub async fn export_blind_code_file(
    module_name: String,
    pin: String,
    file_path: String,
    expires_at: Option<String>,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    enforce_unlocked_or_auto_lock(&state)?;
    validate_pin(&pin)?;

    // Get master key
    let master_key = {
        let key_guard = state
            .master_key
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        key_guard
            .ok_or_else(|| "App is locked -- unlock first".to_string())?
    };

    // Look up the module
    let module = {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        let db = db_guard
            .as_ref()
            .ok_or_else(|| "Database not initialised".to_string())?;
        db.get_blind_code_module(&module_name)
            .map_err(|e| format!("DB error: {e}"))?
            .ok_or_else(|| format!("Module '{}' not found", module_name))?
    };

    // Decrypt the code
    let encrypted_data = encryption::EncryptedData::from_bytes(&module.encrypted_code)
        .map_err(|e| format!("Invalid encrypted data: {e}"))?;
    let mut code_bytes = encryption::decrypt(&encrypted_data, &master_key)
        .map_err(|e| format!("Decryption failed: {e}"))?;
    let mut code = String::from_utf8(code_bytes.clone())
        .map_err(|e| format!("Invalid UTF-8 in code: {e}"))?;
    code_bytes.zeroize();

    let required_secrets: Vec<String> =
        serde_json::from_str(&module.required_secrets).unwrap_or_default();
    let allowed_params: Vec<String> =
        serde_json::from_str(&module.allowed_params).unwrap_or_default();

    // Build the code module entry
    let entry = crate::secrets::blind_code::CodeModuleEntry {
        name: module.name.clone(),
        description: module.description.clone(),
        language: module.language.clone(),
        code: code.clone(),
        required_secrets,
        allowed_params,
    };

    // Security: zeroize code
    code.zeroize();

    // Export to .tmcode format
    let file_bytes = crate::secrets::blind_code::export_code(entry, &pin, expires_at)
        .map_err(|e| format!("Export failed: {e}"))?;

    // Security: zeroize PIN
    let mut pin_buf = pin;
    pin_buf.zeroize();

    // Write to file
    std::fs::write(&file_path, &file_bytes)
        .map_err(|e| format!("Failed to write code file: {e}"))?;

    // Log audit event
    {
        let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
        if let Some(db) = db_guard.as_ref() {
            let _ = db.log_event("blind_code_exported", None, Some(&module_name));
        }
    }

    Ok(())
}

/// Create a new blind code module directly (for code authors).
/// The code is encrypted with the master key before storage.
#[tauri::command]
pub async fn create_blind_code_module(
    name: String,
    description: String,
    language: String,
    code: String,
    required_secrets: Vec<String>,
    allowed_params: Vec<String>,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    enforce_unlocked_or_auto_lock(&state)?;
    validate_secret_name(&name)?;

    // Get master key
    let master_key = {
        let key_guard = state
            .master_key
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        key_guard
            .ok_or_else(|| "App is locked -- unlock first".to_string())?
    };

    // Encrypt the code
    let encrypted = encryption::encrypt(code.as_bytes(), &master_key)
        .map_err(|e| format!("Encryption failed: {e}"))?;
    let encrypted_bytes = encrypted.to_bytes();

    // Security: zeroize plaintext code
    let mut code_buf = code;
    code_buf.zeroize();

    // Serialize required_secrets and allowed_params
    let required_secrets_json = serde_json::to_string(&required_secrets)
        .map_err(|e| format!("JSON error: {e}"))?;
    let allowed_params_json = serde_json::to_string(&allowed_params)
        .map_err(|e| format!("JSON error: {e}"))?;

    // Store in DB
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    db.create_blind_code_module(
        &name,
        &description,
        &encrypted_bytes,
        &language,
        &required_secrets_json,
        &allowed_params_json,
        false, // not blind when author creates locally -- they can see their own code
        None,
    )
    .map_err(|e| format!("Failed to create module: {e}"))?;

    db.log_event("blind_code_created", None, Some(&name))
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

/// Approve a blind code module for execution.
#[tauri::command]
pub async fn approve_blind_code_module(
    name: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    db.approve_blind_code_module(&name)
        .map_err(|e| format!("Failed to approve module: {e}"))?;

    db.log_event("blind_code_approved", None, Some(&name))
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

/// Revoke approval for a blind code module.
#[tauri::command]
pub async fn revoke_blind_code_module(
    name: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    db.revoke_blind_code_module(&name)
        .map_err(|e| format!("Failed to revoke module: {e}"))?;

    db.log_event("blind_code_revoked", None, Some(&name))
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

/// Delete a blind code module and all its access records.
#[tauri::command]
pub async fn delete_blind_code_module(
    name: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    db.delete_blind_code_module(&name)
        .map_err(|e| format!("Failed to delete module: {e}"))?;

    db.log_event("blind_code_deleted", None, Some(&name))
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

/// List all code module access records for a given script.
#[tauri::command]
pub async fn list_script_code_access(
    script_id: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Vec<ScriptCodeAccessInfo>, String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    let script = db
        .get_script(&script_id)
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| format!("Script '{}' not found", script_id))?;

    let access = db
        .list_script_code_access(script.id)
        .map_err(|e| format!("DB error: {e}"))?;

    let result: Vec<ScriptCodeAccessInfo> = access
        .into_iter()
        .map(|a| ScriptCodeAccessInfo {
            module_name: a.module_name,
            approved: a.approved,
            created_at: a.created_at,
        })
        .collect();

    Ok(result)
}

/// Set access for a script to a specific code module.
#[tauri::command]
pub async fn set_script_code_module_access(
    script_id: String,
    module_name: String,
    approved: bool,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    let script = db
        .get_script(&script_id)
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| format!("Script '{}' not found", script_id))?;

    let module = db
        .get_blind_code_module(&module_name)
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| format!("Module '{}' not found", module_name))?;

    db.set_script_code_access(script.id, module.id, approved)
        .map_err(|e| format!("Failed to set access: {e}"))?;

    db.log_event("script_code_access_updated", Some(&script_id), Some(&module_name))
        .map_err(|e| format!("Failed to log event: {e}"))?;

    Ok(())
}

/// Get the Rhai code for a non-blind module (code author viewing their own code).
/// Returns None if the module is blind (imported, cannot be viewed).
#[tauri::command]
pub async fn get_blind_code_module_code(
    name: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<Option<String>, String> {
    enforce_unlocked_or_auto_lock(&state)?;

    let master_key = {
        let key_guard = state
            .master_key
            .lock()
            .map_err(|e| format!("Lock error: {e}"))?;
        key_guard
            .ok_or_else(|| "App is locked -- unlock first".to_string())?
    };

    let db_guard = state.db.lock().map_err(|e| format!("Lock error: {e}"))?;
    let db = db_guard
        .as_ref()
        .ok_or_else(|| "Database not initialised".to_string())?;

    let module = db
        .get_blind_code_module(&name)
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| format!("Module '{}' not found", name))?;

    if module.blind {
        // Blind modules never expose code to frontend
        return Ok(None);
    }

    // Non-blind: decrypt and return
    let encrypted_data = encryption::EncryptedData::from_bytes(&module.encrypted_code)
        .map_err(|e| format!("Invalid encrypted data: {e}"))?;
    let mut decrypted = encryption::decrypt(&encrypted_data, &master_key)
        .map_err(|e| format!("Decryption failed: {e}"))?;
    let code = String::from_utf8(decrypted.clone())
        .map_err(|e| format!("Invalid UTF-8: {e}"))?;
    decrypted.zeroize();

    Ok(Some(code))
}
