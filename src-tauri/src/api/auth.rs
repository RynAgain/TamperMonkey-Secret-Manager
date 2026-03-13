use std::fs;
use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::ApiError;

/// Generate a cryptographically random bearer token (32 bytes, base64url-encoded, no padding).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Persist the bearer token to `{app_data_dir}/tampermonkey-secrets/api.token`.
///
/// On Windows the file is created with restrictive permissions (current user
/// only). See [`set_owner_only_permissions`] for details.
pub fn save_token(app_data_dir: &Path, token: &str) -> Result<(), ApiError> {
    let dir = app_data_dir.join("tampermonkey-secrets");
    fs::create_dir_all(&dir)?;
    let token_path = dir.join("api.token");

    // Remove read-only attribute if file exists from a previous run
    clear_readonly(&token_path);

    fs::write(&token_path, token)?;

    // Harden file permissions -- best-effort on Windows
    set_owner_only_permissions(&token_path);

    Ok(())
}

/// Load the bearer token from disk, returning `None` if the file does not exist.
pub fn load_token(app_data_dir: &Path) -> Result<Option<String>, ApiError> {
    let token_path = app_data_dir.join("tampermonkey-secrets").join("api.token");
    if token_path.exists() {
        let token = fs::read_to_string(&token_path)?;
        Ok(Some(token.trim().to_string()))
    } else {
        Ok(None)
    }
}

/// Persist the assigned API port to `{app_data_dir}/tampermonkey-secrets/api.port`.
///
/// On Windows the file is created with restrictive permissions.
pub fn save_port(app_data_dir: &Path, port: u16) -> Result<(), ApiError> {
    let dir = app_data_dir.join("tampermonkey-secrets");
    fs::create_dir_all(&dir)?;
    let port_path = dir.join("api.port");

    // Remove read-only attribute if file exists from a previous run
    clear_readonly(&port_path);

    fs::write(&port_path, port.to_string())?;

    // Harden file permissions -- best-effort on Windows
    set_owner_only_permissions(&port_path);

    Ok(())
}

/// Make a previously-hardened file writable again before overwriting.
///
/// This must be called before `fs::write` on files that were previously
/// hardened by [`set_owner_only_permissions`], because:
/// 1. The read-only attribute blocks writes on Windows
/// 2. The ACL may only grant read access to the current user
///
/// We first use `icacls` to grant full control (so the attribute change
/// and subsequent `fs::write` succeed), then clear the read-only flag.
fn clear_readonly(path: &Path) {
    if !path.exists() {
        return;
    }

    // Step 1 (Windows): Grant full control via icacls so we can modify the file
    #[cfg(target_os = "windows")]
    {
        if let Ok(username) = std::env::var("USERNAME") {
            let path_str = path.to_string_lossy();
            let grant_arg = format!("{}:F", username);
            let _ = std::process::Command::new("icacls")
                .args([&*path_str, "/grant", &grant_arg])
                .output();
        }
    }

    // Step 2: Clear the read-only attribute
    if let Ok(metadata) = fs::metadata(path) {
        let mut perms = metadata.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
    }
}

/// Attempt to set restrictive permissions on a file so only the current user
/// can read and write it.
///
/// On Windows we use the `icacls` command to remove inherited permissions and
/// grant read+write access exclusively to the current user. We intentionally
/// do NOT set the file to read-only via `std::fs::Permissions` because the
/// application needs to overwrite these files on each startup (token and port
/// rotate every launch).
///
/// # Limitations
///
/// - Full DACL-based ACL restriction requires the `windows-acl` crate or
///   direct Win32 API calls. Phase 7 should audit this and consider adding
///   native DACL support.
/// - On non-Windows platforms this is a no-op (this app is Windows-only).
pub fn set_owner_only_permissions(path: &Path) {
    // Windows-only: Use icacls to restrict to current user with read+write
    // icacls <path> /inheritance:r /grant:r "%USERNAME%:(R,W)"
    // This removes inherited permissions and grants read+write to current user only.
    #[cfg(target_os = "windows")]
    {
        if let Ok(username) = std::env::var("USERNAME") {
            let path_str = path.to_string_lossy();
            let grant_arg = format!("{}:(R,W)", username);
            // Remove inherited ACLs and grant only current user read+write access
            let _ = std::process::Command::new("icacls")
                .args([&*path_str, "/inheritance:r", "/grant:r", &grant_arg])
                .output();
        }
    }

    // Suppress unused variable warning on non-Windows
    #[cfg(not(target_os = "windows"))]
    let _ = path;
}

/// Apply restrictive permissions to the SQLite database file.
///
/// Unlike token/port files, the DB needs read+write access for the current
/// user but should not be accessible by others.
pub fn harden_db_permissions(path: &Path) {
    #[cfg(target_os = "windows")]
    {
        if let Ok(username) = std::env::var("USERNAME") {
            let path_str = path.to_string_lossy();
            let grant_arg = format!("{}:F", username);
            // Remove inherited ACLs and grant current user full control
            let _ = std::process::Command::new("icacls")
                .args([&*path_str, "/inheritance:r", "/grant:r", &grant_arg])
                .output();
        }
    }

    // Suppress unused variable warning on non-Windows
    #[cfg(not(target_os = "windows"))]
    let _ = path;
}

/// Constant-time comparison of two byte slices to prevent timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token_length() {
        let token = generate_token();
        // 32 bytes -> 43 base64url chars (no padding)
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn test_generate_token_uniqueness() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2, "tokens should be unique");
    }

    #[test]
    fn test_constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn test_save_and_load_token() {
        let dir = std::env::temp_dir().join(format!("tmpsm_auth_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        save_token(&dir, "test-token-value").unwrap();
        let loaded = load_token(&dir).unwrap();
        assert_eq!(loaded, Some("test-token-value".to_string()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_token_missing() {
        let dir = std::env::temp_dir().join(format!("tmpsm_auth_missing_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let loaded = load_token(&dir).unwrap();
        assert_eq!(loaded, None);
    }

    #[test]
    fn test_save_port() {
        let dir = std::env::temp_dir().join(format!("tmpsm_port_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        save_port(&dir, 54321).unwrap();
        let port_path = dir.join("tampermonkey-secrets").join("api.port");
        // File may be read-only now due to hardening; read it
        let content = fs::read_to_string(&port_path).unwrap();
        assert_eq!(content, "54321");

        let _ = fs::remove_dir_all(&dir);
    }
}
