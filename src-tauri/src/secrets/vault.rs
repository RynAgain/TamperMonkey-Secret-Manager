use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{encryption, kdf};
use crate::error::CryptoError;

/// Magic bytes identifying a .tmvault file: "TMVT" (0x544D5654).
const VAULT_MAGIC: &[u8; 4] = b"TMVT";

/// Legacy vault file format version (no expiration support).
const VAULT_VERSION_V1: u8 = 0x01;

/// Current vault file format version (with expiration support).
const VAULT_VERSION_V2: u8 = 0x02;

/// Minimum header size: 4 (magic) + 1 (version) + 16 (salt) + 4 (count) = 25 bytes.
const HEADER_SIZE: usize = 25;

/// Minimum PIN length enforced on both export and import.
const MIN_PIN_LENGTH: usize = 6;

/// A single secret entry stored inside a vault file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSecret {
    pub name: String,
    pub value: String,
    pub blind: bool,
}

/// The encrypted payload structure for v2 vaults.
///
/// Contains version, optional expiration timestamp, and the secrets.
/// This goes INSIDE the encrypted payload so it cannot be tampered with
/// without knowing the PIN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPayload {
    /// Payload version: 1
    pub version: u8,
    /// ISO 8601 UTC timestamp, or None for no expiration.
    pub expires_at: Option<String>,
    /// The secrets stored in this vault.
    pub secrets: Vec<VaultSecret>,
}

/// Parsed (but still encrypted) vault file structure -- used internally.
#[allow(dead_code)]
pub struct VaultFile {
    pub version: u8,
    pub salt: [u8; 16],
    pub secret_count: u32,
    pub encrypted_payload: Vec<u8>,
}

/// Check whether an ISO 8601 timestamp is in the past.
fn is_expired(expires_at: &str) -> Result<bool, CryptoError> {
    let expiry = chrono::DateTime::parse_from_rfc3339(expires_at)
        .map_err(|e| CryptoError::InvalidData(format!("Invalid expiration timestamp: {e}")))?;
    Ok(Utc::now() > expiry)
}

/// Export a set of secrets into the `.tmvault` binary format (v2).
///
/// The file is encrypted with a key derived from `pin` via Argon2id.
/// If `expires_at` is provided, the expiration timestamp is stored inside
/// the encrypted payload (tamper-resistant).
/// Returns the complete file bytes ready to be written to disk.
pub fn export_vault(
    secrets: Vec<VaultSecret>,
    pin: &str,
    expires_at: Option<String>,
) -> Result<Vec<u8>, CryptoError> {
    if pin.len() < MIN_PIN_LENGTH {
        return Err(CryptoError::InvalidData(format!(
            "PIN must be at least {} characters",
            MIN_PIN_LENGTH
        )));
    }

    // Validate expires_at format if provided
    if let Some(ref ts) = expires_at {
        chrono::DateTime::parse_from_rfc3339(ts)
            .map_err(|e| CryptoError::InvalidData(format!("Invalid expiration timestamp: {e}")))?;
    }

    // Generate salt and derive key from PIN
    let salt = kdf::generate_salt();
    let derived_key = kdf::derive_key(pin.as_bytes(), &salt)?;

    // Build the VaultPayload
    let payload = VaultPayload {
        version: 1,
        expires_at,
        secrets: secrets.clone(),
    };

    // Serialize payload to JSON
    let mut json_bytes = serde_json::to_vec(&payload)
        .map_err(|e| CryptoError::EncryptionFailed(format!("JSON serialization failed: {e}")))?;

    // Encrypt the JSON payload
    let encrypted = encryption::encrypt(&json_bytes, &derived_key)?;
    let encrypted_bytes = encrypted.to_bytes();

    // Zeroize sensitive data
    json_bytes.zeroize();

    // Build the binary file:
    // [4] magic + [1] version + [16] salt + [4] count (LE) + [N] encrypted payload
    let secret_count = secrets.len() as u32;
    let mut output = Vec::with_capacity(HEADER_SIZE + encrypted_bytes.len());
    output.extend_from_slice(VAULT_MAGIC);
    output.push(VAULT_VERSION_V2);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&secret_count.to_le_bytes());
    output.extend_from_slice(&encrypted_bytes);

    Ok(output)
}

/// Import secrets from `.tmvault` binary data, decrypting with the given PIN.
///
/// Supports both v1 (legacy, no expiration) and v2 (with expiration) formats.
/// For v1 files, `expires_at` will be `None`.
/// For v2 files, if the vault has expired, returns an error.
///
/// Returns the full `VaultPayload` so the caller can inspect `expires_at`.
pub fn import_vault(
    data: &[u8],
    pin: &str,
) -> Result<VaultPayload, CryptoError> {
    if pin.len() < MIN_PIN_LENGTH {
        return Err(CryptoError::InvalidData(format!(
            "PIN must be at least {} characters",
            MIN_PIN_LENGTH
        )));
    }

    if data.len() < HEADER_SIZE {
        return Err(CryptoError::InvalidData(format!(
            "Vault file too short: expected at least {} bytes, got {}",
            HEADER_SIZE,
            data.len()
        )));
    }

    // Validate magic bytes
    if &data[0..4] != VAULT_MAGIC {
        return Err(CryptoError::InvalidData(
            "Invalid vault file: bad magic bytes (expected TMVT)".to_string(),
        ));
    }

    // Read version
    let version = data[4];
    if version != VAULT_VERSION_V1 && version != VAULT_VERSION_V2 {
        return Err(CryptoError::InvalidData(format!(
            "Unsupported vault version: {} (expected {} or {})",
            version, VAULT_VERSION_V1, VAULT_VERSION_V2
        )));
    }

    // Extract salt (bytes 5..21)
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[5..21]);

    // Extract secret count (bytes 21..25, little-endian u32)
    let secret_count = u32::from_le_bytes([data[21], data[22], data[23], data[24]]);

    // Extract encrypted payload (bytes 25+)
    let encrypted_payload = &data[25..];
    if encrypted_payload.is_empty() {
        return Err(CryptoError::InvalidData(
            "Vault file has no encrypted payload".to_string(),
        ));
    }

    // Derive key from PIN + salt
    let derived_key = kdf::derive_key(pin.as_bytes(), &salt)?;

    // Decrypt payload
    let encrypted_data = encryption::EncryptedData::from_bytes(encrypted_payload)?;
    let mut decrypted = encryption::decrypt(&encrypted_data, &derived_key)?;

    // Deserialize based on version
    let payload = if version == VAULT_VERSION_V1 {
        // Legacy v1: payload is Vec<VaultSecret>
        let secrets: Vec<VaultSecret> = serde_json::from_slice(&decrypted)
            .map_err(|e| CryptoError::DecryptionFailed(format!("JSON deserialization failed: {e}")))?;

        // Validate count matches
        if secrets.len() as u32 != secret_count {
            return Err(CryptoError::InvalidData(format!(
                "Secret count mismatch: header says {}, payload contains {}",
                secret_count,
                secrets.len()
            )));
        }

        VaultPayload {
            version: 1,
            expires_at: None,
            secrets,
        }
    } else {
        // v2: payload is VaultPayload
        let vp: VaultPayload = serde_json::from_slice(&decrypted)
            .map_err(|e| CryptoError::DecryptionFailed(format!("JSON deserialization failed: {e}")))?;

        // Validate count matches
        if vp.secrets.len() as u32 != secret_count {
            return Err(CryptoError::InvalidData(format!(
                "Secret count mismatch: header says {}, payload contains {}",
                secret_count,
                vp.secrets.len()
            )));
        }

        vp
    };

    // Zeroize decrypted bytes
    decrypted.zeroize();

    // Check expiration
    if let Some(ref exp) = payload.expires_at {
        if is_expired(exp)? {
            return Err(CryptoError::InvalidData(
                "Vault has expired".to_string(),
            ));
        }
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secrets() -> Vec<VaultSecret> {
        vec![
            VaultSecret {
                name: "API_KEY".to_string(),
                value: "sk-test-12345".to_string(),
                blind: false,
            },
            VaultSecret {
                name: "DB_PASSWORD".to_string(),
                value: "super-secret-pw".to_string(),
                blind: true,
            },
        ]
    }

    #[test]
    fn test_export_import_roundtrip() {
        let secrets = sample_secrets();
        let pin = "mypin123";

        let vault_bytes = export_vault(secrets.clone(), pin, None)
            .expect("export should succeed");

        let payload = import_vault(&vault_bytes, pin)
            .expect("import should succeed");

        assert_eq!(payload.secrets.len(), 2);
        assert_eq!(payload.secrets[0].name, "API_KEY");
        assert_eq!(payload.secrets[0].value, "sk-test-12345");
        assert!(!payload.secrets[0].blind);
        assert_eq!(payload.secrets[1].name, "DB_PASSWORD");
        assert_eq!(payload.secrets[1].value, "super-secret-pw");
        assert!(payload.secrets[1].blind);
        assert!(payload.expires_at.is_none());
    }

    #[test]
    fn test_import_wrong_pin_fails() {
        let secrets = sample_secrets();
        let pin = "correct-pin";
        let wrong_pin = "wrong-pin!";

        let vault_bytes = export_vault(secrets, pin, None)
            .expect("export should succeed");

        let result = import_vault(&vault_bytes, wrong_pin);
        assert!(result.is_err(), "import with wrong PIN must fail");
    }

    #[test]
    fn test_vault_file_format() {
        let secrets = sample_secrets();
        let pin = "format-test";

        let vault_bytes = export_vault(secrets, pin, None)
            .expect("export should succeed");

        // Check magic bytes
        assert_eq!(&vault_bytes[0..4], b"TMVT");

        // Check version -- v2 now
        assert_eq!(vault_bytes[4], 0x02);

        // Check salt is 16 bytes (bytes 5..21)
        let salt = &vault_bytes[5..21];
        assert_eq!(salt.len(), 16);
        // Salt should not be all zeros (statistically near-impossible)
        assert!(salt.iter().any(|&b| b != 0), "salt should not be all zeros");

        // Check secret count (bytes 21..25)
        let count = u32::from_le_bytes([vault_bytes[21], vault_bytes[22], vault_bytes[23], vault_bytes[24]]);
        assert_eq!(count, 2);

        // Encrypted payload should exist after the header
        assert!(vault_bytes.len() > HEADER_SIZE, "vault must have an encrypted payload");
    }

    #[test]
    fn test_blind_flag_preserved() {
        let secrets = vec![
            VaultSecret {
                name: "BLIND_SECRET".to_string(),
                value: "hidden-value".to_string(),
                blind: true,
            },
            VaultSecret {
                name: "VISIBLE_SECRET".to_string(),
                value: "visible-value".to_string(),
                blind: false,
            },
        ];
        let pin = "blind-test";

        let vault_bytes = export_vault(secrets, pin, None)
            .expect("export should succeed");

        let payload = import_vault(&vault_bytes, pin)
            .expect("import should succeed");

        assert_eq!(payload.secrets.len(), 2);
        assert!(payload.secrets[0].blind, "BLIND_SECRET should have blind=true");
        assert!(!payload.secrets[1].blind, "VISIBLE_SECRET should have blind=false");
    }

    #[test]
    fn test_pin_too_short_rejected() {
        let secrets = sample_secrets();
        let short_pin = "12345"; // 5 chars, below minimum 6

        let result = export_vault(secrets, short_pin, None);
        assert!(result.is_err(), "PIN shorter than 6 chars must be rejected");
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let mut bad_data = vec![0x00, 0x00, 0x00, 0x00]; // wrong magic
        bad_data.push(0x01); // version
        bad_data.extend_from_slice(&[0u8; 16]); // salt
        bad_data.extend_from_slice(&0u32.to_le_bytes()); // count
        bad_data.push(0xFF); // fake payload

        let result = import_vault(&bad_data, "somepin123");
        assert!(result.is_err(), "invalid magic bytes must be rejected");
    }

    #[test]
    fn test_empty_vault_roundtrip() {
        let secrets: Vec<VaultSecret> = vec![];
        let pin = "empty-vault";

        let vault_bytes = export_vault(secrets, pin, None)
            .expect("export of empty vault should succeed");

        let payload = import_vault(&vault_bytes, pin)
            .expect("import of empty vault should succeed");

        assert_eq!(payload.secrets.len(), 0);
        assert!(payload.expires_at.is_none());
    }

    #[test]
    fn test_vault_with_expiration() {
        let secrets = sample_secrets();
        let pin = "expire-test";
        // Set expiration far in the future
        let future = (Utc::now() + chrono::Duration::hours(24)).to_rfc3339();

        let vault_bytes = export_vault(secrets, pin, Some(future.clone()))
            .expect("export with expiration should succeed");

        let payload = import_vault(&vault_bytes, pin)
            .expect("import of non-expired vault should succeed");

        assert_eq!(payload.secrets.len(), 2);
        assert_eq!(payload.expires_at, Some(future));
    }

    #[test]
    fn test_vault_expired_fails_import() {
        let secrets = sample_secrets();
        let pin = "expired-test";
        // Set expiration in the past
        let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();

        let vault_bytes = export_vault(secrets, pin, Some(past))
            .expect("export should succeed even with past expiration");

        let result = import_vault(&vault_bytes, pin);
        assert!(result.is_err(), "expired vault must fail import");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("expired"),
            "error should mention expiration, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_vault_no_expiration() {
        let secrets = sample_secrets();
        let pin = "no-expiry";

        let vault_bytes = export_vault(secrets, pin, None)
            .expect("export should succeed");

        let payload = import_vault(&vault_bytes, pin)
            .expect("import should succeed");

        assert!(payload.expires_at.is_none(), "expires_at should be None");
    }

    #[test]
    fn test_vault_v1_backward_compat() {
        // Build a v1-format vault manually to test backward compatibility.
        // v1 format: payload is just Vec<VaultSecret> (not VaultPayload).
        let secrets = sample_secrets();
        let pin = "v1-compat";

        let salt = kdf::generate_salt();
        let derived_key = kdf::derive_key(pin.as_bytes(), &salt).unwrap();

        // Serialize as plain Vec<VaultSecret> (v1 format)
        let json_bytes = serde_json::to_vec(&secrets).unwrap();
        let encrypted = encryption::encrypt(&json_bytes, &derived_key).unwrap();
        let encrypted_bytes = encrypted.to_bytes();

        let secret_count = secrets.len() as u32;
        let mut output = Vec::with_capacity(HEADER_SIZE + encrypted_bytes.len());
        output.extend_from_slice(VAULT_MAGIC);
        output.push(VAULT_VERSION_V1); // v1 version byte
        output.extend_from_slice(&salt);
        output.extend_from_slice(&secret_count.to_le_bytes());
        output.extend_from_slice(&encrypted_bytes);

        // Import should succeed with backward compatibility
        let payload = import_vault(&output, pin)
            .expect("v1 vault import should succeed");

        assert_eq!(payload.secrets.len(), 2);
        assert_eq!(payload.secrets[0].name, "API_KEY");
        assert_eq!(payload.secrets[1].name, "DB_PASSWORD");
        assert!(payload.expires_at.is_none(), "v1 vaults should have no expiration");
    }

    #[test]
    fn test_invalid_expiration_timestamp_rejected() {
        let secrets = sample_secrets();
        let pin = "bad-timestamp";

        let result = export_vault(secrets, pin, Some("not-a-timestamp".to_string()));
        assert!(result.is_err(), "invalid timestamp should be rejected on export");
    }
}
