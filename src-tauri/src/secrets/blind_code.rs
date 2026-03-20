use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{encryption, kdf};
use crate::error::CryptoError;

/// Magic bytes identifying a .tmcode file: "TMCD" (0x544D4344).
const CODE_MAGIC: &[u8; 4] = b"TMCD";

/// Current .tmcode file format version.
const CODE_VERSION_V1: u8 = 0x01;

/// Minimum header size: 4 (magic) + 1 (version) + 16 (salt) + 4 (count) = 25 bytes.
const HEADER_SIZE: usize = 25;

/// Minimum PIN length enforced on both export and import.
const MIN_PIN_LENGTH: usize = 6;

/// A single blind code module entry stored inside a .tmcode file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeModuleEntry {
    /// Unique identifier for the module.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The scripting language: "rhai", "python", "javascript", or "typescript".
    pub language: String,
    /// Source code.
    pub code: String,
    /// List of secret names this module requires.
    pub required_secrets: Vec<String>,
    /// List of parameter names accepted from TM scripts.
    pub allowed_params: Vec<String>,
}

/// The encrypted payload structure for .tmcode files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodePayload {
    /// Payload format version.
    pub version: u8,
    /// Optional ISO 8601 UTC expiration timestamp.
    pub expires_at: Option<String>,
    /// The code modules in this file (v1: always 1 module).
    pub modules: Vec<CodeModuleEntry>,
}

/// Export a blind code module to the `.tmcode` binary format.
///
/// The file is encrypted with a key derived from `pin` via Argon2id.
/// Returns the complete file bytes ready to be written to disk.
pub fn export_code(
    module: CodeModuleEntry,
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

    // Build the CodePayload
    let payload = CodePayload {
        version: 1,
        expires_at,
        modules: vec![module],
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
    let module_count: u32 = 1;
    let mut output = Vec::with_capacity(HEADER_SIZE + encrypted_bytes.len());
    output.extend_from_slice(CODE_MAGIC);
    output.push(CODE_VERSION_V1);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&module_count.to_le_bytes());
    output.extend_from_slice(&encrypted_bytes);

    Ok(output)
}

/// Import a blind code module from `.tmcode` binary data, decrypting with the given PIN.
///
/// Returns the full `CodePayload` so the caller can inspect metadata and code.
pub fn import_code(
    data: &[u8],
    pin: &str,
) -> Result<CodePayload, CryptoError> {
    if pin.len() < MIN_PIN_LENGTH {
        return Err(CryptoError::InvalidData(format!(
            "PIN must be at least {} characters",
            MIN_PIN_LENGTH
        )));
    }

    if data.len() < HEADER_SIZE {
        return Err(CryptoError::InvalidData(format!(
            "Code file too short: expected at least {} bytes, got {}",
            HEADER_SIZE,
            data.len()
        )));
    }

    // Validate magic bytes
    if &data[0..4] != CODE_MAGIC {
        return Err(CryptoError::InvalidData(
            "Invalid code file: bad magic bytes (expected TMCD)".to_string(),
        ));
    }

    // Read version
    let version = data[4];
    if version != CODE_VERSION_V1 {
        return Err(CryptoError::InvalidData(format!(
            "Unsupported code file version: {} (expected {})",
            version, CODE_VERSION_V1
        )));
    }

    // Extract salt (bytes 5..21)
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[5..21]);

    // Extract module count (bytes 21..25, little-endian u32)
    let module_count = u32::from_le_bytes([data[21], data[22], data[23], data[24]]);

    // Extract encrypted payload (bytes 25+)
    let encrypted_payload = &data[25..];
    if encrypted_payload.is_empty() {
        return Err(CryptoError::InvalidData(
            "Code file has no encrypted payload".to_string(),
        ));
    }

    // Derive key from PIN + salt
    let derived_key = kdf::derive_key(pin.as_bytes(), &salt)?;

    // Decrypt payload
    let encrypted_data = encryption::EncryptedData::from_bytes(encrypted_payload)?;
    let mut decrypted = encryption::decrypt(&encrypted_data, &derived_key)?;

    // Deserialize
    let payload: CodePayload = serde_json::from_slice(&decrypted)
        .map_err(|e| CryptoError::DecryptionFailed(format!("JSON deserialization failed: {e}")))?;

    // Validate count matches
    if payload.modules.len() as u32 != module_count {
        return Err(CryptoError::InvalidData(format!(
            "Module count mismatch: header says {}, payload contains {}",
            module_count,
            payload.modules.len()
        )));
    }

    // Zeroize decrypted bytes
    decrypted.zeroize();

    // Check expiration
    if let Some(ref exp) = payload.expires_at {
        let expiry = chrono::DateTime::parse_from_rfc3339(exp)
            .map_err(|e| CryptoError::InvalidData(format!("Invalid expiration timestamp: {e}")))?;
        if chrono::Utc::now() > expiry {
            return Err(CryptoError::InvalidData(
                "Code module has expired".to_string(),
            ));
        }
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_module() -> CodeModuleEntry {
        CodeModuleEntry {
            name: "test-module".to_string(),
            description: "A test module".to_string(),
            language: "rhai".to_string(),
            code: r#"let key = secret("API_KEY"); "result: " + key"#.to_string(),
            required_secrets: vec!["API_KEY".to_string()],
            allowed_params: vec!["url".to_string()],
        }
    }

    #[test]
    fn test_export_import_roundtrip() {
        let module = sample_module();
        let pin = "testpin123";

        let code_bytes = export_code(module.clone(), pin, None)
            .expect("export should succeed");

        let payload = import_code(&code_bytes, pin)
            .expect("import should succeed");

        assert_eq!(payload.modules.len(), 1);
        assert_eq!(payload.modules[0].name, "test-module");
        assert_eq!(payload.modules[0].description, "A test module");
        assert_eq!(payload.modules[0].code, module.code);
        assert_eq!(payload.modules[0].required_secrets, vec!["API_KEY"]);
        assert_eq!(payload.modules[0].allowed_params, vec!["url"]);
        assert!(payload.expires_at.is_none());
    }

    #[test]
    fn test_wrong_pin_fails() {
        let module = sample_module();
        let pin = "correct-pin";
        let wrong = "wrong-pin!";

        let code_bytes = export_code(module, pin, None)
            .expect("export should succeed");

        let result = import_code(&code_bytes, wrong);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_format() {
        let module = sample_module();
        let pin = "format-test";

        let code_bytes = export_code(module, pin, None)
            .expect("export should succeed");

        // Check magic bytes
        assert_eq!(&code_bytes[0..4], b"TMCD");
        // Check version
        assert_eq!(code_bytes[4], 0x01);
        // Check salt is 16 bytes
        let salt = &code_bytes[5..21];
        assert_eq!(salt.len(), 16);
        assert!(salt.iter().any(|&b| b != 0));
        // Check module count
        let count = u32::from_le_bytes([code_bytes[21], code_bytes[22], code_bytes[23], code_bytes[24]]);
        assert_eq!(count, 1);
        // Encrypted payload exists
        assert!(code_bytes.len() > HEADER_SIZE);
    }

    #[test]
    fn test_pin_too_short_rejected() {
        let module = sample_module();
        let result = export_code(module, "12345", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let mut bad_data = vec![0x00, 0x00, 0x00, 0x00]; // wrong magic
        bad_data.push(0x01);
        bad_data.extend_from_slice(&[0u8; 16]);
        bad_data.extend_from_slice(&0u32.to_le_bytes());
        bad_data.push(0xFF);

        let result = import_code(&bad_data, "somepin123");
        assert!(result.is_err());
    }

    #[test]
    fn test_with_expiration() {
        let module = sample_module();
        let pin = "expire-test";
        let future = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();

        let code_bytes = export_code(module, pin, Some(future.clone()))
            .expect("export should succeed");

        let payload = import_code(&code_bytes, pin)
            .expect("import should succeed");

        assert_eq!(payload.expires_at, Some(future));
    }

    #[test]
    fn test_expired_fails_import() {
        let module = sample_module();
        let pin = "expired-test";
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();

        let code_bytes = export_code(module, pin, Some(past))
            .expect("export should succeed");

        let result = import_code(&code_bytes, pin);
        assert!(result.is_err());
    }
}
