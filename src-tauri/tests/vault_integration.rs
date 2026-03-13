//! Integration tests for vault file export/import.
//!
//! Tests the full vault pipeline: export with PIN -> read raw bytes ->
//! verify format -> import with correct/wrong PIN -> tamper detection.
//! Includes expiration-related tests for v2 format.

use tampermonkey_secret_manager_lib::secrets::vault::{export_vault, import_vault, VaultSecret};

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
fn test_export_verify_magic_version_salt() {
    let secrets = sample_secrets();
    let pin = "vault-test-123";

    let vault_bytes = export_vault(secrets, pin, None).expect("export should succeed");

    // 1. Verify magic bytes: "TMVT"
    assert_eq!(&vault_bytes[0..4], b"TMVT", "magic bytes should be TMVT");

    // 2. Verify version byte -- now v2
    assert_eq!(vault_bytes[4], 0x02, "version should be 0x02");

    // 3. Verify salt is 16 bytes (bytes 5..21) and not all zeros
    let salt = &vault_bytes[5..21];
    assert_eq!(salt.len(), 16, "salt should be 16 bytes");
    assert!(
        salt.iter().any(|&b| b != 0),
        "salt should not be all zeros (statistically near-impossible)"
    );

    // 4. Verify secret count (bytes 21..25, little-endian u32)
    let count = u32::from_le_bytes([
        vault_bytes[21],
        vault_bytes[22],
        vault_bytes[23],
        vault_bytes[24],
    ]);
    assert_eq!(count, 2, "secret count should be 2");

    // 5. Payload should exist after header
    assert!(
        vault_bytes.len() > 25,
        "vault should have encrypted payload after header"
    );
}

#[test]
fn test_export_import_roundtrip_correct_pin() {
    let secrets = sample_secrets();
    let pin = "123456";

    let vault_bytes = export_vault(secrets, pin, None).expect("export should succeed");
    let payload = import_vault(&vault_bytes, pin).expect("import with correct PIN should succeed");

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
    let pin = "123456";
    let wrong_pin = "654321";

    let vault_bytes = export_vault(secrets, pin, None).expect("export should succeed");
    let result = import_vault(&vault_bytes, wrong_pin);

    assert!(
        result.is_err(),
        "import with wrong PIN must fail (GCM authentication)"
    );
}

#[test]
fn test_blind_flag_preserved_on_roundtrip() {
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

    let vault_bytes = export_vault(secrets, pin, None).expect("export should succeed");
    let payload = import_vault(&vault_bytes, pin).expect("import should succeed");

    assert_eq!(payload.secrets.len(), 2);
    assert!(payload.secrets[0].blind, "BLIND_SECRET should have blind=true");
    assert_eq!(payload.secrets[0].value, "hidden-value");
    assert!(!payload.secrets[1].blind, "VISIBLE_SECRET should have blind=false");
    assert_eq!(payload.secrets[1].value, "visible-value");
}

#[test]
fn test_tampered_vault_fails_gcm_auth() {
    let secrets = sample_secrets();
    let pin = "tamper-test";

    let mut vault_bytes = export_vault(secrets, pin, None).expect("export should succeed");

    // Flip a byte in the encrypted payload (after the 25-byte header)
    let payload_idx = 30; // well into the encrypted payload
    if payload_idx < vault_bytes.len() {
        vault_bytes[payload_idx] ^= 0xFF;
    }

    let result = import_vault(&vault_bytes, pin);
    assert!(
        result.is_err(),
        "tampered vault file must fail GCM authentication"
    );
}

#[test]
fn test_empty_vault_roundtrip() {
    let secrets: Vec<VaultSecret> = vec![];
    let pin = "empty-vault";

    let vault_bytes = export_vault(secrets, pin, None).expect("export of empty vault should succeed");
    let payload =
        import_vault(&vault_bytes, pin).expect("import of empty vault should succeed");

    assert_eq!(payload.secrets.len(), 0);
    assert!(payload.expires_at.is_none());
}

#[test]
fn test_pin_too_short_rejected_on_export() {
    let secrets = sample_secrets();
    let short_pin = "12345"; // 5 chars, below minimum 6

    let result = export_vault(secrets, short_pin, None);
    assert!(result.is_err(), "PIN shorter than 6 chars must be rejected on export");
}

#[test]
fn test_pin_too_short_rejected_on_import() {
    let secrets = sample_secrets();
    let good_pin = "123456";
    let short_pin = "12345";

    let vault_bytes = export_vault(secrets, good_pin, None).expect("export should succeed");
    let result = import_vault(&vault_bytes, short_pin);
    assert!(result.is_err(), "PIN shorter than 6 chars must be rejected on import");
}

#[test]
fn test_truncated_vault_file_rejected() {
    // A vault file shorter than the minimum header size (25 bytes) should be rejected
    let too_short = vec![0x54, 0x4D, 0x56, 0x54]; // Just magic bytes
    let result = import_vault(&too_short, "somepin123");
    assert!(result.is_err(), "truncated vault file must be rejected");
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
fn test_single_secret_roundtrip() {
    let secrets = vec![VaultSecret {
        name: "SINGLE".to_string(),
        value: "only-one".to_string(),
        blind: false,
    }];
    let pin = "single-test";

    let vault_bytes = export_vault(secrets, pin, None).expect("export should succeed");
    let payload = import_vault(&vault_bytes, pin).expect("import should succeed");

    assert_eq!(payload.secrets.len(), 1);
    assert_eq!(payload.secrets[0].name, "SINGLE");
    assert_eq!(payload.secrets[0].value, "only-one");
}

// ======================================================================
// Expiration-related integration tests
// ======================================================================

#[test]
fn test_vault_with_future_expiration_roundtrip() {
    let secrets = sample_secrets();
    let pin = "future-exp";
    let future = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();

    let vault_bytes = export_vault(secrets, pin, Some(future.clone()))
        .expect("export with future expiration should succeed");

    // Version should be 0x02
    assert_eq!(vault_bytes[4], 0x02, "version should be 0x02 for v2 vaults");

    let payload = import_vault(&vault_bytes, pin)
        .expect("import of non-expired vault should succeed");

    assert_eq!(payload.secrets.len(), 2);
    assert_eq!(payload.expires_at, Some(future));
}

#[test]
fn test_vault_with_past_expiration_rejected() {
    let secrets = sample_secrets();
    let pin = "past-exp";
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();

    let vault_bytes = export_vault(secrets, pin, Some(past))
        .expect("export should succeed even with past expiration");

    let result = import_vault(&vault_bytes, pin);
    assert!(result.is_err(), "expired vault must be rejected on import");

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("expired"),
        "error should mention expiration, got: {}",
        err_msg
    );
}

#[test]
fn test_vault_no_expiration_has_none() {
    let secrets = sample_secrets();
    let pin = "no-expiry";

    let vault_bytes = export_vault(secrets, pin, None)
        .expect("export should succeed");

    let payload = import_vault(&vault_bytes, pin)
        .expect("import should succeed");

    assert!(payload.expires_at.is_none(), "expires_at should be None for vaults without expiration");
}

#[test]
fn test_vault_v1_backward_compat_integration() {
    // Build a v1-format vault manually to test backward compatibility.
    use tampermonkey_secret_manager_lib::crypto::{encryption, kdf};

    let secrets = sample_secrets();
    let pin = "v1-compat";

    let salt = kdf::generate_salt();
    let derived_key = kdf::derive_key(pin.as_bytes(), &salt).unwrap();

    // Serialize as plain Vec<VaultSecret> (v1 format)
    let json_bytes = serde_json::to_vec(&secrets).unwrap();
    let encrypted = encryption::encrypt(&json_bytes, &derived_key).unwrap();
    let encrypted_bytes = encrypted.to_bytes();

    let secret_count = secrets.len() as u32;
    let mut output = Vec::with_capacity(25 + encrypted_bytes.len());
    output.extend_from_slice(b"TMVT");
    output.push(0x01); // v1 version byte
    output.extend_from_slice(&salt);
    output.extend_from_slice(&secret_count.to_le_bytes());
    output.extend_from_slice(&encrypted_bytes);

    // Import should succeed with backward compatibility
    let payload = import_vault(&output, pin)
        .expect("v1 vault import should succeed with backward compatibility");

    assert_eq!(payload.secrets.len(), 2);
    assert_eq!(payload.secrets[0].name, "API_KEY");
    assert_eq!(payload.secrets[1].name, "DB_PASSWORD");
    assert!(payload.expires_at.is_none(), "v1 vaults should have no expiration");
}
