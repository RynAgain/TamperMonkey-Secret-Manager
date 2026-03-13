//! Integration tests for the cryptographic pipeline.
//!
//! Tests the full flow: salt generation -> key derivation -> encryption ->
//! decryption -> roundtrip verification.

use tampermonkey_secret_manager_lib::crypto::{encryption, kdf};
use zeroize::Zeroize;

#[test]
fn test_full_crypto_pipeline_roundtrip() {
    // 1. Generate a random salt
    let salt = kdf::generate_salt();
    assert_eq!(salt.len(), 16);

    // 2. Derive a key from a password
    let password = b"integration-test-password!";
    let key = kdf::derive_key(password, &salt).expect("key derivation should succeed");
    assert_eq!(key.len(), 32);

    // 3. Encrypt some plaintext
    let plaintext = b"This is a secret value for the integration test";
    let encrypted = encryption::encrypt(plaintext, &key).expect("encryption should succeed");

    // Verify the encrypted data has a 12-byte nonce
    assert_eq!(encrypted.nonce.len(), 12);
    // Ciphertext should be longer than plaintext (includes GCM auth tag)
    assert!(encrypted.ciphertext.len() > plaintext.len());

    // 4. Decrypt and verify roundtrip
    let decrypted = encryption::decrypt(&encrypted, &key).expect("decryption should succeed");
    assert_eq!(decrypted, plaintext, "decrypted output must match original");
}

#[test]
fn test_different_passwords_produce_different_ciphertexts() {
    let salt = kdf::generate_salt();
    let plaintext = b"same plaintext for both";

    let key1 = kdf::derive_key(b"password-alpha", &salt).unwrap();
    let key2 = kdf::derive_key(b"password-beta", &salt).unwrap();

    // Keys should differ
    assert_ne!(key1, key2, "different passwords must produce different keys");

    let enc1 = encryption::encrypt(plaintext, &key1).unwrap();
    let enc2 = encryption::encrypt(plaintext, &key2).unwrap();

    // Ciphertexts should differ (different keys + different random nonces)
    assert_ne!(
        enc1.ciphertext, enc2.ciphertext,
        "ciphertexts should differ with different keys"
    );

    // Each can only be decrypted with its own key
    assert!(encryption::decrypt(&enc1, &key2).is_err());
    assert!(encryption::decrypt(&enc2, &key1).is_err());
}

#[test]
fn test_corrupted_ciphertext_fails_gcm_authentication() {
    let salt = kdf::generate_salt();
    let key = kdf::derive_key(b"corruption-test", &salt).unwrap();
    let plaintext = b"data that will be corrupted";

    let mut encrypted = encryption::encrypt(plaintext, &key).unwrap();

    // Corrupt one byte of the ciphertext
    if let Some(byte) = encrypted.ciphertext.get_mut(0) {
        *byte ^= 0xFF;
    }

    let result = encryption::decrypt(&encrypted, &key);
    assert!(
        result.is_err(),
        "corrupted ciphertext must fail GCM authentication"
    );
}

#[test]
fn test_key_derivation_regression() {
    // Fixed inputs should always produce the same key (regression test).
    let password = b"regression-test-password";
    let salt = [0xAA_u8; 16];

    let key1 = kdf::derive_key(password, &salt).unwrap();
    let key2 = kdf::derive_key(password, &salt).unwrap();

    assert_eq!(
        key1, key2,
        "same password + salt must produce identical keys"
    );

    // Different salt must produce a different key
    let salt2 = [0xBB_u8; 16];
    let key3 = kdf::derive_key(password, &salt2).unwrap();
    assert_ne!(key1, key3, "different salt must produce a different key");
}

#[test]
fn test_encrypted_data_serialization_roundtrip() {
    let salt = kdf::generate_salt();
    let key = kdf::derive_key(b"serialization-test", &salt).unwrap();
    let plaintext = b"test serialization roundtrip";

    let encrypted = encryption::encrypt(plaintext, &key).unwrap();

    // Serialize to bytes and back
    let bytes = encrypted.to_bytes();
    let restored = encryption::EncryptedData::from_bytes(&bytes)
        .expect("from_bytes should succeed");

    assert_eq!(restored.nonce, encrypted.nonce);
    assert_eq!(restored.ciphertext, encrypted.ciphertext);

    // Decryption should still work
    let decrypted = encryption::decrypt(&restored, &key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_zeroize_derived_key() {
    let salt = kdf::generate_salt();
    let mut key = kdf::derive_key(b"zeroize-test", &salt).unwrap();

    // Verify key is non-zero
    assert!(key.iter().any(|&b| b != 0), "key should not be all zeros");

    // Zeroize and verify
    key.zeroize();
    assert!(
        key.iter().all(|&b| b == 0),
        "key should be all zeros after zeroize"
    );
}

#[test]
fn test_empty_plaintext_roundtrip() {
    let salt = kdf::generate_salt();
    let key = kdf::derive_key(b"empty-test", &salt).unwrap();
    let plaintext = b"";

    let encrypted = encryption::encrypt(plaintext, &key).unwrap();
    let decrypted = encryption::decrypt(&encrypted, &key).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_large_plaintext_roundtrip() {
    let salt = kdf::generate_salt();
    let key = kdf::derive_key(b"large-test", &salt).unwrap();

    // 1 MB of data
    let plaintext = vec![0x42_u8; 1024 * 1024];

    let encrypted = encryption::encrypt(&plaintext, &key).unwrap();
    let decrypted = encryption::decrypt(&encrypted, &key).unwrap();

    assert_eq!(decrypted, plaintext);
}
