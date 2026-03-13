use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::CryptoError;

const NONCE_LENGTH: usize = 12;

/// Container for AES-256-GCM encrypted output (nonce + ciphertext with auth tag).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Concatenate nonce + ciphertext into a single byte vector for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.nonce.len() + self.ciphertext.len());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Split a byte slice back into `EncryptedData` (first 12 bytes = nonce, rest = ciphertext).
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() <= NONCE_LENGTH {
            return Err(CryptoError::InvalidData(format!(
                "Data too short: expected more than {NONCE_LENGTH} bytes, got {}",
                data.len()
            )));
        }

        Ok(Self {
            nonce: data[..NONCE_LENGTH].to_vec(),
            ciphertext: data[NONCE_LENGTH..].to_vec(),
        })
    }
}

/// Encrypt plaintext with AES-256-GCM using a random 12-byte nonce.
///
/// Returns an `EncryptedData` containing the nonce and ciphertext (with GCM auth tag appended).
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<EncryptedData, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionFailed(format!("Cipher init failed: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("AES-GCM encrypt failed: {e}")))?;

    Ok(EncryptedData {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt an `EncryptedData` payload with AES-256-GCM using the provided key.
///
/// Returns the original plaintext bytes on success.
pub fn decrypt(encrypted: &EncryptedData, key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::DecryptionFailed(format!("Cipher init failed: {e}")))?;

    let nonce = Nonce::from_slice(&encrypted.nonce);

    cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|e| CryptoError::DecryptionFailed(format!("AES-GCM decrypt failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: produce a deterministic 32-byte key for testing (NOT for production).
    fn test_key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key(0x42);
        let plaintext = b"the quick brown fox jumps over the lazy dog";

        let encrypted = encrypt(plaintext, &key).expect("encryption should succeed");
        let decrypted = decrypt(&encrypted, &key).expect("decryption should succeed");

        assert_eq!(
            decrypted, plaintext,
            "decrypted output must match original plaintext"
        );
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = test_key(0x42);
        let wrong_key = test_key(0xFF);
        let plaintext = b"secret data";

        let encrypted = encrypt(plaintext, &key).expect("encryption should succeed");
        let result = decrypt(&encrypted, &wrong_key);

        assert!(
            result.is_err(),
            "decryption with a wrong key must return an error"
        );
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let key = test_key(0x42);
        let plaintext = b"roundtrip through bytes";

        let encrypted = encrypt(plaintext, &key).expect("encryption should succeed");
        let bytes = encrypted.to_bytes();
        let restored =
            EncryptedData::from_bytes(&bytes).expect("from_bytes should succeed");

        assert_eq!(restored.nonce, encrypted.nonce);
        assert_eq!(restored.ciphertext, encrypted.ciphertext);

        // Also verify decryption still works after the roundtrip.
        let decrypted = decrypt(&restored, &key).expect("decryption after from_bytes should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonce_per_encryption() {
        let key = test_key(0x42);
        let plaintext = b"identical plaintext";

        let enc1 = encrypt(plaintext, &key).expect("first encryption should succeed");
        let enc2 = encrypt(plaintext, &key).expect("second encryption should succeed");

        assert_ne!(
            enc1.nonce, enc2.nonce,
            "each encryption must use a unique nonce"
        );
        assert_ne!(
            enc1.ciphertext, enc2.ciphertext,
            "ciphertexts should differ due to different nonces"
        );
    }
}
