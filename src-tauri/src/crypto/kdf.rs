use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::CryptoError;

/// Argon2id parameters per specification:
/// - 64 MB memory (65536 KiB)
/// - 3 iterations
/// - 1 parallelism lane
const ARGON2_MEMORY_KIB: u32 = 65536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;

/// Derive a 256-bit key from a password and salt using Argon2id.
///
/// Sensitive intermediate material is zeroized after use.
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_LENGTH),
    )
    .map_err(|e| CryptoError::KeyDerivationFailed(format!("Invalid Argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LENGTH];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| {
            key.zeroize();
            CryptoError::KeyDerivationFailed(format!("Argon2id hashing failed: {e}"))
        })?;

    Ok(key)
}

/// Generate a cryptographically secure random 16-byte salt using `OsRng`.
pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"test-password-123";
        let salt = [0xAA; 16];

        let key1 = derive_key(password, &salt).expect("first derivation should succeed");
        let key2 = derive_key(password, &salt).expect("second derivation should succeed");

        assert_eq!(key1, key2, "same password + salt must produce the same key");
    }

    #[test]
    fn test_derive_key_different_salt() {
        let password = b"test-password-123";
        let salt1 = [0xAA; 16];
        let salt2 = [0xBB; 16];

        let key1 = derive_key(password, &salt1).expect("derivation with salt1 should succeed");
        let key2 = derive_key(password, &salt2).expect("derivation with salt2 should succeed");

        assert_ne!(
            key1, key2,
            "same password with different salts must produce different keys"
        );
    }

    #[test]
    fn test_salt_generation_unique() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        assert_ne!(
            salt1, salt2,
            "two independently generated salts should differ"
        );
    }
}
