use thiserror::Error;

/// Cryptographic operation errors used across the crypto module.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),
}

/// Database operation errors.
#[derive(Debug, Error)]
pub enum DbError {
    #[error("SQLite error: {0}")]
    SqliteError(#[from] rusqlite::Error),

    #[error("Migration failed: {0}")]
    MigrationFailed(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),
}

/// Local HTTP API errors.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Server error: {0}")]
    ServerError(String),

    #[error("Auth error: {0}")]
    AuthError(String),
}
