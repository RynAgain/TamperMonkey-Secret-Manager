use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Master password configuration stored in the database.
/// Contains the encrypted verification token and the Argon2id salt
/// used for master key derivation. Only one row should ever exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterConfig {
    pub id: i64,
    /// Encrypted verification token (NOT the password itself).
    pub password_hash: Vec<u8>,
    /// Argon2id salt used for master key derivation.
    pub salt: Vec<u8>,
    /// ISO 8601 timestamp of creation.
    pub created_at: String,
}

/// A stored secret entry with its encrypted value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub id: i64,
    /// Unique human-readable name (e.g., "GITHUB_API_KEY").
    pub name: String,
    /// AES-256-GCM encrypted value (nonce + ciphertext via `EncryptedData::to_bytes()`).
    pub encrypted_value: Vec<u8>,
    /// Classification of the secret.
    pub secret_type: SecretType,
    /// If true, value cannot be sent to the frontend.
    pub blind: bool,
    /// ISO 8601 timestamp of creation.
    pub created_at: String,
    /// ISO 8601 timestamp of last update.
    pub updated_at: String,
    /// Optional ISO 8601 UTC expiration timestamp. If set and in the past,
    /// the secret is considered expired and should not be served.
    pub expires_at: Option<String>,
}

/// Classification of a secret entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretType {
    KeyValue,
    EnvironmentVariable,
    VaultImport,
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretType::KeyValue => write!(f, "KeyValue"),
            SecretType::EnvironmentVariable => write!(f, "EnvironmentVariable"),
            SecretType::VaultImport => write!(f, "VaultImport"),
        }
    }
}

impl FromStr for SecretType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "KeyValue" => Ok(SecretType::KeyValue),
            "EnvironmentVariable" => Ok(SecretType::EnvironmentVariable),
            "VaultImport" => Ok(SecretType::VaultImport),
            other => Err(format!("Unknown SecretType: {}", other)),
        }
    }
}

/// A registered TamperMonkey script that may request secret access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptRegistration {
    pub id: i64,
    /// TamperMonkey script identifier.
    pub script_id: String,
    /// Human-readable name of the script.
    pub script_name: String,
    /// Domain the script runs on.
    pub domain: String,
    /// Whether the script has been approved by the user.
    pub approved: bool,
    /// ISO 8601 timestamp of creation.
    pub created_at: String,
}

/// Maps which scripts have access to which secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptSecretAccess {
    pub id: i64,
    /// FK to `ScriptRegistration`.
    pub script_id: i64,
    /// FK to `SecretEntry`.
    pub secret_id: i64,
    /// Whether the access has been approved by the user.
    pub approved: bool,
    /// ISO 8601 timestamp of creation.
    pub created_at: String,
}

/// Joined detail for a script's access to a specific secret.
/// Returned by `Database::list_script_access()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptAccessDetail {
    /// Name of the secret.
    pub secret_name: String,
    /// Whether the access has been approved by the user.
    pub approved: bool,
    /// ISO 8601 timestamp of creation.
    pub created_at: String,
}

/// An entry in the audit log tracking security-relevant events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: i64,
    /// Event type, e.g. "secret_accessed", "secret_created", "script_approved".
    pub event_type: String,
    /// Which script triggered the event (if applicable).
    pub script_id: Option<String>,
    /// Which secret was involved (if applicable).
    pub secret_name: Option<String>,
    /// ISO 8601 timestamp.
    pub timestamp: String,
}

/// An environment variable name on the user-managed allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVarConfig {
    pub id: i64,
    /// Environment variable name.
    pub var_name: String,
    /// ISO 8601 timestamp of creation.
    pub created_at: String,
}

/// A blind code module -- encrypted script that executes server-side.
/// Code is never sent to the frontend; only metadata is visible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindCodeModule {
    pub id: i64,
    /// Unique human-readable name (e.g., "github-api-caller").
    pub name: String,
    /// Description of what the module does.
    pub description: String,
    /// AES-256-GCM encrypted source code.
    pub encrypted_code: Vec<u8>,
    /// The scripting language: "rhai", "python", "javascript", or "typescript".
    pub language: String,
    /// JSON array of secret names this module needs (e.g., `["GITHUB_TOKEN"]`).
    pub required_secrets: String,
    /// JSON array of parameter names accepted from TM scripts (e.g., `["url", "method"]`).
    pub allowed_params: String,
    /// Whether the module has been approved for execution.
    pub approved: bool,
    /// If true, code cannot be sent to the frontend (always true for imported modules).
    pub blind: bool,
    /// ISO 8601 timestamp of creation.
    pub created_at: String,
    /// ISO 8601 timestamp of last update.
    pub updated_at: String,
    /// Optional ISO 8601 UTC expiration timestamp.
    pub expires_at: Option<String>,
}

/// Maps which scripts have access to which blind code modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptCodeAccess {
    pub id: i64,
    /// FK to `ScriptRegistration`.
    pub script_reg_id: i64,
    /// FK to `BlindCodeModule`.
    pub code_module_id: i64,
    /// Whether the access has been approved by the user.
    pub approved: bool,
    /// ISO 8601 timestamp of creation.
    pub created_at: String,
}

/// Joined detail for a script's access to a specific code module.
/// Returned by `Database::list_script_code_access()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptCodeAccessDetail {
    /// Name of the code module.
    pub module_name: String,
    /// Whether the access has been approved by the user.
    pub approved: bool,
    /// ISO 8601 timestamp of creation.
    pub created_at: String,
}
