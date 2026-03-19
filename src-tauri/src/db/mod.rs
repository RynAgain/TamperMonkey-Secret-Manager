pub mod migrations;
pub mod models;

use crate::error::DbError;
use models::*;
use rusqlite::{params, Connection};
use std::path::Path;

/// Wrapper around a [`rusqlite::Connection`] that provides typed CRUD
/// operations for the TamperMonkey Secret Manager schema.
///
/// # Opening
///
/// ```no_run
/// # use std::path::Path;
/// # use tampermonkey_secret_manager_lib::db::Database;
/// let db = Database::open(Path::new("path/to/secrets.db")).unwrap();
/// ```
///
/// The recommended storage path is `{app_data_dir}/tampermonkey-secrets/secrets.db`
/// but the caller decides what to pass.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open (or create) the SQLite database at `path`, enable WAL journal
    /// mode, and run any pending schema migrations.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Open an in-memory database -- useful for testing.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, DbError> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, DbError> {
        // Enable WAL journal mode for better concurrent access.
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        // Enable foreign key enforcement.
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;

        migrations::run_migrations(&conn)?;

        Ok(Self { conn })
    }

    // ------------------------------------------------------------------
    // Master Config
    // ------------------------------------------------------------------

    /// Persist a master config row. Typically only one row ever exists.
    pub fn save_master_config(&self, config: &MasterConfig) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT INTO master_config (password_hash, salt, created_at) VALUES (?1, ?2, ?3)",
            params![config.password_hash, config.salt, config.created_at],
        )?;
        Ok(())
    }

    /// Retrieve the (single) master config, if it exists.
    pub fn get_master_config(&self) -> Result<Option<MasterConfig>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, password_hash, salt, created_at FROM master_config ORDER BY id LIMIT 1",
        )?;

        let mut rows = stmt.query_map([], |row| {
            Ok(MasterConfig {
                id: row.get(0)?,
                password_hash: row.get(1)?,
                salt: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Update the master config (salt + verification token). Used during password change.
    pub fn update_master_config(&self, config: &MasterConfig) -> Result<(), DbError> {
        let changed = self.conn.execute(
            "UPDATE master_config SET password_hash = ?1, salt = ?2 WHERE id = ?3",
            params![config.password_hash, config.salt, config.id],
        )?;

        if changed == 0 {
            return Err(DbError::NotFound("Master config not found".to_string()));
        }
        Ok(())
    }

    /// Check whether a master config has been saved (i.e. the vault is initialised).
    pub fn has_master_config(&self) -> Result<bool, DbError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM master_config",
            [],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    // ------------------------------------------------------------------
    // Secrets
    // ------------------------------------------------------------------

    /// Create a new secret entry. Returns the inserted row.
    pub fn create_secret(
        &self,
        name: &str,
        encrypted_value: &[u8],
        secret_type: SecretType,
        blind: bool,
    ) -> Result<SecretEntry, DbError> {
        self.create_secret_with_expiry(name, encrypted_value, secret_type, blind, None)
    }

    /// Create a new secret entry with an optional expiration timestamp.
    /// Returns the inserted row.
    pub fn create_secret_with_expiry(
        &self,
        name: &str,
        encrypted_value: &[u8],
        secret_type: SecretType,
        blind: bool,
        expires_at: Option<&str>,
    ) -> Result<SecretEntry, DbError> {
        let now = chrono::Utc::now().to_rfc3339();

        let result = self.conn.execute(
            "INSERT INTO secrets (name, encrypted_value, secret_type, blind, created_at, updated_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                name,
                encrypted_value,
                secret_type.to_string(),
                blind as i32,
                now,
                now,
                expires_at,
            ],
        );

        match result {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(DbError::AlreadyExists(format!(
                    "Secret with name '{}' already exists",
                    name
                )));
            }
            Err(e) => return Err(DbError::SqliteError(e)),
        }

        let id = self.conn.last_insert_rowid();
        Ok(SecretEntry {
            id,
            name: name.to_string(),
            encrypted_value: encrypted_value.to_vec(),
            secret_type,
            blind,
            created_at: now.clone(),
            updated_at: now,
            expires_at: expires_at.map(|s| s.to_string()),
        })
    }

    /// Retrieve a secret by its unique name.
    pub fn get_secret_by_name(&self, name: &str) -> Result<Option<SecretEntry>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, encrypted_value, secret_type, blind, created_at, updated_at, expires_at
             FROM secrets WHERE name = ?1",
        )?;

        let mut rows = stmt.query_map(params![name], |row| {
            let type_str: String = row.get(3)?;
            let blind_int: i32 = row.get(4)?;
            Ok(SecretEntry {
                id: row.get(0)?,
                name: row.get(1)?,
                encrypted_value: row.get(2)?,
                secret_type: type_str.parse::<SecretType>().unwrap_or(SecretType::KeyValue),
                blind: blind_int != 0,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                expires_at: row.get(7)?,
            })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// List all stored secrets.
    pub fn list_secrets(&self) -> Result<Vec<SecretEntry>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, encrypted_value, secret_type, blind, created_at, updated_at, expires_at
             FROM secrets ORDER BY name",
        )?;

        let rows = stmt.query_map([], |row| {
            let type_str: String = row.get(3)?;
            let blind_int: i32 = row.get(4)?;
            Ok(SecretEntry {
                id: row.get(0)?,
                name: row.get(1)?,
                encrypted_value: row.get(2)?,
                secret_type: type_str.parse::<SecretType>().unwrap_or(SecretType::KeyValue),
                blind: blind_int != 0,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                expires_at: row.get(7)?,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Update the encrypted value of an existing secret (sets `updated_at` to now).
    pub fn update_secret(&self, name: &str, encrypted_value: &[u8]) -> Result<(), DbError> {
        let now = chrono::Utc::now().to_rfc3339();
        let changed = self.conn.execute(
            "UPDATE secrets SET encrypted_value = ?1, updated_at = ?2 WHERE name = ?3",
            params![encrypted_value, now, name],
        )?;

        if changed == 0 {
            return Err(DbError::NotFound(format!("Secret '{}' not found", name)));
        }
        Ok(())
    }

    /// Delete a secret by name.
    ///
    /// Also removes any `script_secret_access` rows that reference the secret
    /// so that the foreign-key constraint is satisfied.
    pub fn delete_secret(&self, name: &str) -> Result<(), DbError> {
        // Look up the secret id first so we can clean up FK references.
        let secret = self.get_secret_by_name(name)?;
        let secret = match secret {
            Some(s) => s,
            None => return Err(DbError::NotFound(format!("Secret '{}' not found", name))),
        };

        // Remove script-secret access records that reference this secret.
        self.conn.execute(
            "DELETE FROM script_secret_access WHERE secret_id = ?1",
            params![secret.id],
        )?;

        let changed = self.conn.execute(
            "DELETE FROM secrets WHERE id = ?1",
            params![secret.id],
        )?;

        if changed == 0 {
            return Err(DbError::NotFound(format!("Secret '{}' not found", name)));
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Audit Log
    // ------------------------------------------------------------------

    /// Record a security-relevant event in the audit log.
    pub fn log_event(
        &self,
        event_type: &str,
        script_id: Option<&str>,
        secret_name: Option<&str>,
    ) -> Result<(), DbError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO audit_log (event_type, script_id, secret_name, timestamp)
             VALUES (?1, ?2, ?3, ?4)",
            params![event_type, script_id, secret_name, now],
        )?;
        Ok(())
    }

    /// Retrieve the most recent audit events, newest first.
    pub fn get_recent_events(&self, limit: u32) -> Result<Vec<AuditLogEntry>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, event_type, script_id, secret_name, timestamp
             FROM audit_log ORDER BY id DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            Ok(AuditLogEntry {
                id: row.get(0)?,
                event_type: row.get(1)?,
                script_id: row.get(2)?,
                secret_name: row.get(3)?,
                timestamp: row.get(4)?,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    // ------------------------------------------------------------------
    // Script Registrations
    // ------------------------------------------------------------------

    /// Register a new TamperMonkey script. Returns the inserted row.
    pub fn register_script(
        &self,
        script_id: &str,
        script_name: &str,
        domain: &str,
    ) -> Result<ScriptRegistration, DbError> {
        let now = chrono::Utc::now().to_rfc3339();

        let result = self.conn.execute(
            "INSERT INTO script_registrations (script_id, script_name, domain, approved, created_at)
             VALUES (?1, ?2, ?3, 0, ?4)",
            params![script_id, script_name, domain, now],
        );

        match result {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(DbError::AlreadyExists(format!(
                    "Script '{}' is already registered",
                    script_id
                )));
            }
            Err(e) => return Err(DbError::SqliteError(e)),
        }

        let id = self.conn.last_insert_rowid();
        Ok(ScriptRegistration {
            id,
            script_id: script_id.to_string(),
            script_name: script_name.to_string(),
            domain: domain.to_string(),
            approved: false,
            created_at: now,
        })
    }

    /// Look up a script registration by its script identifier.
    pub fn get_script(&self, script_id: &str) -> Result<Option<ScriptRegistration>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, script_id, script_name, domain, approved, created_at
             FROM script_registrations WHERE script_id = ?1",
        )?;

        let mut rows = stmt.query_map(params![script_id], |row| {
            let approved_int: i32 = row.get(4)?;
            Ok(ScriptRegistration {
                id: row.get(0)?,
                script_id: row.get(1)?,
                script_name: row.get(2)?,
                domain: row.get(3)?,
                approved: approved_int != 0,
                created_at: row.get(5)?,
            })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Mark a script registration as approved.
    pub fn approve_script(&self, script_id: &str) -> Result<(), DbError> {
        let changed = self.conn.execute(
            "UPDATE script_registrations SET approved = 1 WHERE script_id = ?1",
            params![script_id],
        )?;

        if changed == 0 {
            return Err(DbError::NotFound(format!(
                "Script '{}' not found",
                script_id
            )));
        }
        Ok(())
    }

    /// Revoke approval for a script registration (set approved = false).
    pub fn revoke_script(&self, script_id: &str) -> Result<(), DbError> {
        let changed = self.conn.execute(
            "UPDATE script_registrations SET approved = 0 WHERE script_id = ?1",
            params![script_id],
        )?;

        if changed == 0 {
            return Err(DbError::NotFound(format!(
                "Script '{}' not found",
                script_id
            )));
        }
        Ok(())
    }

    /// Delete a script registration and all its access records.
    pub fn delete_script(&self, script_id: &str) -> Result<(), DbError> {
        // Delete access records first (FK constraint)
        let script = self.get_script(script_id)?;
        if let Some(s) = script {
            self.conn.execute(
                "DELETE FROM script_secret_access WHERE script_reg_id = ?1",
                params![s.id],
            )?;
        }
        let changed = self.conn.execute(
            "DELETE FROM script_registrations WHERE script_id = ?1",
            params![script_id],
        )?;

        if changed == 0 {
            return Err(DbError::NotFound(format!(
                "Script '{}' not found",
                script_id
            )));
        }
        Ok(())
    }

    /// List all registered scripts.
    pub fn list_scripts(&self) -> Result<Vec<ScriptRegistration>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, script_id, script_name, domain, approved, created_at
             FROM script_registrations ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            let approved_int: i32 = row.get(4)?;
            Ok(ScriptRegistration {
                id: row.get(0)?,
                script_id: row.get(1)?,
                script_name: row.get(2)?,
                domain: row.get(3)?,
                approved: approved_int != 0,
                created_at: row.get(5)?,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// List all secret access records for a given script registration.
    /// Joins with secrets table to return secret names.
    pub fn list_script_access(&self, script_reg_id: i64) -> Result<Vec<ScriptAccessDetail>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT s.name, ssa.approved, ssa.created_at
             FROM script_secret_access ssa
             JOIN secrets s ON s.id = ssa.secret_id
             WHERE ssa.script_reg_id = ?1
             ORDER BY s.name",
        )?;

        let rows = stmt.query_map(params![script_reg_id], |row| {
            let approved_int: i32 = row.get(1)?;
            Ok(ScriptAccessDetail {
                secret_name: row.get(0)?,
                approved: approved_int != 0,
                created_at: row.get(2)?,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Create or update a script-secret access record.
    /// Uses INSERT OR REPLACE on the unique(script_reg_id, secret_id) constraint.
    pub fn set_script_secret_access(
        &self,
        script_reg_id: i64,
        secret_id: i64,
        approved: bool,
    ) -> Result<(), DbError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO script_secret_access (script_reg_id, secret_id, approved, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(script_reg_id, secret_id) DO UPDATE SET approved = ?3",
            params![script_reg_id, secret_id, approved as i32, now],
        )?;
        Ok(())
    }

    /// Check if a script has approved access to a specific secret.
    /// Returns None if no access record exists, Some(bool) for the approval status.
    pub fn check_script_secret_access(
        &self,
        script_reg_id: i64,
        secret_id: i64,
    ) -> Result<Option<bool>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT approved FROM script_secret_access
             WHERE script_reg_id = ?1 AND secret_id = ?2",
        )?;

        let mut rows = stmt.query_map(params![script_reg_id, secret_id], |row| {
            let approved_int: i32 = row.get(0)?;
            Ok(approved_int != 0)
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Create an unapproved access request for a script+secret pair.
    /// Does nothing if the record already exists.
    pub fn create_access_request(
        &self,
        script_reg_id: i64,
        secret_id: i64,
    ) -> Result<(), DbError> {
        let now = chrono::Utc::now().to_rfc3339();
        // Use INSERT OR IGNORE to avoid duplicates
        self.conn.execute(
            "INSERT OR IGNORE INTO script_secret_access (script_reg_id, secret_id, approved, created_at)
             VALUES (?1, ?2, 0, ?3)",
            params![script_reg_id, secret_id, now],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Config key-value store
    // ------------------------------------------------------------------

    /// Get a config value by key.
    pub fn get_config(&self, key: &str) -> Result<Option<String>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT value FROM config WHERE key = ?1",
        )?;

        let mut rows = stmt.query_map(params![key], |row| row.get(0))?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Set a config value (insert or update).
    pub fn set_config(&self, key: &str, value: &str) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT INTO config (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![key, value],
        )?;
        Ok(())
    }

    /// Get a reference to the underlying connection (for transactions).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    // ------------------------------------------------------------------
    // Env Var Config
    // ------------------------------------------------------------------

    /// Add an environment variable name to the allowlist.
    pub fn add_env_var(&self, var_name: &str) -> Result<EnvVarConfig, DbError> {
        let now = chrono::Utc::now().to_rfc3339();

        let result = self.conn.execute(
            "INSERT INTO env_var_config (var_name, created_at) VALUES (?1, ?2)",
            params![var_name, now],
        );

        match result {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(DbError::AlreadyExists(format!(
                    "Env var '{}' already in allowlist",
                    var_name
                )));
            }
            Err(e) => return Err(DbError::SqliteError(e)),
        }

        let id = self.conn.last_insert_rowid();
        Ok(EnvVarConfig {
            id,
            var_name: var_name.to_string(),
            created_at: now,
        })
    }

    /// List all environment variable names on the allowlist.
    pub fn list_env_vars(&self) -> Result<Vec<EnvVarConfig>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, var_name, created_at FROM env_var_config ORDER BY var_name",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(EnvVarConfig {
                id: row.get(0)?,
                var_name: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Remove an environment variable from the allowlist.
    pub fn remove_env_var(&self, var_name: &str) -> Result<(), DbError> {
        let changed = self.conn.execute(
            "DELETE FROM env_var_config WHERE var_name = ?1",
            params![var_name],
        )?;

        if changed == 0 {
            return Err(DbError::NotFound(format!(
                "Env var '{}' not found in allowlist",
                var_name
            )));
        }
        Ok(())
    }
}

// ======================================================================
// Tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a fresh in-memory Database.
    fn test_db() -> Database {
        Database::open_in_memory().expect("Failed to open in-memory database")
    }

    #[test]
    fn test_open_creates_database() {
        let dir = std::env::temp_dir().join(format!(
            "tmpsm_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test_secrets.db");

        // Ensure the file doesn't exist yet.
        if db_path.exists() {
            std::fs::remove_file(&db_path).unwrap();
        }

        let _db = Database::open(&db_path).unwrap();
        assert!(db_path.exists(), "Database file should have been created");

        // Cleanup.
        std::fs::remove_file(&db_path).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_migrations_run_on_open() {
        let db = test_db();

        // Verify that the core tables exist by querying sqlite_master.
        let tables: Vec<String> = {
            let mut stmt = db
                .conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                .unwrap();
            let rows = stmt.query_map([], |row| row.get(0)).unwrap();
            rows.filter_map(|r| r.ok()).collect()
        };

        let expected = [
            "audit_log",
            "config",
            "env_var_config",
            "master_config",
            "schema_version",
            "script_registrations",
            "script_secret_access",
            "secrets",
        ];

        for table in &expected {
            assert!(
                tables.contains(&table.to_string()),
                "Expected table '{}' to exist, found: {:?}",
                table,
                tables
            );
        }
    }

    #[test]
    fn test_master_config_save_and_get() {
        let db = test_db();

        assert!(!db.has_master_config().unwrap());
        assert!(db.get_master_config().unwrap().is_none());

        let config = MasterConfig {
            id: 0, // Ignored on insert.
            password_hash: vec![1, 2, 3, 4],
            salt: vec![5, 6, 7, 8],
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        db.save_master_config(&config).unwrap();
        assert!(db.has_master_config().unwrap());

        let loaded = db.get_master_config().unwrap().expect("Should exist");
        assert_eq!(loaded.password_hash, vec![1, 2, 3, 4]);
        assert_eq!(loaded.salt, vec![5, 6, 7, 8]);
    }

    #[test]
    fn test_secret_crud() {
        let db = test_db();

        // Create
        let secret = db
            .create_secret("MY_API_KEY", b"encrypted_data", SecretType::KeyValue, false)
            .unwrap();
        assert_eq!(secret.name, "MY_API_KEY");
        assert!(!secret.blind);

        // Get by name
        let fetched = db
            .get_secret_by_name("MY_API_KEY")
            .unwrap()
            .expect("Should exist");
        assert_eq!(fetched.encrypted_value, b"encrypted_data");
        assert_eq!(fetched.secret_type, SecretType::KeyValue);

        // List
        let all = db.list_secrets().unwrap();
        assert_eq!(all.len(), 1);

        // Update
        db.update_secret("MY_API_KEY", b"new_encrypted_data")
            .unwrap();
        let updated = db
            .get_secret_by_name("MY_API_KEY")
            .unwrap()
            .expect("Should still exist");
        assert_eq!(updated.encrypted_value, b"new_encrypted_data");
        assert!(updated.updated_at >= updated.created_at);

        // Delete
        db.delete_secret("MY_API_KEY").unwrap();
        assert!(db.get_secret_by_name("MY_API_KEY").unwrap().is_none());

        // Delete non-existent should error
        let err = db.delete_secret("MY_API_KEY").unwrap_err();
        assert!(matches!(err, DbError::NotFound(_)));
    }

    #[test]
    fn test_secret_name_unique() {
        let db = test_db();

        db.create_secret("DUPLICATE", b"data1", SecretType::KeyValue, false)
            .unwrap();
        let err = db
            .create_secret("DUPLICATE", b"data2", SecretType::EnvironmentVariable, true)
            .unwrap_err();
        assert!(matches!(err, DbError::AlreadyExists(_)));
    }

    #[test]
    fn test_audit_log() {
        let db = test_db();

        db.log_event("secret_created", None, Some("MY_SECRET"))
            .unwrap();
        db.log_event(
            "secret_accessed",
            Some("script-abc"),
            Some("MY_SECRET"),
        )
        .unwrap();
        db.log_event("script_approved", Some("script-abc"), None)
            .unwrap();

        let events = db.get_recent_events(10).unwrap();
        assert_eq!(events.len(), 3);

        // Most recent first.
        assert_eq!(events[0].event_type, "script_approved");
        assert_eq!(events[1].event_type, "secret_accessed");
        assert_eq!(events[2].event_type, "secret_created");

        // Limit works.
        let limited = db.get_recent_events(1).unwrap();
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].event_type, "script_approved");
    }

    #[test]
    fn test_env_var_config_crud() {
        let db = test_db();

        // Add
        let var1 = db.add_env_var("HOME").unwrap();
        assert_eq!(var1.var_name, "HOME");
        let _var2 = db.add_env_var("PATH").unwrap();

        // List
        let vars = db.list_env_vars().unwrap();
        assert_eq!(vars.len(), 2);
        // Ordered by name
        assert_eq!(vars[0].var_name, "HOME");
        assert_eq!(vars[1].var_name, "PATH");

        // Duplicate
        let err = db.add_env_var("HOME").unwrap_err();
        assert!(matches!(err, DbError::AlreadyExists(_)));

        // Remove
        db.remove_env_var("HOME").unwrap();
        let vars = db.list_env_vars().unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].var_name, "PATH");

        // Remove non-existent
        let err = db.remove_env_var("NONEXISTENT").unwrap_err();
        assert!(matches!(err, DbError::NotFound(_)));
    }

    #[test]
    fn test_script_registration() {
        let db = test_db();

        // Register
        let script = db
            .register_script("tm-script-123", "My Script", "example.com")
            .unwrap();
        assert_eq!(script.script_id, "tm-script-123");
        assert!(!script.approved);

        // Get
        let fetched = db
            .get_script("tm-script-123")
            .unwrap()
            .expect("Should exist");
        assert_eq!(fetched.script_name, "My Script");
        assert_eq!(fetched.domain, "example.com");

        // Approve
        db.approve_script("tm-script-123").unwrap();
        let approved = db
            .get_script("tm-script-123")
            .unwrap()
            .expect("Should exist");
        assert!(approved.approved);

        // Duplicate registration
        let err = db
            .register_script("tm-script-123", "Dup", "other.com")
            .unwrap_err();
        assert!(matches!(err, DbError::AlreadyExists(_)));

        // Not found
        assert!(db.get_script("nonexistent").unwrap().is_none());
        let err = db.approve_script("nonexistent").unwrap_err();
        assert!(matches!(err, DbError::NotFound(_)));
    }
}
