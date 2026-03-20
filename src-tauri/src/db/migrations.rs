use crate::error::DbError;
use rusqlite::Connection;

/// Current schema version. Increment when adding new migrations.
#[allow(dead_code)]
const CURRENT_VERSION: i64 = 5;

/// Run all pending migrations on the given database connection.
///
/// Creates a `schema_version` table to track migration state and applies
/// each migration in sequence up to [`CURRENT_VERSION`].
pub fn run_migrations(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        );",
    )
    .map_err(|e| DbError::MigrationFailed(format!("Failed to create schema_version table: {e}")))?;

    let current: Option<i64> = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .map_err(|e| DbError::MigrationFailed(format!("Failed to read schema version: {e}")))?;

    let version = current.unwrap_or(0);

    if version < 1 {
        migrate_v1(conn)?;
    }

    if version < 2 {
        migrate_v2(conn)?;
    }

    if version < 3 {
        migrate_v3(conn)?;
    }

    if version < 4 {
        migrate_v4(conn)?;
    }

    if version < 5 {
        migrate_v5(conn)?;
    }

    // Future migrations go here:
    // if version < 6 { migrate_v6(conn)?; }

    Ok(())
}

/// Migration v1: Create all initial tables.
fn migrate_v1(conn: &Connection) -> Result<(), DbError> {
    let sql = "
        CREATE TABLE IF NOT EXISTS master_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            encrypted_value BLOB NOT NULL,
            secret_type TEXT NOT NULL DEFAULT 'KeyValue',
            blind INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS script_registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            script_id TEXT NOT NULL UNIQUE,
            script_name TEXT NOT NULL,
            domain TEXT NOT NULL,
            approved INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS script_secret_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            script_reg_id INTEGER NOT NULL,
            secret_id INTEGER NOT NULL,
            approved INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (script_reg_id) REFERENCES script_registrations(id),
            FOREIGN KEY (secret_id) REFERENCES secrets(id),
            UNIQUE(script_reg_id, secret_id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            script_id TEXT,
            secret_name TEXT,
            timestamp TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS env_var_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            var_name TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );

        INSERT INTO schema_version (version) VALUES (1);
    ";

    conn.execute_batch(sql)
        .map_err(|e| DbError::MigrationFailed(format!("Migration v1 failed: {e}")))?;

    Ok(())
}

/// Migration v2: Add config key-value table for application settings.
fn migrate_v2(conn: &Connection) -> Result<(), DbError> {
    let sql = "
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        INSERT OR IGNORE INTO config (key, value) VALUES ('auto_lock_minutes', '15');

        INSERT INTO schema_version (version) VALUES (2);
    ";

    conn.execute_batch(sql)
        .map_err(|e| DbError::MigrationFailed(format!("Migration v2 failed: {e}")))?;

    Ok(())
}

/// Migration v3: Add expires_at column to secrets table for time-limited vault secrets.
fn migrate_v3(conn: &Connection) -> Result<(), DbError> {
    let sql = "
        ALTER TABLE secrets ADD COLUMN expires_at TEXT;

        INSERT INTO schema_version (version) VALUES (3);
    ";

    conn.execute_batch(sql)
        .map_err(|e| DbError::MigrationFailed(format!("Migration v3 failed: {e}")))?;

    Ok(())
}

/// Migration v4: Add blind code modules and script-code access tables.
fn migrate_v4(conn: &Connection) -> Result<(), DbError> {
    let sql = "
        CREATE TABLE IF NOT EXISTS blind_code_modules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            encrypted_code BLOB NOT NULL,
            required_secrets TEXT NOT NULL DEFAULT '[]',
            allowed_params TEXT NOT NULL DEFAULT '[]',
            approved INTEGER NOT NULL DEFAULT 0,
            blind INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at TEXT
        );

        CREATE TABLE IF NOT EXISTS script_code_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            script_reg_id INTEGER NOT NULL,
            code_module_id INTEGER NOT NULL,
            approved INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (script_reg_id) REFERENCES script_registrations(id),
            FOREIGN KEY (code_module_id) REFERENCES blind_code_modules(id),
            UNIQUE(script_reg_id, code_module_id)
        );

        INSERT INTO schema_version (version) VALUES (4);
    ";

    conn.execute_batch(sql)
        .map_err(|e| DbError::MigrationFailed(format!("Migration v4 failed: {e}")))?;

    Ok(())
}

/// Migration v5: Add language column to blind_code_modules for multi-language support.
fn migrate_v5(conn: &Connection) -> Result<(), DbError> {
    let sql = "
        ALTER TABLE blind_code_modules ADD COLUMN language TEXT NOT NULL DEFAULT 'rhai';

        INSERT INTO schema_version (version) VALUES (5);
    ";

    conn.execute_batch(sql)
        .map_err(|e| DbError::MigrationFailed(format!("Migration v5 failed: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migrations_are_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        // Running a second time should not fail.
        run_migrations(&conn).unwrap();
    }
}
