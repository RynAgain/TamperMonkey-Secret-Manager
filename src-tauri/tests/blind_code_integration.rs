//! Integration tests for blind code modules: .tmcode file format, Rhai
//! execution engine, and database CRUD operations.
//!
//! Covers three areas:
//! 1. `.tmcode` binary export/import round-trips (PIN encryption, expiration)
//! 2. Sandboxed Rhai execution (secrets, params, resource limits, zeroize)
//! 3. Database layer for blind code modules and script-code access

use std::collections::HashMap;
use std::path::Path;

use tampermonkey_secret_manager_lib::secrets::blind_code::{
    export_code, import_code, CodeModuleEntry,
};
use tampermonkey_secret_manager_lib::secrets::executor::{
    dispatch_execute, execute_module, ExecutionContext, ExecutionError,
};
use tampermonkey_secret_manager_lib::db::Database;
use tampermonkey_secret_manager_lib::error::DbError;

// ======================================================================
// Helpers
// ======================================================================

/// Build a sample `CodeModuleEntry` for reuse across tests.
fn sample_module() -> CodeModuleEntry {
    CodeModuleEntry {
        name: "test-module".to_string(),
        description: "A test blind code module".to_string(),
        language: "rhai".to_string(),
        code: r#"let x = 42; x.to_string()"#.to_string(),
        required_secrets: vec!["API_KEY".to_string()],
        allowed_params: vec!["url".to_string(), "method".to_string()],
    }
}

/// Create a temporary database file with a unique name based on the test
/// function, returning the `Database` handle and the directory path (for
/// cleanup).
fn temp_db(label: &str) -> (Database, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "tmpsm_blind_{}_{}_{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("failed to create temp dir");
    let db_path = dir.join("test.db");
    let db = Database::open(&db_path).expect("failed to open temp database");
    (db, dir)
}

/// Remove the temporary directory (best-effort cleanup).
fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

// ======================================================================
// Group 1: .tmcode File Format Tests
// ======================================================================

#[test]
fn test_tmcode_export_import_roundtrip() {
    let module = sample_module();
    let pin = "roundtrip-pin";

    let code_bytes = export_code(module.clone(), pin, None)
        .expect("export should succeed");

    let payload = import_code(&code_bytes, pin)
        .expect("import should succeed with correct PIN");

    assert_eq!(payload.modules.len(), 1);
    let m = &payload.modules[0];
    assert_eq!(m.name, "test-module");
    assert_eq!(m.description, "A test blind code module");
    assert_eq!(m.language, "rhai");
    assert_eq!(m.code, r#"let x = 42; x.to_string()"#);
    assert_eq!(m.required_secrets, vec!["API_KEY"]);
    assert_eq!(m.allowed_params, vec!["url", "method"]);
    assert!(payload.expires_at.is_none());
}

#[test]
fn test_tmcode_wrong_pin_fails() {
    let module = sample_module();
    let pin = "correct-pin!";
    let wrong = "wrong-pin!!";

    let code_bytes = export_code(module, pin, None)
        .expect("export should succeed");

    let result = import_code(&code_bytes, wrong);
    assert!(
        result.is_err(),
        "import with wrong PIN must fail (GCM authentication)"
    );
}

#[test]
fn test_tmcode_expired_module_rejected() {
    let module = sample_module();
    let pin = "expired-test";
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();

    let code_bytes = export_code(module, pin, Some(past))
        .expect("export should succeed even with past expiration");

    let result = import_code(&code_bytes, pin);
    assert!(result.is_err(), "expired .tmcode must be rejected on import");

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("expired"),
        "error should mention expiration, got: {}",
        err_msg
    );
}

#[test]
fn test_tmcode_future_expiration_accepted() {
    let module = sample_module();
    let pin = "future-exp";
    let future = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();

    let code_bytes = export_code(module, pin, Some(future.clone()))
        .expect("export should succeed");

    let payload = import_code(&code_bytes, pin)
        .expect("import of non-expired .tmcode should succeed");

    assert_eq!(payload.expires_at, Some(future));
    assert_eq!(payload.modules.len(), 1);
}

#[test]
fn test_tmcode_language_field_preserved() {
    let pin = "lang-test!";

    for lang in &["python", "javascript", "typescript"] {
        let module = CodeModuleEntry {
            name: format!("{}-module", lang),
            description: format!("Module in {}", lang),
            language: lang.to_string(),
            code: "print('hello')".to_string(),
            required_secrets: vec![],
            allowed_params: vec![],
        };

        let code_bytes = export_code(module, pin, None)
            .expect("export should succeed");

        let payload = import_code(&code_bytes, pin)
            .expect("import should succeed");

        assert_eq!(
            payload.modules[0].language, *lang,
            "language '{}' must survive export/import roundtrip",
            lang
        );
    }
}

// ======================================================================
// Group 2: Rhai Execution Engine Tests
// ======================================================================

#[test]
fn test_rhai_basic_execution() {
    let mut ctx = ExecutionContext {
        code: r#"let x = 42; x.to_string()"#.to_string(),
        required_secrets: vec![],
        allowed_params: vec![],
        params: HashMap::new(),
        secrets: HashMap::new(),
    };

    let result = execute_module(&mut ctx).expect("simple execution should succeed");
    assert_eq!(result.output, "42");
}

#[test]
fn test_rhai_secret_access() {
    let mut secrets = HashMap::new();
    secrets.insert("API_KEY".to_string(), "sk-live-abc123".to_string());

    let mut ctx = ExecutionContext {
        code: r#"secrets["API_KEY"]"#.to_string(),
        required_secrets: vec!["API_KEY".to_string()],
        allowed_params: vec![],
        params: HashMap::new(),
        secrets,
    };

    let result = execute_module(&mut ctx).expect("secret access should succeed");
    assert_eq!(result.output, "sk-live-abc123");
}

#[test]
fn test_rhai_param_access() {
    let mut params = HashMap::new();
    params.insert("url".to_string(), "https://api.example.com/v1".to_string());

    let mut ctx = ExecutionContext {
        code: r#"params["url"]"#.to_string(),
        required_secrets: vec![],
        allowed_params: vec!["url".to_string()],
        params,
        secrets: HashMap::new(),
    };

    let result = execute_module(&mut ctx).expect("param access should succeed");
    assert_eq!(result.output, "https://api.example.com/v1");
}

#[test]
fn test_rhai_disallowed_param_rejected() {
    let mut params = HashMap::new();
    params.insert("evil_param".to_string(), "bad-value".to_string());

    let mut ctx = ExecutionContext {
        code: r#""this should not run""#.to_string(),
        required_secrets: vec![],
        allowed_params: vec!["url".to_string()],
        params,
        secrets: HashMap::new(),
    };

    let result = execute_module(&mut ctx);
    assert!(result.is_err(), "disallowed param must be rejected");
    assert!(
        matches!(result.unwrap_err(), ExecutionError::ParameterNotAllowed(_)),
        "error variant must be ParameterNotAllowed"
    );
}

#[test]
fn test_rhai_resource_limits_enforced() {
    let mut ctx = ExecutionContext {
        code: r#"let x = 0; loop { x += 1; }"#.to_string(),
        required_secrets: vec![],
        allowed_params: vec![],
        params: HashMap::new(),
        secrets: HashMap::new(),
    };

    let result = execute_module(&mut ctx);
    assert!(
        result.is_err(),
        "infinite loop must be stopped by max operations limit"
    );
}

#[test]
fn test_rhai_secrets_zeroized_after_execution() {
    let mut secrets = HashMap::new();
    secrets.insert("SECRET".to_string(), "sensitive-data-12345".to_string());

    let mut ctx = ExecutionContext {
        code: r#"secrets["SECRET"]"#.to_string(),
        required_secrets: vec!["SECRET".to_string()],
        allowed_params: vec![],
        params: HashMap::new(),
        secrets,
    };

    let _ = execute_module(&mut ctx).expect("execution should succeed");

    // After execution, secret values in the context must be zeroized
    for (_, value) in &ctx.secrets {
        assert!(
            value.chars().all(|c| c == '\0') || value.is_empty(),
            "Secret value should be zeroized after execution, got: {:?}",
            value
        );
    }
}

#[test]
fn test_rhai_dispatch_routes_correctly() {
    let mut ctx = ExecutionContext {
        code: r#"let a = 10; let b = 20; (a + b).to_string()"#.to_string(),
        required_secrets: vec![],
        allowed_params: vec![],
        params: HashMap::new(),
        secrets: HashMap::new(),
    };

    let result = dispatch_execute("rhai", &mut ctx)
        .expect("dispatch for 'rhai' should succeed");
    assert_eq!(result.output, "30");
}

#[test]
fn test_dispatch_unsupported_language_error() {
    let mut ctx = ExecutionContext {
        code: "print('hello')".to_string(),
        required_secrets: vec![],
        allowed_params: vec![],
        params: HashMap::new(),
        secrets: HashMap::new(),
    };

    let result = dispatch_execute("lua", &mut ctx);
    assert!(
        result.is_err(),
        "unsupported language 'lua' must produce an error"
    );

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("Unsupported language"),
        "error should mention unsupported language, got: {}",
        err_msg
    );
}

// ======================================================================
// Group 3: DB Operations Tests
// ======================================================================

#[test]
fn test_blind_code_module_crud() {
    let (db, dir) = temp_db("crud");

    // Create
    let module = db
        .create_blind_code_module(
            "my-module",
            "A test module",
            b"encrypted-code-bytes",
            "rhai",
            r#"["API_KEY"]"#,
            r#"["url"]"#,
            true,
            None,
        )
        .expect("create should succeed");
    assert_eq!(module.name, "my-module");
    assert!(!module.approved);
    assert!(module.blind);

    // Get by name
    let fetched = db
        .get_blind_code_module("my-module")
        .expect("get should succeed")
        .expect("module should exist");
    assert_eq!(fetched.description, "A test module");
    assert_eq!(fetched.language, "rhai");
    assert_eq!(fetched.encrypted_code, b"encrypted-code-bytes");

    // List all (should have 1)
    let all = db.list_blind_code_modules().expect("list should succeed");
    assert_eq!(all.len(), 1);

    // Approve
    db.approve_blind_code_module("my-module")
        .expect("approve should succeed");
    let approved = db
        .get_blind_code_module("my-module")
        .unwrap()
        .unwrap();
    assert!(approved.approved, "module should be approved");

    // Revoke
    db.revoke_blind_code_module("my-module")
        .expect("revoke should succeed");
    let revoked = db
        .get_blind_code_module("my-module")
        .unwrap()
        .unwrap();
    assert!(!revoked.approved, "module should no longer be approved");

    // Delete
    db.delete_blind_code_module("my-module")
        .expect("delete should succeed");
    let gone = db
        .get_blind_code_module("my-module")
        .expect("get should succeed");
    assert!(gone.is_none(), "module should be deleted");

    cleanup(&dir);
}

#[test]
fn test_blind_code_module_duplicate_name_rejected() {
    let (db, dir) = temp_db("dup");

    db.create_blind_code_module(
        "unique-name",
        "First",
        b"code1",
        "rhai",
        "[]",
        "[]",
        false,
        None,
    )
    .expect("first create should succeed");

    let err = db
        .create_blind_code_module(
            "unique-name",
            "Second",
            b"code2",
            "python",
            "[]",
            "[]",
            false,
            None,
        )
        .expect_err("duplicate name must be rejected");

    assert!(
        matches!(err, DbError::AlreadyExists(_)),
        "error should be AlreadyExists, got: {:?}",
        err
    );

    cleanup(&dir);
}

#[test]
fn test_script_code_access_crud() {
    let (db, dir) = temp_db("access");

    // Create a module
    let module = db
        .create_blind_code_module(
            "access-module",
            "Module for access test",
            b"code",
            "rhai",
            "[]",
            "[]",
            false,
            None,
        )
        .expect("create module should succeed");

    // Register a script
    let script = db
        .register_script("tm-test-script", "Test Script", "example.com")
        .expect("register script should succeed");

    // Check access (should be None -- no record exists)
    let access = db
        .check_script_code_access(script.id, module.id)
        .expect("check should succeed");
    assert!(access.is_none(), "no access record should exist yet");

    // Create access request (unapproved)
    db.create_code_access_request(script.id, module.id)
        .expect("create access request should succeed");

    // Check access (should be Some(false) -- unapproved)
    let access = db
        .check_script_code_access(script.id, module.id)
        .expect("check should succeed");
    assert_eq!(access, Some(false), "access should exist but be unapproved");

    // Set access to approved
    db.set_script_code_access(script.id, module.id, true)
        .expect("set access should succeed");

    // Check access (should be Some(true))
    let access = db
        .check_script_code_access(script.id, module.id)
        .expect("check should succeed");
    assert_eq!(access, Some(true), "access should now be approved");

    // List access for the script
    let access_list = db
        .list_script_code_access(script.id)
        .expect("list should succeed");
    assert_eq!(access_list.len(), 1);
    assert_eq!(access_list[0].module_name, "access-module");
    assert!(access_list[0].approved);

    cleanup(&dir);
}

#[test]
fn test_delete_module_cascades_access() {
    let (db, dir) = temp_db("cascade");

    // Create module and script
    let module = db
        .create_blind_code_module(
            "cascade-module",
            "Will be deleted",
            b"code",
            "rhai",
            "[]",
            "[]",
            false,
            None,
        )
        .expect("create module should succeed");

    let script = db
        .register_script("tm-cascade-script", "Cascade Script", "example.com")
        .expect("register script should succeed");

    // Create access record
    db.set_script_code_access(script.id, module.id, true)
        .expect("set access should succeed");

    // Verify access exists
    let access = db
        .check_script_code_access(script.id, module.id)
        .expect("check should succeed");
    assert_eq!(access, Some(true));

    // Delete the module
    db.delete_blind_code_module("cascade-module")
        .expect("delete should succeed");

    // The access record should be gone (cascaded delete)
    let access_list = db
        .list_script_code_access(script.id)
        .expect("list should succeed");
    assert!(
        access_list.is_empty(),
        "access records should be removed when module is deleted"
    );

    cleanup(&dir);
}

#[test]
fn test_blind_code_module_with_language() {
    let (db, dir) = temp_db("lang");

    let languages = ["rhai", "python", "javascript", "typescript"];

    for lang in &languages {
        let name = format!("{}-module", lang);
        let module = db
            .create_blind_code_module(
                &name,
                &format!("Module in {}", lang),
                b"code",
                lang,
                "[]",
                "[]",
                false,
                None,
            )
            .expect("create should succeed");
        assert_eq!(module.language, *lang);

        // Verify on retrieval
        let fetched = db
            .get_blind_code_module(&name)
            .expect("get should succeed")
            .expect("module should exist");
        assert_eq!(
            fetched.language, *lang,
            "language '{}' must be preserved in DB",
            lang
        );
    }

    // List all -- should have 4
    let all = db.list_blind_code_modules().expect("list should succeed");
    assert_eq!(all.len(), 4);

    cleanup(&dir);
}
