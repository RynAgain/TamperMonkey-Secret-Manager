use std::collections::HashMap;

use rhai::{Dynamic, Engine, Scope, AST};
use zeroize::Zeroize;

use crate::crypto::encryption;
use crate::db::Database;

/// Result of executing a blind code module.
#[derive(Debug)]
pub struct ExecutionResult {
    /// The value returned by the Rhai script, serialized as a string.
    pub output: String,
}

/// Error returned when blind code execution fails.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("Compilation error: {0}")]
    CompilationError(String),

    #[error("Runtime error: {0}")]
    RuntimeError(String),

    #[error("Secret not available: {0}")]
    SecretNotAvailable(String),

    #[error("Parameter not allowed: {0}")]
    ParameterNotAllowed(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("HTTP error: {0}")]
    HttpError(String),

    #[error("Module expired")]
    ModuleExpired,
}

/// Configuration for a single module execution.
pub struct ExecutionContext {
    /// The Rhai source code to execute.
    pub code: String,
    /// Secret names this module is allowed to access.
    pub required_secrets: Vec<String>,
    /// Parameter names the TM script is allowed to provide.
    pub allowed_params: Vec<String>,
    /// Actual parameter values from the TM script's request.
    pub params: HashMap<String, String>,
    /// Resolved secret values (name -> decrypted plaintext).
    /// These are injected into the Rhai scope and zeroized after execution.
    pub secrets: HashMap<String, String>,
}

/// Build a sandboxed Rhai engine with limited capabilities.
///
/// The engine has NO access to:
/// - File system
/// - Process management
/// - Arbitrary module imports
///
/// The engine HAS access to:
/// - String manipulation
/// - Math operations
/// - Array/map operations
/// - `http_get(url, headers_map)` -- make an HTTP GET request
/// - `http_post(url, headers_map, body)` -- make an HTTP POST request
fn build_engine() -> Engine {
    let mut engine = Engine::new();

    // Set resource limits to prevent abuse
    engine.set_max_expr_depths(64, 32);
    engine.set_max_operations(100_000);
    engine.set_max_string_size(1_048_576); // 1 MB
    engine.set_max_array_size(10_000);
    engine.set_max_map_size(10_000);

    // Register HTTP GET function: http_get(url: String, headers: Map) -> String
    engine.register_fn("http_get", |url: String, headers: rhai::Map| -> Result<String, Box<rhai::EvalAltResult>> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| Box::new(rhai::EvalAltResult::ErrorRuntime(
                format!("Failed to create HTTP client: {e}").into(),
                rhai::Position::NONE,
            )))?;

        let mut request = client.get(&url);

        // Add headers from the map
        for (key, value) in &headers {
            let val_str = value.to_string();
            request = request.header(key.as_str(), val_str);
        }

        let response = request.send().map_err(|e| Box::new(rhai::EvalAltResult::ErrorRuntime(
            format!("HTTP GET failed: {e}").into(),
            rhai::Position::NONE,
        )))?;

        let status = response.status().as_u16();
        let body = response.text().map_err(|e| Box::new(rhai::EvalAltResult::ErrorRuntime(
            format!("Failed to read response body: {e}").into(),
            rhai::Position::NONE,
        )))?;

        // Return a JSON string with status and body
        Ok(format!(r#"{{"status":{},"body":{}}}"#, status, serde_json::json!(body)))
    });

    // Register HTTP GET with no headers: http_get(url: String) -> String
    engine.register_fn("http_get", |url: String| -> Result<String, Box<rhai::EvalAltResult>> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| Box::new(rhai::EvalAltResult::ErrorRuntime(
                format!("Failed to create HTTP client: {e}").into(),
                rhai::Position::NONE,
            )))?;

        let response = client.get(&url).send().map_err(|e| Box::new(rhai::EvalAltResult::ErrorRuntime(
            format!("HTTP GET failed: {e}").into(),
            rhai::Position::NONE,
        )))?;

        let status = response.status().as_u16();
        let body = response.text().map_err(|e| Box::new(rhai::EvalAltResult::ErrorRuntime(
            format!("Failed to read response body: {e}").into(),
            rhai::Position::NONE,
        )))?;

        Ok(format!(r#"{{"status":{},"body":{}}}"#, status, serde_json::json!(body)))
    });

    // Register HTTP POST function: http_post(url: String, headers: Map, body: String) -> String
    engine.register_fn("http_post", |url: String, headers: rhai::Map, body: String| -> Result<String, Box<rhai::EvalAltResult>> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| Box::new(rhai::EvalAltResult::ErrorRuntime(
                format!("Failed to create HTTP client: {e}").into(),
                rhai::Position::NONE,
            )))?;

        let mut request = client.post(&url).body(body);

        // Add headers from the map
        for (key, value) in &headers {
            let val_str = value.to_string();
            request = request.header(key.as_str(), val_str);
        }

        let response = request.send().map_err(|e| Box::new(rhai::EvalAltResult::ErrorRuntime(
            format!("HTTP POST failed: {e}").into(),
            rhai::Position::NONE,
        )))?;

        let status = response.status().as_u16();
        let resp_body = response.text().map_err(|e| Box::new(rhai::EvalAltResult::ErrorRuntime(
            format!("Failed to read response body: {e}").into(),
            rhai::Position::NONE,
        )))?;

        Ok(format!(r#"{{"status":{},"body":{}}}"#, status, serde_json::json!(resp_body)))
    });

    // Register HTTP POST with no headers: http_post(url: String, body: String) -> String
    engine.register_fn("http_post", |url: String, body: String| -> Result<String, Box<rhai::EvalAltResult>> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| Box::new(rhai::EvalAltResult::ErrorRuntime(
                format!("Failed to create HTTP client: {e}").into(),
                rhai::Position::NONE,
            )))?;

        let response = client.post(&url).body(body).send().map_err(|e| Box::new(rhai::EvalAltResult::ErrorRuntime(
            format!("HTTP POST failed: {e}").into(),
            rhai::Position::NONE,
        )))?;

        let status = response.status().as_u16();
        let resp_body = response.text().map_err(|e| Box::new(rhai::EvalAltResult::ErrorRuntime(
            format!("Failed to read response body: {e}").into(),
            rhai::Position::NONE,
        )))?;

        Ok(format!(r#"{{"status":{},"body":{}}}"#, status, serde_json::json!(resp_body)))
    });

    engine
}

/// Resolve the secret values needed by a module.
///
/// Decrypts each required secret from the database using the master key.
/// Returns a map of secret_name -> plaintext_value.
pub fn resolve_secrets(
    db: &Database,
    master_key: &[u8; 32],
    required_secrets: &[String],
) -> Result<HashMap<String, String>, ExecutionError> {
    let mut secrets = HashMap::new();

    for name in required_secrets {
        let entry = db
            .get_secret_by_name(name)
            .map_err(|e| ExecutionError::SecretNotAvailable(format!("DB error for '{}': {e}", name)))?
            .ok_or_else(|| ExecutionError::SecretNotAvailable(format!("Secret '{}' not found", name)))?;

        // Check expiration
        if let Some(ref exp) = entry.expires_at {
            if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(exp) {
                if chrono::Utc::now() > expiry {
                    return Err(ExecutionError::SecretNotAvailable(
                        format!("Secret '{}' has expired", name),
                    ));
                }
            }
        }

        let encrypted_data = encryption::EncryptedData::from_bytes(&entry.encrypted_value)
            .map_err(|e| ExecutionError::DecryptionError(format!("Invalid data for '{}': {e}", name)))?;

        let decrypted = encryption::decrypt(&encrypted_data, master_key)
            .map_err(|e| ExecutionError::DecryptionError(format!("Decryption failed for '{}': {e}", name)))?;

        let value = String::from_utf8(decrypted)
            .map_err(|e| ExecutionError::DecryptionError(format!("Invalid UTF-8 in '{}': {e}", name)))?;

        secrets.insert(name.clone(), value);
    }

    Ok(secrets)
}

/// Validate that all provided params are in the allowed list.
pub fn validate_params(
    params: &HashMap<String, String>,
    allowed_params: &[String],
) -> Result<(), ExecutionError> {
    for key in params.keys() {
        if !allowed_params.contains(key) {
            return Err(ExecutionError::ParameterNotAllowed(format!(
                "Parameter '{}' is not in the allowed list: {:?}",
                key, allowed_params
            )));
        }
    }
    Ok(())
}

/// Execute a blind code module in a sandboxed Rhai engine.
///
/// 1. Validates parameters against the allowed list
/// 2. Builds a sandboxed engine
/// 3. Injects secrets and params into the scope
/// 4. Compiles and runs the Rhai code
/// 5. Zeroizes all secret values after execution
/// 6. Returns the script's return value as a string
pub fn execute_module(ctx: &mut ExecutionContext) -> Result<ExecutionResult, ExecutionError> {
    // Validate params
    validate_params(&ctx.params, &ctx.allowed_params)?;

    // Build sandboxed engine
    let engine = build_engine();

    // Compile the code first to catch syntax errors
    let ast: AST = engine
        .compile(&ctx.code)
        .map_err(|e| ExecutionError::CompilationError(format!("{e}")))?;

    // Build scope with secrets and params
    let mut scope = Scope::new();

    // Inject secrets as a map accessible via `secrets["NAME"]`
    let mut secrets_map = rhai::Map::new();
    for (name, value) in &ctx.secrets {
        secrets_map.insert(name.clone().into(), Dynamic::from(value.clone()));
    }
    scope.push("secrets", secrets_map);

    // Inject params as a map accessible via `params["key"]`
    let mut params_map = rhai::Map::new();
    for (key, value) in &ctx.params {
        params_map.insert(key.clone().into(), Dynamic::from(value.clone()));
    }
    scope.push("params", params_map);

    // Execute
    let result = engine
        .eval_ast_with_scope::<Dynamic>(&mut scope, &ast)
        .map_err(|e| ExecutionError::RuntimeError(format!("{e}")))?;

    // Convert result to string
    let output = if result.is_unit() {
        String::new()
    } else {
        result.to_string()
    };

    // Security: zeroize all secret values
    for (_, value) in ctx.secrets.iter_mut() {
        value.zeroize();
    }

    Ok(ExecutionResult { output })
}

/// Dispatch execution to the appropriate engine based on language.
///
/// Supported languages: "rhai", "python", "javascript", "typescript"
pub fn dispatch_execute(
    language: &str,
    ctx: &mut ExecutionContext,
) -> Result<ExecutionResult, ExecutionError> {
    match language {
        "rhai" => execute_module(ctx),
        "python" => {
            let output = super::subprocess_executor::execute_python(
                &ctx.code,
                &mut ctx.secrets,
                &ctx.params,
            )?;
            Ok(ExecutionResult { output })
        }
        "javascript" => {
            let output = super::subprocess_executor::execute_deno(
                &ctx.code,
                &mut ctx.secrets,
                &ctx.params,
                false,
            )?;
            Ok(ExecutionResult { output })
        }
        "typescript" => {
            let output = super::subprocess_executor::execute_deno(
                &ctx.code,
                &mut ctx.secrets,
                &ctx.params,
                true,
            )?;
            Ok(ExecutionResult { output })
        }
        other => Err(ExecutionError::RuntimeError(
            format!("Unsupported language: {}", other),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_execution() {
        let mut ctx = ExecutionContext {
            code: r#"let x = 40 + 2; x.to_string()"#.to_string(),
            required_secrets: vec![],
            allowed_params: vec![],
            params: HashMap::new(),
            secrets: HashMap::new(),
        };

        let result = execute_module(&mut ctx).expect("execution should succeed");
        assert_eq!(result.output, "42");
    }

    #[test]
    fn test_secret_access() {
        let mut secrets = HashMap::new();
        secrets.insert("API_KEY".to_string(), "sk-test-123".to_string());

        let mut ctx = ExecutionContext {
            code: r#"let key = secrets["API_KEY"]; "got: " + key"#.to_string(),
            required_secrets: vec!["API_KEY".to_string()],
            allowed_params: vec![],
            params: HashMap::new(),
            secrets,
        };

        let result = execute_module(&mut ctx).expect("execution should succeed");
        assert_eq!(result.output, "got: sk-test-123");
    }

    #[test]
    fn test_param_access() {
        let mut params = HashMap::new();
        params.insert("url".to_string(), "https://api.example.com".to_string());

        let mut ctx = ExecutionContext {
            code: r#"let u = params["url"]; "calling: " + u"#.to_string(),
            required_secrets: vec![],
            allowed_params: vec!["url".to_string()],
            params,
            secrets: HashMap::new(),
        };

        let result = execute_module(&mut ctx).expect("execution should succeed");
        assert_eq!(result.output, "calling: https://api.example.com");
    }

    #[test]
    fn test_disallowed_param_rejected() {
        let mut params = HashMap::new();
        params.insert("evil_param".to_string(), "value".to_string());

        let mut ctx = ExecutionContext {
            code: r#""hello""#.to_string(),
            required_secrets: vec![],
            allowed_params: vec!["url".to_string()],
            params,
            secrets: HashMap::new(),
        };

        let result = execute_module(&mut ctx);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ExecutionError::ParameterNotAllowed(_)));
    }

    #[test]
    fn test_compilation_error() {
        let mut ctx = ExecutionContext {
            code: r#"this is not valid rhai code @#$"#.to_string(),
            required_secrets: vec![],
            allowed_params: vec![],
            params: HashMap::new(),
            secrets: HashMap::new(),
        };

        let result = execute_module(&mut ctx);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ExecutionError::CompilationError(_)));
    }

    #[test]
    fn test_resource_limits() {
        // Infinite loop should be caught by max operations
        let mut ctx = ExecutionContext {
            code: r#"let x = 0; loop { x += 1; }"#.to_string(),
            required_secrets: vec![],
            allowed_params: vec![],
            params: HashMap::new(),
            secrets: HashMap::new(),
        };

        let result = execute_module(&mut ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_secrets_zeroized_after_execution() {
        let mut secrets = HashMap::new();
        secrets.insert("SECRET".to_string(), "sensitive-value".to_string());

        let mut ctx = ExecutionContext {
            code: r#"secrets["SECRET"]"#.to_string(),
            required_secrets: vec!["SECRET".to_string()],
            allowed_params: vec![],
            params: HashMap::new(),
            secrets,
        };

        let _ = execute_module(&mut ctx);

        // After execution, secrets should be zeroized
        for (_, value) in &ctx.secrets {
            assert!(
                value.chars().all(|c| c == '\0') || value.is_empty(),
                "Secret value should be zeroized, got: {}",
                value
            );
        }
    }

    #[test]
    fn test_combined_secrets_and_params() {
        let mut secrets = HashMap::new();
        secrets.insert("TOKEN".to_string(), "bearer-xyz".to_string());

        let mut params = HashMap::new();
        params.insert("endpoint".to_string(), "/api/users".to_string());

        let mut ctx = ExecutionContext {
            code: r#"
                let token = secrets["TOKEN"];
                let ep = params["endpoint"];
                "Authorization: " + token + " -> " + ep
            "#.to_string(),
            required_secrets: vec!["TOKEN".to_string()],
            allowed_params: vec!["endpoint".to_string()],
            params,
            secrets,
        };

        let result = execute_module(&mut ctx).expect("execution should succeed");
        assert_eq!(result.output, "Authorization: bearer-xyz -> /api/users");
    }
}
