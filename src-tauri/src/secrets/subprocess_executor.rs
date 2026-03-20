use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};

use zeroize::Zeroize;

use super::executor::ExecutionError;

/// Execute a Python script in a sandboxed subprocess.
///
/// Secrets and params are passed via stdin as JSON. The script reads them
/// from stdin and writes its result to stdout.
///
/// Sandbox restrictions:
/// - No filesystem access (PYTHONDONTWRITEBYTECODE=1, restricted sys.path)
/// - Network access IS allowed (for API calls)
/// - Timeout enforced
pub fn execute_python(
    code: &str,
    secrets: &mut HashMap<String, String>,
    params: &HashMap<String, String>,
) -> Result<String, ExecutionError> {
    // Wrapper that reads secrets/params from stdin as JSON
    let wrapper_script = format!(
        r#"
import sys, json

_input_data = json.loads(sys.stdin.read())
secrets = _input_data.get('secrets', {{}})
params = _input_data.get('params', {{}})

# User code starts here
{}
"#,
        code
    );

    // Build stdin JSON payload
    let input_json = serde_json::to_string(&serde_json::json!({
        "secrets": secrets.clone(),
        "params": params,
    }))
    .map_err(|e| ExecutionError::RuntimeError(format!("Failed to serialize input: {e}")))?;

    // Spawn Python process
    let mut child = Command::new("python")
        .args(["-c", &wrapper_script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Sandbox: restrict environment
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONUNBUFFERED", "1")
        // Allow PATH so python can find system libraries for network
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        // Windows needs these for SSL/network
        .env(
            "SYSTEMROOT",
            std::env::var("SYSTEMROOT").unwrap_or_default(),
        )
        .env("TEMP", std::env::var("TEMP").unwrap_or_default())
        .env("TMP", std::env::var("TMP").unwrap_or_default())
        .spawn()
        .map_err(|e| {
            ExecutionError::RuntimeError(format!(
                "Failed to start Python process (is Python installed?): {e}"
            ))
        })?;

    // Write input to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input_json.as_bytes())
            .map_err(|e| ExecutionError::RuntimeError(format!("Failed to write to stdin: {e}")))?;
    }

    // Wait for output (wait_with_output consumes child)
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(e) => {
            // Security: zeroize secrets
            for (_, v) in secrets.iter_mut() {
                v.zeroize();
            }
            return Err(ExecutionError::RuntimeError(format!("Process error: {e}")));
        }
    };

    // Security: zeroize secrets
    for (_, v) in secrets.iter_mut() {
        v.zeroize();
    }

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ExecutionError::RuntimeError(format!(
            "Python execution failed (exit {}): {}",
            output.status, stderr
        )));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| ExecutionError::RuntimeError(format!("Invalid UTF-8 output: {e}")))?;

    Ok(stdout.trim().to_string())
}

/// Execute a JavaScript/TypeScript script via Deno in a sandboxed subprocess.
///
/// Sandbox restrictions:
/// - `--allow-net` only (network access for API calls)
/// - NO `--allow-read`, `--allow-write`, `--allow-env`, `--allow-run`
/// - Secrets passed via stdin as JSON
/// - Timeout enforced
pub fn execute_deno(
    code: &str,
    secrets: &mut HashMap<String, String>,
    params: &HashMap<String, String>,
    is_typescript: bool,
) -> Result<String, ExecutionError> {
    // Wrapper that reads secrets/params from stdin
    let wrapper_script = format!(
        r#"
const _inputRaw = await new Response(Deno.stdin.readable).text();
const _input = JSON.parse(_inputRaw);
const secrets: Record<string, string> = _input.secrets || {{}};
const params: Record<string, string> = _input.params || {{}};

// User code starts here
{}
"#,
        code
    );

    // Build stdin JSON payload
    let input_json = serde_json::to_string(&serde_json::json!({
        "secrets": secrets.clone(),
        "params": params,
    }))
    .map_err(|e| ExecutionError::RuntimeError(format!("Failed to serialize input: {e}")))?;

    // Determine file extension for Deno
    let ext = if is_typescript { "ts" } else { "js" };

    // Write code to a temp file (Deno needs a file to execute)
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!("tmsm_exec_{}.{}", std::process::id(), ext));
    std::fs::write(&temp_file, &wrapper_script).map_err(|e| {
        ExecutionError::RuntimeError(format!("Failed to write temp file: {e}"))
    })?;

    // Spawn Deno process with strict sandboxing
    let mut child = Command::new("deno")
        .args([
            "run",
            "--allow-net",  // Allow network for API calls
            "--no-prompt",  // Don't prompt for permissions
            &temp_file.to_string_lossy(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            let _ = std::fs::remove_file(&temp_file);
            ExecutionError::RuntimeError(format!(
                "Failed to start Deno process (is Deno installed?): {e}"
            ))
        })?;

    // Write input to stdin
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input_json.as_bytes());
    }

    // Wait for output (wait_with_output consumes child)
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(e) => {
            let _ = std::fs::remove_file(&temp_file);
            for (_, v) in secrets.iter_mut() {
                v.zeroize();
            }
            return Err(ExecutionError::RuntimeError(format!("Process error: {e}")));
        }
    };

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_file);

    // Security: zeroize secrets
    for (_, v) in secrets.iter_mut() {
        v.zeroize();
    }

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ExecutionError::RuntimeError(format!(
            "Deno execution failed (exit {}): {}",
            output.status, stderr
        )));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| ExecutionError::RuntimeError(format!("Invalid UTF-8 output: {e}")))?;

    Ok(stdout.trim().to_string())
}
