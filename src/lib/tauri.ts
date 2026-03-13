import { invoke } from '@tauri-apps/api/core';

// ------------------------------------------------------------------
// Auth types & wrappers
// ------------------------------------------------------------------

export interface AppStatus {
  is_first_run: boolean;
  is_unlocked: boolean;
}

export async function checkFirstRun(): Promise<boolean> {
  return invoke<boolean>('check_first_run');
}

export async function setupMasterPassword(password: string): Promise<void> {
  return invoke<void>('setup_master_password', { password });
}

export async function unlock(password: string): Promise<boolean> {
  return invoke<boolean>('unlock', { password });
}

export async function lockApp(): Promise<void> {
  return invoke<void>('lock');
}

export async function getAppStatus(): Promise<AppStatus> {
  return invoke<AppStatus>('get_app_status');
}

export async function changeMasterPassword(
  currentPassword: string,
  newPassword: string,
): Promise<void> {
  return invoke<void>('change_master_password', { currentPassword, newPassword });
}

export async function setAutoLockMinutes(minutes: number): Promise<void> {
  return invoke<void>('set_auto_lock_minutes', { minutes });
}

export async function getAutoLockMinutes(): Promise<number> {
  return invoke<number>('get_auto_lock_minutes');
}

// ------------------------------------------------------------------
// Secret types & wrappers
// ------------------------------------------------------------------

export interface SecretMetadata {
  id: number;
  name: string;
  secret_type: string;
  blind: boolean;
  created_at: string;
  updated_at: string;
  expires_at: string | null;
}

export interface SecretValue extends SecretMetadata {
  value: string | null;
}

export async function createSecret(name: string, value: string): Promise<void> {
  return invoke<void>('create_secret', { name, value });
}

export async function getSecret(name: string): Promise<SecretValue | null> {
  return invoke<SecretValue | null>('get_secret', { name });
}

export async function listSecrets(): Promise<SecretMetadata[]> {
  return invoke<SecretMetadata[]>('list_secrets');
}

export async function updateSecret(name: string, value: string): Promise<void> {
  return invoke<void>('update_secret', { name, value });
}

export async function deleteSecret(name: string): Promise<void> {
  return invoke<void>('delete_secret', { name });
}

// ------------------------------------------------------------------
// API info types & wrappers
// ------------------------------------------------------------------

export interface ApiInfo {
  port: number | null;
  token: string | null;
}

export async function getApiInfo(): Promise<ApiInfo> {
  return invoke<ApiInfo>('get_api_info');
}

export async function rotateApiToken(): Promise<string> {
  return invoke<string>('rotate_api_token');
}

// ------------------------------------------------------------------
// Environment variable types & wrappers
// ------------------------------------------------------------------

export interface EnvVarInfo {
  var_name: string;
  is_set: boolean;
}

export async function addEnvVar(varName: string): Promise<void> {
  return invoke<void>('add_env_var_to_allowlist', { varName });
}

export async function removeEnvVar(varName: string): Promise<void> {
  return invoke<void>('remove_env_var_from_allowlist', { varName });
}

export async function listEnvVars(): Promise<EnvVarInfo[]> {
  return invoke<EnvVarInfo[]>('list_env_var_allowlist');
}

// ------------------------------------------------------------------
// Script types & wrappers
// ------------------------------------------------------------------

export interface ScriptInfo {
  id: number;
  script_id: string;
  script_name: string;
  domain: string;
  approved: boolean;
  created_at: string;
}

export interface ScriptAccessInfo {
  secret_name: string;
  approved: boolean;
  created_at: string;
}

export interface AuditEntry {
  event_type: string;
  script_id: string | null;
  secret_name: string | null;
  timestamp: string;
}

export async function listScripts(): Promise<ScriptInfo[]> {
  return invoke<ScriptInfo[]>('list_scripts_cmd');
}

export async function approveScript(scriptId: string): Promise<void> {
  return invoke<void>('approve_script_cmd', { scriptId });
}

export async function revokeScript(scriptId: string): Promise<void> {
  return invoke<void>('revoke_script', { scriptId });
}

export async function deleteScript(scriptId: string): Promise<void> {
  return invoke<void>('delete_script_cmd', { scriptId });
}

export async function listScriptAccess(scriptId: string): Promise<ScriptAccessInfo[]> {
  return invoke<ScriptAccessInfo[]>('list_script_access', { scriptId });
}

export async function setScriptSecretAccess(
  scriptId: string,
  secretName: string,
  approved: boolean,
): Promise<void> {
  return invoke<void>('set_script_secret_access', { scriptId, secretName, approved });
}

export async function getAuditLog(limit?: number): Promise<AuditEntry[]> {
  return invoke<AuditEntry[]>('get_audit_log', { limit: limit ?? null });
}

// ------------------------------------------------------------------
// Vault types & wrappers
// ------------------------------------------------------------------

export interface ImportedSecretInfo {
  name: string;
  blind: boolean;
  success: boolean;
  error: string | null;
  expires_at: string | null;
}

export async function exportVault(
  secretNames: string[],
  pin: string,
  filePath: string,
  markBlind: boolean,
  expiresAt: string | null,
): Promise<void> {
  return invoke<void>('export_vault_file', {
    secretNames,
    pin,
    filePath,
    markBlind,
    expiresAt,
  });
}

export async function importVault(
  filePath: string,
  pin: string,
): Promise<ImportedSecretInfo[]> {
  return invoke<ImportedSecretInfo[]>('import_vault_file', {
    filePath,
    pin,
  });
}
