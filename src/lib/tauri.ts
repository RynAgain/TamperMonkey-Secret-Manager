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

// ------------------------------------------------------------------
// Blind Code Module types & wrappers
// ------------------------------------------------------------------

export interface BlindCodeModuleMetadata {
  id: number;
  name: string;
  description: string;
  language: string;
  required_secrets: string[];
  allowed_params: string[];
  approved: boolean;
  blind: boolean;
  created_at: string;
  updated_at: string;
  expires_at: string | null;
}

export interface ImportedCodeModuleInfo {
  name: string;
  description: string;
  success: boolean;
  error: string | null;
}

export interface ScriptCodeAccessInfo {
  module_name: string;
  approved: boolean;
  created_at: string;
}

export async function listBlindCodeModules(): Promise<BlindCodeModuleMetadata[]> {
  return invoke<BlindCodeModuleMetadata[]>('list_blind_code_modules');
}

export async function importBlindCodeFile(
  filePath: string,
  pin: string,
): Promise<ImportedCodeModuleInfo> {
  return invoke<ImportedCodeModuleInfo>('import_blind_code_file', {
    filePath,
    pin,
  });
}

export async function exportBlindCodeFile(
  moduleName: string,
  pin: string,
  filePath: string,
  expiresAt?: string | null,
): Promise<void> {
  return invoke<void>('export_blind_code_file', {
    moduleName,
    pin,
    filePath,
    expiresAt: expiresAt ?? null,
  });
}

export async function createBlindCodeModule(
  name: string,
  description: string,
  language: string,
  code: string,
  requiredSecrets: string[],
  allowedParams: string[],
): Promise<void> {
  return invoke<void>('create_blind_code_module', {
    name,
    description,
    language,
    code,
    requiredSecrets,
    allowedParams,
  });
}

export async function approveBlindCodeModule(name: string): Promise<void> {
  return invoke<void>('approve_blind_code_module', { name });
}

export async function revokeBlindCodeModule(name: string): Promise<void> {
  return invoke<void>('revoke_blind_code_module', { name });
}

export async function deleteBlindCodeModule(name: string): Promise<void> {
  return invoke<void>('delete_blind_code_module', { name });
}

export async function listScriptCodeAccess(scriptId: string): Promise<ScriptCodeAccessInfo[]> {
  return invoke<ScriptCodeAccessInfo[]>('list_script_code_access', { scriptId });
}

export async function setScriptCodeModuleAccess(
  scriptId: string,
  moduleName: string,
  approved: boolean,
): Promise<void> {
  return invoke<void>('set_script_code_module_access', { scriptId, moduleName, approved });
}

export async function getBlindCodeModuleCode(name: string): Promise<string | null> {
  return invoke<string | null>('get_blind_code_module_code', { name });
}
