import { useEffect, useState, useCallback } from 'react';
import { Lock, ShieldCheck, Key, Terminal, Archive, Download, Upload, ScrollText, FileCode, Settings } from 'lucide-react';
import { useAuthStore } from '../stores/auth';
import { useSecretsStore } from '../stores/secrets';
import { useScriptsStore } from '../stores/scripts';
import {
  lockApp,
  listSecrets,
  createSecret,
  updateSecret,
  deleteSecret,
  getSecret,
  listScripts,
  SecretMetadata,
  ScriptInfo,
} from '../lib/tauri';
import SecretList from '../components/secrets/SecretList';
import SecretEditor from '../components/secrets/SecretEditor';
import EnvVarConfig from '../components/secrets/EnvVarConfig';
import VaultExport from '../components/vault/VaultExport';
import VaultImport from '../components/vault/VaultImport';
import ScriptListView from '../components/scripts/ScriptList';
import ScriptDetail from '../components/scripts/ScriptDetail';
import AuditLog from '../components/audit/AuditLog';
import AccessRequestToast from '../components/ui/AccessRequestToast';
import SettingsView from './Settings';

type EditorState =
  | { open: false }
  | { open: true; mode: 'create' }
  | { open: true; mode: 'edit'; secret: SecretMetadata; currentValue: string };

type ActiveTab = 'secrets' | 'envvars' | 'vault' | 'scripts' | 'audit' | 'settings';

export default function Dashboard() {
  const { setUnlocked } = useAuthStore();
  const { secrets, isLoading, error, setSecrets, setLoading, setError } = useSecretsStore();
  const {
    scripts,
    isLoading: scriptsLoading,
    setScripts: setScriptsState,
    setLoading: setScriptsLoading,
    setError: setScriptsError,
    selectedScript,
    setSelectedScript,
  } = useScriptsStore();
  const [editor, setEditor] = useState<EditorState>({ open: false });
  const [activeTab, setActiveTab] = useState<ActiveTab>('secrets');
  const [showVaultExport, setShowVaultExport] = useState(false);
  const [showVaultImport, setShowVaultImport] = useState(false);

  const fetchSecrets = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await listSecrets();
      setSecrets(list);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [setSecrets, setLoading, setError]);

  const fetchScripts = useCallback(async () => {
    setScriptsLoading(true);
    setScriptsError(null);
    try {
      const list = await listScripts();
      setScriptsState(list);
    } catch (err) {
      setScriptsError(String(err));
    } finally {
      setScriptsLoading(false);
    }
  }, [setScriptsState, setScriptsLoading, setScriptsError]);

  useEffect(() => {
    fetchSecrets();
  }, [fetchSecrets]);

  useEffect(() => {
    if (activeTab === 'scripts') {
      fetchScripts();
    }
  }, [activeTab, fetchScripts]);

  async function handleLock() {
    try {
      await lockApp();
      setUnlocked(false);
    } catch (err) {
      console.error('Failed to lock:', err);
    }
  }

  function handleAdd() {
    setEditor({ open: true, mode: 'create' });
  }

  async function handleEdit(secret: SecretMetadata) {
    if (secret.blind) {
      setEditor({
        open: true,
        mode: 'edit',
        secret,
        currentValue: '',
      });
      return;
    }
    try {
      const full = await getSecret(secret.name);
      setEditor({
        open: true,
        mode: 'edit',
        secret,
        currentValue: full?.value ?? '',
      });
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleDelete(name: string) {
    try {
      await deleteSecret(name);
      await fetchSecrets();
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleSave(name: string, value: string) {
    if (editor.open && editor.mode === 'create') {
      await createSecret(name, value);
    } else {
      await updateSecret(name, value);
    }
    setEditor({ open: false });
    await fetchSecrets();
  }

  function handleCancel() {
    setEditor({ open: false });
  }

  function handleManageAccess(script: ScriptInfo) {
    setSelectedScript(script);
  }

  const tabs: { id: ActiveTab; label: string; icon: React.ReactNode }[] = [
    { id: 'secrets', label: 'Secrets', icon: <Key className="w-4 h-4" /> },
    { id: 'envvars', label: 'Env Vars', icon: <Terminal className="w-4 h-4" /> },
    { id: 'vault', label: 'Vault', icon: <Archive className="w-4 h-4" /> },
    { id: 'scripts', label: 'Scripts', icon: <FileCode className="w-4 h-4" /> },
    { id: 'audit', label: 'Activity Log', icon: <ScrollText className="w-4 h-4" /> },
    { id: 'settings', label: 'Settings', icon: <Settings className="w-4 h-4" /> },
  ];

  return (
    <div className="min-h-screen flex bg-[var(--color-bg-primary)]">
      {/* Sidebar */}
      <aside className="w-64 flex-shrink-0 sidebar-deco flex flex-col">
        {/* Brand */}
        <div className="px-5 py-6 border-b border-[var(--color-border-subtle)]">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-8 h-8 text-[var(--color-accent-gold)]" strokeWidth={1.5} />
            <div>
              <h1 className="text-[var(--color-accent-gold)] text-lg font-heading tracking-wide leading-tight">
                TM Secret
              </h1>
              <span className="text-[var(--color-accent-gold)] text-xs font-heading tracking-widest uppercase opacity-60">
                Manager
              </span>
            </div>
          </div>
          {/* Small gold diamond */}
          <div className="divider-diamond mt-4">
            <div className="w-1.5 h-1.5 rotate-45 bg-[var(--color-accent-gold)] opacity-40" />
          </div>
        </div>

        {/* Navigation tabs */}
        <nav className="flex-1 py-4 px-3">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-r text-sm font-medium mb-1
                         ${
                           activeTab === tab.id
                             ? 'sidebar-nav-active'
                             : 'sidebar-nav-item'
                         }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </nav>

        {/* Lock button */}
        <div className="px-4 py-4 border-t border-[var(--color-border-subtle)]">
          <button
            onClick={handleLock}
            className="btn-outlined w-full flex items-center justify-center gap-2 px-4 py-2.5
                       rounded text-sm uppercase tracking-wider"
          >
            <Lock className="w-4 h-4" />
            Lock Vault
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 p-8 overflow-y-auto">
        {/* Error banner */}
        {error && (
          <div className="error-banner mb-6 text-sm rounded px-4 py-3">
            {error}
          </div>
        )}

        {/* Secrets tab */}
        {activeTab === 'secrets' && (
          <SecretList
            secrets={secrets}
            isLoading={isLoading}
            onAdd={handleAdd}
            onEdit={handleEdit}
            onDelete={handleDelete}
          />
        )}

        {/* Env Vars tab */}
        {activeTab === 'envvars' && <EnvVarConfig />}

        {/* Vault tab */}
        {activeTab === 'vault' && (
          <div>
            <h2 className="text-[var(--color-accent-gold)] text-xl font-heading tracking-wide mb-6">
              Vault Files
            </h2>

            <div className="info-banner text-xs rounded px-4 py-3 mb-6">
              Export secrets to encrypted <code className="text-[var(--color-accent-gold)] font-mono">.tmvault</code> files
              for secure transfer, or import vault files received from others.
              Vault files are protected with a PIN-derived encryption key.
            </div>

            <div className="grid grid-cols-2 gap-6">
              {/* Export card */}
              <button
                onClick={() => setShowVaultExport(true)}
                className="group card-deco flex flex-col items-center gap-4 p-8 rounded-lg
                           hover:border-[var(--color-border)] transition-all text-center"
              >
                <Download className="w-10 h-10 text-[var(--color-accent-gold)] opacity-60 group-hover:opacity-100 transition-opacity" />
                <div>
                  <p className="text-[var(--color-accent-gold)] text-sm font-medium uppercase tracking-wider mb-1">
                    Export
                  </p>
                  <p className="text-[var(--color-text-secondary)] text-xs">
                    Select secrets and export to an encrypted vault file.
                  </p>
                </div>
              </button>

              {/* Import card */}
              <button
                onClick={() => setShowVaultImport(true)}
                className="group card-deco flex flex-col items-center gap-4 p-8 rounded-lg
                           hover:border-[var(--color-border)] transition-all text-center"
              >
                <Upload className="w-10 h-10 text-[var(--color-accent-gold)] opacity-60 group-hover:opacity-100 transition-opacity" />
                <div>
                  <p className="text-[var(--color-accent-gold)] text-sm font-medium uppercase tracking-wider mb-1">
                    Import
                  </p>
                  <p className="text-[var(--color-text-secondary)] text-xs">
                    Decrypt and import secrets from a vault file.
                  </p>
                </div>
              </button>
            </div>
          </div>
        )}

        {/* Scripts tab */}
        {activeTab === 'scripts' && (
          <ScriptListView
            scripts={scripts}
            isLoading={scriptsLoading}
            onRefresh={fetchScripts}
            onManageAccess={handleManageAccess}
          />
        )}

        {/* Audit Log tab */}
        {activeTab === 'audit' && <AuditLog />}

        {/* Settings tab */}
        {activeTab === 'settings' && <SettingsView />}
      </main>

      {/* Editor modal */}
      {editor.open && (
        <SecretEditor
          mode={editor.mode}
          blind={editor.mode === 'edit' ? editor.secret.blind : false}
          initialName={editor.mode === 'edit' ? editor.secret.name : ''}
          initialValue={editor.mode === 'edit' ? editor.currentValue : ''}
          onSave={handleSave}
          onCancel={handleCancel}
        />
      )}

      {/* Vault export modal */}
      {showVaultExport && (
        <VaultExport onClose={() => setShowVaultExport(false)} />
      )}

      {/* Vault import modal */}
      {showVaultImport && (
        <VaultImport
          onClose={() => setShowVaultImport(false)}
          onImported={fetchSecrets}
        />
      )}

      {/* Script detail modal */}
      {selectedScript && (
        <ScriptDetail
          script={selectedScript}
          onClose={() => setSelectedScript(null)}
          onRefresh={fetchScripts}
        />
      )}

      {/* Access request toasts from HTTP API */}
      <AccessRequestToast />
    </div>
  );
}
