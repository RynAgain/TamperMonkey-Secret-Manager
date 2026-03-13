import { useState, useEffect } from 'react';
import {
  Copy, Check, Sun, Moon, Lock, Info, Code2, Shield, RefreshCw,
  KeyRound, Timer, Eye, EyeOff,
} from 'lucide-react';
import { useTheme } from '../hooks/useTheme';
import { useAuthStore } from '../stores/auth';
import {
  getApiInfo, lockApp, rotateApiToken,
  changeMasterPassword, getAutoLockMinutes, setAutoLockMinutes,
} from '../lib/tauri';
import PasswordStrength from '../components/ui/PasswordStrength';

const AUTO_LOCK_OPTIONS = [
  { value: 0, label: 'Off' },
  { value: 1, label: '1 min' },
  { value: 5, label: '5 min' },
  { value: 10, label: '10 min' },
  { value: 15, label: '15 min' },
  { value: 30, label: '30 min' },
  { value: 60, label: '60 min' },
];

export default function Settings() {
  const { isDark, toggle } = useTheme();
  const { setUnlocked } = useAuthStore();
  const [port, setPort] = useState<number | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [isRotating, setIsRotating] = useState(false);

  // Change password state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [showCurrentPw, setShowCurrentPw] = useState(false);
  const [showNewPw, setShowNewPw] = useState(false);
  const [showConfirmPw, setShowConfirmPw] = useState(false);
  const [changePwLoading, setChangePwLoading] = useState(false);
  const [changePwError, setChangePwError] = useState<string | null>(null);
  const [changePwSuccess, setChangePwSuccess] = useState(false);

  // Auto-lock state
  const [autoLockMinutes, setAutoLockMinutesState] = useState<number>(15);
  const [autoLockLoading, setAutoLockLoading] = useState(false);

  useEffect(() => {
    async function loadSettings() {
      try {
        const info = await getApiInfo();
        setPort(info.port);
        setToken(info.token);
      } catch (err) {
        console.error('Failed to load API info:', err);
      }

      try {
        const mins = await getAutoLockMinutes();
        setAutoLockMinutesState(mins);
      } catch (err) {
        console.error('Failed to load auto-lock setting:', err);
      }
    }
    loadSettings();
  }, []);

  function copyToClipboard(text: string, field: string) {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  }

  function getHelperSnippet(): string {
    return `// TamperMonkey Secret Manager Helper
// Paste this into your TamperMonkey script
// Required: @grant GM_xmlhttpRequest

async function getSecret(name) {
    const PORT = ${port ?? 'PORT'};
    const TOKEN = '${token ?? 'TOKEN'}';
    return new Promise((resolve, reject) => {
        GM_xmlhttpRequest({
            method: 'POST',
            url: \`http://127.0.0.1:\${PORT}/api/secrets/\${name}\`,
            headers: {
                'Authorization': \`Bearer \${TOKEN}\`,
                'Content-Type': 'application/json'
            },
            data: JSON.stringify({
                script_id: GM_info.script.name,
                domain: window.location.hostname
            }),
            onload: (res) => {
                if (res.status === 200) resolve(res.responseText);
                else reject(new Error(\`Secret Manager: \${res.status} \${res.responseText}\`));
            },
            onerror: (err) => reject(err)
        });
    });
}`;
  }

  async function handleLock() {
    try {
      await lockApp();
      setUnlocked(false);
    } catch (err) {
      console.error('Failed to lock:', err);
    }
  }

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault();
    setChangePwError(null);
    setChangePwSuccess(false);

    // Validation
    if (!currentPassword) {
      setChangePwError('Current password is required.');
      return;
    }
    if (!newPassword) {
      setChangePwError('New password is required.');
      return;
    }
    if (newPassword.length < 8) {
      setChangePwError('New password must be at least 8 characters.');
      return;
    }
    if (newPassword !== confirmNewPassword) {
      setChangePwError('New passwords do not match.');
      return;
    }
    if (currentPassword === newPassword) {
      setChangePwError('New password must differ from current password.');
      return;
    }

    setChangePwLoading(true);
    try {
      await changeMasterPassword(currentPassword, newPassword);
      setChangePwSuccess(true);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmNewPassword('');
    } catch (err) {
      setChangePwError(String(err));
    } finally {
      setChangePwLoading(false);
    }
  }

  async function handleAutoLockChange(minutes: number) {
    setAutoLockLoading(true);
    try {
      await setAutoLockMinutes(minutes);
      setAutoLockMinutesState(minutes);
    } catch (err) {
      console.error('Failed to set auto-lock:', err);
    } finally {
      setAutoLockLoading(false);
    }
  }

  function CopyButton({ text, field }: { text: string; field: string }) {
    const isCopied = copiedField === field;
    return (
      <button
        onClick={() => copyToClipboard(text, field)}
        className="btn-outlined rounded px-3 py-1.5 text-xs flex items-center gap-1.5 uppercase tracking-wider"
      >
        {isCopied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
        {isCopied ? 'Copied' : 'Copy'}
      </button>
    );
  }

  function PasswordInput({
    id, value, onChange, show, onToggle, placeholder,
  }: {
    id: string;
    value: string;
    onChange: (v: string) => void;
    show: boolean;
    onToggle: () => void;
    placeholder: string;
  }) {
    return (
      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <KeyRound className="w-4 h-4 text-[var(--color-accent-gold)] opacity-50" />
        </div>
        <input
          id={id}
          type={show ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          className="input-deco w-full rounded pl-10 pr-10 py-2.5 text-sm"
        />
        <button
          type="button"
          onClick={onToggle}
          className="absolute inset-y-0 right-0 pr-3 flex items-center text-[var(--color-accent-gold)] opacity-50 hover:opacity-100 transition-opacity"
          tabIndex={-1}
        >
          {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-2xl">
      <h2 className="text-[var(--color-accent-gold)] text-xl font-heading tracking-wide mb-6">
        Settings
      </h2>

      {/* -- API Connection Info ----------------------------------------- */}
      <section className="card-deco rounded-lg p-6 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <Code2 className="w-5 h-5 text-[var(--color-accent-gold)]" />
          <h3 className="text-[var(--color-accent-gold)] text-sm font-heading tracking-wide uppercase">
            API Connection
          </h3>
        </div>

        <div className="space-y-3">
          {/* Port */}
          <div className="flex items-center justify-between">
            <div>
              <span className="text-[var(--color-text-secondary)] text-xs uppercase tracking-wider block mb-0.5">
                Port
              </span>
              <span className="text-[var(--color-text-primary)] font-mono text-sm">
                {port ?? 'Loading...'}
              </span>
            </div>
            {port && <CopyButton text={String(port)} field="port" />}
          </div>

          <div className="border-b border-[var(--color-border-subtle)]" />

          {/* Token */}
          <div className="flex items-center justify-between">
            <div className="min-w-0 flex-1 mr-4">
              <span className="text-[var(--color-text-secondary)] text-xs uppercase tracking-wider block mb-0.5">
                Bearer Token
              </span>
              <span className="text-[var(--color-text-primary)] font-mono text-xs truncate block">
                {token ?? 'Loading...'}
              </span>
            </div>
            {token && <CopyButton text={token} field="token" />}
          </div>
        </div>
      </section>

      {/* -- TamperMonkey Helper Snippet ---------------------------------- */}
      <section className="card-deco rounded-lg p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Info className="w-5 h-5 text-[var(--color-accent-gold)]" />
            <h3 className="text-[var(--color-accent-gold)] text-sm font-heading tracking-wide uppercase">
              TamperMonkey Helper Snippet
            </h3>
          </div>
          <button
            onClick={() => copyToClipboard(getHelperSnippet(), 'snippet')}
            className="btn-gold rounded px-3 py-1.5 text-xs flex items-center gap-1.5 uppercase tracking-wider"
          >
            {copiedField === 'snippet' ? (
              <Check className="w-3.5 h-3.5" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
            {copiedField === 'snippet' ? 'Copied' : 'Copy Snippet'}
          </button>
        </div>

        <div className="code-block rounded p-4 overflow-x-auto max-h-64 overflow-y-auto">
          <pre className="whitespace-pre text-xs">{getHelperSnippet()}</pre>
        </div>

        <p className="text-[var(--color-text-muted)] text-xs mt-3">
          Paste this helper function into your TamperMonkey script. Make sure to
          include <code className="text-[var(--color-accent-gold)] font-mono">@grant GM_xmlhttpRequest</code> in
          your script headers.
        </p>
      </section>

      {/* -- Theme -------------------------------------------------------- */}
      <section className="card-deco rounded-lg p-6 mb-6">
        <div className="flex items-center gap-2 mb-4">
          {isDark ? (
            <Moon className="w-5 h-5 text-[var(--color-accent-gold)]" />
          ) : (
            <Sun className="w-5 h-5 text-[var(--color-accent-gold)]" />
          )}
          <h3 className="text-[var(--color-accent-gold)] text-sm font-heading tracking-wide uppercase">
            Theme
          </h3>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <span className="text-[var(--color-text-primary)] text-sm">
              {isDark ? 'Dark Mode' : 'Light Mode'}
            </span>
            <p className="text-[var(--color-text-muted)] text-xs mt-0.5">
              Art Deco looks best in dark mode with gold accents.
            </p>
          </div>

          {/* Toggle switch */}
          <button
            onClick={toggle}
            className={`relative inline-flex h-7 w-12 items-center rounded-full transition-colors ${
              isDark
                ? 'bg-[var(--color-accent-gold)]'
                : 'bg-[var(--color-border-subtle)]'
            }`}
            role="switch"
            aria-checked={isDark}
          >
            <span
              className={`inline-block h-5 w-5 transform rounded-full bg-white shadow-md transition-transform ${
                isDark ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>
      </section>

      {/* -- Security ----------------------------------------------------- */}
      <section className="card-deco rounded-lg p-6 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-5 h-5 text-[var(--color-accent-gold)]" />
          <h3 className="text-[var(--color-accent-gold)] text-sm font-heading tracking-wide uppercase">
            Security
          </h3>
        </div>

        <div className="space-y-4">
          <div className="info-banner rounded px-4 py-3 text-xs">
            The API bearer token rotates automatically on every app restart.
            You can also manually rotate it below. Scripts must use the current token.
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={async () => {
                setIsRotating(true);
                try {
                  const newToken = await rotateApiToken();
                  setToken(newToken);
                } catch (err) {
                  console.error('Failed to rotate token:', err);
                } finally {
                  setIsRotating(false);
                }
              }}
              disabled={isRotating}
              className="btn-outlined rounded px-4 py-2.5 text-sm flex items-center gap-2 uppercase tracking-wider"
            >
              <RefreshCw className={`w-4 h-4 ${isRotating ? 'animate-spin' : ''}`} />
              {isRotating ? 'Rotating...' : 'Rotate Token'}
            </button>

            <button
              onClick={handleLock}
              className="btn-danger rounded px-4 py-2.5 text-sm flex items-center gap-2 uppercase tracking-wider"
            >
              <Lock className="w-4 h-4" />
              Lock App
            </button>
          </div>
        </div>
      </section>

      {/* -- Auto-Lock ---------------------------------------------------- */}
      <section className="card-deco rounded-lg p-6 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <Timer className="w-5 h-5 text-[var(--color-accent-gold)]" />
          <h3 className="text-[var(--color-accent-gold)] text-sm font-heading tracking-wide uppercase">
            Auto-Lock
          </h3>
        </div>

        <div className="space-y-3">
          <p className="text-[var(--color-text-secondary)] text-sm">
            Automatically lock the vault after a period of inactivity.
          </p>

          <div className="flex items-center gap-3">
            <label
              htmlFor="auto-lock-select"
              className="text-[var(--color-text-secondary)] text-xs uppercase tracking-wider"
            >
              Lock after inactivity:
            </label>
            <select
              id="auto-lock-select"
              value={autoLockMinutes}
              onChange={(e) => handleAutoLockChange(Number(e.target.value))}
              disabled={autoLockLoading}
              className="input-deco rounded px-3 py-2 text-sm min-w-[120px]"
            >
              {AUTO_LOCK_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            {autoLockLoading && (
              <span className="inline-block w-4 h-4 border-2 border-[var(--color-accent-gold)] border-t-transparent rounded-full animate-spin" />
            )}
          </div>
        </div>
      </section>

      {/* -- Change Master Password --------------------------------------- */}
      <section className="card-deco rounded-lg p-6 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <KeyRound className="w-5 h-5 text-[var(--color-accent-gold)]" />
          <h3 className="text-[var(--color-accent-gold)] text-sm font-heading tracking-wide uppercase">
            Change Master Password
          </h3>
        </div>

        <form onSubmit={handleChangePassword} className="space-y-4">
          <div className="info-banner rounded px-4 py-3 text-xs">
            Changing your master password will re-encrypt all stored secrets.
            This may take a moment if you have many secrets.
          </div>

          {/* Current Password */}
          <div>
            <label
              htmlFor="current-password"
              className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80"
            >
              Current Password
            </label>
            <PasswordInput
              id="current-password"
              value={currentPassword}
              onChange={setCurrentPassword}
              show={showCurrentPw}
              onToggle={() => setShowCurrentPw(!showCurrentPw)}
              placeholder="Enter current password"
            />
          </div>

          {/* New Password */}
          <div>
            <label
              htmlFor="new-password"
              className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80"
            >
              New Password
            </label>
            <PasswordInput
              id="new-password"
              value={newPassword}
              onChange={setNewPassword}
              show={showNewPw}
              onToggle={() => setShowNewPw(!showNewPw)}
              placeholder="Minimum 8 characters"
            />
            <PasswordStrength password={newPassword} />
          </div>

          {/* Confirm New Password */}
          <div>
            <label
              htmlFor="confirm-new-password"
              className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80"
            >
              Confirm New Password
            </label>
            <PasswordInput
              id="confirm-new-password"
              value={confirmNewPassword}
              onChange={setConfirmNewPassword}
              show={showConfirmPw}
              onToggle={() => setShowConfirmPw(!showConfirmPw)}
              placeholder="Re-enter new password"
            />
          </div>

          {/* Error message */}
          {changePwError && (
            <div className="error-banner text-sm text-center rounded px-3 py-2">
              {changePwError}
            </div>
          )}

          {/* Success message */}
          {changePwSuccess && (
            <div
              className="text-sm text-center rounded px-3 py-2"
              style={{
                color: 'var(--color-success)',
                background: 'var(--color-success-bg)',
                border: '1px solid var(--color-success)',
              }}
            >
              Master password changed successfully. All secrets have been re-encrypted.
            </div>
          )}

          <button
            type="submit"
            disabled={changePwLoading}
            className="btn-gold rounded px-4 py-2.5 text-sm flex items-center gap-2 uppercase tracking-wider"
          >
            {changePwLoading ? (
              <span className="inline-block w-4 h-4 border-2 border-[#1A1A2E] border-t-transparent rounded-full animate-spin" />
            ) : (
              <KeyRound className="w-4 h-4" />
            )}
            {changePwLoading ? 'Re-encrypting...' : 'Change Password'}
          </button>
        </form>
      </section>

      {/* -- About -------------------------------------------------------- */}
      <section className="card-deco rounded-lg p-6">
        <h3 className="text-[var(--color-accent-gold)] text-sm font-heading tracking-wide uppercase mb-3">
          About
        </h3>
        <div className="space-y-1.5 text-sm">
          <div className="flex items-center justify-between">
            <span className="text-[var(--color-text-secondary)]">Version</span>
            <span className="text-[var(--color-text-primary)] font-mono">0.1.0</span>
          </div>
          <div className="border-b border-[var(--color-border-subtle)]" />
          <p className="text-[var(--color-text-muted)] text-xs pt-2">
            TamperMonkey Secret Manager is a local-only desktop vault for managing
            secrets used by TamperMonkey userscripts. All data is encrypted with
            AES-256-GCM and keys are derived using Argon2id.
          </p>
        </div>
      </section>
    </div>
  );
}
