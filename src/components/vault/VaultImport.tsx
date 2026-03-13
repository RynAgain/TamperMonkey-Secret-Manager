import { useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { X, Upload, Check, AlertTriangle, Clock } from 'lucide-react';
import { ImportedSecretInfo, importVault } from '../../lib/tauri';

interface VaultImportProps {
  onClose: () => void;
  onImported: () => void;
}

/** Format an ISO timestamp as a human-readable local date/time. */
function formatExpiry(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

/** Compute how much time remains until the given ISO timestamp. */
function timeRemaining(iso: string): string {
  try {
    const now = Date.now();
    const expiry = new Date(iso).getTime();
    const diffMs = expiry - now;
    if (diffMs <= 0) return 'Expired';

    const hours = Math.floor(diffMs / (1000 * 60 * 60));
    const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));

    if (hours >= 24) {
      const days = Math.floor(hours / 24);
      return `${days}d ${hours % 24}h remaining`;
    }
    if (hours > 0) return `${hours}h ${minutes}m remaining`;
    return `${minutes}m remaining`;
  } catch {
    return '';
  }
}

/** Check if an ISO timestamp is within the next 24 hours. */
function isExpiringSoon(iso: string): boolean {
  try {
    const diffMs = new Date(iso).getTime() - Date.now();
    return diffMs > 0 && diffMs < 24 * 60 * 60 * 1000;
  } catch {
    return false;
  }
}

export default function VaultImport({ onClose, onImported }: VaultImportProps) {
  const [filePath, setFilePath] = useState<string | null>(null);
  const [pin, setPin] = useState('');
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<ImportedSecretInfo[] | null>(null);

  async function handleBrowse() {
    const selected = await open({
      multiple: false,
      filters: [{ name: 'TM Vault', extensions: ['tmvault'] }],
    });

    if (selected) {
      setFilePath(selected as string);
    }
  }

  function validate(): string | null {
    if (!filePath) return 'Select a .tmvault file first.';
    if (pin.length < 6) return 'PIN must be at least 6 characters.';
    return null;
  }

  async function handleImport() {
    setError(null);
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    setImporting(true);
    try {
      const res = await importVault(filePath!, pin);
      setResults(res);
      onImported();
    } catch (err) {
      setError(String(err));
    } finally {
      setImporting(false);
    }
  }

  const successCount = results?.filter((r) => r.success).length ?? 0;
  const failCount = results?.filter((r) => !r.success).length ?? 0;

  // Check if any imported secrets have expiration
  const vaultExpiresAt = results?.[0]?.expires_at ?? null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg mx-4">
        <div className="card-deco modal-gold-bar rounded-lg shadow-2xl overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--color-border-subtle)]">
            <h3 className="text-[var(--color-accent-gold)] text-lg font-heading tracking-wide">Import Vault</h3>
            <button onClick={onClose} className="text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Body */}
          <div className="px-6 py-5 max-h-[60vh] overflow-y-auto">
            {results ? (
              /* Results view */
              <div>
                <div className="flex items-center gap-3 mb-4">
                  <Check className="w-6 h-6 text-[var(--color-success)]" />
                  <p className="text-[var(--color-text-primary)] text-sm">
                    Import complete: {successCount} succeeded, {failCount} failed
                  </p>
                </div>

                {/* Expiration banner */}
                {vaultExpiresAt && (
                  <div className={`mb-4 flex items-start gap-2 text-xs rounded px-3 py-2 ${
                    isExpiringSoon(vaultExpiresAt)
                      ? 'bg-[var(--color-warning)]/10 border border-[var(--color-warning)]/30'
                      : 'info-banner'
                  }`}>
                    <Clock className={`w-4 h-4 flex-shrink-0 mt-0.5 ${
                      isExpiringSoon(vaultExpiresAt) ? 'text-[var(--color-warning)]' : 'text-[var(--color-accent-gold)]'
                    }`} />
                    <div>
                      <span className={isExpiringSoon(vaultExpiresAt) ? 'text-[var(--color-warning)]' : ''}>
                        Imported secrets expire: {formatExpiry(vaultExpiresAt)}
                      </span>
                      <span className="block text-[var(--color-text-muted)] mt-0.5">
                        {timeRemaining(vaultExpiresAt)}
                      </span>
                    </div>
                  </div>
                )}

                <div className="border border-[var(--color-border-subtle)] rounded max-h-48 overflow-y-auto mb-4">
                  {results.map((r) => (
                    <div
                      key={r.name}
                      className="flex items-center justify-between px-3 py-2 border-b border-[var(--color-border-subtle)] last:border-b-0"
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-[var(--color-text-primary)] text-sm font-mono truncate">
                          {r.name}
                        </span>
                        {r.blind && (
                          <span className="text-[var(--color-accent-gold)] text-[10px] uppercase tracking-wider">
                            blind
                          </span>
                        )}
                        {r.expires_at && (
                          <span className="text-[var(--color-text-muted)] text-[10px] uppercase tracking-wider flex items-center gap-0.5">
                            <Clock className="w-2.5 h-2.5" />
                            timed
                          </span>
                        )}
                      </div>
                      {r.success ? (
                        <Check className="w-4 h-4 text-[var(--color-success)] flex-shrink-0" />
                      ) : (
                        <span className="text-[var(--color-danger)] text-xs truncate max-w-[200px]" title={r.error ?? ''}>
                          {r.error ?? 'Failed'}
                        </span>
                      )}
                    </div>
                  ))}
                </div>

                <div className="flex justify-end">
                  <button
                    onClick={onClose}
                    className="btn-outlined px-6 py-2 rounded text-sm uppercase tracking-wider"
                  >
                    Close
                  </button>
                </div>
              </div>
            ) : (
              /* Import form */
              <>
                {/* Error */}
                {error && (
                  <div className="error-banner mb-4 text-sm rounded px-3 py-2">
                    {error}
                  </div>
                )}

                {/* File selection */}
                <div className="mb-4">
                  <label className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80">
                    Vault File
                  </label>
                  <div className="flex items-center gap-3">
                    <button
                      type="button"
                      onClick={handleBrowse}
                      className="btn-outlined px-4 py-2.5 text-sm rounded"
                    >
                      Browse...
                    </button>
                    <span className="text-[var(--color-text-secondary)] text-sm truncate flex-1 font-mono">
                      {filePath ?? 'No file selected'}
                    </span>
                  </div>
                </div>

                {/* PIN */}
                <div className="mb-4">
                  <label className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80">
                    Decryption PIN
                  </label>
                  <input
                    type="password"
                    value={pin}
                    onChange={(e) => setPin(e.target.value)}
                    placeholder="Enter PIN..."
                    className="input-deco w-full rounded px-3 py-2.5 text-sm font-mono"
                  />
                </div>

                {/* Warning */}
                <div className="info-banner mb-4 flex items-start gap-2 text-xs rounded px-3 py-2">
                  <AlertTriangle className="w-4 h-4 text-[var(--color-warning)] flex-shrink-0 mt-0.5" />
                  <span>
                    Secrets with duplicate names will fail to import. Existing secrets will not be overwritten.
                  </span>
                </div>

                {/* Actions */}
                <div className="flex items-center justify-end gap-3 pt-2">
                  <button
                    type="button"
                    onClick={onClose}
                    className="btn-ghost px-4 py-2 text-sm rounded"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={handleImport}
                    disabled={importing}
                    className="btn-gold flex items-center gap-2 px-5 py-2 text-sm rounded uppercase tracking-wider"
                  >
                    {importing ? (
                      <span className="inline-block w-4 h-4 border-2 border-[#1A1A2E] border-t-transparent rounded-full animate-spin" />
                    ) : (
                      <Upload className="w-4 h-4" />
                    )}
                    {importing ? 'Importing...' : 'Import'}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
