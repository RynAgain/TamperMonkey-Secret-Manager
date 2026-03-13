import { useState, useEffect } from 'react';
import { save } from '@tauri-apps/plugin-dialog';
import { X, Download, Loader2, Check, Clock } from 'lucide-react';
import { SecretMetadata, listSecrets, exportVault } from '../../lib/tauri';

interface VaultExportProps {
  onClose: () => void;
}

/** Preset durations for the expiration picker. */
const DURATION_PRESETS = [
  { label: '1 hour', hours: 1 },
  { label: '6 hours', hours: 6 },
  { label: '24 hours', hours: 24 },
  { label: '7 days', hours: 7 * 24 },
  { label: '30 days', hours: 30 * 24 },
] as const;

export default function VaultExport({ onClose }: VaultExportProps) {
  const [secrets, setSecrets] = useState<SecretMetadata[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [markBlind, setMarkBlind] = useState(false);
  const [pin, setPin] = useState('');
  const [pinConfirm, setPinConfirm] = useState('');
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  // Expiration state
  const [enableExpiration, setEnableExpiration] = useState(false);
  const [expirationMode, setExpirationMode] = useState<'preset' | 'custom'>('preset');
  const [selectedPreset, setSelectedPreset] = useState(2); // default: 24 hours
  const [customDatetime, setCustomDatetime] = useState('');

  useEffect(() => {
    async function load() {
      try {
        const list = await listSecrets();
        setSecrets(list);
      } catch (err) {
        setError(String(err));
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  function toggleSecret(name: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }
      return next;
    });
  }

  function toggleAll() {
    if (selected.size === secrets.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(secrets.map((s) => s.name)));
    }
  }

  /** Compute the ISO 8601 UTC expiration timestamp from the selected option. */
  function computeExpiresAt(): string | null {
    if (!enableExpiration) return null;

    if (expirationMode === 'preset') {
      const preset = DURATION_PRESETS[selectedPreset];
      const expiryDate = new Date(Date.now() + preset.hours * 60 * 60 * 1000);
      return expiryDate.toISOString();
    }

    // Custom datetime -- convert local input to UTC ISO string
    if (!customDatetime) return null;
    const d = new Date(customDatetime);
    if (isNaN(d.getTime())) return null;
    return d.toISOString();
  }

  function validate(): string | null {
    if (selected.size === 0) return 'Select at least one secret to export.';
    if (pin.length < 6) return 'PIN must be at least 6 characters.';
    if (pin !== pinConfirm) return 'PIN and confirmation do not match.';
    if (enableExpiration && expirationMode === 'custom') {
      if (!customDatetime) return 'Select a custom expiration date and time.';
      const d = new Date(customDatetime);
      if (isNaN(d.getTime())) return 'Invalid expiration date/time.';
      if (d.getTime() <= Date.now()) return 'Expiration must be in the future.';
    }
    return null;
  }

  async function handleExport() {
    setError(null);
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    const filePath = await save({
      defaultPath: 'secrets.tmvault',
      filters: [{ name: 'TM Vault', extensions: ['tmvault'] }],
    });

    if (!filePath) return;

    setExporting(true);
    try {
      const expiresAt = computeExpiresAt();
      await exportVault(Array.from(selected), pin, filePath, markBlind, expiresAt);
      setSuccess(true);
    } catch (err) {
      setError(String(err));
    } finally {
      setExporting(false);
    }
  }

  /** Format the minimum datetime-local value (now). */
  function minDatetime(): string {
    const now = new Date();
    // datetime-local expects YYYY-MM-DDTHH:MM
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}:${pad(now.getMinutes())}`;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg mx-4">
        <div className="card-deco modal-gold-bar rounded-lg shadow-2xl overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--color-border-subtle)]">
            <h3 className="text-[var(--color-accent-gold)] text-lg font-heading tracking-wide">Export Vault</h3>
            <button onClick={onClose} className="text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Body */}
          <div className="px-6 py-5 max-h-[60vh] overflow-y-auto">
            {success ? (
              <div className="text-center py-8">
                <div className="flex justify-center mb-4">
                  <Check className="w-12 h-12 text-[var(--color-success)]" />
                </div>
                <p className="text-[var(--color-success)] text-lg font-medium mb-2">Vault exported successfully</p>
                <p className="text-[var(--color-text-secondary)] text-sm">
                  {selected.size} secret{selected.size !== 1 ? 's' : ''} exported.
                  {enableExpiration && (
                    <span className="block mt-1 text-[var(--color-warning)]">
                      <Clock className="w-3 h-3 inline mr-1" />
                      This vault has an expiration set.
                    </span>
                  )}
                </p>
                <button
                  onClick={onClose}
                  className="btn-outlined mt-6 px-6 py-2 rounded text-sm uppercase tracking-wider"
                >
                  Close
                </button>
              </div>
            ) : (
              <>
                {/* Error */}
                {error && (
                  <div className="error-banner mb-4 text-sm rounded px-3 py-2">
                    {error}
                  </div>
                )}

                {/* Secret selection */}
                <div className="mb-4">
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-[var(--color-accent-gold)] text-xs uppercase tracking-wider opacity-80">
                      Select Secrets ({selected.size}/{secrets.length})
                    </label>
                    <button
                      type="button"
                      onClick={toggleAll}
                      className="text-[var(--color-accent-gold)] text-xs hover:text-[var(--color-accent-gold-bright)] transition-colors"
                    >
                      {selected.size === secrets.length ? 'Deselect All' : 'Select All'}
                    </button>
                  </div>

                  {loading ? (
                    <div className="flex items-center justify-center py-6">
                      <Loader2 className="w-5 h-5 text-[var(--color-accent-gold)] animate-spin" />
                    </div>
                  ) : secrets.length === 0 ? (
                    <p className="text-[var(--color-text-muted)] text-sm py-4 text-center">No secrets to export.</p>
                  ) : (
                    <div className="border border-[var(--color-border-subtle)] rounded max-h-40 overflow-y-auto">
                      {secrets.map((secret) => (
                        <label
                          key={secret.name}
                          className="flex items-center gap-3 px-3 py-2 hover:bg-[var(--color-accent-gold-dim)] cursor-pointer transition-colors"
                        >
                          <input
                            type="checkbox"
                            checked={selected.has(secret.name)}
                            onChange={() => toggleSecret(secret.name)}
                            className="checkbox-gold"
                          />
                          <span className="text-[var(--color-text-primary)] text-sm font-mono truncate">
                            {secret.name}
                          </span>
                          {secret.blind && (
                            <span className="text-[var(--color-accent-gold)] text-[10px] uppercase tracking-wider">
                              blind
                            </span>
                          )}
                        </label>
                      ))}
                    </div>
                  )}
                </div>

                {/* Blind checkbox */}
                <label className="flex items-center gap-3 mb-4 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={markBlind}
                    onChange={(e) => setMarkBlind(e.target.checked)}
                    className="checkbox-gold"
                  />
                  <span className="text-[var(--color-text-secondary)] text-sm">
                    Mark all as blind (recipients cannot view values)
                  </span>
                </label>

                {/* Expiration section */}
                <div className="mb-4 border border-[var(--color-border-subtle)] rounded p-3">
                  <label className="flex items-center gap-3 cursor-pointer mb-2">
                    <input
                      type="checkbox"
                      checked={enableExpiration}
                      onChange={(e) => setEnableExpiration(e.target.checked)}
                      className="checkbox-gold"
                    />
                    <span className="text-[var(--color-text-secondary)] text-sm flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-[var(--color-accent-gold)]" />
                      Set expiration for this vault
                    </span>
                  </label>

                  {enableExpiration && (
                    <div className="ml-6 mt-2 space-y-3">
                      {/* Mode selector */}
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => setExpirationMode('preset')}
                          className={`px-3 py-1 text-xs rounded uppercase tracking-wider transition-colors ${
                            expirationMode === 'preset'
                              ? 'bg-[var(--color-accent-gold)] text-[#1A1A2E] font-medium'
                              : 'btn-ghost'
                          }`}
                        >
                          Preset
                        </button>
                        <button
                          type="button"
                          onClick={() => setExpirationMode('custom')}
                          className={`px-3 py-1 text-xs rounded uppercase tracking-wider transition-colors ${
                            expirationMode === 'custom'
                              ? 'bg-[var(--color-accent-gold)] text-[#1A1A2E] font-medium'
                              : 'btn-ghost'
                          }`}
                        >
                          Custom
                        </button>
                      </div>

                      {expirationMode === 'preset' ? (
                        <div className="flex flex-wrap gap-2">
                          {DURATION_PRESETS.map((preset, idx) => (
                            <button
                              key={preset.label}
                              type="button"
                              onClick={() => setSelectedPreset(idx)}
                              className={`px-3 py-1.5 text-xs rounded border transition-colors ${
                                selectedPreset === idx
                                  ? 'border-[var(--color-accent-gold)] text-[var(--color-accent-gold)] bg-[var(--color-accent-gold-dim)]'
                                  : 'border-[var(--color-border-subtle)] text-[var(--color-text-secondary)] hover:border-[var(--color-accent-gold)]'
                              }`}
                            >
                              {preset.label}
                            </button>
                          ))}
                        </div>
                      ) : (
                        <input
                          type="datetime-local"
                          value={customDatetime}
                          min={minDatetime()}
                          onChange={(e) => setCustomDatetime(e.target.value)}
                          className="input-deco w-full rounded px-3 py-2 text-sm"
                        />
                      )}
                    </div>
                  )}
                </div>

                {/* PIN fields */}
                <div className="mb-4">
                  <label className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80">
                    Encryption PIN (min 6 characters)
                  </label>
                  <input
                    type="password"
                    value={pin}
                    onChange={(e) => setPin(e.target.value)}
                    placeholder="Enter PIN..."
                    className="input-deco w-full rounded px-3 py-2.5 text-sm font-mono"
                  />
                </div>

                <div className="mb-4">
                  <label className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80">
                    Confirm PIN
                  </label>
                  <input
                    type="password"
                    value={pinConfirm}
                    onChange={(e) => setPinConfirm(e.target.value)}
                    placeholder="Confirm PIN..."
                    className="input-deco w-full rounded px-3 py-2.5 text-sm font-mono"
                  />
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
                    onClick={handleExport}
                    disabled={exporting || secrets.length === 0}
                    className="btn-gold flex items-center gap-2 px-5 py-2 text-sm rounded uppercase tracking-wider"
                  >
                    {exporting ? (
                      <span className="inline-block w-4 h-4 border-2 border-[#1A1A2E] border-t-transparent rounded-full animate-spin" />
                    ) : (
                      <Download className="w-4 h-4" />
                    )}
                    {exporting ? 'Exporting...' : 'Export'}
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
