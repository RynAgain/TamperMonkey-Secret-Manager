import { useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { X, Upload, Check, AlertTriangle } from 'lucide-react';
import { ImportedCodeModuleInfo, importBlindCodeFile } from '../../lib/tauri';

interface BlindCodeImportProps {
  onClose: () => void;
  onImported: () => void;
}

export default function BlindCodeImport({ onClose, onImported }: BlindCodeImportProps) {
  const [filePath, setFilePath] = useState<string | null>(null);
  const [pin, setPin] = useState('');
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImportedCodeModuleInfo | null>(null);

  async function handleBrowse() {
    const selected = await open({
      multiple: false,
      filters: [{ name: 'TM Code Module', extensions: ['tmcode'] }],
    });

    if (selected) {
      setFilePath(selected as string);
    }
  }

  function validate(): string | null {
    if (!filePath) return 'Select a .tmcode file first.';
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
      const res = await importBlindCodeFile(filePath!, pin);
      setResult(res);
      onImported();
    } catch (err) {
      setError(String(err));
    } finally {
      setImporting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg mx-4">
        <div className="card-deco modal-gold-bar rounded-lg shadow-2xl overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--color-border-subtle)]">
            <h3 className="text-[var(--color-accent-gold)] text-lg font-heading tracking-wide">Import Code Module</h3>
            <button onClick={onClose} className="text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Body */}
          <div className="px-6 py-5 max-h-[60vh] overflow-y-auto">
            {result ? (
              /* Results view */
              <div>
                <div className="flex items-center gap-3 mb-4">
                  {result.success ? (
                    <Check className="w-6 h-6 text-[var(--color-success)]" />
                  ) : (
                    <AlertTriangle className="w-6 h-6 text-[var(--color-danger)]" />
                  )}
                  <p className="text-[var(--color-text-primary)] text-sm">
                    {result.success ? 'Import successful' : 'Import failed'}
                  </p>
                </div>

                <div className="border border-[var(--color-border-subtle)] rounded p-4 mb-4">
                  <div className="mb-2">
                    <span className="text-[var(--color-text-muted)] text-xs uppercase tracking-wider block mb-0.5">
                      Module Name
                    </span>
                    <span className="text-[var(--color-text-primary)] text-sm font-mono">{result.name}</span>
                  </div>
                  <div className="mb-2">
                    <span className="text-[var(--color-text-muted)] text-xs uppercase tracking-wider block mb-0.5">
                      Description
                    </span>
                    <span className="text-[var(--color-text-secondary)] text-sm">{result.description}</span>
                  </div>
                  {result.error && (
                    <div className="mt-2">
                      <span className="text-[var(--color-danger)] text-xs">{result.error}</span>
                    </div>
                  )}
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
                    Code Module File
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
                    Imported code modules require explicit approval before scripts can execute them.
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
