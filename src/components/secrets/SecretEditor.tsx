import { useState, useEffect } from 'react';
import { Eye, EyeOff, Save, X, ShieldAlert } from 'lucide-react';

interface SecretEditorProps {
  mode: 'create' | 'edit';
  blind?: boolean;
  initialName?: string;
  initialValue?: string;
  onSave: (name: string, value: string) => Promise<void>;
  onCancel: () => void;
}

/** Regex: only alphanumeric and underscores, non-empty */
const NAME_PATTERN = /^[A-Za-z0-9_]+$/;

export default function SecretEditor({
  mode,
  blind = false,
  initialName = '',
  initialValue = '',
  onSave,
  onCancel,
}: SecretEditorProps) {
  const [name, setName] = useState(initialName);
  const [value, setValue] = useState(initialValue);
  const [showValue, setShowValue] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setName(initialName);
    setValue(initialValue);
    setError(null);
  }, [initialName, initialValue, mode]);

  function validate(): string | null {
    if (!name.trim()) return 'Secret name is required.';
    if (!NAME_PATTERN.test(name))
      return 'Name must contain only alphanumeric characters and underscores (A-Z, a-z, 0-9, _).';
    if (!value) return 'Secret value is required.';
    return null;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    setSubmitting(true);
    try {
      await onSave(name, value);
    } catch (err) {
      setError(String(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg mx-4">
        {/* Modal card */}
        <div className="card-deco modal-gold-bar rounded-lg shadow-2xl overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--color-border-subtle)]">
            <h3 className="text-[var(--color-accent-gold)] text-lg font-heading tracking-wide">
              {mode === 'create' ? 'New Secret' : 'Edit Secret'}
            </h3>
            <button
              onClick={onCancel}
              className="text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Body */}
          {blind && mode === 'edit' ? (
            <div className="px-6 py-8 text-center">
              <div className="flex justify-center mb-4">
                <ShieldAlert className="w-12 h-12 text-[var(--color-accent-gold)] opacity-60" />
              </div>
              <p className="text-[var(--color-accent-gold)] text-lg font-heading mb-2">Blind Secret</p>
              <p className="text-[var(--color-text-secondary)] text-sm mb-6">
                This is a blind secret. Its value cannot be viewed or modified.
                It can only be accessed by approved scripts via the HTTP API.
              </p>
              <button
                type="button"
                onClick={onCancel}
                className="btn-outlined px-6 py-2 rounded text-sm uppercase tracking-wider"
              >
                Close
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="px-6 py-5">
              {/* Name field */}
              <div className="mb-4">
                <label
                  htmlFor="secret-name"
                  className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80"
                >
                  Name
                </label>
                <input
                  id="secret-name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  disabled={mode === 'edit'}
                  placeholder="MY_API_KEY"
                  autoFocus={mode === 'create'}
                  className="input-deco w-full rounded px-3 py-2.5 text-sm font-mono"
                />
                <p className="text-[var(--color-text-muted)] text-xs mt-1">
                  Alphanumeric and underscores only (e.g. GITHUB_TOKEN)
                </p>
              </div>

              {/* Value field */}
              <div className="mb-4">
                <label
                  htmlFor="secret-value"
                  className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80"
                >
                  Value
                </label>
                <div className="relative">
                  <textarea
                    id="secret-value"
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                    placeholder="Enter secret value..."
                    rows={4}
                    autoFocus={mode === 'edit'}
                    className="input-deco w-full rounded px-3 py-2.5 text-sm font-mono resize-y"
                    style={!showValue ? { WebkitTextSecurity: 'disc' } as React.CSSProperties : undefined}
                  />
                  <button
                    type="button"
                    onClick={() => setShowValue(!showValue)}
                    className="absolute top-2.5 right-2.5 text-[var(--color-accent-gold)] opacity-50 hover:opacity-100 transition-opacity"
                    tabIndex={-1}
                  >
                    {showValue ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Error */}
              {error && (
                <div className="error-banner mb-4 text-sm rounded px-3 py-2">
                  {error}
                </div>
              )}

              {/* Actions */}
              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={onCancel}
                  className="btn-ghost px-4 py-2 text-sm rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="btn-gold flex items-center gap-2 px-5 py-2 text-sm rounded uppercase tracking-wider"
                >
                  {submitting ? (
                    <span className="inline-block w-4 h-4 border-2 border-[#1A1A2E] border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <Save className="w-4 h-4" />
                  )}
                  {submitting ? 'Saving...' : 'Save'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
