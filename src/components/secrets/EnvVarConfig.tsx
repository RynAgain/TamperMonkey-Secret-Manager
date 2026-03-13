import { useState, useEffect, useCallback } from 'react';
import { Plus, Trash2, Loader2, AlertTriangle, CircleDot } from 'lucide-react';
import { EnvVarInfo, addEnvVar, removeEnvVar, listEnvVars } from '../../lib/tauri';

const NAME_PATTERN = /^[A-Za-z0-9_]+$/;

export default function EnvVarConfig() {
  const [envVars, setEnvVars] = useState<EnvVarInfo[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newVarName, setNewVarName] = useState('');
  const [adding, setAdding] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const fetchEnvVars = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const list = await listEnvVars();
      setEnvVars(list);
    } catch (err) {
      setError(String(err));
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchEnvVars();
  }, [fetchEnvVars]);

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const trimmed = newVarName.trim();
    if (!trimmed) {
      setError('Variable name is required.');
      return;
    }
    if (!NAME_PATTERN.test(trimmed)) {
      setError('Name must contain only alphanumeric characters and underscores.');
      return;
    }

    setAdding(true);
    try {
      await addEnvVar(trimmed);
      setNewVarName('');
      await fetchEnvVars();
    } catch (err) {
      setError(String(err));
    } finally {
      setAdding(false);
    }
  }

  async function handleRemove(varName: string) {
    setError(null);
    try {
      await removeEnvVar(varName);
      setConfirmDelete(null);
      await fetchEnvVars();
    } catch (err) {
      setError(String(err));
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-6 h-6 text-[var(--color-accent-gold)] animate-spin" />
        <span className="ml-3 text-[var(--color-text-secondary)] text-sm">Loading environment variables...</span>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-[var(--color-accent-gold)] text-xl font-heading tracking-wide">
          Environment Variables
        </h2>
      </div>

      {/* Info note */}
      <div className="info-banner mb-6 text-xs rounded px-4 py-3">
        Manage the allowlist of system environment variables that can be accessed via the HTTP API.
        Values are read from the system at runtime and are never stored to disk.
      </div>

      {/* Error banner */}
      {error && (
        <div className="error-banner mb-4 text-sm rounded px-4 py-3">
          {error}
        </div>
      )}

      {/* Add form */}
      <form onSubmit={handleAdd} className="flex items-center gap-3 mb-6">
        <input
          type="text"
          value={newVarName}
          onChange={(e) => setNewVarName(e.target.value)}
          placeholder="VARIABLE_NAME"
          className="input-deco flex-1 rounded px-3 py-2.5 text-sm font-mono"
        />
        <button
          type="submit"
          disabled={adding}
          className="btn-outlined flex items-center gap-2 px-4 py-2.5 rounded text-sm uppercase tracking-wider disabled:opacity-50"
        >
          {adding ? (
            <span className="inline-block w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
          ) : (
            <Plus className="w-4 h-4" />
          )}
          Add
        </button>
      </form>

      {/* Empty state */}
      {envVars.length === 0 && (
        <div className="text-center py-16">
          <div className="flex justify-center mb-4">
            <AlertTriangle className="w-10 h-10 text-[var(--color-accent-gold)] opacity-40" />
          </div>
          <p className="text-[var(--color-text-secondary)] text-sm">No environment variables on the allowlist.</p>
          <p className="text-[var(--color-text-muted)] text-xs mt-1">
            Add a variable name above to allow API access to its value.
          </p>
        </div>
      )}

      {/* Env var list */}
      {envVars.length > 0 && (
        <div className="table-deco rounded-lg overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[1fr_100px_80px] gap-4 px-4 py-3 table-deco-header">
            <span className="text-xs uppercase tracking-wider font-medium">
              Variable Name
            </span>
            <span className="text-xs uppercase tracking-wider font-medium">
              Status
            </span>
            <span className="text-xs uppercase tracking-wider font-medium text-right">
              Actions
            </span>
          </div>

          {/* Rows */}
          {envVars.map((ev, idx) => (
            <div key={ev.var_name}>
              <div className="grid grid-cols-[1fr_100px_80px] gap-4 px-4 py-3 items-center table-deco-row">
                <span className="text-[var(--color-text-primary)] text-sm font-mono truncate" title={ev.var_name}>
                  {ev.var_name}
                </span>
                <span className="flex items-center gap-1.5 text-xs">
                  <CircleDot
                    className={`w-3 h-3 ${ev.is_set ? 'text-[var(--color-success)]' : 'text-[var(--color-danger)]'}`}
                  />
                  <span className={ev.is_set ? 'text-[var(--color-success)]' : 'text-[var(--color-danger)]'}>
                    {ev.is_set ? 'Set' : 'Not found'}
                  </span>
                </span>
                <div className="flex items-center justify-end">
                  <button
                    onClick={() => setConfirmDelete(ev.var_name)}
                    className="btn-danger p-1.5 rounded"
                    title="Remove"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Delete confirmation */}
              {confirmDelete === ev.var_name && (
                <div className="px-4 py-3 bg-[var(--color-danger-bg)] border-t border-[var(--color-danger)] flex items-center justify-between">
                  <span className="text-[var(--color-danger)] text-sm">
                    Remove "{ev.var_name}" from allowlist?
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleRemove(ev.var_name)}
                      className="px-3 py-1 bg-[var(--color-danger)] text-white text-xs rounded font-medium hover:opacity-80 transition-opacity"
                    >
                      Remove
                    </button>
                    <button
                      onClick={() => setConfirmDelete(null)}
                      className="btn-ghost px-3 py-1 text-xs rounded"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}

              {/* Row separator */}
              {idx < envVars.length - 1 && (
                <div className="table-deco-separator" />
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
