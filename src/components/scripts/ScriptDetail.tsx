import { useEffect, useState, useCallback } from 'react';
import { X, Loader2, CheckCircle, XCircle, Shield } from 'lucide-react';
import {
  ScriptInfo,
  ScriptAccessInfo,
  listScriptAccess,
  setScriptSecretAccess,
  approveScript,
  revokeScript,
} from '../../lib/tauri';

interface ScriptDetailProps {
  script: ScriptInfo;
  onClose: () => void;
  onRefresh: () => void;
}

export default function ScriptDetail({ script, onClose, onRefresh }: ScriptDetailProps) {
  const [accessList, setAccessList] = useState<ScriptAccessInfo[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [currentApproved, setCurrentApproved] = useState(script.approved);

  const fetchAccess = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const list = await listScriptAccess(script.script_id);
      setAccessList(list);
    } catch (err) {
      setError(String(err));
    } finally {
      setIsLoading(false);
    }
  }, [script.script_id]);

  useEffect(() => {
    fetchAccess();
  }, [fetchAccess]);

  async function handleToggleGlobal() {
    setError(null);
    try {
      if (currentApproved) {
        await revokeScript(script.script_id);
        setCurrentApproved(false);
      } else {
        await approveScript(script.script_id);
        setCurrentApproved(true);
      }
      onRefresh();
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleToggleAccess(secretName: string, approved: boolean) {
    setError(null);
    try {
      await setScriptSecretAccess(script.script_id, secretName, approved);
      await fetchAccess();
      onRefresh();
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleBulkAccess(approved: boolean) {
    setError(null);
    try {
      for (const access of accessList) {
        await setScriptSecretAccess(script.script_id, access.secret_name, approved);
      }
      await fetchAccess();
      onRefresh();
    } catch (err) {
      setError(String(err));
    }
  }

  function formatDate(iso: string): string {
    try {
      const d = new Date(iso);
      return d.toLocaleDateString(undefined, {
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

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="card-deco modal-gold-bar rounded-lg w-full max-w-2xl max-h-[80vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--color-border-subtle)]">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-[var(--color-accent-gold)]" />
            <div>
              <h2 className="text-[var(--color-accent-gold)] text-lg font-heading tracking-wide">
                {script.script_name}
              </h2>
              <p className="text-[var(--color-text-secondary)] text-xs font-mono">{script.script_id}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Script info */}
        <div className="px-6 py-4 border-b border-[var(--color-border-subtle)]">
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div>
              <span className="text-[var(--color-text-secondary)] text-xs uppercase tracking-wider block mb-1">Domain</span>
              <span className="text-[var(--color-text-primary)]">{script.domain}</span>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)] text-xs uppercase tracking-wider block mb-1">Status</span>
              <span className="flex items-center gap-1.5">
                {currentApproved ? (
                  <span className="badge-success px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wider">
                    Approved
                  </span>
                ) : (
                  <span className="badge-warning px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wider">
                    Pending
                  </span>
                )}
              </span>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)] text-xs uppercase tracking-wider block mb-1">Registered</span>
              <span className="text-[var(--color-text-primary)] text-xs">{formatDate(script.created_at)}</span>
            </div>
          </div>

          {/* Toggle global approval */}
          <div className="mt-4">
            <button
              onClick={handleToggleGlobal}
              className={`px-4 py-2 rounded text-xs font-medium uppercase tracking-wider transition-colors ${
                currentApproved
                  ? 'btn-outlined'
                  : 'border border-[var(--color-success)] text-[var(--color-success)] hover:bg-[var(--color-success-bg)]'
              }`}
            >
              {currentApproved ? 'Revoke Global Approval' : 'Approve Script'}
            </button>
          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="error-banner mx-6 mt-4 text-sm rounded px-4 py-3">
            {error}
          </div>
        )}

        {/* Per-secret access table */}
        <div className="flex-1 overflow-y-auto px-6 py-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-[var(--color-accent-gold)] text-sm font-heading tracking-wide uppercase">
              Secret Access
            </h3>
            {accessList.length > 0 && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleBulkAccess(true)}
                  className="px-3 py-1 text-xs border border-[var(--color-success)] text-[var(--color-success)] hover:bg-[var(--color-success-bg)] rounded transition-colors"
                >
                  Approve All
                </button>
                <button
                  onClick={() => handleBulkAccess(false)}
                  className="btn-danger px-3 py-1 text-xs rounded"
                >
                  Revoke All
                </button>
              </div>
            )}
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-10">
              <Loader2 className="w-5 h-5 text-[var(--color-accent-gold)] animate-spin" />
              <span className="ml-2 text-[var(--color-text-secondary)] text-sm">Loading access records...</span>
            </div>
          ) : accessList.length === 0 ? (
            <div className="text-center py-10">
              <p className="text-[var(--color-text-secondary)] text-sm">No secret access requests yet.</p>
              <p className="text-[var(--color-text-muted)] text-xs mt-1">
                Access records appear when the script requests specific secrets via the HTTP API.
              </p>
            </div>
          ) : (
            <div className="table-deco rounded-lg overflow-hidden">
              {/* Header */}
              <div className="grid grid-cols-[1fr_100px_160px_80px] gap-4 px-4 py-2 table-deco-header">
                <span className="text-xs uppercase tracking-wider font-medium">
                  Secret
                </span>
                <span className="text-xs uppercase tracking-wider font-medium">
                  Status
                </span>
                <span className="text-xs uppercase tracking-wider font-medium">
                  Requested
                </span>
                <span className="text-xs uppercase tracking-wider font-medium text-right">
                  Toggle
                </span>
              </div>
              {accessList.map((access, idx) => (
                <div key={access.secret_name}>
                  <div className="grid grid-cols-[1fr_100px_160px_80px] gap-4 px-4 py-2.5 items-center table-deco-row">
                    <span className="text-[var(--color-text-primary)] text-sm font-mono truncate">
                      {access.secret_name}
                    </span>
                    <span className="flex items-center gap-1.5 text-xs">
                      {access.approved ? (
                        <span className="badge-success px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wider">
                          Approved
                        </span>
                      ) : (
                        <span className="badge-danger px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wider">
                          Denied
                        </span>
                      )}
                    </span>
                    <span className="text-[var(--color-text-secondary)] text-xs">{formatDate(access.created_at)}</span>
                    <div className="flex justify-end">
                      {access.approved ? (
                        <button
                          onClick={() => handleToggleAccess(access.secret_name, false)}
                          className="btn-danger p-1.5 rounded"
                          title="Revoke access"
                        >
                          <XCircle className="w-3.5 h-3.5" />
                        </button>
                      ) : (
                        <button
                          onClick={() => handleToggleAccess(access.secret_name, true)}
                          className="p-1.5 border border-[var(--color-success)] text-[var(--color-success)] hover:bg-[var(--color-success-bg)] rounded transition-colors"
                          title="Approve access"
                        >
                          <CheckCircle className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                  {idx < accessList.length - 1 && (
                    <div className="table-deco-separator" />
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
