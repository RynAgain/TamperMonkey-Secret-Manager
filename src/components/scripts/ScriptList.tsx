import { useState } from 'react';
import { Loader2, AlertTriangle, Trash2, CheckCircle, XCircle, Settings } from 'lucide-react';
import { ScriptInfo, approveScript, revokeScript, deleteScript } from '../../lib/tauri';

interface ScriptListProps {
  scripts: ScriptInfo[];
  isLoading: boolean;
  onRefresh: () => void;
  onManageAccess: (script: ScriptInfo) => void;
}

export default function ScriptList({
  scripts,
  isLoading,
  onRefresh,
  onManageAccess,
}: ScriptListProps) {
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

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

  async function handleApprove(scriptId: string) {
    setActionError(null);
    try {
      await approveScript(scriptId);
      onRefresh();
    } catch (err) {
      setActionError(String(err));
    }
  }

  async function handleRevoke(scriptId: string) {
    setActionError(null);
    try {
      await revokeScript(scriptId);
      onRefresh();
    } catch (err) {
      setActionError(String(err));
    }
  }

  async function handleDelete(scriptId: string) {
    setActionError(null);
    try {
      await deleteScript(scriptId);
      setConfirmDelete(null);
      onRefresh();
    } catch (err) {
      setActionError(String(err));
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-6 h-6 text-[var(--color-accent-gold)] animate-spin" />
        <span className="ml-3 text-[var(--color-text-secondary)] text-sm">Loading scripts...</span>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-[var(--color-accent-gold)] text-xl font-heading tracking-wide">Scripts</h2>
      </div>

      {/* Error banner */}
      {actionError && (
        <div className="error-banner mb-4 text-sm rounded px-4 py-3">
          {actionError}
        </div>
      )}

      {/* Empty state */}
      {scripts.length === 0 && (
        <div className="text-center py-16">
          <div className="flex justify-center mb-4">
            <AlertTriangle className="w-10 h-10 text-[var(--color-accent-gold)] opacity-40" />
          </div>
          <p className="text-[var(--color-text-secondary)] text-sm">No scripts have registered yet.</p>
          <p className="text-[var(--color-text-muted)] text-xs mt-1">
            Scripts will appear here when they first connect via the HTTP API.
          </p>
        </div>
      )}

      {/* Script list */}
      {scripts.length > 0 && (
        <div className="table-deco rounded-lg overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[1fr_140px_120px_100px_160px_120px] gap-4 px-4 py-3 table-deco-header">
            <span className="text-xs uppercase tracking-wider font-medium">
              Script Name
            </span>
            <span className="text-xs uppercase tracking-wider font-medium">
              Script ID
            </span>
            <span className="text-xs uppercase tracking-wider font-medium">
              Domain
            </span>
            <span className="text-xs uppercase tracking-wider font-medium">
              Status
            </span>
            <span className="text-xs uppercase tracking-wider font-medium">
              Created
            </span>
            <span className="text-xs uppercase tracking-wider font-medium text-right">
              Actions
            </span>
          </div>

          {/* Table rows */}
          {scripts.map((script, idx) => (
            <div key={script.id}>
              <div className="grid grid-cols-[1fr_140px_120px_100px_160px_120px] gap-4 px-4 py-3 items-center table-deco-row">
                <span className="text-[var(--color-text-primary)] text-sm truncate" title={script.script_name}>
                  {script.script_name}
                </span>
                <span className="text-[var(--color-text-secondary)] text-xs font-mono truncate" title={script.script_id}>
                  {script.script_id}
                </span>
                <span className="text-[var(--color-text-secondary)] text-xs truncate" title={script.domain}>
                  {script.domain}
                </span>
                <span className="flex items-center gap-1.5 text-xs">
                  {script.approved ? (
                    <span className="badge-success px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wider">
                      Approved
                    </span>
                  ) : (
                    <span className="badge-warning px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wider">
                      Pending
                    </span>
                  )}
                </span>
                <span className="text-[var(--color-text-secondary)] text-xs">{formatDate(script.created_at)}</span>
                <div className="flex items-center justify-end gap-1.5">
                  {/* Approve / Revoke toggle */}
                  {script.approved ? (
                    <button
                      onClick={() => handleRevoke(script.script_id)}
                      className="btn-outlined p-1.5 rounded"
                      title="Revoke approval"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                    </button>
                  ) : (
                    <button
                      onClick={() => handleApprove(script.script_id)}
                      className="p-1.5 border border-[var(--color-success)] text-[var(--color-success)] hover:bg-[var(--color-success-bg)] rounded transition-colors"
                      title="Approve script"
                    >
                      <CheckCircle className="w-3.5 h-3.5" />
                    </button>
                  )}
                  {/* Manage Access */}
                  <button
                    onClick={() => onManageAccess(script)}
                    className="btn-outlined p-1.5 rounded"
                    title="Manage secret access"
                  >
                    <Settings className="w-3.5 h-3.5" />
                  </button>
                  {/* Delete */}
                  <button
                    onClick={() => setConfirmDelete(script.script_id)}
                    className="btn-danger p-1.5 rounded"
                    title="Delete script"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Delete confirmation inline */}
              {confirmDelete === script.script_id && (
                <div className="px-4 py-3 bg-[var(--color-danger-bg)] border-t border-[var(--color-danger)] flex items-center justify-between">
                  <span className="text-[var(--color-danger)] text-sm">
                    Delete "{script.script_name}"? This removes all access records.
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleDelete(script.script_id)}
                      className="px-3 py-1 bg-[var(--color-danger)] text-white text-xs rounded font-medium hover:opacity-80 transition-opacity"
                    >
                      Delete
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
              {idx < scripts.length - 1 && (
                <div className="table-deco-separator" />
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
