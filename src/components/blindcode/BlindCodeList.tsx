import { useState } from 'react';
import { Loader2, AlertTriangle, Trash2, CheckCircle, XCircle, Lock, Unlock, Clock, Tag, Settings } from 'lucide-react';
import {
  BlindCodeModuleMetadata,
  approveBlindCodeModule,
  revokeBlindCodeModule,
  deleteBlindCodeModule,
} from '../../lib/tauri';

interface BlindCodeListProps {
  modules: BlindCodeModuleMetadata[];
  isLoading: boolean;
  onRefresh: () => void;
  onManageModule: (module: BlindCodeModuleMetadata) => void;
  onImport: () => void;
  onCreate: () => void;
}

export default function BlindCodeList({
  modules,
  isLoading,
  onRefresh,
  onManageModule,
  onImport,
  onCreate,
}: BlindCodeListProps) {
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

  function isExpired(iso: string): boolean {
    try {
      return new Date(iso).getTime() <= Date.now();
    } catch {
      return false;
    }
  }

  async function handleApprove(name: string) {
    setActionError(null);
    try {
      await approveBlindCodeModule(name);
      onRefresh();
    } catch (err) {
      setActionError(String(err));
    }
  }

  async function handleRevoke(name: string) {
    setActionError(null);
    try {
      await revokeBlindCodeModule(name);
      onRefresh();
    } catch (err) {
      setActionError(String(err));
    }
  }

  async function handleDelete(name: string) {
    setActionError(null);
    try {
      await deleteBlindCodeModule(name);
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
        <span className="ml-3 text-[var(--color-text-secondary)] text-sm">Loading code modules...</span>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-[var(--color-accent-gold)] text-xl font-heading tracking-wide">Blind Code Modules</h2>
        <div className="flex items-center gap-2">
          <button
            onClick={onImport}
            className="btn-outlined px-4 py-2 rounded text-xs uppercase tracking-wider"
          >
            Import
          </button>
          <button
            onClick={onCreate}
            className="btn-gold px-4 py-2 rounded text-xs uppercase tracking-wider"
          >
            Create Module
          </button>
        </div>
      </div>

      {/* Error banner */}
      {actionError && (
        <div className="error-banner mb-4 text-sm rounded px-4 py-3">
          {actionError}
        </div>
      )}

      {/* Empty state */}
      {modules.length === 0 && (
        <div className="text-center py-16">
          <div className="flex justify-center mb-4">
            <AlertTriangle className="w-10 h-10 text-[var(--color-accent-gold)] opacity-40" />
          </div>
          <p className="text-[var(--color-text-secondary)] text-sm">No blind code modules found.</p>
          <p className="text-[var(--color-text-muted)] text-xs mt-1">
            Import a .tmcode file or create a new module to get started.
          </p>
        </div>
      )}

      {/* Module cards */}
      {modules.length > 0 && (
        <div className="space-y-3">
          {modules.map((mod) => (
            <div key={mod.id} className="card-deco rounded-lg overflow-hidden">
              <div className="px-5 py-4">
                {/* Top row: name + badges + actions */}
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    {/* Name */}
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="text-[var(--color-text-primary)] text-sm font-semibold truncate">
                        {mod.name}
                      </h3>
                      {/* Language badge */}
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wider bg-[var(--color-bg-secondary)] text-[var(--color-text-secondary)] border border-[var(--color-border-subtle)]">
                        {mod.language === 'rhai' ? 'Rhai' : mod.language === 'python' ? 'Python' : mod.language === 'javascript' ? 'JS' : mod.language === 'typescript' ? 'TS' : mod.language}
                      </span>
                      {/* Approval badge */}
                      {mod.approved ? (
                        <span className="badge-success px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wider">
                          Approved
                        </span>
                      ) : (
                        <span className="badge-warning px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wider">
                          Pending
                        </span>
                      )}
                      {/* Blind badge */}
                      {mod.blind ? (
                        <span className="flex items-center gap-0.5 text-[var(--color-accent-gold)] text-[10px] uppercase tracking-wider">
                          <Lock className="w-3 h-3" />
                          Blind
                        </span>
                      ) : (
                        <span className="flex items-center gap-0.5 text-[var(--color-text-muted)] text-[10px] uppercase tracking-wider">
                          <Unlock className="w-3 h-3" />
                          Editable
                        </span>
                      )}
                    </div>

                    {/* Description */}
                    <p className="text-[var(--color-text-secondary)] text-xs mb-2 line-clamp-2">
                      {mod.description}
                    </p>

                    {/* Required secrets tags */}
                    {mod.required_secrets.length > 0 && (
                      <div className="flex items-center gap-1.5 flex-wrap mb-1.5">
                        <Tag className="w-3 h-3 text-[var(--color-accent-gold)] opacity-60" />
                        <span className="text-[var(--color-text-muted)] text-[10px] uppercase tracking-wider mr-1">
                          Secrets:
                        </span>
                        {mod.required_secrets.map((s) => (
                          <span
                            key={s}
                            className="px-1.5 py-0.5 rounded text-[10px] font-mono
                                       bg-[var(--color-accent-gold-dim)] text-[var(--color-accent-gold)] border border-[var(--color-border-subtle)]"
                          >
                            {s}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Allowed params tags */}
                    {mod.allowed_params.length > 0 && (
                      <div className="flex items-center gap-1.5 flex-wrap mb-1.5">
                        <Tag className="w-3 h-3 text-[var(--color-text-muted)] opacity-60" />
                        <span className="text-[var(--color-text-muted)] text-[10px] uppercase tracking-wider mr-1">
                          Params:
                        </span>
                        {mod.allowed_params.map((p) => (
                          <span
                            key={p}
                            className="px-1.5 py-0.5 rounded text-[10px] font-mono
                                       bg-[var(--color-bg-secondary)] text-[var(--color-text-secondary)] border border-[var(--color-border-subtle)]"
                          >
                            {p}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Expiration */}
                    {mod.expires_at && (
                      <div className="flex items-center gap-1 text-[10px] mt-1">
                        <Clock className={`w-3 h-3 ${isExpired(mod.expires_at) ? 'text-[var(--color-danger)]' : 'text-[var(--color-warning)]'}`} />
                        <span className={isExpired(mod.expires_at) ? 'text-[var(--color-danger)]' : 'text-[var(--color-warning)]'}>
                          {isExpired(mod.expires_at) ? 'Expired' : `Expires ${formatDate(mod.expires_at)}`}
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1.5 flex-shrink-0">
                    {/* Approve / Revoke toggle */}
                    {mod.approved ? (
                      <button
                        onClick={() => handleRevoke(mod.name)}
                        className="btn-outlined p-1.5 rounded"
                        title="Revoke approval"
                      >
                        <XCircle className="w-3.5 h-3.5" />
                      </button>
                    ) : (
                      <button
                        onClick={() => handleApprove(mod.name)}
                        className="p-1.5 border border-[var(--color-success)] text-[var(--color-success)] hover:bg-[var(--color-success-bg)] rounded transition-colors"
                        title="Approve module"
                      >
                        <CheckCircle className="w-3.5 h-3.5" />
                      </button>
                    )}
                    {/* Manage / Detail */}
                    <button
                      onClick={() => onManageModule(mod)}
                      className="btn-outlined p-1.5 rounded"
                      title="View details"
                    >
                      <Settings className="w-3.5 h-3.5" />
                    </button>
                    {/* Delete */}
                    <button
                      onClick={() => setConfirmDelete(mod.name)}
                      className="btn-danger p-1.5 rounded"
                      title="Delete module"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>

              {/* Delete confirmation inline */}
              {confirmDelete === mod.name && (
                <div className="px-5 py-3 bg-[var(--color-danger-bg)] border-t border-[var(--color-danger)] flex items-center justify-between">
                  <span className="text-[var(--color-danger)] text-sm">
                    Delete "{mod.name}"? This cannot be undone.
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleDelete(mod.name)}
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
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
