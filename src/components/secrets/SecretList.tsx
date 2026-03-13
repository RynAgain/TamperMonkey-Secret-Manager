import { useState } from 'react';
import { Pencil, Trash2, Plus, Loader2, AlertTriangle, EyeOff, ShieldAlert, Clock } from 'lucide-react';
import { SecretMetadata } from '../../lib/tauri';

interface SecretListProps {
  secrets: SecretMetadata[];
  isLoading: boolean;
  onAdd: () => void;
  onEdit: (secret: SecretMetadata) => void;
  onDelete: (name: string) => void;
}

/** Determine expiration status for a secret. */
function getExpirationStatus(expiresAt: string | null): 'none' | 'expired' | 'expiring-soon' | 'active' {
  if (!expiresAt) return 'none';
  try {
    const now = Date.now();
    const expiry = new Date(expiresAt).getTime();
    if (now > expiry) return 'expired';
    if (expiry - now < 24 * 60 * 60 * 1000) return 'expiring-soon';
    return 'active';
  } catch {
    return 'none';
  }
}

/** Format remaining time until expiration. */
function formatTimeRemaining(expiresAt: string): string {
  try {
    const now = Date.now();
    const expiry = new Date(expiresAt).getTime();
    const diffMs = expiry - now;
    if (diffMs <= 0) return 'Expired';

    const hours = Math.floor(diffMs / (1000 * 60 * 60));
    const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));

    if (hours >= 24) {
      const days = Math.floor(hours / 24);
      return `${days}d ${hours % 24}h`;
    }
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  } catch {
    return '';
  }
}

export default function SecretList({
  secrets,
  isLoading,
  onAdd,
  onEdit,
  onDelete,
}: SecretListProps) {
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  function handleDeleteClick(name: string) {
    setConfirmDelete(name);
  }

  function handleConfirmDelete(name: string) {
    onDelete(name);
    setConfirmDelete(null);
  }

  function handleCancelDelete() {
    setConfirmDelete(null);
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

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-6 h-6 text-[var(--color-accent-gold)] animate-spin" />
        <span className="ml-3 text-[var(--color-text-secondary)] text-sm">Loading secrets...</span>
      </div>
    );
  }

  return (
    <div>
      {/* Header row */}
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-[var(--color-accent-gold)] text-xl font-heading tracking-wide">Secrets</h2>
        <button
          onClick={onAdd}
          className="btn-outlined flex items-center gap-2 px-4 py-2 rounded text-sm uppercase tracking-wider"
        >
          <Plus className="w-4 h-4" />
          Add Secret
        </button>
      </div>

      {/* Empty state */}
      {secrets.length === 0 && (
        <div className="text-center py-16">
          <div className="flex justify-center mb-4">
            <AlertTriangle className="w-10 h-10 text-[var(--color-accent-gold)] opacity-40" />
          </div>
          <p className="text-[var(--color-text-secondary)] text-sm">No secrets stored yet.</p>
          <p className="text-[var(--color-text-muted)] text-xs mt-1">
            Click "Add Secret" to create your first key-value secret.
          </p>
        </div>
      )}

      {/* Secret list */}
      {secrets.length > 0 && (
        <div className="table-deco rounded-lg overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[1fr_120px_100px_160px_100px] gap-4 px-4 py-3 table-deco-header">
            <span className="text-xs uppercase tracking-wider font-medium">
              Name
            </span>
            <span className="text-xs uppercase tracking-wider font-medium">
              Type
            </span>
            <span className="text-xs uppercase tracking-wider font-medium">
              Visibility
            </span>
            <span className="text-xs uppercase tracking-wider font-medium">
              Updated
            </span>
            <span className="text-xs uppercase tracking-wider font-medium text-right">
              Actions
            </span>
          </div>

          {/* Table rows */}
          {secrets.map((secret, idx) => {
            const expStatus = getExpirationStatus(secret.expires_at);

            return (
              <div key={secret.id}>
                <div className={`grid grid-cols-[1fr_120px_100px_160px_100px] gap-4 px-4 py-3 items-center table-deco-row ${
                  expStatus === 'expired' ? 'opacity-60' : ''
                }`}>
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[var(--color-text-primary)] text-sm font-mono truncate" title={secret.name}>
                      {secret.name}
                    </span>
                    {/* Expiration badge */}
                    {expStatus === 'expired' && (
                      <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] uppercase tracking-wider font-medium rounded bg-[var(--color-danger)]/15 text-[var(--color-danger)] border border-[var(--color-danger)]/30 flex-shrink-0">
                        <Clock className="w-2.5 h-2.5" />
                        Expired
                      </span>
                    )}
                    {expStatus === 'expiring-soon' && (
                      <span
                        className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] uppercase tracking-wider font-medium rounded bg-[var(--color-warning)]/15 text-[var(--color-warning)] border border-[var(--color-warning)]/30 flex-shrink-0"
                        title={`Expires in ${formatTimeRemaining(secret.expires_at!)}`}
                      >
                        <Clock className="w-2.5 h-2.5" />
                        {formatTimeRemaining(secret.expires_at!)}
                      </span>
                    )}
                    {expStatus === 'active' && (
                      <span
                        className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] uppercase tracking-wider font-medium rounded bg-[var(--color-accent-gold)]/10 text-[var(--color-text-muted)] border border-[var(--color-border-subtle)] flex-shrink-0"
                        title={`Expires in ${formatTimeRemaining(secret.expires_at!)}`}
                      >
                        <Clock className="w-2.5 h-2.5" />
                        {formatTimeRemaining(secret.expires_at!)}
                      </span>
                    )}
                  </div>
                  <span className="text-[var(--color-text-secondary)] text-xs">{secret.secret_type}</span>
                  <span className="flex items-center gap-1 text-xs">
                    {secret.blind ? (
                      <>
                        <ShieldAlert className="w-3 h-3 text-[var(--color-accent-gold)]" />
                        <span className="text-[var(--color-accent-gold)]">Blind</span>
                      </>
                    ) : (
                      <span className="text-[var(--color-text-secondary)]">Visible</span>
                    )}
                  </span>
                  <span className="text-[var(--color-text-secondary)] text-xs">{formatDate(secret.updated_at)}</span>
                  <div className="flex items-center justify-end gap-2">
                    {secret.blind ? (
                      <span
                        className="p-1.5 border border-[var(--color-border-subtle)] text-[var(--color-accent-gold)] opacity-40 rounded cursor-not-allowed"
                        title="Blind secret -- value cannot be viewed or edited"
                      >
                        <EyeOff className="w-3.5 h-3.5" />
                      </span>
                    ) : (
                      <button
                        onClick={() => onEdit(secret)}
                        className="btn-outlined p-1.5 rounded"
                        title="Edit"
                        disabled={expStatus === 'expired'}
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                    )}
                    <button
                      onClick={() => handleDeleteClick(secret.name)}
                      className="btn-danger p-1.5 rounded"
                      title="Delete"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Delete confirmation inline */}
                {confirmDelete === secret.name && (
                  <div className="px-4 py-3 bg-[var(--color-danger-bg)] border-t border-[var(--color-danger)] flex items-center justify-between">
                    <span className="text-[var(--color-danger)] text-sm">
                      Delete "{secret.name}"? This cannot be undone.
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleConfirmDelete(secret.name)}
                        className="px-3 py-1 bg-[var(--color-danger)] text-white text-xs rounded font-medium hover:opacity-80 transition-opacity"
                      >
                        Delete
                      </button>
                      <button
                        onClick={handleCancelDelete}
                        className="btn-ghost px-3 py-1 text-xs rounded"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}

                {/* Row separator */}
                {idx < secrets.length - 1 && (
                  <div className="table-deco-separator" />
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
