import { useEffect, useState, useCallback } from 'react';
import { Loader2, RefreshCw } from 'lucide-react';
import { AuditEntry, getAuditLog } from '../../lib/tauri';

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchLog = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const log = await getAuditLog(50);
      setEntries(log);
    } catch (err) {
      setError(String(err));
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLog();
  }, [fetchLog]);

  function formatTimestamp(iso: string): string {
    try {
      const d = new Date(iso);
      return d.toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return iso;
    }
  }

  function getEventBadgeClass(eventType: string): string {
    if (eventType.includes('access') || eventType.includes('read')) return 'badge-info';
    if (eventType.includes('created') || eventType.includes('added') || eventType.includes('imported')) return 'badge-success';
    if (eventType.includes('deleted') || eventType.includes('removed')) return 'badge-danger';
    if (eventType.includes('approved') || eventType.includes('revoked') || eventType.includes('registered')) return 'badge-warning';
    return 'badge-info';
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-[var(--color-accent-gold)] text-xl font-heading tracking-wide">Activity Log</h2>
        <button
          onClick={fetchLog}
          disabled={isLoading}
          className="btn-outlined flex items-center gap-2 px-4 py-2 rounded text-sm uppercase tracking-wider disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="error-banner mb-4 text-sm rounded px-4 py-3">
          {error}
        </div>
      )}

      {/* Loading */}
      {isLoading && entries.length === 0 && (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-6 h-6 text-[var(--color-accent-gold)] animate-spin" />
          <span className="ml-3 text-[var(--color-text-secondary)] text-sm">Loading audit log...</span>
        </div>
      )}

      {/* Empty state */}
      {!isLoading && entries.length === 0 && (
        <div className="text-center py-16">
          <p className="text-[var(--color-text-secondary)] text-sm">No audit events recorded yet.</p>
          <p className="text-[var(--color-text-muted)] text-xs mt-1">
            Events will appear here as secrets are accessed, scripts register, and changes are made.
          </p>
        </div>
      )}

      {/* Audit log table */}
      {entries.length > 0 && (
        <div className="table-deco rounded-lg overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[180px_1fr_140px_140px] gap-4 px-4 py-3 table-deco-header">
            <span className="text-xs uppercase tracking-wider font-medium">
              Timestamp
            </span>
            <span className="text-xs uppercase tracking-wider font-medium">
              Event
            </span>
            <span className="text-xs uppercase tracking-wider font-medium">
              Script
            </span>
            <span className="text-xs uppercase tracking-wider font-medium">
              Secret
            </span>
          </div>

          {/* Table rows */}
          {entries.map((entry, idx) => (
            <div key={idx}>
              <div className="grid grid-cols-[180px_1fr_140px_140px] gap-4 px-4 py-2.5 items-center table-deco-row">
                <span className="text-[var(--color-text-secondary)] text-xs">
                  {formatTimestamp(entry.timestamp)}
                </span>
                <span className="flex items-center gap-2 text-sm">
                  <span className={`${getEventBadgeClass(entry.event_type)} px-2 py-0.5 rounded-full font-mono text-[10px] font-medium uppercase tracking-wider`}>
                    {entry.event_type}
                  </span>
                </span>
                <span className="text-[var(--color-text-secondary)] text-xs font-mono truncate" title={entry.script_id ?? ''}>
                  {entry.script_id ?? '--'}
                </span>
                <span className="text-[var(--color-text-secondary)] text-xs font-mono truncate" title={entry.secret_name ?? ''}>
                  {entry.secret_name ?? '--'}
                </span>
              </div>
              {idx < entries.length - 1 && (
                <div className="table-deco-separator" />
              )}
            </div>
          ))}
        </div>
      )}

      <div className="mt-3 text-[var(--color-text-muted)] text-xs text-right">
        Showing last {entries.length} event{entries.length !== 1 ? 's' : ''}
      </div>
    </div>
  );
}
