import { useEffect, useState, useCallback } from 'react';
import { listen } from '@tauri-apps/api/event';
import { ShieldAlert, FileCode, Check, X } from 'lucide-react';
import { setScriptSecretAccess, approveScript } from '../../lib/tauri';

// -- Event payloads from the backend ----------------------------------

interface AccessRequestPayload {
  script_id: string;
  script_name: string;
  secret_name: string;
}

interface ScriptPendingPayload {
  script_id: string;
  script_name: string;
  domain: string;
}

// -- Unified notification model ---------------------------------------

type Notification =
  | {
      kind: 'secret-access';
      key: string;
      scriptId: string;
      scriptName: string;
      secretName: string;
      busy: boolean;
    }
  | {
      kind: 'script-pending';
      key: string;
      scriptId: string;
      scriptName: string;
      domain: string;
      busy: boolean;
    };

/**
 * Floating notification stack for approval requests originating from the
 * HTTP API.  Notifications **stay visible** until the user explicitly
 * approves or dismisses them. Duplicates (same key) are suppressed.
 *
 * Two event types are handled:
 * - `secret-access-requested` -- a script wants a secret it hasn't been
 *   approved for yet.
 * - `script-pending-approval` -- a new script registered and needs the
 *   user to approve it.
 */
export default function AccessRequestToast() {
  const [items, setItems] = useState<Notification[]>([]);

  // -- Listen for backend events --------------------------------------

  useEffect(() => {
    const unlisteners: Promise<() => void>[] = [];

    unlisteners.push(
      listen<AccessRequestPayload>('secret-access-requested', (event) => {
        const p = event.payload;
        const key = `sa::${p.script_id}::${p.secret_name}`;

        setItems((prev) => {
          if (prev.some((n) => n.key === key)) return prev;
          return [
            ...prev,
            {
              kind: 'secret-access',
              key,
              scriptId: p.script_id,
              scriptName: p.script_name,
              secretName: p.secret_name,
              busy: false,
            },
          ];
        });
      }),
    );

    unlisteners.push(
      listen<ScriptPendingPayload>('script-pending-approval', (event) => {
        const p = event.payload;
        const key = `sp::${p.script_id}`;

        setItems((prev) => {
          if (prev.some((n) => n.key === key)) return prev;
          return [
            ...prev,
            {
              kind: 'script-pending',
              key,
              scriptId: p.script_id,
              scriptName: p.script_name,
              domain: p.domain,
              busy: false,
            },
          ];
        });
      }),
    );

    return () => {
      unlisteners.forEach((p) => p.then((fn) => fn()));
    };
  }, []);

  // -- Actions --------------------------------------------------------

  const dismiss = useCallback((key: string) => {
    setItems((prev) => prev.filter((n) => n.key !== key));
  }, []);

  const markBusy = useCallback((key: string) => {
    setItems((prev) =>
      prev.map((n) => (n.key === key ? { ...n, busy: true } : n)),
    );
  }, []);

  const handleApproveAccess = useCallback(
    async (n: Extract<Notification, { kind: 'secret-access' }>) => {
      markBusy(n.key);
      try {
        await setScriptSecretAccess(n.scriptId, n.secretName, true);
      } catch (err) {
        console.error('Failed to approve secret access:', err);
      }
      setTimeout(() => dismiss(n.key), 400);
    },
    [markBusy, dismiss],
  );

  const handleApproveScript = useCallback(
    async (n: Extract<Notification, { kind: 'script-pending' }>) => {
      markBusy(n.key);
      try {
        await approveScript(n.scriptId);
      } catch (err) {
        console.error('Failed to approve script:', err);
      }
      setTimeout(() => dismiss(n.key), 400);
    },
    [markBusy, dismiss],
  );

  // -- Render ---------------------------------------------------------

  if (items.length === 0) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-3 max-w-sm">
      {items.map((n) => (
        <div
          key={n.key}
          className="animate-slide-up rounded-lg border border-[var(--color-border)]
                     bg-[var(--color-bg-secondary)] shadow-lg overflow-hidden"
        >
          {/* Gold accent bar */}
          <div className="h-1 bg-gradient-to-r from-[var(--color-accent-gold)] to-[var(--color-accent-gold-bright)]" />

          <div className="p-4">
            {/* Header */}
            <div className="flex items-start gap-3">
              {n.kind === 'secret-access' ? (
                <ShieldAlert
                  className="w-5 h-5 text-[var(--color-warning)] flex-shrink-0 mt-0.5"
                  strokeWidth={1.5}
                />
              ) : (
                <FileCode
                  className="w-5 h-5 text-[var(--color-info)] flex-shrink-0 mt-0.5"
                  strokeWidth={1.5}
                />
              )}

              <div className="flex-1 min-w-0">
                {n.kind === 'secret-access' ? (
                  <>
                    <p className="text-[var(--color-text-primary)] text-sm font-semibold leading-tight">
                      Secret Access Request
                    </p>
                    <p className="text-[var(--color-text-secondary)] text-xs mt-1">
                      <span className="font-mono text-[var(--color-accent-gold)]">
                        {n.scriptName}
                      </span>{' '}
                      wants access to{' '}
                      <span className="font-mono text-[var(--color-accent-gold)]">
                        {n.secretName}
                      </span>
                    </p>
                  </>
                ) : (
                  <>
                    <p className="text-[var(--color-text-primary)] text-sm font-semibold leading-tight">
                      New Script Registration
                    </p>
                    <p className="text-[var(--color-text-secondary)] text-xs mt-1">
                      <span className="font-mono text-[var(--color-accent-gold)]">
                        {n.scriptName}
                      </span>{' '}
                      from{' '}
                      <span className="font-mono text-[var(--color-text-muted)]">
                        {n.domain}
                      </span>{' '}
                      wants approval
                    </p>
                  </>
                )}
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2 mt-3 ml-8">
              <button
                onClick={() =>
                  n.kind === 'secret-access'
                    ? handleApproveAccess(n)
                    : handleApproveScript(n)
                }
                disabled={n.busy}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold
                           uppercase tracking-wider transition-all
                           bg-[var(--color-success-bg)] text-[var(--color-success)]
                           border border-[var(--color-success)]
                           hover:bg-[var(--color-success)] hover:text-white
                           disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Check className="w-3.5 h-3.5" />
                {n.busy ? 'Approving...' : 'Approve'}
              </button>
              <button
                onClick={() => dismiss(n.key)}
                disabled={n.busy}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold
                           uppercase tracking-wider transition-all
                           text-[var(--color-text-muted)]
                           border border-[var(--color-border-subtle)]
                           hover:text-[var(--color-text-secondary)] hover:border-[var(--color-border)]
                           disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <X className="w-3.5 h-3.5" />
                Dismiss
              </button>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
