import { useEffect, useState, useCallback } from 'react';
import { X, Loader2, CheckCircle, Shield, Lock, Unlock, Eye, Download, Tag, Clock } from 'lucide-react';
import { save } from '@tauri-apps/plugin-dialog';
import {
  BlindCodeModuleMetadata,
  ScriptCodeAccessInfo,
  listScriptCodeAccess,
  approveBlindCodeModule,
  revokeBlindCodeModule,
  getBlindCodeModuleCode,
  exportBlindCodeFile,
  listScripts,
} from '../../lib/tauri';

interface BlindCodeDetailProps {
  module: BlindCodeModuleMetadata;
  onClose: () => void;
  onRefresh: () => void;
}

export default function BlindCodeDetail({ module: mod, onClose, onRefresh }: BlindCodeDetailProps) {
  const [currentApproved, setCurrentApproved] = useState(mod.approved);
  const [code, setCode] = useState<string | null>(null);
  const [showCode, setShowCode] = useState(false);
  const [codeLoading, setCodeLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Export state
  const [showExport, setShowExport] = useState(false);
  const [exportPin, setExportPin] = useState('');
  const [exportPinConfirm, setExportPinConfirm] = useState('');
  const [exporting, setExporting] = useState(false);
  const [exportSuccess, setExportSuccess] = useState(false);

  // Script code access state
  const [scriptAccess, setScriptAccess] = useState<(ScriptCodeAccessInfo & { scriptName?: string })[]>([]);
  const [accessLoading, setAccessLoading] = useState(false);

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

  const fetchScriptAccess = useCallback(async () => {
    setAccessLoading(true);
    try {
      // Get all scripts to map script_id -> script_name
      const scripts = await listScripts();
      // For each script, check code access
      const allAccess: (ScriptCodeAccessInfo & { scriptName?: string })[] = [];
      for (const script of scripts) {
        try {
          const accessList = await listScriptCodeAccess(script.script_id);
          const matching = accessList.filter((a) => a.module_name === mod.name);
          for (const a of matching) {
            allAccess.push({ ...a, scriptName: script.script_name });
          }
        } catch {
          // skip scripts with errors
        }
      }
      setScriptAccess(allAccess);
    } catch (err) {
      console.error('Failed to fetch script code access:', err);
    } finally {
      setAccessLoading(false);
    }
  }, [mod.name]);

  useEffect(() => {
    fetchScriptAccess();
  }, [fetchScriptAccess]);

  async function handleToggleGlobal() {
    setError(null);
    try {
      if (currentApproved) {
        await revokeBlindCodeModule(mod.name);
        setCurrentApproved(false);
      } else {
        await approveBlindCodeModule(mod.name);
        setCurrentApproved(true);
      }
      onRefresh();
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleViewCode() {
    setCodeLoading(true);
    setError(null);
    try {
      const result = await getBlindCodeModuleCode(mod.name);
      setCode(result);
      setShowCode(true);
    } catch (err) {
      setError(String(err));
    } finally {
      setCodeLoading(false);
    }
  }

  async function handleExport() {
    setError(null);
    if (exportPin.length < 6) {
      setError('PIN must be at least 6 characters.');
      return;
    }
    if (exportPin !== exportPinConfirm) {
      setError('PIN and confirmation do not match.');
      return;
    }

    const filePath = await save({
      defaultPath: `${mod.name}.tmcode`,
      filters: [{ name: 'TM Code Module', extensions: ['tmcode'] }],
    });

    if (!filePath) return;

    setExporting(true);
    try {
      await exportBlindCodeFile(mod.name, exportPin, filePath);
      setExportSuccess(true);
    } catch (err) {
      setError(String(err));
    } finally {
      setExporting(false);
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
                {mod.name}
              </h2>
              <p className="text-[var(--color-text-secondary)] text-xs">{mod.description}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Module info */}
        <div className="px-6 py-4 border-b border-[var(--color-border-subtle)]">
          <div className="grid grid-cols-4 gap-4 text-sm">
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
              <span className="text-[var(--color-text-secondary)] text-xs uppercase tracking-wider block mb-1">Language</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-medium uppercase tracking-wider bg-[var(--color-bg-secondary)] text-[var(--color-text-secondary)] border border-[var(--color-border-subtle)] inline-block">
                {mod.language === 'rhai' ? 'Rhai' : mod.language === 'python' ? 'Python' : mod.language === 'javascript' ? 'JavaScript' : mod.language === 'typescript' ? 'TypeScript' : mod.language}
              </span>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)] text-xs uppercase tracking-wider block mb-1">Visibility</span>
              <span className="flex items-center gap-1.5 text-xs">
                {mod.blind ? (
                  <span className="flex items-center gap-1 text-[var(--color-accent-gold)]">
                    <Lock className="w-3 h-3" /> Blind
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-[var(--color-text-secondary)]">
                    <Unlock className="w-3 h-3" /> Editable
                  </span>
                )}
              </span>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)] text-xs uppercase tracking-wider block mb-1">Created</span>
              <span className="text-[var(--color-text-primary)] text-xs">{formatDate(mod.created_at)}</span>
            </div>
          </div>

          {/* Expiration */}
          {mod.expires_at && (
            <div className="mt-3 flex items-center gap-1.5 text-xs">
              <Clock className={`w-3.5 h-3.5 ${isExpired(mod.expires_at) ? 'text-[var(--color-danger)]' : 'text-[var(--color-warning)]'}`} />
              <span className={isExpired(mod.expires_at) ? 'text-[var(--color-danger)]' : 'text-[var(--color-warning)]'}>
                {isExpired(mod.expires_at) ? 'Expired' : `Expires ${formatDate(mod.expires_at)}`}
              </span>
            </div>
          )}

          {/* Required secrets */}
          {mod.required_secrets.length > 0 && (
            <div className="mt-3 flex items-center gap-1.5 flex-wrap">
              <Tag className="w-3 h-3 text-[var(--color-accent-gold)] opacity-60" />
              <span className="text-[var(--color-text-muted)] text-[10px] uppercase tracking-wider mr-1">
                Required Secrets:
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

          {/* Allowed params */}
          {mod.allowed_params.length > 0 && (
            <div className="mt-2 flex items-center gap-1.5 flex-wrap">
              <Tag className="w-3 h-3 text-[var(--color-text-muted)] opacity-60" />
              <span className="text-[var(--color-text-muted)] text-[10px] uppercase tracking-wider mr-1">
                Allowed Params:
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

          {/* Action buttons */}
          <div className="mt-4 flex items-center gap-2">
            <button
              onClick={handleToggleGlobal}
              className={`px-4 py-2 rounded text-xs font-medium uppercase tracking-wider transition-colors ${
                currentApproved
                  ? 'btn-outlined'
                  : 'border border-[var(--color-success)] text-[var(--color-success)] hover:bg-[var(--color-success-bg)]'
              }`}
            >
              {currentApproved ? 'Revoke Approval' : 'Approve Module'}
            </button>
            {!mod.blind && (
              <button
                onClick={handleViewCode}
                disabled={codeLoading}
                className="btn-outlined px-4 py-2 rounded text-xs font-medium uppercase tracking-wider flex items-center gap-1.5"
              >
                {codeLoading ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Eye className="w-3.5 h-3.5" />
                )}
                View Code
              </button>
            )}
            <button
              onClick={() => setShowExport(!showExport)}
              className="btn-outlined px-4 py-2 rounded text-xs font-medium uppercase tracking-wider flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" />
              Export
            </button>
          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="error-banner mx-6 mt-4 text-sm rounded px-4 py-3">
            {error}
          </div>
        )}

        {/* Scrollable content area */}
        <div className="flex-1 overflow-y-auto px-6 py-4">
          {/* Export form */}
          {showExport && !exportSuccess && (
            <div className="mb-4 border border-[var(--color-border-subtle)] rounded-lg p-4">
              <h4 className="text-[var(--color-accent-gold)] text-xs font-heading uppercase tracking-wider mb-3">
                Export Module
              </h4>
              <div className="mb-3">
                <label className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-1 opacity-80">
                  Encryption PIN (min 6 characters)
                </label>
                <input
                  type="password"
                  value={exportPin}
                  onChange={(e) => setExportPin(e.target.value)}
                  placeholder="Enter PIN..."
                  className="input-deco w-full rounded px-3 py-2 text-sm font-mono"
                />
              </div>
              <div className="mb-3">
                <label className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-1 opacity-80">
                  Confirm PIN
                </label>
                <input
                  type="password"
                  value={exportPinConfirm}
                  onChange={(e) => setExportPinConfirm(e.target.value)}
                  placeholder="Confirm PIN..."
                  className="input-deco w-full rounded px-3 py-2 text-sm font-mono"
                />
              </div>
              <div className="flex items-center justify-end gap-2">
                <button
                  onClick={() => setShowExport(false)}
                  className="btn-ghost px-3 py-1.5 text-xs rounded"
                >
                  Cancel
                </button>
                <button
                  onClick={handleExport}
                  disabled={exporting}
                  className="btn-gold flex items-center gap-1.5 px-4 py-1.5 text-xs rounded uppercase tracking-wider"
                >
                  {exporting ? (
                    <span className="inline-block w-3.5 h-3.5 border-2 border-[#1A1A2E] border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <Download className="w-3.5 h-3.5" />
                  )}
                  {exporting ? 'Exporting...' : 'Export'}
                </button>
              </div>
            </div>
          )}

          {/* Export success */}
          {exportSuccess && (
            <div className="mb-4 border border-[var(--color-success)] rounded-lg p-4 text-center">
              <CheckCircle className="w-8 h-8 text-[var(--color-success)] mx-auto mb-2" />
              <p className="text-[var(--color-success)] text-sm font-medium">Module exported successfully</p>
              <button
                onClick={() => { setShowExport(false); setExportSuccess(false); setExportPin(''); setExportPinConfirm(''); }}
                className="btn-outlined mt-3 px-4 py-1.5 rounded text-xs uppercase tracking-wider"
              >
                Close
              </button>
            </div>
          )}

          {/* Code viewer */}
          {showCode && (
            <div className="mb-4">
              <h4 className="text-[var(--color-accent-gold)] text-xs font-heading uppercase tracking-wider mb-2">
                Module Code
              </h4>
              {code !== null ? (
                <pre className="bg-[var(--color-bg-primary)] border border-[var(--color-border-subtle)] rounded p-3 text-xs font-mono text-[var(--color-text-primary)] overflow-x-auto max-h-64 overflow-y-auto whitespace-pre-wrap">
                  {code}
                </pre>
              ) : (
                <p className="text-[var(--color-text-muted)] text-sm">Code not available (blind module).</p>
              )}
            </div>
          )}

          {/* Script code access */}
          <div>
            <h3 className="text-[var(--color-accent-gold)] text-sm font-heading tracking-wide uppercase mb-4">
              Script Access
            </h3>

            {accessLoading ? (
              <div className="flex items-center justify-center py-10">
                <Loader2 className="w-5 h-5 text-[var(--color-accent-gold)] animate-spin" />
                <span className="ml-2 text-[var(--color-text-secondary)] text-sm">Loading access records...</span>
              </div>
            ) : scriptAccess.length === 0 ? (
              <div className="text-center py-10">
                <p className="text-[var(--color-text-secondary)] text-sm">No scripts have requested access to this module.</p>
                <p className="text-[var(--color-text-muted)] text-xs mt-1">
                  Access records appear when scripts request to execute this code module.
                </p>
              </div>
            ) : (
              <div className="table-deco rounded-lg overflow-hidden">
                {/* Header */}
                <div className="grid grid-cols-[1fr_100px_160px] gap-4 px-4 py-2 table-deco-header">
                  <span className="text-xs uppercase tracking-wider font-medium">
                    Script
                  </span>
                  <span className="text-xs uppercase tracking-wider font-medium">
                    Status
                  </span>
                  <span className="text-xs uppercase tracking-wider font-medium">
                    Granted
                  </span>
                </div>
                {scriptAccess.map((access, idx) => (
                  <div key={`${access.module_name}-${idx}`}>
                    <div className="grid grid-cols-[1fr_100px_160px] gap-4 px-4 py-2.5 items-center table-deco-row">
                      <span className="text-[var(--color-text-primary)] text-sm truncate">
                        {access.scriptName ?? access.module_name}
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
                    </div>
                    {idx < scriptAccess.length - 1 && (
                      <div className="table-deco-separator" />
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
