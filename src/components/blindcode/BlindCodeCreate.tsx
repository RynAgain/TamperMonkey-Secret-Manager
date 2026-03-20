import { useState } from 'react';
import { X, Plus, AlertTriangle, Tag } from 'lucide-react';
import { createBlindCodeModule } from '../../lib/tauri';

interface BlindCodeCreateProps {
  onClose: () => void;
  onCreated: () => void;
}

export default function BlindCodeCreate({ onClose, onCreated }: BlindCodeCreateProps) {
  const [name, setName] = useState('');
  const [language, setLanguage] = useState('rhai');
  const [description, setDescription] = useState('');
  const [code, setCode] = useState('');
  const [secretsInput, setSecretsInput] = useState('');
  const [paramsInput, setParamsInput] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  function parseCommaSeparated(input: string): string[] {
    return input
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  function validate(): string | null {
    if (!name.trim()) return 'Module name is required.';
    if (!/^[a-zA-Z0-9_-]+$/.test(name.trim())) {
      return 'Module name may only contain letters, numbers, hyphens, and underscores.';
    }
    if (!description.trim()) return 'Description is required.';
    if (!code.trim()) return 'Code is required.';
    return null;
  }

  async function handleCreate() {
    setError(null);
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    setCreating(true);
    try {
      const requiredSecrets = parseCommaSeparated(secretsInput);
      const allowedParams = parseCommaSeparated(paramsInput);
      await createBlindCodeModule(name.trim(), description.trim(), language, code, requiredSecrets, allowedParams);
      setSuccess(true);
      onCreated();
    } catch (err) {
      setError(String(err));
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg mx-4">
        <div className="card-deco modal-gold-bar rounded-lg shadow-2xl overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--color-border-subtle)]">
            <h3 className="text-[var(--color-accent-gold)] text-lg font-heading tracking-wide">Create Code Module</h3>
            <button onClick={onClose} className="text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Body */}
          <div className="px-6 py-5 max-h-[70vh] overflow-y-auto">
            {success ? (
              <div className="text-center py-8">
                <div className="flex justify-center mb-4">
                  <Plus className="w-12 h-12 text-[var(--color-success)]" />
                </div>
                <p className="text-[var(--color-success)] text-lg font-medium mb-2">Module created</p>
                <p className="text-[var(--color-text-secondary)] text-sm">
                  "{name}" has been created and is pending approval.
                </p>
                <button
                  onClick={onClose}
                  className="btn-outlined mt-6 px-6 py-2 rounded text-sm uppercase tracking-wider"
                >
                  Close
                </button>
              </div>
            ) : (
              <>
                {/* Error */}
                {error && (
                  <div className="error-banner mb-4 text-sm rounded px-3 py-2">
                    {error}
                  </div>
                )}

                {/* Name */}
                <div className="mb-4">
                  <label className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80">
                    Module Name
                  </label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="my-code-module"
                    className="input-deco w-full rounded px-3 py-2.5 text-sm font-mono"
                  />
                  <p className="text-[var(--color-text-muted)] text-xs mt-1">
                    Letters, numbers, hyphens, and underscores only.
                  </p>
                </div>

                {/* Language */}
                <div className="mb-4">
                  <label className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80">
                    Language
                  </label>
                  <select
                    value={language}
                    onChange={(e) => setLanguage(e.target.value)}
                    className="input-deco w-full rounded px-3 py-2.5 text-sm bg-[var(--color-bg-primary)] appearance-none cursor-pointer"
                  >
                    <option value="rhai">Rhai (Embedded)</option>
                    <option value="python">Python</option>
                    <option value="javascript">JavaScript (Deno)</option>
                    <option value="typescript">TypeScript (Deno)</option>
                  </select>
                </div>

                {/* Description */}
                <div className="mb-4">
                  <label className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80">
                    Description
                  </label>
                  <textarea
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="What does this code module do?"
                    rows={2}
                    className="input-deco w-full rounded px-3 py-2.5 text-sm resize-none"
                  />
                </div>

                {/* Code */}
                <div className="mb-4">
                  <label className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80">
                    {language === 'rhai' ? 'Rhai' : language === 'python' ? 'Python' : language === 'javascript' ? 'JavaScript' : 'TypeScript'} Code
                  </label>
                  <textarea
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    placeholder={
                      language === 'rhai'
                        ? '// Rhai script code\nlet result = get_secret("API_KEY");\nresult'
                        : language === 'python'
                          ? '# Python code\nimport json\nresult = get_secret("API_KEY")\nprint(result)'
                          : language === 'javascript'
                            ? '// JavaScript (Deno) code\nconst result = get_secret("API_KEY");\nconsole.log(result);'
                            : '// TypeScript (Deno) code\nconst result: string = get_secret("API_KEY");\nconsole.log(result);'
                    }
                    rows={8}
                    className="input-deco w-full rounded px-3 py-2.5 text-sm font-mono resize-y"
                  />
                </div>

                {/* Required Secrets */}
                <div className="mb-4">
                  <label className="flex items-center gap-1.5 text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80">
                    <Tag className="w-3 h-3" />
                    Required Secrets
                  </label>
                  <input
                    type="text"
                    value={secretsInput}
                    onChange={(e) => setSecretsInput(e.target.value)}
                    placeholder="API_KEY, DB_PASSWORD, ..."
                    className="input-deco w-full rounded px-3 py-2.5 text-sm font-mono"
                  />
                  <p className="text-[var(--color-text-muted)] text-xs mt-1">
                    Comma-separated list of secret names this module requires.
                  </p>
                </div>

                {/* Allowed Params */}
                <div className="mb-4">
                  <label className="flex items-center gap-1.5 text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80">
                    <Tag className="w-3 h-3" />
                    Allowed Params
                  </label>
                  <input
                    type="text"
                    value={paramsInput}
                    onChange={(e) => setParamsInput(e.target.value)}
                    placeholder="url, timeout, ..."
                    className="input-deco w-full rounded px-3 py-2.5 text-sm font-mono"
                  />
                  <p className="text-[var(--color-text-muted)] text-xs mt-1">
                    Comma-separated list of parameter names scripts can pass to this module.
                  </p>
                </div>

                {/* Warning */}
                <div className="info-banner mb-4 flex items-start gap-2 text-xs rounded px-3 py-2">
                  <AlertTriangle className="w-4 h-4 text-[var(--color-warning)] flex-shrink-0 mt-0.5" />
                  <span>
                    Locally created modules are not blind -- their code can be viewed and edited. Export to .tmcode to share as blind modules.
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
                    onClick={handleCreate}
                    disabled={creating}
                    className="btn-gold flex items-center gap-2 px-5 py-2 text-sm rounded uppercase tracking-wider"
                  >
                    {creating ? (
                      <span className="inline-block w-4 h-4 border-2 border-[#1A1A2E] border-t-transparent rounded-full animate-spin" />
                    ) : (
                      <Plus className="w-4 h-4" />
                    )}
                    {creating ? 'Creating...' : 'Create Module'}
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
