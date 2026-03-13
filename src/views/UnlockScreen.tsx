import { useState } from 'react';
import { useAuthStore } from '../stores/auth';
import { setupMasterPassword, unlock } from '../lib/tauri';
import { Lock, Eye, EyeOff, ShieldCheck, KeyRound } from 'lucide-react';
import PasswordStrength from '../components/ui/PasswordStrength';

export default function UnlockScreen() {
  const { isFirstRun, setUnlocked, setFirstRun, error, setError } = useAuthStore();

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (isFirstRun) {
      if (password.length < 8) {
        setError('Password must be at least 8 characters.');
        return;
      }
      if (password !== confirmPassword) {
        setError('Passwords do not match.');
        return;
      }

      setSubmitting(true);
      try {
        await setupMasterPassword(password);
        setUnlocked(true);
        setFirstRun(false);
      } catch (err) {
        setError(String(err));
      } finally {
        setSubmitting(false);
      }
    } else {
      if (!password) {
        setError('Please enter your master password.');
        return;
      }

      setSubmitting(true);
      try {
        const success = await unlock(password);
        if (success) {
          setUnlocked(true);
        } else {
          setError('Incorrect master password.');
        }
      } catch (err) {
        setError(String(err));
      } finally {
        setSubmitting(false);
      }
    }
  }

  return (
    <div className="min-h-screen bg-deco-pattern flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Card */}
        <div className="card-deco modal-gold-bar rounded-lg shadow-2xl overflow-hidden">
          {/* Header */}
          <div className="pt-10 pb-6 px-8 text-center">
            {/* Decorative fan element */}
            <div className="flex justify-center mb-2">
              <div className="relative">
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 w-16 h-8 overflow-hidden">
                  <div
                    className="w-16 h-16 border-2 border-[var(--color-accent-gold-dim)] rounded-full"
                    style={{ clipPath: 'polygon(0 0, 100% 0, 100% 50%, 0 50%)' }}
                  />
                </div>
              </div>
            </div>

            <div className="flex justify-center mb-4 mt-4">
              <ShieldCheck className="w-12 h-12 text-[var(--color-accent-gold)]" strokeWidth={1.5} />
            </div>
            <h1 className="text-[var(--color-accent-gold)] text-3xl font-heading tracking-wide">
              TamperMonkey
            </h1>
            <h2 className="text-[var(--color-accent-gold-bright)] text-lg font-heading tracking-widest uppercase mt-1 opacity-80">
              Secret Manager
            </h2>

            {/* Sunburst divider */}
            <div className="divider-diamond mt-6">
              <div className="w-2 h-2 rotate-45 border border-[var(--color-border)]" />
            </div>
          </div>

          {/* Body */}
          <form onSubmit={handleSubmit} className="px-8 pb-8">
            <p className="text-[var(--color-text-secondary)] text-sm text-center mb-6">
              {isFirstRun
                ? 'Create a master password to secure your secrets.'
                : 'Enter your master password to unlock the vault.'}
            </p>

            {/* Password field */}
            <div className="mb-4">
              <label
                htmlFor="password"
                className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80"
              >
                {isFirstRun ? 'New Master Password' : 'Master Password'}
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <KeyRound className="w-4 h-4 text-[var(--color-accent-gold)] opacity-50" />
                </div>
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={isFirstRun ? 'Minimum 8 characters' : 'Enter password'}
                  autoFocus
                  className="input-deco w-full rounded pl-10 pr-10 py-2.5 text-sm"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-[var(--color-accent-gold)] opacity-50 hover:opacity-100 transition-opacity"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>

              {/* Password strength meter (first run only) */}
              {isFirstRun && <PasswordStrength password={password} />}
            </div>

            {/* Confirm password (first run only) */}
            {isFirstRun && (
              <div className="mb-4">
                <label
                  htmlFor="confirm-password"
                  className="block text-[var(--color-accent-gold)] text-xs uppercase tracking-wider mb-2 opacity-80"
                >
                  Confirm Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <KeyRound className="w-4 h-4 text-[var(--color-accent-gold)] opacity-50" />
                  </div>
                  <input
                    id="confirm-password"
                    type={showConfirm ? 'text' : 'password'}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Re-enter password"
                    className="input-deco w-full rounded pl-10 pr-10 py-2.5 text-sm"
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirm(!showConfirm)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-[var(--color-accent-gold)] opacity-50 hover:opacity-100 transition-opacity"
                    tabIndex={-1}
                  >
                    {showConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            )}

            {/* Error message */}
            {error && (
              <div className="error-banner mb-4 text-sm text-center rounded px-3 py-2">
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={submitting}
              className="btn-gold w-full flex items-center justify-center gap-2
                         rounded py-2.5 text-sm uppercase tracking-wider"
            >
              {submitting ? (
                <span className="inline-block w-4 h-4 border-2 border-[#1A1A2E] border-t-transparent rounded-full animate-spin" />
              ) : (
                <Lock className="w-4 h-4" />
              )}
              {submitting
                ? isFirstRun
                  ? 'Creating...'
                  : 'Unlocking...'
                : isFirstRun
                  ? 'Create Master Password'
                  : 'Unlock'}
            </button>

            {/* Decorative footer line */}
            <div className="divider-diamond mt-8">
              <div className="w-1.5 h-1.5 rotate-45 border border-[var(--color-border-subtle)]" />
            </div>
            <p className="text-[var(--color-text-muted)] text-xs text-center mt-3">
              AES-256-GCM &middot; Argon2id &middot; Local only
            </p>
          </form>
        </div>
      </div>
    </div>
  );
}
