import { useEffect } from 'react';
import { useAuthStore } from './stores/auth';
import { getAppStatus } from './lib/tauri';
import { useAutoLock } from './hooks/useAutoLock';
import UnlockScreen from './views/UnlockScreen';
import Dashboard from './views/Dashboard';

function App() {
  const { isUnlocked, isLoading, setFirstRun, setUnlocked, setLoading } = useAuthStore();

  // Poll backend for auto-lock status changes
  useAutoLock();

  useEffect(() => {
    async function init() {
      try {
        const status = await getAppStatus();
        setFirstRun(status.is_first_run);
        setUnlocked(status.is_unlocked);
      } catch (err) {
        console.error('Failed to get app status:', err);
      } finally {
        setLoading(false);
      }
    }
    init();
  }, [setFirstRun, setUnlocked, setLoading]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[var(--color-bg-primary)] flex items-center justify-center">
        <div className="text-center">
          <div className="text-[var(--color-accent-gold)] text-2xl font-heading tracking-widest uppercase mb-2">
            TamperMonkey
          </div>
          <div className="text-[var(--color-accent-gold-bright)] text-sm font-heading tracking-[0.3em] uppercase">
            Secret Manager
          </div>
          <div className="mt-6 flex items-center justify-center gap-2">
            <div className="h-px w-8 bg-gradient-to-r from-transparent to-[var(--color-border)]" />
            <div className="w-2 h-2 rotate-45 border border-[var(--color-border)]" />
            <div className="h-px w-8 bg-gradient-to-l from-transparent to-[var(--color-border)]" />
          </div>
          <div className="mt-4 text-[var(--color-text-muted)] text-xs tracking-wider">Loading...</div>
        </div>
      </div>
    );
  }

  if (!isUnlocked) {
    return <UnlockScreen />;
  }

  return <Dashboard />;
}

export default App;
