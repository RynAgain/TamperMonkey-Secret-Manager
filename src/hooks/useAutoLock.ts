import { useEffect, useRef } from 'react';
import { getAppStatus } from '../lib/tauri';
import { useAuthStore } from '../stores/auth';

/**
 * Polls the backend every 30 seconds to check if the app has been auto-locked
 * due to inactivity. If the backend reports locked, updates the auth store
 * so the UI transitions to the unlock screen.
 *
 * Only active when the app is currently unlocked.
 */
export function useAutoLock() {
  const { isUnlocked, setUnlocked, setFirstRun } = useAuthStore();
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!isUnlocked) {
      // Not unlocked -- no need to poll
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
      return;
    }

    async function checkStatus() {
      try {
        const status = await getAppStatus();
        if (!status.is_unlocked) {
          // Backend reports locked (auto-lock triggered)
          setUnlocked(false);
          setFirstRun(status.is_first_run);
        }
      } catch {
        // Ignore polling errors silently
      }
    }

    // Poll every 30 seconds
    intervalRef.current = setInterval(checkStatus, 30_000);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [isUnlocked, setUnlocked, setFirstRun]);
}
