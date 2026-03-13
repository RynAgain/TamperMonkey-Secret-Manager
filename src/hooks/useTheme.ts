import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface ThemeState {
  isDark: boolean;
  toggle: () => void;
  setDark: (value: boolean) => void;
}

export const useTheme = create<ThemeState>()(
  persist(
    (set) => ({
      isDark: true, // Default to dark mode -- Art Deco looks best dark
      toggle: () =>
        set((state) => {
          const newDark = !state.isDark;
          applyThemeClass(newDark);
          return { isDark: newDark };
        }),
      setDark: (value) =>
        set(() => {
          applyThemeClass(value);
          return { isDark: value };
        }),
    }),
    { name: 'tm-secrets-theme' },
  ),
);

/** Apply or remove the .dark class on the document root */
function applyThemeClass(isDark: boolean) {
  if (isDark) {
    document.documentElement.classList.add('dark');
  } else {
    document.documentElement.classList.remove('dark');
  }
}

/** Call once at app startup to sync the DOM class with persisted state */
export function initTheme() {
  const stored = localStorage.getItem('tm-secrets-theme');
  let isDark = true; // default
  if (stored) {
    try {
      const parsed = JSON.parse(stored);
      isDark = parsed?.state?.isDark ?? true;
    } catch {
      // ignore parse errors, use default
    }
  }
  applyThemeClass(isDark);
}
