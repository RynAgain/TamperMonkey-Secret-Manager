import { create } from 'zustand';

interface AuthState {
  isFirstRun: boolean | null; // null = loading
  isUnlocked: boolean;
  isLoading: boolean;
  error: string | null;

  setFirstRun: (value: boolean) => void;
  setUnlocked: (value: boolean) => void;
  setLoading: (value: boolean) => void;
  setError: (value: string | null) => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  isFirstRun: null,
  isUnlocked: false,
  isLoading: true,
  error: null,

  setFirstRun: (value) => set({ isFirstRun: value }),
  setUnlocked: (value) => set({ isUnlocked: value }),
  setLoading: (value) => set({ isLoading: value }),
  setError: (value) => set({ error: value }),
}));
