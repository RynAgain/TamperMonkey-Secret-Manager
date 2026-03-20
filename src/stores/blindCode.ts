import { create } from 'zustand';
import { BlindCodeModuleMetadata } from '../lib/tauri';

interface BlindCodeState {
  modules: BlindCodeModuleMetadata[];
  isLoading: boolean;
  error: string | null;
  selectedModule: BlindCodeModuleMetadata | null;

  setModules: (modules: BlindCodeModuleMetadata[]) => void;
  setLoading: (value: boolean) => void;
  setError: (value: string | null) => void;
  setSelectedModule: (module: BlindCodeModuleMetadata | null) => void;
}

export const useBlindCodeStore = create<BlindCodeState>((set) => ({
  modules: [],
  isLoading: false,
  error: null,
  selectedModule: null,

  setModules: (modules) => set({ modules }),
  setLoading: (value) => set({ isLoading: value }),
  setError: (value) => set({ error: value }),
  setSelectedModule: (module) => set({ selectedModule: module }),
}));
