import { create } from 'zustand';
import { ScriptInfo } from '../lib/tauri';

interface ScriptsState {
  scripts: ScriptInfo[];
  isLoading: boolean;
  error: string | null;
  selectedScript: ScriptInfo | null;

  setScripts: (scripts: ScriptInfo[]) => void;
  setLoading: (value: boolean) => void;
  setError: (value: string | null) => void;
  setSelectedScript: (script: ScriptInfo | null) => void;
}

export const useScriptsStore = create<ScriptsState>((set) => ({
  scripts: [],
  isLoading: false,
  error: null,
  selectedScript: null,

  setScripts: (scripts) => set({ scripts }),
  setLoading: (value) => set({ isLoading: value }),
  setError: (value) => set({ error: value }),
  setSelectedScript: (script) => set({ selectedScript: script }),
}));
