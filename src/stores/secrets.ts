import { create } from 'zustand';
import { SecretMetadata } from '../lib/tauri';

interface SecretsState {
  secrets: SecretMetadata[];
  isLoading: boolean;
  error: string | null;

  setSecrets: (secrets: SecretMetadata[]) => void;
  setLoading: (value: boolean) => void;
  setError: (value: string | null) => void;
  addSecret: (secret: SecretMetadata) => void;
  removeSecret: (name: string) => void;
  updateSecretInList: (name: string, updated: SecretMetadata) => void;
}

export const useSecretsStore = create<SecretsState>((set) => ({
  secrets: [],
  isLoading: false,
  error: null,

  setSecrets: (secrets) => set({ secrets }),
  setLoading: (value) => set({ isLoading: value }),
  setError: (value) => set({ error: value }),

  addSecret: (secret) =>
    set((state) => ({ secrets: [...state.secrets, secret] })),

  removeSecret: (name) =>
    set((state) => ({
      secrets: state.secrets.filter((s) => s.name !== name),
    })),

  updateSecretInList: (name, updated) =>
    set((state) => ({
      secrets: state.secrets.map((s) => (s.name === name ? updated : s)),
    })),
}));
