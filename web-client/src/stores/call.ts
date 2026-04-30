import { create } from 'zustand';
import type { ActiveCall } from '../calling/call-manager.ts';

export type CallStore = {
  call: ActiveCall | null;
  setCall: (call: ActiveCall | null) => void;
  errorMessage: string | null;
  setError: (msg: string | null) => void;
};

export const useCallStore = create<CallStore>((set) => ({
  call: null,
  setCall: (call) => set({ call }),
  errorMessage: null,
  setError: (msg) => set({ errorMessage: msg }),
}));
