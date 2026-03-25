import { create } from 'zustand';

export type ConnectionStatus = 'idle' | 'connecting' | 'connected' | 'reconnecting' | 'failed' | 'disconnected' | 'waiting_approval';

interface ConnectionState {
  status: ConnectionStatus;
  serverUrl: string | null;
  authNonce: string | null;
  sessionToken: string | null;
  localPeerId: string | null;
  poolId: string | null;
  error: string | null;
  powProgress: number | null;
  setStatus: (status: ConnectionStatus) => void;
  setServerUrl: (url: string) => void;
  setAuthNonce: (nonce: string) => void;
  setJoinAccepted: (data: { sessionToken: string; peerId: string; poolId: string }) => void;
  setError: (error: string | null) => void;
  setPowProgress: (progress: number | null) => void;
  reset: () => void;
}

export const useConnectionStore = create<ConnectionState>((set) => ({
  status: 'idle',
  serverUrl: null,
  authNonce: null,
  sessionToken: null,
  localPeerId: null,
  poolId: null,
  error: null,
  powProgress: null,
  setStatus: (status) => set({ status, error: status === 'connecting' ? null : undefined }),
  setServerUrl: (serverUrl) => set({ serverUrl }),
  setAuthNonce: (authNonce) => set({ authNonce }),
  setJoinAccepted: ({ sessionToken, peerId, poolId }) =>
    set({ sessionToken, localPeerId: peerId, poolId, status: 'connected', error: null }),
  setError: (error) => set({ error }),
  setPowProgress: (powProgress) => set({ powProgress }),
  reset: () =>
    set({
      status: 'idle',
      serverUrl: null,
      authNonce: null,
      sessionToken: null,
      localPeerId: null,
      poolId: null,
      error: null,
      powProgress: null,
    }),
}));
