import { create } from 'zustand';

export interface Peer {
  peerId: string;
  displayName: string;
  publicKey: string;
  connectedAt: number;
  avatarEmoji: string;
  avatarColorIndex: number;
}

export interface PoolInfo {
  poolId: string;
  name: string;
  hostPeerId: string;
  maxPeers: number;
  currentPeers: number;
}

export interface UserProfile {
  displayName: string;
  avatarEmoji: string;
  avatarColorIndex: number;
}

const PROFILE_STORAGE_KEY = 'stealth_user_profile';

function loadProfile(): UserProfile {
  const stored = localStorage.getItem(PROFILE_STORAGE_KEY);
  if (stored) {
    try {
      const parsed = JSON.parse(stored) as UserProfile;
      if (parsed.displayName && parsed.avatarEmoji !== undefined && parsed.avatarColorIndex !== undefined) {
        return parsed;
      }
    } catch {
      // Fall through to default
    }
  }
  return {
    displayName: `Guest${Math.floor(Math.random() * 10000)}`,
    avatarEmoji: '😀',
    avatarColorIndex: 0,
  };
}

function saveProfile(profile: UserProfile): void {
  localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(profile));
}

interface PoolState {
  peers: Peer[];
  poolInfo: PoolInfo | null;
  userProfile: UserProfile;
  addPeer: (peer: Peer) => void;
  removePeer: (peerId: string) => void;
  setPeers: (peers: Peer[]) => void;
  updatePeerProfile: (peerId: string, profile: { displayName: string; avatarEmoji: string; avatarColorIndex: number }) => void;
  setPoolInfo: (info: PoolInfo) => void;
  setUserProfile: (profile: Partial<UserProfile>) => void;
  reset: () => void;
}

export const usePoolStore = create<PoolState>((set) => ({
  peers: [],
  poolInfo: null,
  userProfile: loadProfile(),
  addPeer: (peer) =>
    set((state) => {
      if (state.peers.some((p) => p.peerId === peer.peerId)) return state;
      return { peers: [...state.peers, peer] };
    }),
  removePeer: (peerId) =>
    set((state) => ({ peers: state.peers.filter((p) => p.peerId !== peerId) })),
  setPeers: (peers) => set({ peers }),
  updatePeerProfile: (peerId, profile) =>
    set((state) => ({
      peers: state.peers.map((p) =>
        p.peerId === peerId
          ? { ...p, displayName: profile.displayName, avatarEmoji: profile.avatarEmoji, avatarColorIndex: profile.avatarColorIndex }
          : p,
      ),
    })),
  setPoolInfo: (poolInfo) => set({ poolInfo }),
  setUserProfile: (partial) =>
    set((state) => {
      const newProfile = { ...state.userProfile, ...partial };
      saveProfile(newProfile);
      return { userProfile: newProfile };
    }),
  reset: () => set({ peers: [], poolInfo: null }),
}));
