import { create } from 'zustand';
import type { GameInvitation, MultiplayerGameSession, ConnectFourState, ChainReactionState, ChessState } from '../protocol/messages.ts';

export type ActiveGameType = 'connect_four' | 'chain_reaction' | 'chess';

interface GameState {
  currentSession: MultiplayerGameSession | null;
  pendingInvitation: GameInvitation | null;
  isGameActive: boolean;
  activeGameType: ActiveGameType | null;
  connectFourState: ConnectFourState | null;
  chainReactionState: ChainReactionState | null;
  chessState: ChessState | null;
  setSession: (session: MultiplayerGameSession | null) => void;
  setPendingInvitation: (inv: GameInvitation | null) => void;
  clearInvitation: () => void;
  setGameActive: (active: boolean) => void;
  setActiveGameType: (type: ActiveGameType | null) => void;
  setConnectFourState: (state: ConnectFourState | null) => void;
  setChainReactionState: (state: ChainReactionState | null) => void;
  setChessState: (state: ChessState | null) => void;
  reset: () => void;
}

export const useGameStore = create<GameState>((set) => ({
  currentSession: null,
  pendingInvitation: null,
  isGameActive: false,
  activeGameType: null,
  connectFourState: null,
  chainReactionState: null,
  chessState: null,
  setSession: (currentSession) => set({ currentSession }),
  setPendingInvitation: (pendingInvitation) => set({ pendingInvitation }),
  clearInvitation: () => set({ pendingInvitation: null }),
  setGameActive: (isGameActive) => set({ isGameActive }),
  setActiveGameType: (activeGameType) => set({ activeGameType }),
  setConnectFourState: (connectFourState) => set({ connectFourState }),
  setChainReactionState: (chainReactionState) => set({ chainReactionState }),
  setChessState: (chessState) => set({ chessState }),
  reset: () =>
    set({
      currentSession: null,
      pendingInvitation: null,
      isGameActive: false,
      activeGameType: null,
      connectFourState: null,
      chainReactionState: null,
      chessState: null,
    }),
}));
