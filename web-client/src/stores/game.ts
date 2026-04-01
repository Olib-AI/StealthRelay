import { create } from 'zustand';
import type { GameInvitation, MultiplayerGameSession, ConnectFourState, ChainReactionState, ChessState, LudoBoardState, LudoAction } from '../protocol/messages.ts';

export type ActiveGameType = 'connect_four' | 'chain_reaction' | 'chess' | 'ludo';

interface GameState {
  currentSession: MultiplayerGameSession | null;
  pendingInvitation: GameInvitation | null;
  isGameActive: boolean;
  activeGameType: ActiveGameType | null;
  connectFourState: ConnectFourState | null;
  chainReactionState: ChainReactionState | null;
  chessState: ChessState | null;
  ludoState: LudoBoardState | null;
  ludoAction: LudoAction | null;
  setSession: (session: MultiplayerGameSession | null) => void;
  setPendingInvitation: (inv: GameInvitation | null) => void;
  clearInvitation: () => void;
  setGameActive: (active: boolean) => void;
  setActiveGameType: (type: ActiveGameType | null) => void;
  setConnectFourState: (state: ConnectFourState | null) => void;
  setChainReactionState: (state: ChainReactionState | null) => void;
  setChessState: (state: ChessState | null) => void;
  setLudoState: (state: LudoBoardState | null) => void;
  setLudoAction: (action: GameState['ludoAction']) => void;
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
  ludoState: null,
  ludoAction: null,
  setSession: (currentSession) => set({ currentSession }),
  setPendingInvitation: (pendingInvitation) => set({ pendingInvitation }),
  clearInvitation: () => set({ pendingInvitation: null }),
  setGameActive: (isGameActive) => set({ isGameActive }),
  setActiveGameType: (activeGameType) => set({ activeGameType }),
  setConnectFourState: (connectFourState) => set({ connectFourState }),
  setChainReactionState: (chainReactionState) => set({ chainReactionState }),
  setChessState: (chessState) => set({ chessState }),
  setLudoState: (ludoState) => set({ ludoState }),
  setLudoAction: (ludoAction) => set({ ludoAction }),
  reset: () =>
    set({
      currentSession: null,
      pendingInvitation: null,
      isGameActive: false,
      activeGameType: null,
      connectFourState: null,
      chainReactionState: null,
      chessState: null,
      ludoState: null,
      ludoAction: null,
    }),
}));
