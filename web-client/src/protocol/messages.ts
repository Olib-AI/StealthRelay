import type { PoolMessageType } from './constants.ts';

export interface PoolMessage {
  id: string;
  type: PoolMessageType;
  senderID: string;
  senderName: string;
  timestamp: number;
  payload: string;
  isReliable: boolean;
}

export interface ChatPayload {
  text: string;
}

export interface EncryptedChatMessage {
  id: string;
  senderID: string;
  senderName: string;
  contentType: 'text' | 'image' | 'voice' | 'emoji' | 'system' | 'poll';
  timestamp: number;
  text?: string;
  imageData?: string;
  voiceData?: string;
  voiceDuration?: number;
  emoji?: string;
  pollData?: PollData;
  reactions: Record<string, string[]>;
  replyTo?: { messageID: string; senderName: string; previewText: string };
  mentions: string[];
  senderAvatarEmoji?: string;
  senderAvatarColorIndex?: number;
}

export interface PollData {
  question: string;
  options: string[];
  votes: Record<string, string[]>;
  allowVoteChange: boolean;
}

export interface KeyExchangePayload {
  publicKey: string;
  senderPeerID: string;
}

export interface ProfileUpdatePayload {
  peerID: string;
  profile: {
    displayName: string;
    avatarEmoji: string;
    avatarColorIndex: number;
  };
}

export interface PeerInfoPayload {
  peerID: string;
  displayName: string;
  isHost: boolean;
  capabilities: string[];
  profile?: {
    displayName: string;
    avatarEmoji: string;
    avatarColorIndex: number;
  };
}

export interface GameControlPayload {
  controlType: 'invite' | 'invite_response' | 'session_update' | 'ready' | 'start' | 'pause' | 'resume' | 'forfeit' | 'rematch';
  gameType: 'chain_reaction' | 'connect_four' | 'prompt_party' | 'chess';
  sessionID?: string;
  data?: string;
}

export interface ChainReactionAction {
  cellID: number;
  playerIndex: number;
  moveNumber: number;
  timestamp: number;
}

export interface ChainReactionCell {
  id: number;
  orbs: number;
  ownerIndex: number | null;
}

export interface ChainReactionState {
  sessionID: string;
  cells: ChainReactionCell[];
  currentPlayerIndex: number;
  moveCount: number;
  gameOver: boolean;
  winnerIndex?: number;
  timestamp: number;
}

export interface ConnectFourAction {
  column: number;
  playerIndex: number;
  moveNumber: number;
  timestamp: number;
}

export interface ConnectFourCell {
  id: number;
  row: number;
  column: number;
  ownerIndex: number | null;
}

export interface ConnectFourState {
  sessionID: string;
  cells: ConnectFourCell[];
  currentPlayerIndex: number;
  moveCount: number;
  gameOver: boolean;
  winnerIndex?: number;
  winningCells?: number[];
  timestamp: number;
}

export interface GamePlayer {
  id: string;
  name: string;
  playerIndex: number;
  isHost: boolean;
  isReady: boolean;
  colorIndex: number;
  profile?: {
    displayName: string;
    avatarEmoji: string;
    avatarColorIndex: number;
  };
}

export interface MultiplayerGameSession {
  sessionID: string;
  gameType: string;
  hostPeerID: string;
  hostName: string;
  players: GamePlayer[];
  state: 'waiting' | 'starting' | 'playing' | 'paused' | 'finished' | 'cancelled';
  createdAt: number;
}

export interface GameInvitation {
  invitationID: string;
  gameType: string;
  hostPeerID: string;
  hostName: string;
  sessionID: string;
  timestamp: number;
}

export interface GameInvitationResponse {
  invitationID: string;
  accepted: boolean;
  responderPeerID: string;
  responderName: string;
}

/* Chess types */
export type ChessPieceType = 'king' | 'queen' | 'rook' | 'bishop' | 'knight' | 'pawn';
export type ChessColor = 'white' | 'black';

export interface ChessAction {
  fromRow: number;
  fromCol: number;
  toRow: number;
  toCol: number;
  promotionPiece?: string;
  playerIndex: number;
  moveNumber: number;
  timestamp: number;
}

export interface ChessPiece {
  type: ChessPieceType;
  color: ChessColor;
}

export interface ChessState {
  sessionID: string;
  board: (ChessPiece | null)[];
  currentPlayerIndex: number;
  moveCount: number;
  gameOver: boolean;
  winnerIndex?: number;
  inCheck: boolean;
  isStalemate: boolean;
  isCheckmate: boolean;
  castlingRights: {
    whiteKingside: boolean;
    whiteQueenside: boolean;
    blackKingside: boolean;
    blackQueenside: boolean;
  };
  enPassantSquare: number | null;
  moveHistory: ChessAction[];
  capturedPieces: { white: ChessPieceType[]; black: ChessPieceType[] };
  timestamp: number;
}
