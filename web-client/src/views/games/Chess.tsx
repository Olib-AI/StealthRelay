import { useState, useMemo, useEffect } from 'react';
import { ArrowLeft, RotateCcw, LogOut } from 'lucide-react';
import { useGameStore } from '../../stores/game.ts';
import { useConnectionStore } from '../../stores/connection.ts';
import { usePoolStore } from '../../stores/pool.ts';
import { transport } from '../../transport/websocket.ts';
import { appleTimestamp } from '../../utils/time.ts';
import type { ChessAction, ChessPiece, ChessState, ChessPieceType, ChessColor, GameControlPayload } from '../../protocol/messages.ts';
import PeerAvatar from '../../components/PeerAvatar.tsx';

const PIECE_SYMBOLS: Record<ChessColor, Record<ChessPieceType, string>> = {
  white: { king: '♔', queen: '♕', rook: '♖', bishop: '♗', knight: '♘', pawn: '♙' },
  black: { king: '♚', queen: '♛', rook: '♜', bishop: '♝', knight: '♞', pawn: '♟' },
};

const PIECE_SVG: Record<ChessColor, Record<ChessPieceType, string>> = {
  white: {
    king: '/chess/chess-king-white.svg',
    queen: '/chess/chess-queen-white.svg',
    rook: '/chess/chess-rook-white.svg',
    bishop: '/chess/chess-bishop-white.svg',
    knight: '/chess/chess-knight-white.svg',
    pawn: '/chess/chess-pawn-white.svg',
  },
  black: {
    king: '/chess/chess-king-black.svg',
    queen: '/chess/chess-queen-black.svg',
    rook: '/chess/chess-rook-black.svg',
    bishop: '/chess/chess-bishop-black.svg',
    knight: '/chess/chess-knight-black.svg',
    pawn: '/chess/chess-pawn-black.svg',
  },
};

function initialBoard(): (ChessPiece | null)[] {
  const board: (ChessPiece | null)[] = new Array(64).fill(null);
  const backRow: ChessPieceType[] = ['rook', 'knight', 'bishop', 'queen', 'king', 'bishop', 'knight', 'rook'];

  for (let i = 0; i < 8; i++) {
    board[i] = { type: backRow[i]!, color: 'black' };
    board[8 + i] = { type: 'pawn', color: 'black' };
    board[48 + i] = { type: 'pawn', color: 'white' };
    board[56 + i] = { type: backRow[i]!, color: 'white' };
  }
  return board;
}

function squareToCoords(sq: number): [number, number] {
  return [Math.floor(sq / 8), sq % 8];
}

function coordsToSquare(row: number, col: number): number {
  return row * 8 + col;
}

function isInBounds(row: number, col: number): boolean {
  return row >= 0 && row < 8 && col >= 0 && col < 8;
}

function findKing(board: (ChessPiece | null)[], color: ChessColor): number {
  return board.findIndex((p) => p?.type === 'king' && p.color === color);
}

function isSquareAttackedBy(board: (ChessPiece | null)[], sq: number, attackerColor: ChessColor): boolean {
  const [tr, tc] = squareToCoords(sq);

  // Pawn attacks
  const pawnDir = attackerColor === 'white' ? 1 : -1;
  for (const dc of [-1, 1]) {
    const pr = tr + pawnDir;
    const pc = tc + dc;
    if (isInBounds(pr, pc)) {
      const p = board[coordsToSquare(pr, pc)];
      if (p?.type === 'pawn' && p.color === attackerColor) return true;
    }
  }

  // Knight attacks
  const knightMoves = [[-2, -1], [-2, 1], [-1, -2], [-1, 2], [1, -2], [1, 2], [2, -1], [2, 1]];
  for (const [dr, dc] of knightMoves) {
    const nr = tr + dr!, nc = tc + dc!;
    if (isInBounds(nr, nc)) {
      const p = board[coordsToSquare(nr, nc)];
      if (p?.type === 'knight' && p.color === attackerColor) return true;
    }
  }

  // King attacks (for checking adjacency)
  const kingMoves = [[-1, -1], [-1, 0], [-1, 1], [0, -1], [0, 1], [1, -1], [1, 0], [1, 1]];
  for (const [dr, dc] of kingMoves) {
    const nr = tr + dr!, nc = tc + dc!;
    if (isInBounds(nr, nc)) {
      const p = board[coordsToSquare(nr, nc)];
      if (p?.type === 'king' && p.color === attackerColor) return true;
    }
  }

  // Sliding pieces (rook/queen for straights, bishop/queen for diagonals)
  const straightDirs = [[0, 1], [0, -1], [1, 0], [-1, 0]];
  for (const [dr, dc] of straightDirs) {
    let nr = tr + dr!, nc = tc + dc!;
    while (isInBounds(nr, nc)) {
      const p = board[coordsToSquare(nr, nc)];
      if (p) {
        if (p.color === attackerColor && (p.type === 'rook' || p.type === 'queen')) return true;
        break;
      }
      nr += dr!;
      nc += dc!;
    }
  }

  const diagDirs = [[1, 1], [1, -1], [-1, 1], [-1, -1]];
  for (const [dr, dc] of diagDirs) {
    let nr = tr + dr!, nc = tc + dc!;
    while (isInBounds(nr, nc)) {
      const p = board[coordsToSquare(nr, nc)];
      if (p) {
        if (p.color === attackerColor && (p.type === 'bishop' || p.type === 'queen')) return true;
        break;
      }
      nr += dr!;
      nc += dc!;
    }
  }

  return false;
}

function isInCheck(board: (ChessPiece | null)[], color: ChessColor): boolean {
  const kingPos = findKing(board, color);
  if (kingPos === -1) return false;
  const opponent = color === 'white' ? 'black' : 'white';
  return isSquareAttackedBy(board, kingPos, opponent);
}

function getPseudoLegalMoves(board: (ChessPiece | null)[], sq: number, castling: ChessState['castlingRights'], enPassant: number | null): number[] {
  const piece = board[sq];
  if (!piece) return [];

  const [row, col] = squareToCoords(sq);
  const moves: number[] = [];

  function addIfValid(r: number, c: number): boolean {
    if (!isInBounds(r, c)) return false;
    const target = board[coordsToSquare(r, c)];
    if (target && target.color === piece!.color) return false;
    moves.push(coordsToSquare(r, c));
    return !target;
  }

  switch (piece.type) {
    case 'pawn': {
      const dir = piece.color === 'white' ? -1 : 1;
      const startRow = piece.color === 'white' ? 6 : 1;
      // Forward
      const fwd = row + dir;
      if (isInBounds(fwd, col) && !board[coordsToSquare(fwd, col)]) {
        moves.push(coordsToSquare(fwd, col));
        // Double push
        if (row === startRow) {
          const dbl = row + dir * 2;
          if (!board[coordsToSquare(dbl, col)]) {
            moves.push(coordsToSquare(dbl, col));
          }
        }
      }
      // Captures
      for (const dc of [-1, 1]) {
        const nc = col + dc;
        if (isInBounds(fwd, nc)) {
          const target = board[coordsToSquare(fwd, nc)];
          if (target && target.color !== piece.color) {
            moves.push(coordsToSquare(fwd, nc));
          }
          // En passant
          if (enPassant !== null && coordsToSquare(fwd, nc) === enPassant) {
            moves.push(enPassant);
          }
        }
      }
      break;
    }
    case 'knight': {
      const knightMoves = [[-2, -1], [-2, 1], [-1, -2], [-1, 2], [1, -2], [1, 2], [2, -1], [2, 1]];
      for (const [dr, dc] of knightMoves) addIfValid(row + dr!, col + dc!);
      break;
    }
    case 'bishop': {
      for (const [dr, dc] of [[1, 1], [1, -1], [-1, 1], [-1, -1]]) {
        let nr = row + dr!, nc = col + dc!;
        while (addIfValid(nr, nc)) { nr += dr!; nc += dc!; }
      }
      break;
    }
    case 'rook': {
      for (const [dr, dc] of [[0, 1], [0, -1], [1, 0], [-1, 0]]) {
        let nr = row + dr!, nc = col + dc!;
        while (addIfValid(nr, nc)) { nr += dr!; nc += dc!; }
      }
      break;
    }
    case 'queen': {
      for (const [dr, dc] of [[0, 1], [0, -1], [1, 0], [-1, 0], [1, 1], [1, -1], [-1, 1], [-1, -1]]) {
        let nr = row + dr!, nc = col + dc!;
        while (addIfValid(nr, nc)) { nr += dr!; nc += dc!; }
      }
      break;
    }
    case 'king': {
      for (const [dr, dc] of [[-1, -1], [-1, 0], [-1, 1], [0, -1], [0, 1], [1, -1], [1, 0], [1, 1]]) {
        addIfValid(row + dr!, col + dc!);
      }
      // Castling
      const opponent = piece.color === 'white' ? 'black' : 'white';
      if (piece.color === 'white' && row === 7 && col === 4) {
        if (castling.whiteKingside && !board[61] && !board[62] && board[63]?.type === 'rook' &&
          !isSquareAttackedBy(board, 60, opponent) && !isSquareAttackedBy(board, 61, opponent) && !isSquareAttackedBy(board, 62, opponent)) {
          moves.push(62);
        }
        if (castling.whiteQueenside && !board[59] && !board[58] && !board[57] && board[56]?.type === 'rook' &&
          !isSquareAttackedBy(board, 60, opponent) && !isSquareAttackedBy(board, 59, opponent) && !isSquareAttackedBy(board, 58, opponent)) {
          moves.push(58);
        }
      }
      if (piece.color === 'black' && row === 0 && col === 4) {
        if (castling.blackKingside && !board[5] && !board[6] && board[7]?.type === 'rook' &&
          !isSquareAttackedBy(board, 4, opponent) && !isSquareAttackedBy(board, 5, opponent) && !isSquareAttackedBy(board, 6, opponent)) {
          moves.push(6);
        }
        if (castling.blackQueenside && !board[3] && !board[2] && !board[1] && board[0]?.type === 'rook' &&
          !isSquareAttackedBy(board, 4, opponent) && !isSquareAttackedBy(board, 3, opponent) && !isSquareAttackedBy(board, 2, opponent)) {
          moves.push(2);
        }
      }
      break;
    }
  }

  return moves;
}

function getLegalMoves(board: (ChessPiece | null)[], sq: number, castling: ChessState['castlingRights'], enPassant: number | null): number[] {
  const piece = board[sq];
  if (!piece) return [];

  const pseudoMoves = getPseudoLegalMoves(board, sq, castling, enPassant);
  return pseudoMoves.filter((to) => {
    const testBoard = [...board];
    // Handle en passant capture
    if (piece.type === 'pawn' && to === enPassant) {
      const capturedPawnSq = piece.color === 'white' ? to + 8 : to - 8;
      testBoard[capturedPawnSq] = null;
    }
    testBoard[to] = testBoard[sq] ?? null;
    testBoard[sq] = null;
    // Handle castling rook move
    if (piece.type === 'king' && Math.abs((sq % 8) - (to % 8)) === 2) {
      if (to === 62) { testBoard[61] = testBoard[63] ?? null; testBoard[63] = null; }
      else if (to === 58) { testBoard[59] = testBoard[56] ?? null; testBoard[56] = null; }
      else if (to === 6) { testBoard[5] = testBoard[7] ?? null; testBoard[7] = null; }
      else if (to === 2) { testBoard[3] = testBoard[0] ?? null; testBoard[0] = null; }
    }
    return !isInCheck(testBoard, piece.color);
  });
}

function hasAnyLegalMove(board: (ChessPiece | null)[], color: ChessColor, castling: ChessState['castlingRights'], enPassant: number | null): boolean {
  for (let sq = 0; sq < 64; sq++) {
    const piece = board[sq];
    if (piece && piece.color === color) {
      if (getLegalMoves(board, sq, castling, enPassant).length > 0) return true;
    }
  }
  return false;
}

function createInitialChessState(sessionID: string): ChessState {
  return {
    sessionID,
    board: initialBoard(),
    currentPlayerIndex: 0,
    moveCount: 0,
    gameOver: false,
    inCheck: false,
    isStalemate: false,
    isCheckmate: false,
    castlingRights: { whiteKingside: true, whiteQueenside: true, blackKingside: true, blackQueenside: true },
    enPassantSquare: null,
    moveHistory: [],
    capturedPieces: { white: [], black: [] },
    timestamp: appleTimestamp(),
  };
}

interface ChessProps {
  onBack: () => void;
}

function Chess({ onBack }: ChessProps) {
  const gameState = useGameStore((s) => s.chessState);
  const session = useGameStore((s) => s.currentSession);
  const localPeerId = useConnectionStore((s) => s.localPeerId);
  const peers = usePoolStore((s) => s.peers);
  const userProfile = usePoolStore((s) => s.userProfile);
  const [selectedSquare, setSelectedSquare] = useState<number | null>(null);
  const [promotionSquare, setPromotionSquare] = useState<{ from: number; to: number } | null>(null);

  const localPlayerIndex = useMemo(() => {
    if (!session) return -1;
    return session.players.find((p) => p.id === localPeerId)?.playerIndex ?? -1;
  }, [session, localPeerId]);

  const myColor: ChessColor = localPlayerIndex === 0 ? 'white' : 'black';
  const isFlipped = myColor === 'black';

  const legalMoves = useMemo(() => {
    if (!gameState || selectedSquare === null) return [];
    return getLegalMoves(gameState.board, selectedSquare, gameState.castlingRights, gameState.enPassantSquare);
  }, [gameState, selectedSquare]);

  const legalMoveSet = useMemo(() => new Set(legalMoves), [legalMoves]);

  const isMyTurn = gameState ? gameState.currentPlayerIndex === localPlayerIndex : false;
  const currentColor: ChessColor = gameState ? (gameState.currentPlayerIndex === 0 ? 'white' : 'black') : 'white';

  function handleSquareClick(sq: number) {
    if (!gameState || gameState.gameOver) return;

    const piece = gameState.board[sq];

    if (selectedSquare === null) {
      if (piece && piece.color === myColor && isMyTurn) {
        setSelectedSquare(sq);
      }
      return;
    }

    if (sq === selectedSquare) {
      setSelectedSquare(null);
      return;
    }

    // Clicking own piece: reselect
    if (piece && piece.color === myColor) {
      setSelectedSquare(sq);
      return;
    }

    // Attempt move
    if (!legalMoveSet.has(sq)) {
      setSelectedSquare(null);
      return;
    }

    const movingPiece = gameState.board[selectedSquare];
    // Check pawn promotion
    if (movingPiece?.type === 'pawn') {
      const [toRow] = squareToCoords(sq);
      if ((movingPiece.color === 'white' && toRow === 0) || (movingPiece.color === 'black' && toRow === 7)) {
        setPromotionSquare({ from: selectedSquare, to: sq });
        return;
      }
    }

    executeMove(selectedSquare, sq);
  }

  function executeMove(from: number, to: number, promotion?: ChessPieceType) {
    if (!gameState) return;

    const [fromRow, fromCol] = squareToCoords(from);
    const [toRow, toCol] = squareToCoords(to);
    // Transform to iOS coordinate system: iOS row 0 = white's back rank (rank 1)
    // Web row 0 = black's back rank (rank 8). So wireRow = 7 - webRow.
    const action: ChessAction = {
      fromRow: 7 - fromRow,
      fromCol,
      toRow: 7 - toRow,
      toCol,
      promotionPiece: promotion,
      playerIndex: localPlayerIndex,
      moveNumber: gameState.moveCount,
      timestamp: appleTimestamp(),
    };

    transport.sendGameAction(action, null);

    // Apply locally
    const board = [...gameState.board];
    const piece = board[from];
    if (!piece) return;

    const captured = board[to];
    const capturedPieces = { ...gameState.capturedPieces, white: [...gameState.capturedPieces.white], black: [...gameState.capturedPieces.black] };
    if (captured) {
      capturedPieces[piece.color === 'white' ? 'black' : 'white'].push(captured.type);
    }

    // En passant capture
    let enPassantSquare: number | null = null;
    if (piece.type === 'pawn' && to === gameState.enPassantSquare) {
      const capturedSq = piece.color === 'white' ? to + 8 : to - 8;
      const epCaptured = board[capturedSq];
      if (epCaptured) {
        capturedPieces[piece.color === 'white' ? 'black' : 'white'].push(epCaptured.type);
      }
      board[capturedSq] = null;
    }

    // Set en passant square
    if (piece.type === 'pawn' && Math.abs(from - to) === 16) {
      enPassantSquare = (from + to) / 2;
    }

    board[to] = promotion ? { type: promotion, color: piece.color } : piece;
    board[from] = null;

    // Castling rook move
    if (piece.type === 'king' && Math.abs((from % 8) - (to % 8)) === 2) {
      if (to === 62) { board[61] = board[63] ?? null; board[63] = null; }
      else if (to === 58) { board[59] = board[56] ?? null; board[56] = null; }
      else if (to === 6) { board[5] = board[7] ?? null; board[7] = null; }
      else if (to === 2) { board[3] = board[0] ?? null; board[0] = null; }
    }

    // Update castling rights
    const cr = { ...gameState.castlingRights };
    if (piece.type === 'king') {
      if (piece.color === 'white') { cr.whiteKingside = false; cr.whiteQueenside = false; }
      else { cr.blackKingside = false; cr.blackQueenside = false; }
    }
    if (piece.type === 'rook') {
      if (from === 63) cr.whiteKingside = false;
      if (from === 56) cr.whiteQueenside = false;
      if (from === 7) cr.blackKingside = false;
      if (from === 0) cr.blackQueenside = false;
    }
    if (to === 63) cr.whiteKingside = false;
    if (to === 56) cr.whiteQueenside = false;
    if (to === 7) cr.blackKingside = false;
    if (to === 0) cr.blackQueenside = false;

    const nextPlayerIndex = localPlayerIndex === 0 ? 1 : 0;
    const nextColor: ChessColor = nextPlayerIndex === 0 ? 'white' : 'black';
    const inCheck = isInCheck(board, nextColor);
    const hasLegalMove = hasAnyLegalMove(board, nextColor, cr, enPassantSquare);
    const isCheckmate = inCheck && !hasLegalMove;
    const isStalemate = !inCheck && !hasLegalMove;
    const gameOver = isCheckmate || isStalemate;

    const newState: ChessState = {
      ...gameState,
      board,
      currentPlayerIndex: nextPlayerIndex,
      moveCount: gameState.moveCount + 1,
      gameOver,
      winnerIndex: isCheckmate ? localPlayerIndex : undefined,
      inCheck,
      isStalemate,
      isCheckmate,
      castlingRights: cr,
      enPassantSquare,
      moveHistory: [...gameState.moveHistory, action],
      capturedPieces,
      timestamp: action.timestamp,
    };

    useGameStore.getState().setChessState(newState);
    setSelectedSquare(null);
    setPromotionSquare(null);

    if (gameOver) {
      transport.sendGameState(newState, null);

      // Game over is communicated via state sync — no system messages needed
    }
  }

  function handlePromotion(type: ChessPieceType) {
    if (!promotionSquare) return;
    executeMove(promotionSquare.from, promotionSquare.to, type);
  }

  function handleRematch() {
    if (!session) return;
    const payload: GameControlPayload = { controlType: 'rematch', gameType: 'chess', sessionID: session.sessionID };
    transport.sendGameControl(payload, null);
    useGameStore.getState().setChessState(
      createInitialChessState(session.sessionID),
    );
    setSelectedSquare(null);
  }

  function handleQuit() {
    if (session) {
      const payload: GameControlPayload = { controlType: 'forfeit', gameType: 'chess', sessionID: session.sessionID };
      transport.sendGameControl(payload, null);
    }
    useGameStore.getState().setChessState(null);
    useGameStore.getState().setGameActive(false);
    onBack();
  }

  useEffect(() => {
    const store = useGameStore.getState();
    if (!gameState && store.isGameActive && session?.sessionID) {
      store.setChessState(
        createInitialChessState(session.sessionID),
      );
    }
  }, [gameState, session?.sessionID]);

  if (!gameState) return null;

  const kingInCheckSq = gameState.inCheck ? findKing(gameState.board, currentColor) : -1;

  const currentPlayer = session?.players.find((p) => p.playerIndex === gameState.currentPlayerIndex);
  const winner = gameState.winnerIndex !== undefined ? session?.players.find((p) => p.playerIndex === gameState.winnerIndex) : null;

  function renderSquare(displayRow: number, displayCol: number) {
    const row = isFlipped ? 7 - displayRow : displayRow;
    const col = isFlipped ? 7 - displayCol : displayCol;
    const sq = coordsToSquare(row, col);
    const piece = gameState!.board[sq];
    const isLight = (row + col) % 2 === 0;
    const isSelected = sq === selectedSquare;
    const isLegalTarget = legalMoveSet.has(sq);
    const isKingCheck = sq === kingInCheckSq;

    return (
      <button
        key={sq}
        type="button"
        onClick={() => handleSquareClick(sq)}
        className={`aspect-square flex items-center justify-center text-[clamp(1.1rem,4vw,1.6rem)] relative transition-all
          ${isLight ? 'bg-[#EDD9B8]' : 'bg-[#B3875C]'}
          ${isSelected ? 'bg-[#73A540]/50' : ''}
          ${isKingCheck ? 'ring-2 ring-red-500 ring-inset bg-red-400/50' : ''}
        `}
      >
        {piece && (
          <img
            src={PIECE_SVG[piece.color][piece.type]}
            alt={`${piece.color} ${piece.type}`}
            className={`w-[65%] h-[65%] select-none pointer-events-none ${
              piece.color === 'white'
                ? 'drop-shadow-[0_0_1px_rgba(0,0,0,0.8)] [filter:drop-shadow(0_0.5px_0.8px_rgba(0,0,0,0.4))]'
                : ''
            }`}
            draggable={false}
          />
        )}
        {isLegalTarget && !piece && (
          <div className="absolute h-2.5 w-2.5 sm:h-3 sm:w-3 rounded-full bg-blue-500/40" />
        )}
        {isLegalTarget && piece && (
          <div className="absolute inset-0 rounded-sm ring-2 ring-inset ring-blue-400/60" />
        )}
      </button>
    );
  }

  return (
    <div className="flex-1 flex flex-col min-h-0">
      {/* Top bar */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm">
        <button type="button" onClick={onBack} className="text-slate-400 hover:text-white transition-colors">
          <ArrowLeft className="h-5 w-5" />
        </button>
        <span className="text-lg">♟️</span>
        <span className="text-sm font-medium text-white flex-1">Chess</span>
        <button type="button" onClick={handleQuit} className="text-red-400 hover:text-red-300 transition-colors flex items-center gap-1 text-xs">
          <LogOut className="h-3.5 w-3.5" /> Leave
        </button>
      </div>

      <div className="flex-1 flex flex-col items-center p-3 sm:p-4 min-h-0">
        {/* Fixed board area — doesn't shift with content below */}
        <div className="flex flex-col items-center w-full max-w-[min(100%,24rem)] mx-auto mt-2">
          {/* Opponent info + captured pieces */}
          {session?.players.filter((p) => p.id !== localPeerId).map((player) => {
            const peer = peers.find((p) => p.peerId === player.id);
            const capturedColor = player.playerIndex === 0 ? 'black' : 'white';
            return (
              <div key={player.id} className="flex items-center gap-2 w-full mb-1.5 px-0.5">
                <PeerAvatar
                  emoji={peer?.avatarEmoji ?? player.profile?.avatarEmoji ?? '😀'}
                  colorIndex={peer?.avatarColorIndex ?? player.profile?.avatarColorIndex ?? 0}
                  size="sm"
                />
                <p className="text-xs font-medium text-white truncate">{peer?.displayName ?? player.name}</p>
                {gameState.capturedPieces[capturedColor].length > 0 && (
                  <div className="flex gap-0.5 flex-wrap flex-1 justify-end bg-[#B3875C]/40 rounded px-1.5 py-0.5">
                    {gameState.capturedPieces[capturedColor].map((pt, i) => (
                      <img key={i} src={PIECE_SVG[capturedColor][pt]} alt={pt} className="h-4 w-4" />
                    ))}
                  </div>
                )}
              </div>
            );
          })}

          {/* Board */}
          <div className="bg-[#5C3A1E] p-0.5 rounded-lg shadow-lg w-full">
            <div className="grid grid-cols-8">
              {Array.from({ length: 64 }, (_, i) => renderSquare(Math.floor(i / 8), i % 8))}
            </div>
          </div>

          {/* Self info + captured pieces */}
          <div className="flex items-center gap-2 w-full mt-1.5 px-0.5">
            <PeerAvatar emoji={userProfile.avatarEmoji} colorIndex={userProfile.avatarColorIndex} size="sm" />
            <p className="text-xs font-medium text-white truncate">{userProfile.displayName} (you)</p>
            {(() => {
              const capColor = myColor === 'white' ? 'black' as const : 'white' as const;
              const pieces = gameState.capturedPieces[capColor];
              return pieces.length > 0 ? (
                <div className="flex gap-0.5 flex-wrap flex-1 justify-end bg-[#B3875C]/40 rounded px-1.5 py-0.5">
                  {pieces.map((pt, i) => (
                    <img key={i} src={PIECE_SVG[capColor][pt]} alt={pt} className="h-4 w-4" />
                  ))}
                </div>
              ) : null;
            })()}
          </div>
        </div>

        {/* Status */}
        <div className="mt-2 text-center">
          {!gameState.gameOver && (
            <p className="text-sm text-slate-300">
              {isMyTurn ? (gameState.inCheck ? 'You are in check! Your turn.' : 'Your turn') : `${currentPlayer?.name ?? 'Opponent'}'s turn`}
            </p>
          )}
        </div>

        {/* Promotion dialog */}
        {promotionSquare && (
          <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
            <div className="glass-card p-4 space-y-3 animate-slide-up w-full max-w-xs">
              <p className="text-sm font-medium text-white text-center">Promote pawn to:</p>
              <div className="flex gap-2 sm:gap-3 justify-center">
                {(['queen', 'rook', 'bishop', 'knight'] as const).map((type) => (
                  <button
                    key={type}
                    type="button"
                    onClick={() => handlePromotion(type)}
                    className="h-12 w-12 sm:h-14 sm:w-14 rounded-lg bg-slate-800 hover:bg-slate-700 flex items-center justify-center transition-colors p-2"
                  >
                    <img src={PIECE_SVG[myColor][type]} alt={type} className="w-full h-full" />
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Game over */}
        {gameState.gameOver && (
          <div className="glass-card p-5 text-center space-y-3 animate-slide-up mt-2">
            <h3 className="text-lg font-bold text-white">
              {gameState.isCheckmate
                ? winner?.id === localPeerId ? 'Checkmate! You won! 🎉' : `Checkmate! ${winner?.name ?? 'Opponent'} wins!`
                : 'Stalemate - Draw!'}
            </h3>
            <div className="flex gap-3 justify-center">
              <button type="button" onClick={handleRematch} className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg transition-colors">
                <RotateCcw className="h-4 w-4" /> Rematch
              </button>
              <button type="button" onClick={handleQuit} className="px-4 py-2 border border-slate-700 text-slate-300 text-sm rounded-lg hover:bg-slate-800 transition-colors">
                Back to Lobby
              </button>
            </div>
          </div>
        )}

        {/* Move history — scrollable, doesn't push the board */}
        {gameState.moveHistory.length > 0 && (
          <div className="w-full max-w-[min(100%,24rem)] mt-2">
            <p className="text-xs text-slate-500 mb-1">Move History</p>
            <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
              {gameState.moveHistory.map((move, i) => {
                const files = 'abcdefgh';
                const notation = `${files[move.fromCol] ?? '?'}${move.fromRow + 1}→${files[move.toCol] ?? '?'}${move.toRow + 1}`;
                return (
                  <span key={i} className={`text-[11px] px-1.5 py-0.5 rounded ${i % 2 === 0 ? 'bg-slate-800 text-slate-300' : 'bg-slate-800/50 text-slate-400'}`}>
                    {Math.floor(i / 2) + 1}{i % 2 === 0 ? '.' : '...'} {notation}
                  </span>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Chess;
