import { useState, useMemo, useEffect, useCallback, useRef } from 'react';
import { ArrowLeft, LogOut, RotateCcw } from 'lucide-react';
import { useGameStore } from '../../stores/game.ts';
import { useConnectionStore } from '../../stores/connection.ts';
import { usePoolStore } from '../../stores/pool.ts';
import { transport } from '../../transport/websocket.ts';
import { appleTimestamp } from '../../utils/time.ts';
import { base64Encode, base64Decode } from '../../utils/base64.ts';
import type {
  LudoBoardState,
  LudoPlayer,
  LudoToken,
  LudoTokenPosition,
  LudoValidMove,
  LudoAction,
  GameControlPayload,
} from '../../protocol/messages.ts';
import PeerAvatar from '../../components/PeerAvatar.tsx';

/** Convert a web LudoTokenPosition to iOS Swift enum JSON format */
function positionToiOS(pos: LudoTokenPosition): Record<string, unknown> {
  switch (pos.type) {
    case 'yard': return { yard: {} };
    case 'home': return { home: {} };
    case 'board': return { board: { step: pos.step ?? 0 } };
    case 'homeColumn': return { homeColumn: { step: pos.step ?? 0 } };
  }
}

/** Convert a web LudoToken to iOS format: { id: { playerIndex, tokenIndex }, position } */
function tokenToiOS(token: LudoToken, playerIndex: number): Record<string, unknown> {
  return {
    id: { playerIndex, tokenIndex: token.tokenIndex },
    position: positionToiOS(token.position),
  };
}

/** Convert a web LudoBoardState to iOS-compatible JSON format */
function stateToiOS(state: LudoBoardState): Record<string, unknown> {
  return {
    ...state,
    players: state.players.map(p => ({
      ...p,
      tokens: p.tokens.map(t => tokenToiOS(t, p.playerIndex)),
    })),
  };
}

/** Send LudoBoardState wrapped as a LudoBroadcast stateSync, matching iOS protocol */
function broadcastStateSync(state: LudoBoardState): void {
  const iosState = stateToiOS(state);
  const payload = base64Encode(new TextEncoder().encode(JSON.stringify(iosState)));
  transport.sendGameState(
    { type: 'stateSync', timestamp: appleTimestamp(), payload },
    null,
  );
}

function broadcastDiceRolled(playerIndex: number, rollValue: number, validMoves: LudoValidMove[], turnNumber: number): void {
  const payloadStr = JSON.stringify({ 
    playerIndex, 
    rollValue, 
    validMoves: validMoves.map(m => ({
      tokenIndex: m.tokenIndex,
      fromPosition: positionToiOS(m.fromPosition),
      toPosition: positionToiOS(m.toPosition),
      capturesOpponent: m.capturesOpponent ? {
        playerIndex: m.capturesOpponent.playerIndex,
        tokenIndex: m.capturesOpponent.tokenIndex,
      } : null,
    })),
    turnNumber 
  });
  const payload = base64Encode(new TextEncoder().encode(payloadStr));
  transport.sendGameState({ type: 'diceRolled', timestamp: appleTimestamp(), payload }, null);
}

function broadcastTokenMoved(playerIndex: number, tokenIndex: number, from: LudoTokenPosition, to: LudoTokenPosition, capturedToken: { playerIndex: number; tokenIndex: number } | null, turnNumber: number): void {
  const payloadStr = JSON.stringify({
    playerIndex,
    tokenIndex,
    from: positionToiOS(from),
    to: positionToiOS(to),
    capturedToken,
    turnNumber,
  });
  const payload = base64Encode(new TextEncoder().encode(payloadStr));
  transport.sendGameState({ type: 'tokenMoved', timestamp: appleTimestamp(), payload }, null);
}

function broadcastTurnChanged(currentPlayerIndex: number, turnNumber: number): void {
  const payloadStr = JSON.stringify({ currentPlayerIndex, turnNumber });
  const payload = base64Encode(new TextEncoder().encode(payloadStr));
  transport.sendGameState({ type: 'turnChanged', timestamp: appleTimestamp(), payload }, null);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PLAYER_COLORS = ['#DC2626', '#16A34A', '#EAB308', '#2563EB'] as const;
const PLAYER_LIGHT_COLORS = ['#FEE2E2', '#DCFCE7', '#FEF9C3', '#DBEAFE'] as const;
const PLAYER_COLOR_NAMES = ['Red', 'Green', 'Yellow', 'Blue'] as const;
const SAFE_POSITIONS = new Set([0, 8, 13, 21, 26, 34, 39, 47]);
const BOARD_CELLS = 52;
const HOME_COLUMN_LENGTH = 6;
const TOKENS_PER_PLAYER = 4;

// ---------------------------------------------------------------------------
// Board coordinate system — 15x15 grid. Direct port of LudoBoardView.swift.
// ---------------------------------------------------------------------------

/** Track positions 0-51 mapped to [row, col] on the 15x15 grid. */
const TRACK_COORDS: [number, number][] = [
  // Red start area going up (steps 0-4)
  [13, 6], [12, 6], [11, 6], [10, 6], [9, 6],
  // Turn left across top of bottom arm (steps 5-10)
  [8, 5], [8, 4], [8, 3], [8, 2], [8, 1], [8, 0],
  // Up left side (steps 11-12)
  [7, 0], [6, 0],
  // Green arm going right (steps 13-17)
  [6, 1], [6, 2], [6, 3], [6, 4], [6, 5],
  // Turn up (steps 18-23)
  [5, 6], [4, 6], [3, 6], [2, 6], [1, 6], [0, 6],
  // Across top (steps 24-25)
  [0, 7], [0, 8],
  // Yellow arm going down (steps 26-30)
  [1, 8], [2, 8], [3, 8], [4, 8], [5, 8],
  // Turn right (steps 31-36)
  [6, 9], [6, 10], [6, 11], [6, 12], [6, 13], [6, 14],
  // Down right side (steps 37-38)
  [7, 14], [8, 14],
  // Blue arm going left (steps 39-43)
  [8, 13], [8, 12], [8, 11], [8, 10], [8, 9],
  // Turn down (steps 44-49)
  [9, 8], [10, 8], [11, 8], [12, 8], [13, 8], [14, 8],
  // Back to start (steps 50-51)
  [14, 7], [14, 6],
];

/** Home column grid positions per player (6 cells each). */
const HOME_COLUMN_COORDS: [number, number][][] = [
  [[13, 7], [12, 7], [11, 7], [10, 7], [9, 7], [8, 7]],  // Red: bottom up
  [[7, 1], [7, 2], [7, 3], [7, 4], [7, 5], [7, 6]],       // Green: left right
  [[1, 7], [2, 7], [3, 7], [4, 7], [5, 7], [6, 7]],       // Yellow: top down
  [[7, 13], [7, 12], [7, 11], [7, 10], [7, 9], [7, 8]],   // Blue: right left
];

/** Yard token positions inside the 6x6 corner areas (2x2 within inner area). */
const YARD_COORDS: [number, number][][] = [
  [[10, 1], [10, 4], [13, 1], [13, 4]],   // Red: bottom-left
  [[1, 1], [1, 4], [4, 1], [4, 4]],       // Green: top-left
  [[1, 10], [1, 13], [4, 10], [4, 13]],   // Yellow: top-right
  [[10, 10], [10, 13], [13, 10], [13, 13]], // Blue: bottom-right
];

/** Home center grid coordinate for tokens that have finished. */
const HOME_CENTER: [number, number] = [7, 7];

/** Home center offsets for each player's finished tokens (2x2 within center). */
const HOME_OFFSETS: [number, number][] = [
  [-0.25, -0.25], [0.25, -0.25], [-0.25, 0.25], [0.25, 0.25],
];

// ---------------------------------------------------------------------------
// Geometry helpers
// ---------------------------------------------------------------------------

function getStartPosition(playerIndex: number): number {
  return (playerIndex * 13) % BOARD_CELLS;
}

function isSafeSpot(step: number): boolean {
  if (SAFE_POSITIONS.has(step)) return true;
  for (let i = 0; i < 4; i++) {
    if (getStartPosition(i) === step) return true;
  }
  return false;
}

function distanceFromStart(position: number, playerIndex: number): number {
  const start = getStartPosition(playerIndex);
  return position >= start ? position - start : BOARD_CELLS - start + position;
}

function findPlayer(state: LudoBoardState | null | undefined, playerIndex: number): LudoPlayer | undefined {
  return state?.players?.find(p => p.playerIndex === playerIndex);
}

function getTokenGridCoords(
  position: LudoTokenPosition,
  playerIndex: number,
  tokenIndex: number,
): [number, number] {
  switch (position.type) {
    case 'yard':
      return YARD_COORDS[playerIndex]?.[tokenIndex] ?? [0, 0];
    case 'board':
      return TRACK_COORDS[((position.step ?? 0) % 52 + 52) % 52] ?? [7, 7];
    case 'homeColumn':
      return HOME_COLUMN_COORDS[playerIndex]?.[Math.min(position.step ?? 0, 5)] ?? [7, 7];
    case 'home':
      return HOME_CENTER;
  }
}

// ---------------------------------------------------------------------------
// Game logic — used when web is HOST
// ---------------------------------------------------------------------------

function createInitialLudoState(
  players: { id: string; name: string; playerIndex: number; isHost: boolean; isAI: boolean }[],
): LudoBoardState {
  return {
    players: players.map(p => ({
      id: p.id,
      name: p.name,
      playerIndex: p.playerIndex,
      isHost: p.isHost,
      isAI: p.isAI,
      tokens: Array.from({ length: TOKENS_PER_PLAYER }, (_, i) => ({
        tokenIndex: i,
        position: { type: 'yard' as const },
      })),
      isConnected: true,
      isFinished: false,
    })),
    currentPlayerIndex: 0,
    gamePhase: 'playing',
    gameMode: 'classic',
    teams: [],
    lastDiceRoll: null,
    turnNumber: 1,
    mustRollAgain: false,
    consecutiveSixes: 0,
    winnerPlayerIndex: null,
    winnerTeamIndex: null,
    finishOrder: [],
  };
}

function rollDice(): number {
  return Math.floor(Math.random() * 6) + 1;
}

function findCapture(
  state: LudoBoardState,
  movingPlayerIndex: number,
  targetStep: number,
): { playerIndex: number; tokenIndex: number } | null {
  if (isSafeSpot(targetStep)) return null;
  for (const opponent of state.players) {
    if (opponent.playerIndex === movingPlayerIndex) continue;
    for (const token of opponent.tokens) {
      if (token.position.type === 'board' && token.position.step === targetStep) {
        return { playerIndex: opponent.playerIndex, tokenIndex: token.tokenIndex };
      }
    }
  }
  return null;
}

function computeValidMoves(state: LudoBoardState, playerIndex: number, roll: number): LudoValidMove[] {
  const player = findPlayer(state, playerIndex);
  if (!player) return [];
  const moves: LudoValidMove[] = [];

  for (const token of player.tokens) {
    const from = token.position;
    if (from.type === 'yard') {
      if (roll !== 6) continue;
      const startPos = getStartPosition(playerIndex);
      moves.push({
        tokenIndex: token.tokenIndex,
        fromPosition: from,
        toPosition: { type: 'board', step: startPos },
        capturesOpponent: findCapture(state, playerIndex, startPos),
      });
    } else if (from.type === 'board') {
      const currentStep = from.step ?? 0;
      const dist = distanceFromStart(currentStep, playerIndex);
      const newDist = dist + roll;
      const homeEntry = 50;

      if (newDist > homeEntry + HOME_COLUMN_LENGTH) {
        continue; // overshot
      } else if (newDist === homeEntry + HOME_COLUMN_LENGTH) {
        moves.push({
          tokenIndex: token.tokenIndex,
          fromPosition: from,
          toPosition: { type: 'home' },
          capturesOpponent: null,
        });
      } else if (newDist > homeEntry) {
        const homeStep = newDist - homeEntry - 1;
        const blocked = player.tokens.some(
          t => t.tokenIndex !== token.tokenIndex && t.position.type === 'homeColumn' && t.position.step === homeStep,
        );
        if (!blocked) {
          moves.push({
            tokenIndex: token.tokenIndex,
            fromPosition: from,
            toPosition: { type: 'homeColumn', step: homeStep },
            capturesOpponent: null,
          });
        }
      } else {
        const newStep = (currentStep + roll) % BOARD_CELLS;
        moves.push({
          tokenIndex: token.tokenIndex,
          fromPosition: from,
          toPosition: { type: 'board', step: newStep },
          capturesOpponent: findCapture(state, playerIndex, newStep),
        });
      }
    } else if (from.type === 'homeColumn') {
      const currentStep = from.step ?? 0;
      const newStep = currentStep + roll;
      if (newStep === HOME_COLUMN_LENGTH) {
        moves.push({
          tokenIndex: token.tokenIndex,
          fromPosition: from,
          toPosition: { type: 'home' },
          capturesOpponent: null,
        });
      } else if (newStep < HOME_COLUMN_LENGTH) {
        const blocked = player.tokens.some(
          t => t.tokenIndex !== token.tokenIndex && t.position.type === 'homeColumn' && t.position.step === newStep,
        );
        if (!blocked) {
          moves.push({
            tokenIndex: token.tokenIndex,
            fromPosition: from,
            toPosition: { type: 'homeColumn', step: newStep },
            capturesOpponent: null,
          });
        }
      }
      // newStep > HOME_COLUMN_LENGTH: overshot, skip
    }
    // home tokens don't move
  }
  return moves;
}

function applyMove(state: LudoBoardState, playerIndex: number, move: LudoValidMove): LudoBoardState {
  const newPlayers = state.players.map(p => ({
    ...p,
    tokens: p.tokens.map(t => ({ ...t, position: { ...t.position } })),
  }));

  // Move the token
  const player = newPlayers.find(p => p.playerIndex === playerIndex);
  if (!player) return state;
  const token = player.tokens.find(t => t.tokenIndex === move.tokenIndex);
  if (token) token.position = { ...move.toPosition };

  // Capture
  if (move.capturesOpponent) {
    const capPlayer = newPlayers.find(p => p.playerIndex === move.capturesOpponent!.playerIndex);
    const capToken = capPlayer?.tokens.find(t => t.tokenIndex === move.capturesOpponent!.tokenIndex);
    if (capToken) capToken.position = { type: 'yard' };
  }

  // Check finished
  if (player.tokens.every(t => t.position.type === 'home') && !player.isFinished) {
    player.isFinished = true;
  }

  return { ...state, players: newPlayers };
}

function checkGameOver(state: LudoBoardState): { finished: boolean; winnerIndex: number | null; finishOrder: number[] } {
  const finishedPlayers = state.players.filter(p => p.isFinished);
  const finishOrder = finishedPlayers.map(p => p.playerIndex);
  const activePlayers = state.players.filter(p => !p.isFinished);
  if (activePlayers.length <= 1) {
    for (const p of activePlayers) {
      if (!finishOrder.includes(p.playerIndex)) finishOrder.push(p.playerIndex);
    }
    return { finished: true, winnerIndex: finishOrder[0] ?? null, finishOrder };
  }
  return { finished: false, winnerIndex: null, finishOrder };
}

function getNextPlayerIndex(state: LudoBoardState, current: number): number {
  const maxIdx = Math.max(...state.players.map(p => p.playerIndex), 3);
  let next = (current + 1) % (maxIdx + 1);
  let attempts = 0;
  while (attempts <= maxIdx) {
    const p = findPlayer(state, next);
    if (p && !p.isFinished) return next;
    next = (next + 1) % (maxIdx + 1);
    attempts++;
  }
  return current;
}

// ---------------------------------------------------------------------------
// AI
// ---------------------------------------------------------------------------

function aiSelectMove(moves: LudoValidMove[]): LudoValidMove | null {
  if (moves.length === 0) return null;
  if (moves.length === 1) return moves[0]!;
  const captures = moves.filter(m => m.capturesOpponent !== null);
  if (captures.length > 0) return captures[Math.floor(Math.random() * captures.length)]!;
  const homeMoves = moves.filter(m => m.toPosition.type === 'home');
  if (homeMoves.length > 0) return homeMoves[Math.floor(Math.random() * homeMoves.length)]!;
  const homeCol = moves.filter(m => m.toPosition.type === 'homeColumn');
  if (homeCol.length > 0) return homeCol[Math.floor(Math.random() * homeCol.length)]!;
  const yardExits = moves.filter(m => m.fromPosition.type === 'yard');
  if (yardExits.length > 0) return yardExits[Math.floor(Math.random() * yardExits.length)]!;
  return moves[Math.floor(Math.random() * moves.length)]!;
}

// ---------------------------------------------------------------------------
// Dice Face
// ---------------------------------------------------------------------------

const DOT_LAYOUTS: Record<number, [number, number][]> = {
  1: [[50, 50]],
  2: [[25, 25], [75, 75]],
  3: [[25, 25], [50, 50], [75, 75]],
  4: [[25, 25], [75, 25], [25, 75], [75, 75]],
  5: [[25, 25], [75, 25], [50, 50], [25, 75], [75, 75]],
  6: [[25, 25], [75, 25], [25, 50], [75, 50], [25, 75], [75, 75]],
};

function DiceFace({ value, rolling, color }: { value: number | null; rolling: boolean; color: string }) {
  const dots = value ? (DOT_LAYOUTS[value] ?? []) : [];
  return (
    <div
      className={`w-16 h-16 rounded-xl flex items-center justify-center relative shadow-lg ${rolling ? 'animate-bounce' : ''}`}
      style={{ backgroundColor: 'var(--bg-surface)', border: `2px solid ${color}` }}
    >
      {value ? (
        <svg viewBox="0 0 100 100" className="w-12 h-12">
          {dots.map(([cx, cy], i) => (
            <circle key={i} cx={cx} cy={cy} r="10" fill={color} />
          ))}
        </svg>
      ) : (
        <span className="text-2xl" style={{ color: 'var(--text-tertiary)' }}>?</span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Token Component
// ---------------------------------------------------------------------------

function TokenPiece({
  playerIndex,
  tokenIndex,
  isHighlighted,
  onClick,
  small,
}: {
  playerIndex: number;
  tokenIndex: number;
  isHighlighted: boolean;
  onClick?: () => void;
  small?: boolean;
}) {
  const color = PLAYER_COLORS[playerIndex] ?? '#888';
  const size = small ? 'w-4 h-4' : 'w-6 h-6';
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!onClick}
      className={`${size} rounded-full border-2 border-white shadow-md transition-all ${
        isHighlighted ? 'ring-2 ring-offset-1 animate-pulse scale-110 cursor-pointer z-10' : ''
      } ${onClick ? 'cursor-pointer active:scale-90' : 'cursor-default'}`}
      style={{ backgroundColor: color }}
    >
      {!small && (
        <span className="text-[8px] font-bold text-white leading-none flex items-center justify-center h-full">
          {tokenIndex + 1}
        </span>
      )}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Board Cell Rendering
// ---------------------------------------------------------------------------

/** Determine the color theme for a given grid cell. */
function getCellOwner(row: number, col: number): number | null {
  // Red yard: rows 9-14, cols 0-5
  if (row >= 9 && col <= 5) return 0;
  // Green yard: rows 0-5, cols 0-5
  if (row <= 5 && col <= 5) return 1;
  // Yellow yard: rows 0-5, cols 9-14
  if (row <= 5 && col >= 9) return 2;
  // Blue yard: rows 9-14, cols 9-14
  if (row >= 9 && col >= 9) return 3;
  return null;
}

function isHomeColumnCell(row: number, col: number): number | null {
  for (let pi = 0; pi < 4; pi++) {
    const cols = HOME_COLUMN_COORDS[pi];
    if (!cols) continue;
    for (const [r, c] of cols) {
      if (r === row && c === col) return pi;
    }
  }
  return null;
}

function isCenterCell(row: number, col: number): boolean {
  return row >= 6 && row <= 8 && col >= 6 && col <= 8;
}

function getStartPositionColor(step: number): number | null {
  for (let i = 0; i < 4; i++) {
    if (getStartPosition(i) === step) return i;
  }
  return null;
}

function getTrackStep(row: number, col: number): number | null {
  for (let s = 0; s < TRACK_COORDS.length; s++) {
    const coord = TRACK_COORDS[s]!;
    if (coord[0] === row && coord[1] === col) return s;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

interface LudoProps {
  onBack: () => void;
}

function Ludo({ onBack }: LudoProps) {
  const ludoState = useGameStore((s) => s.ludoState);
  const session = useGameStore((s) => s.currentSession);
  const localPeerId = useConnectionStore((s) => s.localPeerId);
  const peers = usePoolStore((s) => s.peers);
  const userProfile = usePoolStore((s) => s.userProfile);

  const [validMoves, setValidMoves] = useState<LudoValidMove[]>(() => {
    const state = useGameStore.getState().ludoState;
    const peerId = useConnectionStore.getState().localPeerId;
    if (!state || state.gamePhase !== 'playing' || state.lastDiceRoll == null) return [];
    const current = findPlayer(state, state.currentPlayerIndex);
    if (!current || current.id !== peerId || current.isAI) return [];
    return computeValidMoves(state, state.currentPlayerIndex, state.lastDiceRoll);
  });
  const [rolling, setRolling] = useState(false);
  const [diceDisplayValue, setDiceDisplayValue] = useState<number | null>(() => {
    return useGameStore.getState().ludoState?.lastDiceRoll ?? null;
  });
  const aiTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const rollAnimRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const rollingRef = useRef(rolling);

  const isHost = session?.hostPeerID === localPeerId;

  const isMyTurn = useMemo(() => {
    if (!ludoState?.players?.length) return false;
    const current = findPlayer(ludoState, ludoState.currentPlayerIndex);
    if (!current) return false;
    return current.id === localPeerId && !current.isAI;
  }, [ludoState, localPeerId]);

  const isCurrentPlayerAI = useMemo(() => {
    if (!ludoState?.players?.length) return false;
    return findPlayer(ludoState, ludoState.currentPlayerIndex)?.isAI ?? false;
  }, [ludoState]);

  const currentPlayer = useMemo(
    () => ludoState ? findPlayer(ludoState, ludoState.currentPlayerIndex) : undefined,
    [ludoState],
  );

  const currentPlayerColor = PLAYER_COLORS[ludoState?.currentPlayerIndex ?? 0] ?? '#DC2626';

  const validMoveTokenIndices = useMemo(
    () => new Set(validMoves.map(m => m.tokenIndex)),
    [validMoves],
  );

  // Determine if we need roll (no dice result yet) or selection (dice rolled, moves available)
  const canRoll = isMyTurn && !rolling && ludoState?.lastDiceRoll == null && validMoves.length === 0;
  const canSelect = isMyTurn && validMoves.length > 0;

  useEffect(() => {
    rollingRef.current = rolling;
  }, [rolling]);

  // -------------------------------------------------------------------------
  // Initialize state on mount (web host mode)
  // -------------------------------------------------------------------------
  const advanceTurnAsHost = useCallback((stateArg?: LudoBoardState) => {
    const state = stateArg ?? useGameStore.getState().ludoState;
    if (!state) return;

    const nextIdx = getNextPlayerIndex(state, state.currentPlayerIndex);
    const advanced: LudoBoardState = {
      ...state,
      currentPlayerIndex: nextIdx,
      turnNumber: state.turnNumber + 1,
      lastDiceRoll: null,
      consecutiveSixes: 0,
      mustRollAgain: false,
    };
    useGameStore.getState().setLudoState(advanced);
    broadcastTurnChanged(nextIdx, advanced.turnNumber);
  }, []);

  // -------------------------------------------------------------------------
  // Host: handle token selection (from local player or AI)
  // -------------------------------------------------------------------------
  const handleHostTokenSelect = useCallback((tokenIndex: number, moves?: LudoValidMove[]) => {
    const state = useGameStore.getState().ludoState;
    if (!state || state.gamePhase !== 'playing' || state.lastDiceRoll == null) return;

    const availableMoves = moves ?? computeValidMoves(state, state.currentPlayerIndex, state.lastDiceRoll);
    const move = availableMoves.find(m => m.tokenIndex === tokenIndex);
    if (!move) return;

    let newState = applyMove(state, state.currentPlayerIndex, move);
    newState = { ...newState, lastDiceRoll: null };

    setValidMoves([]);

    // Check win
    const gameResult = checkGameOver(newState);
    if (gameResult.finished) {
      newState = {
        ...newState,
        gamePhase: 'finished',
        winnerPlayerIndex: gameResult.winnerIndex,
        finishOrder: gameResult.finishOrder,
      };
      useGameStore.getState().setLudoState(newState);
      broadcastStateSync(newState);
      return;
    }

    const tokenBefore = state.players.find(p => p.playerIndex === state.currentPlayerIndex)?.tokens.find(t => t.tokenIndex === tokenIndex);
    let capturedTokenID: { playerIndex: number; tokenIndex: number } | null = null;
    if (newState.players !== state.players) {
       // Figure out if a capture happened
       for (const p of state.players) {
         if (p.playerIndex === state.currentPlayerIndex) continue;
         const oldYard = p.tokens.filter(t => t.position.type === 'yard').length;
         const newYard = newState.players.find(np => np.playerIndex === p.playerIndex)?.tokens.filter(t => t.position.type === 'yard').length ?? 0;
         if (newYard > oldYard) {
           const newlyCaptured = p.tokens.find(t => t.position.type !== 'yard' && newState.players.find(np => np.playerIndex === p.playerIndex)?.tokens.find(nt => nt.tokenIndex === t.tokenIndex)?.position.type === 'yard');
           if (newlyCaptured) capturedTokenID = { playerIndex: p.playerIndex, tokenIndex: newlyCaptured.tokenIndex };
         }
       }
    }

    broadcastTokenMoved(
       state.currentPlayerIndex,
       tokenIndex,
       tokenBefore?.position ?? { type: 'yard' },
       move.toPosition,
       capturedTokenID,
       state.turnNumber
    );

    useGameStore.getState().setLudoState(newState);

    if (newState.gamePhase === 'finished') {
      broadcastStateSync(newState);
      return;
    }

    if (newState.mustRollAgain) {
      newState = { ...newState, mustRollAgain: false };
      useGameStore.getState().setLudoState(newState);
      // iOS leaves turn intact, player rolls again natively
      // Do not broadcast stateSync!
    } else {
      advanceTurnAsHost(newState);
    }
  }, [advanceTurnAsHost]);

  // -------------------------------------------------------------------------
  // Host: perform dice roll
  // -------------------------------------------------------------------------
  const handleHostDiceRoll = useCallback(() => {
    const state = useGameStore.getState().ludoState;
    if (!state || state.gamePhase !== 'playing') return;

    const roll = rollDice();

    // Handle consecutive sixes
    let newConsecutiveSixes = state.consecutiveSixes;
    let mustRollAgain = false;
    if (roll === 6) {
      newConsecutiveSixes += 1;
      if (newConsecutiveSixes >= 3) {
        // Three sixes — forfeit turn
        const forfeited: LudoBoardState = {
          ...state,
          lastDiceRoll: roll,
          consecutiveSixes: 0,
          mustRollAgain: false,
        };
        useGameStore.getState().setLudoState(forfeited);
        broadcastStateSync(forfeited);
        setTimeout(() => advanceTurnAsHost(forfeited), 600);
        return;
      }
      mustRollAgain = true;
    } else {
      newConsecutiveSixes = 0;
    }

    const withRoll: LudoBoardState = {
      ...state,
      lastDiceRoll: roll,
      consecutiveSixes: newConsecutiveSixes,
      mustRollAgain,
    };

    useGameStore.getState().setLudoState(withRoll);

    const moves = computeValidMoves(withRoll, withRoll.currentPlayerIndex, roll);
    broadcastDiceRolled(withRoll.currentPlayerIndex, roll, moves, withRoll.turnNumber);

    if (moves.length === 0) {
      // No valid moves — wait briefly then advance
      setTimeout(() => advanceTurnAsHost(withRoll), 800);
    } else if (moves.length === 1 && roll !== 6 && !withRoll.mustRollAgain) {
      const isPlayerAI = withRoll.players.find(p => p.playerIndex === withRoll.currentPlayerIndex)?.isAI ?? false;
      if (!isPlayerAI) {
        // Auto-select single valid move for human players to match UX
        setTimeout(() => {
          const move = moves[0];
          if (move) {
            handleHostTokenSelect(move.tokenIndex, moves);
          }
        }, 300);
      }
    }
  }, [advanceTurnAsHost, handleHostTokenSelect]);

  // -------------------------------------------------------------------------
  // Initialize state on mount (web host mode)
  // -------------------------------------------------------------------------
  useEffect(() => {
    const store = useGameStore.getState();
    if (!ludoState && store.isGameActive && session?.sessionID && isHost) {
      const humanPlayers = session.players.map(p => ({
        id: p.id,
        name: p.name,
        playerIndex: p.playerIndex,
        isHost: p.isHost,
        isAI: false,
      }));
      for (let i = humanPlayers.length; i < 4; i++) {
        humanPlayers.push({
          id: `ai-${i}`,
          name: `Bot ${PLAYER_COLOR_NAMES[i] ?? i}`,
          playerIndex: i,
          isHost: false,
          isAI: true,
        });
      }
      const initial = createInitialLudoState(humanPlayers);
      store.setLudoState(initial);
      broadcastStateSync(initial);
    }
  }, [isHost, ludoState, session]);

  // -------------------------------------------------------------------------
  // Mirror external Ludo state updates into local UI state.
  // -------------------------------------------------------------------------
  useEffect(() => {
    const unsubscribe = useGameStore.subscribe((state, prevState) => {
      const nextLudoState = state.ludoState;
      const prevLudoState = prevState.ludoState;
      if (nextLudoState === prevLudoState) return;
      if (!nextLudoState || nextLudoState.gamePhase !== 'playing') {
        setValidMoves([]);
        return;
      }
      if (nextLudoState.lastDiceRoll == null) {
        setValidMoves([]);
        return;
      }

      setDiceDisplayValue(nextLudoState.lastDiceRoll);
      setRolling(false);
      if (rollAnimRef.current) {
        clearInterval(rollAnimRef.current);
        rollAnimRef.current = null;
      }

      const current = findPlayer(nextLudoState, nextLudoState.currentPlayerIndex);
      const nextIsMyTurn = !!current && current.id === localPeerId && !current.isAI;
      setValidMoves(
        nextIsMyTurn
          ? computeValidMoves(nextLudoState, nextLudoState.currentPlayerIndex, nextLudoState.lastDiceRoll)
          : [],
      );
    });
    return () => unsubscribe();
  }, [localPeerId]);

  // -------------------------------------------------------------------------
  // AI auto-play (host only)
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (!isHost || !ludoState || ludoState.gamePhase !== 'playing') return;
    if (!isCurrentPlayerAI) return;

    // AI needs to roll
    if (ludoState.lastDiceRoll == null) {
      aiTimerRef.current = setTimeout(() => {
        handleHostDiceRoll();
      }, 600);
      return () => {
        if (aiTimerRef.current) clearTimeout(aiTimerRef.current);
      };
    }
  }, [handleHostDiceRoll, isCurrentPlayerAI, isHost, ludoState]);

  // AI token selection after dice rolled
  useEffect(() => {
    if (!isHost || !ludoState || ludoState.gamePhase !== 'playing') return;
    if (!isCurrentPlayerAI || ludoState.lastDiceRoll == null) return;

    const moves = computeValidMoves(ludoState, ludoState.currentPlayerIndex, ludoState.lastDiceRoll);
    if (moves.length === 0) {
      // No valid moves — advance turn
      aiTimerRef.current = setTimeout(() => advanceTurnAsHost(ludoState), 500);
      return () => { if (aiTimerRef.current) clearTimeout(aiTimerRef.current); };
    }

    const selected = aiSelectMove(moves);
    if (!selected) return;

    aiTimerRef.current = setTimeout(() => {
      handleHostTokenSelect(selected.tokenIndex, moves);
    }, 400);
    return () => { if (aiTimerRef.current) clearTimeout(aiTimerRef.current); };
  }, [advanceTurnAsHost, handleHostTokenSelect, isCurrentPlayerAI, isHost, ludoState]);

  // -------------------------------------------------------------------------
  // Cleanup on unmount
  // -------------------------------------------------------------------------
  useEffect(() => {
    return () => {
      if (aiTimerRef.current) clearTimeout(aiTimerRef.current);
      if (rollAnimRef.current) clearInterval(rollAnimRef.current);
    };
  }, []);

  // -------------------------------------------------------------------------
  // Player actions
  // -------------------------------------------------------------------------
  useEffect(() => {
    const unsubscribe = useGameStore.subscribe((state, prevState) => {
      const action = state.ludoAction;
      if (!isHost || !action || action === prevState.ludoAction) return;
      useGameStore.getState().setLudoAction(null);

      const currentState = useGameStore.getState().ludoState;
      if (!currentState || currentState.gamePhase !== 'playing') return;

      const { type, playerID, payload } = action as LudoAction;
      const playerIndex = currentState.players.find((p) => p.id === playerID)?.playerIndex;
      if (playerIndex == null || playerIndex !== currentState.currentPlayerIndex) return;

      if (type === 'requestDiceRoll') {
        if (currentState.lastDiceRoll == null && !rollingRef.current) {
          setRolling(true);
          setValidMoves([]);
          rollAnimRef.current = setInterval(() => {
            setDiceDisplayValue(Math.floor(Math.random() * 6) + 1);
          }, 80);
          setTimeout(() => {
            handleHostDiceRoll();
          }, 600);
        }
        return;
      }

      if (type === 'selectToken' && payload) {
        try {
          const json = new TextDecoder().decode(base64Decode(payload));
          const { tokenIndex } = JSON.parse(json);
          const moves = computeValidMoves(currentState, playerIndex, currentState.lastDiceRoll!);
          handleHostTokenSelect(tokenIndex, moves);
        } catch {
          return;
        }
      }
    });
    return () => unsubscribe();
  }, [handleHostDiceRoll, handleHostTokenSelect, isHost]);

  // Handle local roll intent
  function handleRollDice() {
    if (!ludoState || rolling) return;

    if (isHost) {
      setRolling(true);
      setValidMoves([]);
      rollAnimRef.current = setInterval(() => {
        setDiceDisplayValue(Math.floor(Math.random() * 6) + 1);
      }, 80);
      setTimeout(() => {
        handleHostDiceRoll();
      }, 600);
    } else {
      // Client: send requestDiceRoll to iOS host
      setRolling(true);
      rollAnimRef.current = setInterval(() => {
        setDiceDisplayValue(Math.floor(Math.random() * 6) + 1);
      }, 80);
      transport.sendGameAction(
        {
          type: 'requestDiceRoll',
          playerID: localPeerId,
          turnNumber: ludoState.turnNumber,
          timestamp: appleTimestamp(),
        },
        null,
      );
      // Rolling animation will stop when lastDiceRoll arrives from host
    }
  }

  function handleSelectToken(tokenIndex: number) {
    if (!ludoState) return;

    if (isHost) {
      handleHostTokenSelect(tokenIndex, validMoves.length > 0 ? validMoves : undefined);
    } else {
      // Client: send selectToken to iOS host
      transport.sendGameAction(
        {
          type: 'selectToken',
          playerID: localPeerId,
          turnNumber: ludoState.turnNumber,
          timestamp: appleTimestamp(),
          payload: base64Encode(new TextEncoder().encode(JSON.stringify({ tokenIndex }))),
        },
        null,
      );
      setValidMoves([]);
    }
  }

  function handleRematch() {
    if (!session) return;
    const payload: GameControlPayload = { controlType: 'rematch', gameType: 'ludo', sessionID: session.sessionID };
    transport.sendGameControl(payload, null);
    if (isHost) {
      const humanPlayers = session.players.map(p => ({
        id: p.id,
        name: p.name,
        playerIndex: p.playerIndex,
        isHost: p.isHost,
        isAI: false,
      }));
      for (let i = humanPlayers.length; i < 4; i++) {
        humanPlayers.push({
          id: `ai-${i}`,
          name: `Bot ${PLAYER_COLOR_NAMES[i] ?? i}`,
          playerIndex: i,
          isHost: false,
          isAI: true,
        });
      }
      const initial = createInitialLudoState(humanPlayers);
      useGameStore.getState().setLudoState(initial);
      broadcastStateSync(initial);
    }
    setValidMoves([]);
    setDiceDisplayValue(null);
  }

  function handleQuit() {
    if (session) {
      const payload: GameControlPayload = { controlType: 'forfeit', gameType: 'ludo', sessionID: session.sessionID };
      transport.sendGameControl(payload, null);
    }
    if (aiTimerRef.current) clearTimeout(aiTimerRef.current);
    if (rollAnimRef.current) clearInterval(rollAnimRef.current);
    useGameStore.getState().setLudoState(null);
    useGameStore.getState().setGameActive(false);
    onBack();
  }

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  if (!ludoState) return null;

  const isFinished = ludoState.gamePhase === 'finished';
  const winnerPlayer = ludoState.winnerPlayerIndex != null
    ? findPlayer(ludoState, ludoState.winnerPlayerIndex)
    : undefined;
  const isLocalWinner = winnerPlayer?.id === localPeerId;

  // Build token placement map: grid key -> tokens at that cell
  const tokenMap = new Map<string, { playerIndex: number; tokenIndex: number; isHighlighted: boolean }[]>();

  for (const player of ludoState.players) {
    for (const token of player.tokens) {
      const [row, col] = getTokenGridCoords(token.position, player.playerIndex, token.tokenIndex);
      // For home tokens, offset each token slightly
      let key: string;
      if (token.position.type === 'home') {
        const off = HOME_OFFSETS[token.tokenIndex % 4]!;
        key = `${7 + off[0]},${7 + off[1]},${player.playerIndex}`;
      } else {
        key = `${row},${col}`;
      }
      const isHighlighted =
        player.playerIndex === ludoState.currentPlayerIndex &&
        canSelect &&
        validMoveTokenIndices.has(token.tokenIndex);

      const list = tokenMap.get(key) ?? [];
      list.push({ playerIndex: player.playerIndex, tokenIndex: token.tokenIndex, isHighlighted });
      tokenMap.set(key, list);
    }
  }

  // Render the 15x15 grid
  function renderCell(row: number, col: number) {
    const cellKey = `${row},${col}`;

    // Determine cell background
    let bgColor = 'transparent';
    let borderColor = 'transparent';
    const yardOwner = getCellOwner(row, col);
    const homeColOwner = isHomeColumnCell(row, col);
    const center = isCenterCell(row, col);
    const trackStep = getTrackStep(row, col);

    if (center) {
      // Center 3x3 — determine which quadrant of the center for coloring
      const quadrant =
        row <= 7 && col <= 7 ? 1 :
        row <= 7 && col >= 7 ? 2 :
        row >= 7 && col <= 7 ? 0 :
        3;
      bgColor = PLAYER_COLORS[quadrant] ?? '#888';
      // Blend with opacity
      bgColor = `${bgColor}66`;
    } else if (homeColOwner != null) {
      // Home column cell
      bgColor = `${PLAYER_COLORS[homeColOwner]}40`;
      borderColor = `${PLAYER_COLORS[homeColOwner]}80`;
    } else if (trackStep != null) {
      // Track cell
      const startColor = getStartPositionColor(trackStep);
      if (startColor != null) {
        bgColor = PLAYER_LIGHT_COLORS[startColor] ?? '#f3f4f6';
      } else {
        bgColor = 'rgba(156, 163, 175, 0.15)';
      }
      borderColor = 'rgba(156, 163, 175, 0.25)';
    } else if (yardOwner != null) {
      // Yard area — subtle colored background
      bgColor = `${PLAYER_COLORS[yardOwner]}18`;
    }

    // Find tokens at this cell
    const tokensHere: { playerIndex: number; tokenIndex: number; isHighlighted: boolean }[] = [];

    // For regular cells, check exact row,col key
    const directTokens = tokenMap.get(cellKey);
    if (directTokens) tokensHere.push(...directTokens);

    // For home center: check home-offset keys that round to this cell
    if (center) {
      for (const [key, tokens] of tokenMap.entries()) {
        if (key.includes(',') && key.split(',').length === 3) {
          // home token key: "row,col,playerIndex"
          const parts = key.split(',');
          const r = Math.round(parseFloat(parts[0]!));
          const c = Math.round(parseFloat(parts[1]!));
          if (r === row && c === col) tokensHere.push(...tokens);
        }
      }
    }

    // Safe spot marker
    const isSafe = trackStep != null && SAFE_POSITIONS.has(trackStep) && !getStartPositionColor(trackStep);

    return (
      <div
        key={cellKey}
        className="relative flex items-center justify-center"
        style={{
          backgroundColor: bgColor,
          borderRadius: '2px',
          border: borderColor !== 'transparent' ? `0.5px solid ${borderColor}` : undefined,
        }}
      >
        {/* Safe spot indicator */}
        {isSafe && (
          <div className="absolute text-[6px] text-orange-400 opacity-70" style={{ fontSize: 'clamp(4px, 0.5vw, 7px)' }}>
            ★
          </div>
        )}

        {/* Start position marker */}
        {trackStep != null && getStartPositionColor(trackStep) != null && (
          <div
            className="absolute rounded-full"
            style={{
              width: '55%',
              height: '55%',
              border: `1.5px solid ${PLAYER_COLORS[getStartPositionColor(trackStep)!]}`,
            }}
          />
        )}

        {/* Tokens */}
        {tokensHere.length === 1 && (
          <TokenPiece
            playerIndex={tokensHere[0]!.playerIndex}
            tokenIndex={tokensHere[0]!.tokenIndex}
            isHighlighted={tokensHere[0]!.isHighlighted}
            onClick={tokensHere[0]!.isHighlighted ? () => handleSelectToken(tokensHere[0]!.tokenIndex) : undefined}
          />
        )}
        {tokensHere.length > 1 && (
          <div className="flex flex-wrap items-center justify-center gap-px">
            {tokensHere.map((t) => (
              <TokenPiece
                key={`${t.playerIndex}-${t.tokenIndex}`}
                playerIndex={t.playerIndex}
                tokenIndex={t.tokenIndex}
                isHighlighted={t.isHighlighted}
                onClick={t.isHighlighted ? () => handleSelectToken(t.tokenIndex) : undefined}
                small
              />
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col min-h-0">
      {/* Top bar */}
      <div
        className="flex items-center gap-3 px-4 py-3 backdrop-blur-sm"
        style={{
          borderBottomWidth: '1px',
          borderBottomStyle: 'solid',
          borderBottomColor: 'var(--separator)',
          backgroundColor: 'var(--bg-surface)',
        }}
      >
        <button type="button" onClick={onBack} className="transition-colors" style={{ color: 'var(--text-secondary)' }}>
          <ArrowLeft className="h-5 w-5" />
        </button>
        <span className="text-lg">🎲</span>
        <span className="text-sm font-medium flex-1" style={{ color: 'var(--text-primary)' }}>Ludo</span>
        <button
          type="button"
          onClick={handleQuit}
          className="text-red-400 hover:text-red-300 transition-colors flex items-center gap-1 text-xs"
        >
          <LogOut className="h-3.5 w-3.5" /> Leave
        </button>
      </div>

      <div className="flex-1 flex flex-col items-center p-3 sm:p-4 min-h-0 overflow-y-auto">
        {/* Player info bar */}
        <div className="flex flex-wrap gap-2 justify-center w-full max-w-[min(100%,24rem)] mb-2">
          {ludoState.players.map((player) => {
            const isCurrent = player.playerIndex === ludoState.currentPlayerIndex;
            const color = PLAYER_COLORS[player.playerIndex] ?? '#888';
            const peer = peers.find((p) => p.peerId === player.id);
            const name =
              player.id === localPeerId
                ? 'You'
                : peer?.displayName ?? player.name;
            const tokensHome = player.tokens.filter(t => t.position.type === 'home').length;
            return (
              <div
                key={player.playerIndex}
                className={`flex items-center gap-1.5 px-2 py-1 rounded-lg text-xs transition-all ${
                  isCurrent ? 'ring-2 ring-offset-1' : 'opacity-70'
                } ${player.isFinished ? 'opacity-50' : ''}`}
                style={{
                  backgroundColor: `${color}18`,
                  '--tw-ring-color': isCurrent ? color : undefined,
                  borderLeft: `3px solid ${color}`,
                } as React.CSSProperties}
              >
                {player.isAI ? (
                  <span className="text-sm">🤖</span>
                ) : (
                  <PeerAvatar
                    emoji={
                      player.id === localPeerId
                        ? userProfile.avatarEmoji
                        : peer?.avatarEmoji ?? '😀'
                    }
                    colorIndex={
                      player.id === localPeerId
                        ? userProfile.avatarColorIndex
                        : peer?.avatarColorIndex ?? 0
                    }
                    size="sm"
                  />
                )}
                <span style={{ color: 'var(--text-primary)' }} className="font-medium truncate max-w-[4rem]">
                  {name}
                </span>
                {tokensHome > 0 && (
                  <span className="text-[10px] px-1 rounded" style={{ backgroundColor: `${color}30`, color }}>
                    {tokensHome}/4
                  </span>
                )}
              </div>
            );
          })}
        </div>

        {/* Board */}
        <div className="w-full max-w-[min(100%,24rem)] mx-auto">
          <div
            className="rounded-xl shadow-lg overflow-hidden"
            style={{ aspectRatio: '1', backgroundColor: 'var(--bg-surface)', border: '1.5px solid var(--separator)' }}
          >
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(15, 1fr)', gridTemplateRows: 'repeat(15, 1fr)', width: '100%', height: '100%', gap: '1px', padding: '1px' }}>
              {Array.from({ length: 225 }, (_, i) => renderCell(Math.floor(i / 15), i % 15))}
            </div>
          </div>
        </div>

        {/* Dice + Status */}
        <div className="flex flex-col items-center gap-2 mt-3">
          {/* Status text */}
          <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
            {isFinished
              ? winnerPlayer
                ? isLocalWinner
                  ? 'You won! 🎉'
                  : `${winnerPlayer.name} wins!`
                : 'Game Over'
              : isMyTurn
                ? canRoll
                  ? 'Your turn — tap to roll'
                  : canSelect
                    ? 'Select a token to move'
                    : rolling
                      ? 'Rolling...'
                      : 'Your turn'
                : currentPlayer?.isAI
                  ? `${currentPlayer?.name ?? 'AI'} thinking...`
                  : `${currentPlayer?.name ?? 'Opponent'}'s turn`}
          </p>

          {/* Dice */}
          {ludoState.gamePhase === 'playing' && (
            <div className="flex items-center gap-3">
              <DiceFace
                value={diceDisplayValue ?? ludoState.lastDiceRoll}
                rolling={rolling}
                color={currentPlayerColor}
              />
              {canRoll && (
                <button
                  type="button"
                  onClick={handleRollDice}
                  className="px-5 py-2.5 rounded-xl text-white text-sm font-semibold shadow-lg transition-all active:scale-95"
                  style={{ backgroundColor: currentPlayerColor }}
                >
                  Roll
                </button>
              )}
            </div>
          )}

          {/* Valid moves indicator */}
          {canSelect && validMoves.length > 0 && (
            <div className="flex gap-1 items-center">
              <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                {validMoves.length} token{validMoves.length !== 1 ? 's' : ''} can move
              </span>
            </div>
          )}
        </div>

        {/* Game Over overlay */}
        {isFinished && (
          <div className="glass-card p-5 text-center space-y-3 animate-slide-up mt-3">
            <h3 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
              {isLocalWinner
                ? 'Victory! 🎉'
                : winnerPlayer
                  ? `${winnerPlayer.name} wins!`
                  : 'Game Over'}
            </h3>
            {ludoState.finishOrder.length > 0 && (
              <div className="text-xs space-y-1" style={{ color: 'var(--text-secondary)' }}>
                {ludoState.finishOrder.map((pidx, rank) => {
                  const p = findPlayer(ludoState, pidx);
                  return (
                    <div key={pidx} className="flex items-center justify-center gap-2">
                      <span>{rank === 0 ? '🥇' : rank === 1 ? '🥈' : rank === 2 ? '🥉' : `${rank + 1}.`}</span>
                      <span style={{ color: PLAYER_COLORS[pidx] }}>{p?.name ?? `Player ${pidx}`}</span>
                    </div>
                  );
                })}
              </div>
            )}
            <div className="flex gap-3 justify-center">
              <button
                type="button"
                onClick={handleRematch}
                className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg transition-colors"
              >
                <RotateCcw className="h-4 w-4" /> Rematch
              </button>
              <button
                type="button"
                onClick={handleQuit}
                className="px-4 py-2 text-sm rounded-lg transition-colors"
                style={{
                  borderWidth: '1px',
                  borderStyle: 'solid',
                  borderColor: 'var(--separator)',
                  color: 'var(--text-secondary)',
                }}
              >
                Back to Lobby
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Ludo;
