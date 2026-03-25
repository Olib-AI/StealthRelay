import { useMemo, useEffect } from 'react';
import { ArrowLeft, RotateCcw, LogOut } from 'lucide-react';
import { useGameStore } from '../../stores/game.ts';
import { useConnectionStore } from '../../stores/connection.ts';
import { usePoolStore } from '../../stores/pool.ts';
import { transport } from '../../transport/websocket.ts';
import { appleTimestamp } from '../../utils/time.ts';
import type { ChainReactionAction, ChainReactionState, ChainReactionCell, GameControlPayload } from '../../protocol/messages.ts';
import PeerAvatar from '../../components/PeerAvatar.tsx';

// Match iOS: 6x6 grid
const ROWS = 6;
const COLS = 6;

// Match iOS ChainPlayer.color: [.blue, .red, .green, .orange, .purple, .cyan]
const CHAIN_PLAYER_COLORS = ['#007AFF', '#FF3B30', '#34C759', '#FF9500', '#AF52DE', '#32ADE6'];

function createInitialChainReactionState(sessionID: string): ChainReactionState {
  const cells: ChainReactionCell[] = [];
  for (let r = 0; r < ROWS; r++) {
    for (let c = 0; c < COLS; c++) {
      cells.push({ id: r * COLS + c, orbs: 0, ownerIndex: null });
    }
  }
  return {
    sessionID,
    cells,
    currentPlayerIndex: 0,
    moveCount: 0,
    gameOver: false,
    timestamp: appleTimestamp(),
  };
}

interface ChainReactionProps {
  onBack: () => void;
}

function getCellCapacity(cellId: number): number {
  const row = Math.floor(cellId / COLS);
  const col = cellId % COLS;
  const isCorner = (row === 0 || row === ROWS - 1) && (col === 0 || col === COLS - 1);
  const isEdge = row === 0 || row === ROWS - 1 || col === 0 || col === COLS - 1;
  if (isCorner) return 2;
  if (isEdge) return 3;
  return 4;
}

function getAdjacentCells(cellId: number): number[] {
  const row = Math.floor(cellId / COLS);
  const col = cellId % COLS;
  const adjacent: number[] = [];
  if (row > 0) adjacent.push((row - 1) * COLS + col);
  if (row < ROWS - 1) adjacent.push((row + 1) * COLS + col);
  if (col > 0) adjacent.push(row * COLS + col - 1);
  if (col < COLS - 1) adjacent.push(row * COLS + col + 1);
  return adjacent;
}

function processChainReactions(cells: ChainReactionCell[]): void {
  let hasExplosion = true;
  let iterations = 0;
  while (hasExplosion && iterations < 1000) {
    hasExplosion = false;
    iterations++;
    for (const cell of cells) {
      const capacity = getCellCapacity(cell.id);
      if (cell.orbs >= capacity) {
        hasExplosion = true;
        const owner = cell.ownerIndex;
        cell.orbs -= capacity;
        if (cell.orbs === 0) cell.ownerIndex = null;
        for (const adjId of getAdjacentCells(cell.id)) {
          const adjCell = cells.find((c) => c.id === adjId);
          if (adjCell) {
            adjCell.orbs += 1;
            adjCell.ownerIndex = owner;
          }
        }
      }
    }
  }
}

function ChainReaction({ onBack }: ChainReactionProps) {
  const gameState = useGameStore((s) => s.chainReactionState);
  const session = useGameStore((s) => s.currentSession);
  const localPeerId = useConnectionStore((s) => s.localPeerId);
  const peers = usePoolStore((s) => s.peers);
  const userProfile = usePoolStore((s) => s.userProfile);

  const localPlayerIndex = useMemo(() => {
    if (!session) return -1;
    const player = session.players.find((p) => p.id === localPeerId);
    return player?.playerIndex ?? -1;
  }, [session, localPeerId]);

  const isMyTurn = gameState ? gameState.currentPlayerIndex === localPlayerIndex : false;

  function handleCellClick(cellId: number) {
    if (!isMyTurn || !gameState || gameState.gameOver) return;

    const currentState = gameState;
    const cell = currentState.cells.find((c) => c.id === cellId);
    if (!cell) return;

    // Can only click empty cells or own cells
    if (cell.ownerIndex !== null && cell.ownerIndex !== localPlayerIndex) return;

    const action: ChainReactionAction = {
      cellID: cellId,
      playerIndex: localPlayerIndex,
      moveNumber: currentState.moveCount + 1,
      timestamp: appleTimestamp(),
    };

    transport.sendGameAction(action, null);

    // Apply locally
    const cells = currentState.cells.map((c) => ({ ...c }));
    const target = cells.find((c) => c.id === cellId);
    if (target) {
      target.orbs += 1;
      target.ownerIndex = localPlayerIndex;
    }

    processChainReactions(cells);

    const playerCount = session?.players.length ?? 2;
    const nextPlayer = (localPlayerIndex + 1) % playerCount;
    const { gameOver, winnerIndex } = checkWin(cells, currentState.moveCount + 1, playerCount);

    useGameStore.getState().setChainReactionState({
      ...currentState,
      cells,
      currentPlayerIndex: gameOver ? (winnerIndex ?? nextPlayer) : nextPlayer,
      moveCount: currentState.moveCount + 1,
      gameOver,
      winnerIndex,
      timestamp: action.timestamp,
    });

    if (gameOver) {
      transport.sendGameState({
        ...currentState,
        cells,
        moveCount: currentState.moveCount + 1,
        gameOver,
        winnerIndex,
      }, null);

      // Game over is communicated via state sync — no system messages needed
    }
  }

  function handleRematch() {
    if (!session) return;
    const controlPayload: GameControlPayload = {
      controlType: 'rematch',
      gameType: 'chain_reaction',
      sessionID: session.sessionID,
    };
    transport.sendGameControl(controlPayload, null);
    useGameStore.getState().setChainReactionState(
      createInitialChainReactionState(session.sessionID),
    );
  }

  function handleQuit() {
    if (session) {
      const payload: GameControlPayload = {
        controlType: 'forfeit',
        gameType: 'chain_reaction',
        sessionID: session.sessionID,
      };
      transport.sendGameControl(payload, null);
    }
    useGameStore.getState().setChainReactionState(null);
    useGameStore.getState().setGameActive(false);
    onBack();
  }

  useEffect(() => {
    const store = useGameStore.getState();
    if (!gameState && store.isGameActive && session?.sessionID) {
      store.setChainReactionState(
        createInitialChainReactionState(session.sessionID),
      );
    }
  }, [gameState, session?.sessionID]);

  if (!gameState) return null;

  const currentPlayer = session?.players.find((p) => p.playerIndex === gameState.currentPlayerIndex);
  const winner = gameState.winnerIndex !== undefined ? session?.players.find((p) => p.playerIndex === gameState.winnerIndex) : null;

  function renderOrbs(count: number, color: string) {
    if (count === 0) return null;
    const positions: string[] = [];
    if (count === 1) positions.push('top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2');
    else if (count === 2) {
      positions.push('top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2');
      positions.push('bottom-1/4 left-1/2 -translate-x-1/2 translate-y-1/2');
    } else if (count === 3) {
      positions.push('top-1/4 left-1/3 -translate-x-1/2 -translate-y-1/2');
      positions.push('top-1/4 right-1/3 translate-x-1/2 -translate-y-1/2');
      positions.push('bottom-1/4 left-1/2 -translate-x-1/2 translate-y-1/2');
    } else {
      positions.push('top-1/4 left-1/4');
      positions.push('top-1/4 right-1/4');
      positions.push('bottom-1/4 left-1/4');
      positions.push('bottom-1/4 right-1/4');
    }

    return positions.slice(0, count).map((pos, i) => (
      <div
        key={i}
        className={`absolute ${pos} h-2.5 w-2.5 rounded-full`}
        style={{ backgroundColor: color, boxShadow: `0 0 4px ${color}` }}
      />
    ));
  }

  return (
    <div className="flex-1 flex flex-col min-h-0">
      {/* Top bar */}
      <div className="flex items-center gap-3 px-4 py-3 backdrop-blur-sm" style={{ borderBottomWidth: '1px', borderBottomStyle: 'solid', borderBottomColor: 'var(--separator)', backgroundColor: 'var(--bg-surface)' }}>
        <button type="button" onClick={onBack} className="transition-colors" style={{ color: 'var(--text-secondary)' }}>
          <ArrowLeft className="h-5 w-5" />
        </button>
        <span className="text-lg">💥</span>
        <span className="text-sm font-medium flex-1" style={{ color: 'var(--text-primary)' }}>Chain Reaction</span>
        <button type="button" onClick={handleQuit} className="text-red-400 hover:text-red-300 transition-colors flex items-center gap-1 text-xs">
          <LogOut className="h-3.5 w-3.5" /> Leave
        </button>
      </div>

      <div className="flex-1 flex flex-col items-center justify-center p-3 sm:p-4 space-y-3 sm:space-y-4 overflow-y-auto min-h-0">
        {/* Turn indicator */}
        <div className="flex items-center gap-3 flex-wrap justify-center">
          {session?.players.map((player) => {
            const peer = peers.find((p) => p.peerId === player.id);
            const isCurrentTurn = gameState.currentPlayerIndex === player.playerIndex;
            const color = CHAIN_PLAYER_COLORS[player.playerIndex] ?? '#fff';
            const isLocal = player.id === localPeerId;

            return (
              <div
                key={player.id}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg transition-all ${isCurrentTurn ? 'ring-2' : 'opacity-50'}`}
                style={{ outlineColor: isCurrentTurn ? color : undefined, backgroundColor: isCurrentTurn ? 'var(--bg-tertiary)' : undefined }}
              >
                <PeerAvatar
                  emoji={peer?.avatarEmoji ?? player.profile?.avatarEmoji ?? '😀'}
                  colorIndex={peer?.avatarColorIndex ?? player.profile?.avatarColorIndex ?? 0}
                  size="sm"
                />
                <div>
                  <p className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>
                    {isLocal ? userProfile.displayName : (peer?.displayName ?? player.name)}
                  </p>
                  <div className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
                </div>
              </div>
            );
          })}
        </div>

        {/* Board */}
        <div className="bg-slate-800 rounded-xl p-1 sm:p-1.5 w-full max-w-[min(100%,22rem)]">
          <div className="grid gap-[3px] sm:gap-1" style={{ gridTemplateColumns: `repeat(${COLS}, 1fr)` }}>
            {Array.from({ length: ROWS * COLS }, (_, idx) => {
              const r = Math.floor(idx / COLS);
              const c = idx % COLS;
              const cellId = r * COLS + c;
              const cell = gameState.cells.find((ce) => ce.id === cellId);
              const capacity = getCellCapacity(cellId);
              const canClick = isMyTurn && !gameState.gameOver && cell && (cell.ownerIndex === null || cell.ownerIndex === localPlayerIndex);
              const ownerColor = cell?.ownerIndex !== null && cell?.ownerIndex !== undefined
                ? (CHAIN_PLAYER_COLORS[cell.ownerIndex] ?? '#fff')
                : 'transparent';
              const isNearCapacity = cell && cell.orbs >= capacity - 1 && cell.orbs > 0;

              return (
                <button
                  key={cellId}
                  type="button"
                  onClick={() => handleCellClick(cellId)}
                  disabled={!canClick}
                  className={`aspect-square rounded-lg relative transition-all ${
                    canClick ? 'hover:bg-slate-600 cursor-pointer' : 'cursor-default'
                  } ${isNearCapacity ? 'animate-pulse' : ''}`}
                  style={{ backgroundColor: cell?.orbs ? `${ownerColor}15` : 'rgba(51,65,85,0.5)', border: `1px solid ${cell?.orbs ? `${ownerColor}30` : 'rgba(51,65,85,0.3)'}` }}
                >
                  {cell && renderOrbs(cell.orbs, ownerColor)}
                </button>
              );
            })}
          </div>
        </div>

        {/* Status */}
        {!gameState.gameOver && currentPlayer && (
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {currentPlayer.id === localPeerId ? 'Your turn' : `${currentPlayer.name}'s turn`}
          </p>
        )}

        {/* Game over */}
        {gameState.gameOver && (
          <div className="glass-card p-5 text-center space-y-3 animate-slide-up">
            <h3 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
              {winner
                ? winner.id === localPeerId ? 'You won! 🎉' : `${winner.name} wins!`
                : 'Game Over!'}
            </h3>
            <div className="flex gap-3 justify-center">
              <button type="button" onClick={handleRematch} className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg transition-colors">
                <RotateCcw className="h-4 w-4" /> Rematch
              </button>
              <button type="button" onClick={handleQuit} className="px-4 py-2 text-sm rounded-lg transition-colors" style={{ borderWidth: '1px', borderStyle: 'solid', borderColor: 'var(--separator)', color: 'var(--text-secondary)' }}>
                Back to Lobby
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function checkWin(cells: ChainReactionCell[], moveCount: number, playerCount: number): { gameOver: boolean; winnerIndex?: number } {
  if (moveCount < playerCount * 2) return { gameOver: false };
  const occupied = cells.filter((c) => c.orbs > 0);
  if (occupied.length === 0) return { gameOver: false };
  const owners = new Set(occupied.map((c) => c.ownerIndex));
  if (owners.size === 1) {
    const w = occupied[0]?.ownerIndex;
    if (w !== null && w !== undefined) return { gameOver: true, winnerIndex: w };
  }
  return { gameOver: false };
}

export default ChainReaction;
