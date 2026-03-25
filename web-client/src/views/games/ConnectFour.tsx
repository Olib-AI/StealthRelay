import { useMemo, useEffect } from 'react';
import { ArrowLeft, RotateCcw, LogOut } from 'lucide-react';
import { useGameStore } from '../../stores/game.ts';
import { useConnectionStore } from '../../stores/connection.ts';
import { usePoolStore } from '../../stores/pool.ts';
import { transport } from '../../transport/websocket.ts';
import { AVATAR_COLORS } from '../../protocol/constants.ts';
import { appleTimestamp } from '../../utils/time.ts';
import type { ConnectFourAction, ConnectFourState, ConnectFourCell, GameControlPayload } from '../../protocol/messages.ts';
import PeerAvatar from '../../components/PeerAvatar.tsx';

const ROWS = 6;
const COLS = 7;
// Match iOS: Player 0 = yellow, Player 1 = red
const PLAYER_COLORS = ['#EAB308', '#EF4444'] as const;

function createInitialConnectFourState(sessionID: string): ConnectFourState {
  const cells: ConnectFourCell[] = [];
  let id = 0;
  for (let r = 0; r < ROWS; r++) {
    for (let c = 0; c < COLS; c++) {
      cells.push({ id: id++, row: r, column: c, ownerIndex: null });
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

interface ConnectFourProps {
  onBack: () => void;
}

function ConnectFour({ onBack }: ConnectFourProps) {
  const gameState = useGameStore((s) => s.connectFourState);
  const session = useGameStore((s) => s.currentSession);
  const localPeerId = useConnectionStore((s) => s.localPeerId);
  const peers = usePoolStore((s) => s.peers);
  const userProfile = usePoolStore((s) => s.userProfile);

  const localPlayerIndex = useMemo(() => {
    if (!session) return -1;
    const player = session.players.find((p) => p.id === localPeerId);
    return player?.playerIndex ?? -1;
  }, [session, localPeerId]);

  const grid = useMemo(() => {
    const g: (ConnectFourCell | null)[][] = Array.from({ length: ROWS }, () =>
      Array.from({ length: COLS }, () => null),
    );
    if (gameState) {
      for (const cell of gameState.cells) {
        if (g[cell.row]) {
          g[cell.row]![cell.column] = cell;
        }
      }
    }
    return g;
  }, [gameState]);

  const winningSet = useMemo(() => {
    return new Set(gameState?.winningCells ?? []);
  }, [gameState?.winningCells]);

  const isMyTurn = gameState ? gameState.currentPlayerIndex === localPlayerIndex : false;

  function handleColumnClick(col: number) {
    if (!isMyTurn || !gameState || gameState.gameOver) return;

    const currentState = gameState;
    const columnCells = currentState.cells
      .filter((c) => c.column === col && c.ownerIndex === null)
      .sort((a, b) => b.row - a.row);

    if (columnCells.length === 0) return;

    const action: ConnectFourAction = {
      column: col,
      playerIndex: localPlayerIndex,
      moveNumber: currentState.moveCount + 1,
      timestamp: appleTimestamp(),
    };

    transport.sendGameAction(action, null);

    // Apply locally
    const cells = currentState.cells.map((c) => ({ ...c }));
    const target = cells
      .filter((c) => c.column === col && c.ownerIndex === null)
      .sort((a, b) => b.row - a.row)[0];
    if (target) {
      target.ownerIndex = localPlayerIndex;
    }

    const { gameOver, winnerIndex, winningCells } = checkWin(cells);
    const nextPlayer = localPlayerIndex === 0 ? 1 : 0;

    useGameStore.getState().setConnectFourState({
      ...currentState,
      cells,
      currentPlayerIndex: gameOver ? currentState.currentPlayerIndex : nextPlayer,
      moveCount: currentState.moveCount + 1,
      gameOver,
      winnerIndex,
      winningCells,
      timestamp: action.timestamp,
    });

    if (gameOver) {
      // Send final state
      transport.sendGameState({
        ...currentState,
        cells,
        currentPlayerIndex: gameOver ? currentState.currentPlayerIndex : nextPlayer,
        moveCount: currentState.moveCount + 1,
        gameOver,
        winnerIndex,
        winningCells,
      }, null);

      // Game over is communicated via state sync — no system messages needed
    }
  }

  function handleRematch() {
    if (!session) return;
    const controlPayload: GameControlPayload = {
      controlType: 'rematch',
      gameType: 'connect_four',
      sessionID: session.sessionID,
    };
    transport.sendGameControl(controlPayload, null);
    useGameStore.getState().setConnectFourState(
      createInitialConnectFourState(session.sessionID),
    );
  }

  function handleQuit() {
    if (session) {
      const controlPayload: GameControlPayload = {
        controlType: 'forfeit',
        gameType: 'connect_four',
        sessionID: session.sessionID,
      };
      transport.sendGameControl(controlPayload, null);
    }
    useGameStore.getState().setConnectFourState(null);
    useGameStore.getState().setGameActive(false);
    onBack();
  }

  useEffect(() => {
    const store = useGameStore.getState();
    if (!gameState && store.isGameActive && session?.sessionID) {
      store.setConnectFourState(
        createInitialConnectFourState(session.sessionID),
      );
    }
  }, [gameState, session?.sessionID]);

  if (!gameState) return null;

  const currentPlayer = session?.players.find((p) => p.playerIndex === gameState.currentPlayerIndex);
  const winner = gameState.winnerIndex !== undefined ? session?.players.find((p) => p.playerIndex === gameState.winnerIndex) : null;

  return (
    <div className="flex-1 flex flex-col min-h-0">
      {/* Top bar */}
      <div className="flex items-center gap-3 px-4 py-3 backdrop-blur-sm" style={{ borderBottomWidth: '1px', borderBottomStyle: 'solid', borderBottomColor: 'var(--separator)', backgroundColor: 'var(--bg-surface)' }}>
        <button type="button" onClick={onBack} className="transition-colors" style={{ color: 'var(--text-secondary)' }}>
          <ArrowLeft className="h-5 w-5" />
        </button>
        <span className="text-lg">🔴🟡</span>
        <span className="text-sm font-medium flex-1" style={{ color: 'var(--text-primary)' }}>Connect Four</span>
        <button type="button" onClick={handleQuit} className="text-red-400 hover:text-red-300 transition-colors flex items-center gap-1 text-xs">
          <LogOut className="h-3.5 w-3.5" /> Leave
        </button>
      </div>

      <div className="flex-1 flex flex-col items-center justify-center p-3 sm:p-4 space-y-3 sm:space-y-4 overflow-y-auto min-h-0">
        {/* Turn indicator */}
        <div className="flex items-center gap-2 sm:gap-3 flex-wrap justify-center">
          {session?.players.map((player) => {
            const peer = peers.find((p) => p.peerId === player.id);
            const isCurrentTurn = gameState.currentPlayerIndex === player.playerIndex;
            const color = PLAYER_COLORS[player.playerIndex] ?? AVATAR_COLORS[player.colorIndex] ?? '#fff';
            const isLocal = player.id === localPeerId;

            return (
              <div
                key={player.id}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg transition-all ${
                  isCurrentTurn ? 'ring-2' : 'opacity-50'
                }`}
                style={{ borderColor: color, outlineColor: isCurrentTurn ? color : undefined, backgroundColor: isCurrentTurn ? 'var(--bg-tertiary)' : undefined }}
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
        <div className="bg-blue-800 rounded-xl p-1.5 sm:p-2 shadow-lg shadow-blue-900/50 w-full max-w-[min(100%,28rem)]">
          {/* Grid — each cell is a full square button, clicking anywhere in the column works */}
          {grid.map((row, rIdx) => (
            <div key={rIdx} className="grid grid-cols-7">
              {row.map((cell, cIdx) => {
                const isWinning = cell && winningSet.has(cell.id);
                const canDrop = isMyTurn && !gameState.gameOver && grid.some((r) => r[cIdx]?.ownerIndex === null);
                return (
                  <button
                    key={cIdx}
                    type="button"
                    onClick={() => handleColumnClick(cIdx)}
                    disabled={!canDrop}
                    className={`aspect-square p-[3px] sm:p-1 ${canDrop ? 'cursor-pointer hover:bg-blue-700/40' : 'cursor-default'}`}
                  >
                    <div className={`w-full h-full rounded-full bg-slate-900 flex items-center justify-center ${isWinning ? 'animate-pulse-glow' : ''}`}>
                      {cell?.ownerIndex !== null && cell?.ownerIndex !== undefined && (
                        <div
                          className="w-[85%] h-[85%] rounded-full animate-drop"
                          style={{ backgroundColor: PLAYER_COLORS[cell.ownerIndex] ?? '#fff' }}
                        />
                      )}
                    </div>
                  </button>
                );
              })}
            </div>
          ))}
        </div>

        {/* Status */}
        {!gameState.gameOver && currentPlayer && (
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {currentPlayer.id === localPeerId ? 'Your turn' : `${currentPlayer.name}'s turn`}
          </p>
        )}

        {/* Game over overlay */}
        {gameState.gameOver && (
          <div className="glass-card p-5 text-center space-y-3 animate-slide-up">
            <h3 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
              {winner
                ? winner.id === localPeerId
                  ? 'You won! 🎉'
                  : `${winner.name} wins!`
                : 'Draw!'}
            </h3>
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
                style={{ borderWidth: '1px', borderStyle: 'solid', borderColor: 'var(--separator)', color: 'var(--text-secondary)' }}
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

function checkWin(cells: ConnectFourCell[]): { gameOver: boolean; winnerIndex?: number; winningCells?: number[] } {
  const grid: (number | null)[][] = Array.from({ length: ROWS }, () => Array.from({ length: COLS }, () => null));
  const idGrid: number[][] = Array.from({ length: ROWS }, () => Array.from({ length: COLS }, () => 0));

  for (const cell of cells) {
    if (grid[cell.row]) {
      grid[cell.row]![cell.column] = cell.ownerIndex;
      idGrid[cell.row]![cell.column] = cell.id;
    }
  }

  const directions = [[0, 1], [1, 0], [1, 1], [1, -1]] as const;

  for (let r = 0; r < ROWS; r++) {
    for (let c = 0; c < COLS; c++) {
      const owner = grid[r]?.[c];
      if (owner === null || owner === undefined) continue;

      for (const [dr, dc] of directions) {
        const winning: number[] = [idGrid[r]![c]!];
        let valid = true;

        for (let k = 1; k < 4; k++) {
          const nr = r + dr * k;
          const nc = c + dc * k;
          if (nr < 0 || nr >= ROWS || nc < 0 || nc >= COLS || grid[nr]?.[nc] !== owner) {
            valid = false;
            break;
          }
          winning.push(idGrid[nr]![nc]!);
        }

        if (valid) {
          return { gameOver: true, winnerIndex: owner, winningCells: winning };
        }
      }
    }
  }

  const isFull = cells.every((c) => c.ownerIndex !== null);
  return isFull ? { gameOver: true } : { gameOver: false };
}

export default ConnectFour;
