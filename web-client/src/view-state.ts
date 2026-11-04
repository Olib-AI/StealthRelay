import type { ConnectionStatus } from './stores/connection.ts';

export type AppView = 'join' | 'lobby' | 'chat' | 'game_lobby' | 'connect_four' | 'chain_reaction' | 'chess' | 'ludo';
type GameView = 'connect_four' | 'chain_reaction' | 'chess' | 'ludo';

/** Which view to show. While reconnecting someone is still in the pool, so it stays on screen. */
export function effectiveView(
  view: AppView,
  status: ConnectionStatus,
  game: { isGameActive: boolean; activeGameType: string | null },
): AppView {
  const inPool = status === 'connected' || status === 'reconnecting';
  const isJoining = status === 'connecting' || status === 'waiting_approval';
  const isDisconnected = status === 'idle' || status === 'disconnected' || status === 'failed';
  if (isDisconnected && view !== 'join') return 'join';
  if (isJoining) return 'join';
  if (inPool && view === 'join') return 'lobby';
  if (game.isGameActive && game.activeGameType && view === 'game_lobby') return game.activeGameType as GameView;
  return view;
}
