import { useState, useCallback } from 'react';
import { useConnectionStore } from './stores/connection.ts';
import { useGameStore } from './stores/game.ts';
import JoinView from './views/JoinView.tsx';
import LobbyView from './views/LobbyView.tsx';
import ChatView from './views/ChatView.tsx';
import GameLobby from './views/games/GameLobby.tsx';
import ConnectFour from './views/games/ConnectFour.tsx';
import ChainReaction from './views/games/ChainReaction.tsx';
import Chess from './views/games/Chess.tsx';
import Ludo from './views/games/Ludo.tsx';
import GameChatOverlay from './components/GameChatOverlay.tsx';
import ChatNotification from './components/ChatNotification.tsx';
import GameInvitationBanner from './components/GameInvitationBanner.tsx';
import CallView from './views/CallView.tsx';
import SecurityBanner from './components/SecurityBanner.tsx';
import ErrorBoundary from './components/ErrorBoundary.tsx';
import { effectiveView } from './view-state.ts';
import type { AppView } from './view-state.ts';
import { useChatStore } from './stores/chat.ts';

/** Better than a blank page: whatever failed to draw, the pool connection is still up. */
function PageFallback({ onRecover }: { onRecover: () => void }) {
  return (
    <div role="alert" className="flex-1 flex flex-col items-center justify-center gap-3 p-6 text-center">
      <p className="text-[15px]" style={{ color: 'var(--text-primary)' }}>Something on this page couldn't be shown.</p>
      <button type="button" onClick={onRecover} className="px-4 py-2 rounded-xl text-[15px] font-medium text-white bg-[#007AFF]">
        Back to the pool
      </button>
    </div>
  );
}

function App() {
  const status = useConnectionStore((s) => s.status);
  const isGameActive = useGameStore((s) => s.isGameActive);
  const activeGameType = useGameStore((s) => s.activeGameType);
  const [view, setView] = useState<AppView>('join');

  const isConnected = status === 'connected';
  const shownView = effectiveView(view, status, { isGameActive, activeGameType });

  const handleStartGame = useCallback((type: 'connect_four' | 'chain_reaction' | 'chess' | 'ludo') => {
    setView(type);
  }, []);

  const handleGameBack = useCallback(() => {
    setView('lobby');
  }, []);

  const handleNavigateToGames = useCallback(() => {
    setView('game_lobby');
  }, []);

  const handleNotificationNav = useCallback((chatView: 'group' | 'private', peerId?: string) => {
    setView('chat');
    useChatStore.getState().setCurrentView(chatView);
    if (chatView === 'private' && peerId) {
      useChatStore.getState().setSelectedPrivatePeerId(peerId);
    }
  }, []);

  // Game views stay mounted while a game session is active so navigation
  // to chat/lobby and back does not destroy in-progress game state.
  const showConnectFour = isGameActive && activeGameType === 'connect_four';
  const showChainReaction = isGameActive && activeGameType === 'chain_reaction';
  const showChess = isGameActive && activeGameType === 'chess';
  const showLudo = isGameActive && activeGameType === 'ludo';

  return (
    <div className="h-dvh flex items-center justify-center" style={{ backgroundColor: 'var(--bg-page)' }}>
      <div className="relative w-full h-dvh flex flex-col overflow-hidden lg:max-w-[430px] lg:max-h-[932px] lg:rounded-2xl lg:border lg:shadow-2xl lg:shadow-black/50" style={{ backgroundColor: 'var(--bg-page)', color: 'var(--text-primary)', borderColor: 'var(--separator)' }}>
        <ErrorBoundary fallback={<PageFallback onRecover={() => { useChatStore.getState().clearMessages(); setView(isConnected ? 'lobby' : 'join'); }} />}>
        {(isConnected || status === 'reconnecting') && shownView !== 'join' && <SecurityBanner />}
        {(shownView === 'join' || shownView === 'lobby' || shownView === 'chat' || shownView === 'game_lobby') && (
          <div key={shownView} className="flex-1 flex flex-col min-h-0 animate-view-enter">
            {shownView === 'join' && <JoinView />}
            {shownView === 'lobby' && (
              <LobbyView
                onNavigateChat={() => setView('chat')}
                onNavigateGames={() => setView('game_lobby')}
                onReturnToGame={isGameActive && activeGameType ? () => setView(activeGameType) : undefined}
              />
            )}
            {shownView === 'chat' && <ChatView onBack={() => setView('lobby')} />}
            {shownView === 'game_lobby' && (
              <GameLobby onBack={() => setView('lobby')} onStartGame={handleStartGame} />
            )}
          </div>
        )}
        {showConnectFour && (
          <div className={shownView === 'connect_four' ? 'flex-1 flex flex-col min-h-0' : 'hidden'}>
            <ConnectFour onBack={handleGameBack} />
          </div>
        )}
        {showChainReaction && (
          <div className={shownView === 'chain_reaction' ? 'flex-1 flex flex-col min-h-0' : 'hidden'}>
            <ChainReaction onBack={handleGameBack} />
          </div>
        )}
        {showChess && (
          <div className={shownView === 'chess' ? 'flex-1 flex flex-col min-h-0' : 'hidden'}>
            <Chess onBack={handleGameBack} />
          </div>
        )}
        {showLudo && (
          <div className={shownView === 'ludo' ? 'flex-1 flex flex-col min-h-0' : 'hidden'}>
            <Ludo onBack={handleGameBack} />
          </div>
        )}
        {isGameActive && (shownView === 'connect_four' || shownView === 'chain_reaction' || shownView === 'chess' || shownView === 'ludo') && (
          <GameChatOverlay />
        )}
        {isConnected && shownView !== 'join' && (
          <GameInvitationBanner onNavigateToGames={handleNavigateToGames} />
        )}
        {isConnected && shownView !== 'join' && (
          <ChatNotification currentView={shownView} onNavigateToChat={handleNotificationNav} />
        )}
        <CallView />
        </ErrorBoundary>
      </div>
    </div>
  );
}

export default App;
