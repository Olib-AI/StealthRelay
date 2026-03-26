import { useState, useCallback, useRef, useEffect } from 'react';
import { useConnectionStore } from './stores/connection.ts';
import { useGameStore } from './stores/game.ts';
import JoinView from './views/JoinView.tsx';
import LobbyView from './views/LobbyView.tsx';
import ChatView from './views/ChatView.tsx';
import GameLobby from './views/games/GameLobby.tsx';
import ConnectFour from './views/games/ConnectFour.tsx';
import ChainReaction from './views/games/ChainReaction.tsx';
import Chess from './views/games/Chess.tsx';
import GameChatOverlay from './components/GameChatOverlay.tsx';
import ChatNotification from './components/ChatNotification.tsx';
import { useChatStore } from './stores/chat.ts';

type AppView = 'join' | 'lobby' | 'chat' | 'game_lobby' | 'connect_four' | 'chain_reaction' | 'chess';

function App() {
  const status = useConnectionStore((s) => s.status);
  const isGameActive = useGameStore((s) => s.isGameActive);
  const activeGameType = useGameStore((s) => s.activeGameType);
  const [view, setView] = useState<AppView>('join');

  // Auto-navigate based on connection status
  const isConnected = status === 'connected';
  const isJoining = status === 'connecting' || status === 'waiting_approval';
  const isDisconnected = status === 'idle' || status === 'disconnected' || status === 'failed';

  const effectiveView = (() => {
    if (isDisconnected && view !== 'join') return 'join';
    if (isJoining) return 'join';
    if (isConnected && view === 'join') return 'lobby';
    if (isGameActive && activeGameType && view === 'game_lobby') return activeGameType;
    return view;
  })();

  const handleStartGame = useCallback((type: 'connect_four' | 'chain_reaction' | 'chess') => {
    setView(type);
  }, []);

  const handleGameBack = useCallback(() => {
    setView('lobby');
  }, []);

  const handleNotificationNav = useCallback((chatView: 'group' | 'private', peerId?: string) => {
    setView('chat');
    useChatStore.getState().setCurrentView(chatView);
    if (chatView === 'private' && peerId) {
      useChatStore.getState().setSelectedPrivatePeerId(peerId);
    }
  }, []);

  // Track view changes for transition animation
  const prevViewRef = useRef(effectiveView);
  const [viewKey, setViewKey] = useState(0);
  useEffect(() => {
    if (prevViewRef.current !== effectiveView) {
      prevViewRef.current = effectiveView;
      setViewKey((k) => k + 1);
    }
  }, [effectiveView]);

  // Game views stay mounted while a game session is active so navigation
  // to chat/lobby and back does not destroy in-progress game state.
  const showConnectFour = isGameActive && activeGameType === 'connect_four';
  const showChainReaction = isGameActive && activeGameType === 'chain_reaction';
  const showChess = isGameActive && activeGameType === 'chess';

  return (
    <div className="h-dvh flex items-center justify-center" style={{ backgroundColor: 'var(--bg-page)' }}>
      <div className="relative w-full h-dvh flex flex-col overflow-hidden lg:max-w-[430px] lg:max-h-[932px] lg:rounded-2xl lg:border lg:shadow-2xl lg:shadow-black/50" style={{ backgroundColor: 'var(--bg-page)', color: 'var(--text-primary)', borderColor: 'var(--separator)' }}>
        {(effectiveView === 'join' || effectiveView === 'lobby' || effectiveView === 'chat' || effectiveView === 'game_lobby') && (
          <div key={viewKey} className="flex-1 flex flex-col min-h-0 animate-view-enter">
            {effectiveView === 'join' && <JoinView />}
            {effectiveView === 'lobby' && (
              <LobbyView
                onNavigateChat={() => setView('chat')}
                onNavigateGames={() => setView('game_lobby')}
                onReturnToGame={isGameActive && activeGameType ? () => setView(activeGameType) : undefined}
              />
            )}
            {effectiveView === 'chat' && <ChatView onBack={() => setView('lobby')} />}
            {effectiveView === 'game_lobby' && (
              <GameLobby onBack={() => setView('lobby')} onStartGame={handleStartGame} />
            )}
          </div>
        )}
        {showConnectFour && (
          <div className={effectiveView === 'connect_four' ? 'flex-1 flex flex-col min-h-0' : 'hidden'}>
            <ConnectFour onBack={handleGameBack} />
          </div>
        )}
        {showChainReaction && (
          <div className={effectiveView === 'chain_reaction' ? 'flex-1 flex flex-col min-h-0' : 'hidden'}>
            <ChainReaction onBack={handleGameBack} />
          </div>
        )}
        {showChess && (
          <div className={effectiveView === 'chess' ? 'flex-1 flex flex-col min-h-0' : 'hidden'}>
            <Chess onBack={handleGameBack} />
          </div>
        )}
        {isGameActive && (effectiveView === 'connect_four' || effectiveView === 'chain_reaction' || effectiveView === 'chess') && (
          <GameChatOverlay />
        )}
        {isConnected && effectiveView !== 'join' && (
          <ChatNotification currentView={effectiveView} onNavigateToChat={handleNotificationNav} />
        )}
      </div>
    </div>
  );
}

export default App;
