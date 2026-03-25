import { useState } from 'react';
import { MessageSquare, Gamepad2, LogOut, Users, Settings, Globe, Play } from 'lucide-react';
import { usePoolStore } from '../stores/pool.ts';
import { useConnectionStore } from '../stores/connection.ts';
import { useGameStore } from '../stores/game.ts';
import { transport } from '../transport/websocket.ts';
import ConnectionStatus from '../components/ConnectionStatus.tsx';
import PeerList from '../components/PeerList.tsx';
import ProfileSetup from '../components/ProfileSetup.tsx';
import ThemeToggle from '../components/ThemeToggle.tsx';

const GAME_NAMES: Record<string, string> = {
  connect_four: 'Connect Four',
  chain_reaction: 'Chain Reaction',
  chess: 'Chess',
};

interface LobbyViewProps {
  onNavigateChat: () => void;
  onNavigateGames: () => void;
  onReturnToGame?: () => void;
}

function LobbyView({ onNavigateChat, onNavigateGames, onReturnToGame }: LobbyViewProps) {
  const poolInfo = usePoolStore((s) => s.poolInfo);
  const peers = usePoolStore((s) => s.peers);
  const serverUrl = useConnectionStore((s) => s.serverUrl);
  const [showSettings, setShowSettings] = useState(false);

  function handleLeave() {
    transport.disconnect();
  }

  return (
    <div className="flex-1 flex flex-col min-h-0" style={{ backgroundColor: 'var(--bg-page)' }}>
      {/* Top bar */}
      <div className="flex items-center justify-between px-4 py-3" style={{ borderBottomWidth: '1px', borderBottomStyle: 'solid', borderBottomColor: 'var(--separator)', backgroundColor: 'var(--bg-surface)' }}>
        <ConnectionStatus />
        <button
          type="button"
          onClick={() => setShowSettings(!showSettings)}
          className="transition-colors" style={{ color: 'var(--text-secondary)' }}
        >
          <Settings className="h-5 w-5" />
        </button>
      </div>

      {/* Settings panel */}
      {showSettings && (
        <div className="px-4 py-3 space-y-3 animate-slide-up" style={{ backgroundColor: 'var(--bg-surface)', borderBottomWidth: '1px', borderBottomStyle: 'solid', borderBottomColor: 'var(--separator)' }}>
          <ProfileSetup
            compact
            onDone={() => {
              setShowSettings(false);
              transport.updateProfile();
            }}
          />
          <div className="flex items-center justify-between pt-2" style={{ borderTopWidth: '1px', borderTopStyle: 'solid', borderTopColor: 'var(--separator)' }}>
            <span className="text-[12px] font-medium" style={{ color: 'var(--text-secondary)' }}>Appearance</span>
            <ThemeToggle />
          </div>
        </div>
      )}

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Pool info card */}
        <div className="rounded-xl p-4 space-y-3" style={{ backgroundColor: 'var(--bg-surface)' }}>
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl flex items-center justify-center" style={{ backgroundColor: 'rgba(0, 122, 255, 0.1)' }}>
              <Globe className="h-5 w-5 text-[#007AFF]" />
            </div>
            <div className="min-w-0 flex-1">
              <h2 className="text-[17px] font-semibold truncate" style={{ color: 'var(--text-primary)' }}>{poolInfo?.name ?? 'Pool'}</h2>
              <p className="text-[12px] truncate" style={{ color: 'var(--text-tertiary)' }}>{serverUrl}</p>
            </div>
          </div>

          <div className="flex items-center gap-4 text-[12px]" style={{ color: 'var(--text-secondary)' }}>
            <span className="flex items-center gap-1">
              <Users className="h-3.5 w-3.5" />
              {peers.length + 1} / {poolInfo?.maxPeers ?? '?'} peers
            </span>
          </div>
        </div>

        {/* Peers */}
        <div className="rounded-xl p-4" style={{ backgroundColor: 'var(--bg-surface)' }}>
          <h3 className="text-[15px] font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
            <Users className="h-4 w-4" />
            Connected Peers
          </h3>
          <PeerList />
        </div>

        {/* Return to active game */}
        {(() => {
          const isGameActive = useGameStore.getState().isGameActive;
          const activeGameType = useGameStore.getState().activeGameType;
          if (!isGameActive || !activeGameType || !onReturnToGame) return null;
          const gameName = GAME_NAMES[activeGameType] ?? activeGameType;
          return (
            <button
              type="button"
              onClick={onReturnToGame}
              className="w-full rounded-[10px] p-4 flex items-center gap-3 transition-colors"
              style={{ backgroundColor: 'rgba(48, 209, 88, 0.1)' }}
            >
              <div className="h-10 w-10 rounded-xl flex items-center justify-center" style={{ backgroundColor: 'rgba(48, 209, 88, 0.15)' }}>
                <Play className="h-5 w-5 text-[#30D158]" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-[15px] font-medium text-[#30D158]">Return to {gameName}</p>
                <p className="text-[11px]" style={{ color: 'var(--text-tertiary)' }}>Game in progress</p>
              </div>
            </button>
          );
        })()}

        {/* Action buttons */}
        <div className="grid grid-cols-2 gap-3">
          <button
            type="button"
            onClick={onNavigateChat}
            className="rounded-[10px] p-4 flex flex-col items-center gap-2 transition-colors"
            style={{ backgroundColor: 'rgba(0, 122, 255, 0.1)' }}
          >
            <div className="h-12 w-12 rounded-xl flex items-center justify-center" style={{ backgroundColor: 'rgba(0, 122, 255, 0.15)' }}>
              <MessageSquare className="h-6 w-6 text-[#007AFF]" />
            </div>
            <span className="text-[15px] font-medium text-[#007AFF]">Chat</span>
            <span className="text-[11px]" style={{ color: 'var(--text-tertiary)' }}>Group & private messages</span>
          </button>

          <button
            type="button"
            onClick={onNavigateGames}
            className="rounded-[10px] p-4 flex flex-col items-center gap-2 transition-colors"
            style={{ backgroundColor: 'rgba(191, 90, 242, 0.1)' }}
          >
            <div className="h-12 w-12 rounded-xl flex items-center justify-center" style={{ backgroundColor: 'rgba(191, 90, 242, 0.15)' }}>
              <Gamepad2 className="h-6 w-6 text-[#BF5AF2]" />
            </div>
            <span className="text-[15px] font-medium text-[#BF5AF2]">Games</span>
            <span className="text-[11px]" style={{ color: 'var(--text-tertiary)' }}>Play with friends</span>
          </button>
        </div>

        {/* Leave button */}
        <button
          type="button"
          onClick={handleLeave}
          className="w-full flex items-center justify-center gap-2 py-3 rounded-xl text-[15px] transition-colors"
          style={{ backgroundColor: 'rgba(255, 69, 58, 0.1)', color: '#FF453A' }}
        >
          <LogOut className="h-4 w-4" />
          Leave Pool
        </button>
      </div>
    </div>
  );
}

export default LobbyView;
