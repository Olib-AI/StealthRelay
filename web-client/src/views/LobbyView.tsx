import { useState } from 'react';
import { MessageSquare, Gamepad2, LogOut, Settings, Play, Bell, BellOff, ChevronRight, Shield, Lock } from 'lucide-react';
import { usePoolStore } from '../stores/pool.ts';
import { useConnectionStore } from '../stores/connection.ts';
import { useGameStore } from '../stores/game.ts';
import { transport } from '../transport/websocket.ts';
import PeerAvatar from '../components/PeerAvatar.tsx';
import ProfileSetup from '../components/ProfileSetup.tsx';
import ThemeToggle from '../components/ThemeToggle.tsx';
import { isNotificationSupported, isNotificationEnabled, requestNotificationPermission, disableNotifications } from '../hooks/useNotifications.ts';

const GAME_NAMES: Record<string, string> = {
  connect_four: 'Connect Four',
  chain_reaction: 'Chain Reaction',
  chess: 'Chess',
  ludo: 'Ludo',
};

function formatServerUrl(url: string | null): string {
  if (!url) return '';
  try {
    return url.replace(/^wss?:\/\//, '').replace(/\/$/, '');
  } catch {
    return url;
  }
}

interface LobbyViewProps {
  onNavigateChat: () => void;
  onNavigateGames: () => void;
  onReturnToGame?: () => void;
}

function LobbyView({ onNavigateChat, onNavigateGames, onReturnToGame }: LobbyViewProps) {
  const poolInfo = usePoolStore((s) => s.poolInfo);
  const peers = usePoolStore((s) => s.peers);
  const userProfile = usePoolStore((s) => s.userProfile);
  const localPeerId = useConnectionStore((s) => s.localPeerId);
  const serverUrl = useConnectionStore((s) => s.serverUrl);
  const [showSettings, setShowSettings] = useState(false);
  const [notificationsOn, setNotificationsOn] = useState(isNotificationEnabled());

  const otherPeers = peers.filter((p) => p.peerId !== localPeerId);

  function handleLeave() {
    transport.disconnect();
  }

  return (
    <div className="flex-1 flex flex-col min-h-0" style={{ backgroundColor: 'var(--bg-page)' }}>
      {/* Header bar */}
      <div className="shrink-0 px-5 pt-6 pb-4 flex items-center justify-between">
        <div className="flex items-center gap-3 min-w-0">
          <div className="h-11 w-11 shrink-0 rounded-2xl flex items-center justify-center" style={{ background: 'linear-gradient(135deg, #007AFF, #5856D6)' }}>
            <Lock className="h-5 w-5 text-white" />
          </div>
          <div className="min-w-0">
            <h1 className="text-[17px] font-bold truncate" style={{ color: 'var(--text-primary)' }}>
              {formatServerUrl(serverUrl)}
            </h1>
            <div className="flex items-center gap-1.5">
              <span className="h-[6px] w-[6px] rounded-full bg-[#30D158]" />
              <span className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>
                {peers.length + 1} of {poolInfo?.maxPeers ?? '?'} online
              </span>
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setShowSettings(!showSettings)}
          className="h-9 w-9 shrink-0 rounded-full flex items-center justify-center active:scale-90 transition-transform"
          style={{ backgroundColor: 'var(--bg-tertiary)' }}
        >
          <Settings className="h-[18px] w-[18px]" style={{ color: 'var(--text-secondary)' }} />
        </button>
      </div>

      {/* Settings panel */}
      {showSettings && (
        <div className="mx-4 mb-3 rounded-2xl p-4 space-y-3 animate-fade-in" style={{ backgroundColor: 'var(--bg-secondary)' }}>
          <ProfileSetup
            compact
            onDone={() => {
              setShowSettings(false);
              transport.updateProfile();
            }}
          />
          <div className="flex items-center justify-between pt-3" style={{ borderTopWidth: '1px', borderTopStyle: 'solid', borderTopColor: 'var(--separator)' }}>
            <span className="text-[13px] font-medium" style={{ color: 'var(--text-secondary)' }}>Appearance</span>
            <ThemeToggle />
          </div>
          {isNotificationSupported() && (
            <div className="flex items-center justify-between pt-3" style={{ borderTopWidth: '1px', borderTopStyle: 'solid', borderTopColor: 'var(--separator)' }}>
              <span className="text-[13px] font-medium" style={{ color: 'var(--text-secondary)' }}>Notifications</span>
              <button
                type="button"
                onClick={async () => {
                  if (notificationsOn) {
                    disableNotifications();
                    setNotificationsOn(false);
                  } else {
                    const granted = await requestNotificationPermission();
                    setNotificationsOn(granted);
                  }
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium transition-colors"
                style={
                  notificationsOn
                    ? { backgroundColor: '#30D158', color: '#FFFFFF' }
                    : { backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }
                }
              >
                {notificationsOn ? <Bell className="h-3.5 w-3.5" /> : <BellOff className="h-3.5 w-3.5" />}
                {notificationsOn ? 'On' : 'Off'}
              </button>
            </div>
          )}
        </div>
      )}

      {/* Main content — fills remaining space */}
      <div className="flex-1 flex flex-col min-h-0 px-4 pb-6">

        {/* Return to active game banner */}
        {(() => {
          const gameActive = useGameStore.getState().isGameActive;
          const gameType = useGameStore.getState().activeGameType;
          if (!gameActive || !gameType || !onReturnToGame) return null;
          return (
            <button
              type="button"
              onClick={onReturnToGame}
              className="w-full shrink-0 mb-4 rounded-2xl p-4 flex items-center gap-3 active:scale-[0.98] transition-transform"
              style={{ background: 'linear-gradient(135deg, #30D158, #28B84D)' }}
            >
              <Play className="h-5 w-5 text-white" />
              <span className="flex-1 text-left text-[15px] font-semibold text-white">
                Return to {GAME_NAMES[gameType] ?? gameType}
              </span>
              <ChevronRight className="h-4 w-4 text-white/60" />
            </button>
          );
        })()}

        {/* Chat & Games — big tap targets */}
        <div className="grid grid-cols-2 gap-3 shrink-0 mb-4">
          <button
            type="button"
            onClick={onNavigateChat}
            className="rounded-2xl p-5 flex flex-col items-center justify-center gap-3 active:scale-[0.96] transition-transform aspect-[4/3]"
            style={{ backgroundColor: 'var(--bg-secondary)' }}
          >
            <div className="h-14 w-14 rounded-2xl flex items-center justify-center bg-[#007AFF]">
              <MessageSquare className="h-7 w-7 text-white" />
            </div>
            <p className="text-[16px] font-semibold" style={{ color: 'var(--text-primary)' }}>Chat</p>
          </button>

          <button
            type="button"
            onClick={onNavigateGames}
            className="rounded-2xl p-5 flex flex-col items-center justify-center gap-3 active:scale-[0.96] transition-transform aspect-[4/3]"
            style={{ backgroundColor: 'var(--bg-secondary)' }}
          >
            <div className="h-14 w-14 rounded-2xl flex items-center justify-center bg-[#BF5AF2]">
              <Gamepad2 className="h-7 w-7 text-white" />
            </div>
            <p className="text-[16px] font-semibold" style={{ color: 'var(--text-primary)' }}>Games</p>
          </button>
        </div>

        {/* People — takes remaining space and scrolls */}
        <div className="flex-1 flex flex-col min-h-0">
          <p className="shrink-0 text-[13px] font-semibold uppercase tracking-wider mb-2 px-1" style={{ color: 'var(--text-tertiary)' }}>
            People
          </p>
          <div className="flex-1 min-h-0 rounded-2xl overflow-y-auto" style={{ backgroundColor: 'var(--bg-secondary)' }}>
            {/* Self */}
            <div className="flex items-center gap-3 px-4 py-3.5" style={{ borderBottomWidth: '0.5px', borderBottomStyle: 'solid', borderBottomColor: 'var(--separator)' }}>
              <PeerAvatar emoji={userProfile.avatarEmoji} colorIndex={userProfile.avatarColorIndex} size="md" isHost={localPeerId === poolInfo?.hostPeerId} />
              <p className="flex-1 text-[16px] font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                {userProfile.displayName}
              </p>
              <span className="text-[11px] font-medium px-2.5 py-1 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>You</span>
            </div>

            {/* Others */}
            {otherPeers.map((peer, i) => (
              <div
                key={peer.peerId}
                className="flex items-center gap-3 px-4 py-3.5"
                style={i < otherPeers.length - 1 ? { borderBottomWidth: '0.5px', borderBottomStyle: 'solid', borderBottomColor: 'var(--separator)' } : undefined}
              >
                <PeerAvatar emoji={peer.avatarEmoji} colorIndex={peer.avatarColorIndex} size="md" isHost={peer.peerId === poolInfo?.hostPeerId} />
                <p className="flex-1 text-[16px] font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                  {peer.displayName}
                </p>
                {peer.peerId === poolInfo?.hostPeerId && (
                  <span className="flex items-center gap-1 text-[11px] font-semibold px-2.5 py-1 rounded-full bg-[#FF9F0A]/15 text-[#FF9F0A]">
                    <Shield className="h-3 w-3" />
                    Host
                  </span>
                )}
              </div>
            ))}

            {otherPeers.length === 0 && (
              <div className="flex-1 flex items-center justify-center py-10">
                <p className="text-[14px]" style={{ color: 'var(--text-tertiary)' }}>Waiting for others to join...</p>
              </div>
            )}
          </div>
        </div>

        {/* Leave — anchored at bottom */}
        <div className="shrink-0 pt-4" style={{ paddingBottom: 'env(safe-area-inset-bottom, 0px)' }}>
          <button
            type="button"
            onClick={handleLeave}
            className="w-full flex items-center justify-center gap-2 py-3.5 rounded-2xl text-[15px] font-medium active:scale-[0.97] transition-transform"
            style={{ backgroundColor: 'var(--bg-secondary)', color: '#FF453A' }}
          >
            <LogOut className="h-4 w-4" />
            Leave Pool
          </button>
        </div>
      </div>
    </div>
  );
}

export default LobbyView;
