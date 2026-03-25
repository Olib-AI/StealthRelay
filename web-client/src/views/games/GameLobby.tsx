import { ArrowLeft, Swords, X, Check, Play } from 'lucide-react';
import { v4 as uuidv4 } from 'uuid';
import { useGameStore } from '../../stores/game.ts';
import { useConnectionStore } from '../../stores/connection.ts';
import { usePoolStore } from '../../stores/pool.ts';
import { transport } from '../../transport/websocket.ts';
import { appleTimestamp } from '../../utils/time.ts';
import type { GameControlPayload, GameInvitation, GameInvitationResponse, MultiplayerGameSession, GamePlayer } from '../../protocol/messages.ts';
import { base64Encode } from '../../utils/base64.ts';
import PeerAvatar from '../../components/PeerAvatar.tsx';

const textEncoder = new TextEncoder();

const GAMES = [
  { type: 'connect_four' as const, name: 'Connect Four', icon: '🔴🟡', description: 'Drop pieces and get 4 in a row', players: '2 players' },
  { type: 'chain_reaction' as const, name: 'Chain Reaction', icon: '💥', description: 'Strategic orb placement with chain explosions', players: '2-4 players' },
  { type: 'chess' as const, name: 'Chess', icon: '♟️', description: 'Classic chess', players: '2 players' },
] as const;

interface GameLobbyProps {
  onBack: () => void;
  onStartGame: (type: 'connect_four' | 'chain_reaction' | 'chess') => void;
}

function GameLobby({ onBack, onStartGame }: GameLobbyProps) {
  const pendingInvitation = useGameStore((s) => s.pendingInvitation);
  const currentSession = useGameStore((s) => s.currentSession);
  const isGameActive = useGameStore((s) => s.isGameActive);
  const activeGameType = useGameStore((s) => s.activeGameType);
  const localPeerId = useConnectionStore((s) => s.localPeerId);
  const peers = usePoolStore((s) => s.peers);
  const userProfile = usePoolStore((s) => s.userProfile);

  function handleInvite(gameType: 'connect_four' | 'chain_reaction' | 'chess') {
    if (!localPeerId) return;

    const sessionID = uuidv4().toUpperCase();
    const invitationID = uuidv4().toUpperCase();

    // Create local session as host
    const hostPlayer: GamePlayer = {
      id: localPeerId,
      name: userProfile.displayName,
      playerIndex: 0,
      isHost: true,
      isReady: true,
      colorIndex: userProfile.avatarColorIndex,
      profile: {
        displayName: userProfile.displayName,
        avatarEmoji: userProfile.avatarEmoji,
        avatarColorIndex: userProfile.avatarColorIndex,
      },
    };

    const session: MultiplayerGameSession = {
      sessionID,
      gameType,
      hostPeerID: localPeerId,
      hostName: userProfile.displayName,
      players: [hostPlayer],
      state: 'waiting',
      createdAt: appleTimestamp(),
    };

    useGameStore.getState().setSession(session);

    const invitation: GameInvitation = {
      invitationID,
      gameType,
      hostPeerID: localPeerId,
      hostName: userProfile.displayName,
      sessionID,
      timestamp: appleTimestamp(),
    };

    const invData = base64Encode(textEncoder.encode(JSON.stringify(invitation)));

    const controlPayload: GameControlPayload = {
      controlType: 'invite',
      gameType,
      sessionID,
      data: invData,
    };

    transport.sendGameControl(controlPayload, null);
  }

  function handleAcceptInvitation() {
    if (!pendingInvitation || !localPeerId) return;

    // Create local session as joiner
    const joinerPlayer: GamePlayer = {
      id: localPeerId,
      name: userProfile.displayName,
      playerIndex: 1,
      isHost: false,
      isReady: true,
      colorIndex: userProfile.avatarColorIndex,
      profile: {
        displayName: userProfile.displayName,
        avatarEmoji: userProfile.avatarEmoji,
        avatarColorIndex: userProfile.avatarColorIndex,
      },
    };

    const session: MultiplayerGameSession = {
      sessionID: pendingInvitation.sessionID,
      gameType: pendingInvitation.gameType,
      hostPeerID: pendingInvitation.hostPeerID,
      hostName: pendingInvitation.hostName,
      players: [
        {
          id: pendingInvitation.hostPeerID,
          name: pendingInvitation.hostName,
          playerIndex: 0,
          isHost: true,
          isReady: true,
          colorIndex: 0,
        },
        joinerPlayer,
      ],
      state: 'waiting',
      createdAt: pendingInvitation.timestamp,
    };

    useGameStore.getState().setSession(session);

    const response: GameInvitationResponse = {
      invitationID: pendingInvitation.invitationID,
      accepted: true,
      responderPeerID: localPeerId,
      responderName: userProfile.displayName,
    };

    const respData = base64Encode(textEncoder.encode(JSON.stringify(response)));

    const controlPayload: GameControlPayload = {
      controlType: 'invite_response',
      gameType: pendingInvitation.gameType as GameControlPayload['gameType'],
      sessionID: pendingInvitation.sessionID,
      data: respData,
    };

    transport.sendGameControl(controlPayload, [pendingInvitation.hostPeerID]);
    useGameStore.getState().clearInvitation();

    // Send ready status
    const readyPayload: GameControlPayload = {
      controlType: 'ready',
      gameType: pendingInvitation.gameType as GameControlPayload['gameType'],
      sessionID: pendingInvitation.sessionID,
    };
    transport.sendGameControl(readyPayload, [pendingInvitation.hostPeerID]);
  }

  function handleDeclineInvitation() {
    if (!pendingInvitation || !localPeerId) return;

    const response: GameInvitationResponse = {
      invitationID: pendingInvitation.invitationID,
      accepted: false,
      responderPeerID: localPeerId,
      responderName: userProfile.displayName,
    };

    const respData = base64Encode(textEncoder.encode(JSON.stringify(response)));

    const controlPayload: GameControlPayload = {
      controlType: 'invite_response',
      gameType: pendingInvitation.gameType as GameControlPayload['gameType'],
      sessionID: pendingInvitation.sessionID,
      data: respData,
    };

    transport.sendGameControl(controlPayload, [pendingInvitation.hostPeerID]);
    useGameStore.getState().clearInvitation();
  }

  function handleStartGame() {
    const session = useGameStore.getState().currentSession;
    if (!session || !localPeerId) return;

    // Update session state to playing
    const playingSession: MultiplayerGameSession = {
      ...session,
      state: 'playing',
    };

    useGameStore.getState().setSession(playingSession);
    useGameStore.getState().setGameActive(true);
    useGameStore.getState().setActiveGameType(session.gameType as 'connect_four' | 'chain_reaction' | 'chess');

    // Broadcast start to all peers
    const startData = base64Encode(textEncoder.encode(JSON.stringify(playingSession)));
    const controlPayload: GameControlPayload = {
      controlType: 'start',
      gameType: session.gameType as GameControlPayload['gameType'],
      sessionID: session.sessionID,
      data: startData,
    };
    transport.sendGameControl(controlPayload, null);
  }

  // If game is active, redirect to game
  if (isGameActive && activeGameType) {
    onStartGame(activeGameType);
    return null;
  }

  const isHost = currentSession?.hostPeerID === localPeerId;
  const canStart = currentSession && currentSession.players.length >= 2 && isHost;

  return (
    <div className="flex-1 flex flex-col min-h-0" style={{ backgroundColor: 'var(--bg-page)' }}>
      {/* Top bar */}
      <div className="flex items-center gap-3 px-4 py-3" style={{ borderBottomWidth: '1px', borderBottomStyle: 'solid', borderBottomColor: 'var(--separator)', backgroundColor: 'var(--bg-surface)' }}>
        <button type="button" onClick={onBack} className="text-[#007AFF] transition-colors">
          <ArrowLeft className="h-5 w-5" />
        </button>
        <Swords className="h-4 w-4 text-[#BF5AF2]" />
        <span className="text-[17px] font-semibold" style={{ color: 'var(--text-primary)' }}>Games</span>
      </div>

      {/* Invitation modal */}
      {pendingInvitation && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className="rounded-xl w-full max-w-sm p-5 space-y-4 animate-slide-up" style={{ backgroundColor: 'var(--bg-surface)' }}>
            <h3 className="text-[17px] font-semibold text-center" style={{ color: 'var(--text-primary)' }}>Game Invitation</h3>
            <div className="flex items-center justify-center gap-3">
              {(() => {
                const host = peers.find((p) => p.peerId === pendingInvitation.hostPeerID);
                return host ? <PeerAvatar emoji={host.avatarEmoji} colorIndex={host.avatarColorIndex} /> : null;
              })()}
              <div>
                <p className="text-[15px]" style={{ color: 'var(--text-primary)' }}>{pendingInvitation.hostName}</p>
                <p className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>wants to play {pendingInvitation.gameType.replace('_', ' ')}</p>
              </div>
            </div>
            <div className="flex gap-3">
              <button
                type="button"
                onClick={handleDeclineInvitation}
                className="flex-1 flex items-center justify-center gap-1.5 py-3 rounded-xl text-[15px] transition-colors"
                style={{ backgroundColor: 'rgba(255, 69, 58, 0.1)', color: '#FF453A' }}
              >
                <X className="h-4 w-4" /> Decline
              </button>
              <button
                type="button"
                onClick={handleAcceptInvitation}
                className="flex-1 flex items-center justify-center gap-1.5 py-3 bg-[#30D158] text-white rounded-xl text-[15px] font-semibold transition-colors"
              >
                <Check className="h-4 w-4" /> Accept
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Game waiting room */}
      {currentSession && currentSession.state === 'waiting' && (
        <div className="px-4 py-4 space-y-3" style={{ backgroundColor: 'var(--bg-surface)', borderBottomWidth: '1px', borderBottomStyle: 'solid', borderBottomColor: 'var(--separator)' }}>
          <p className="text-[15px] text-center" style={{ color: 'var(--text-secondary)' }}>
            {currentSession.players.length < 2
              ? `Waiting for players to join ${currentSession.gameType.replace('_', ' ')}...`
              : `Ready to play ${currentSession.gameType.replace('_', ' ')}!`}
          </p>
          <div className="flex justify-center gap-3">
            {currentSession.players.map((p) => {
              const peer = peers.find((pe) => pe.peerId === p.id);
              return (
                <div key={p.id} className="flex items-center gap-1.5 text-[12px]" style={{ color: 'var(--text-secondary)' }}>
                  <PeerAvatar emoji={peer?.avatarEmoji ?? p.profile?.avatarEmoji ?? '😀'} colorIndex={peer?.avatarColorIndex ?? p.colorIndex} size="sm" />
                  <span className="text-[13px]" style={{ color: 'var(--text-primary)' }}>{p.id === localPeerId ? 'You' : (peer?.displayName ?? p.name)}</span>
                  <span className={`h-2 w-2 rounded-full ${p.isReady ? 'bg-[#30D158]' : 'bg-[#FF9F0A]'}`} />
                </div>
              );
            })}
          </div>
          {canStart && (
            <button
              type="button"
              onClick={handleStartGame}
              className="w-full flex items-center justify-center gap-2 py-3 bg-[#30D158] text-white text-[15px] font-semibold rounded-xl transition-colors"
            >
              <Play className="h-4 w-4" /> Start Game
            </button>
          )}
        </div>
      )}

      {/* Game cards */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {GAMES.map((game) => (
          <button
            key={game.type}
            type="button"
            onClick={() => handleInvite(game.type)}
            disabled={!!currentSession}
            className="w-full rounded-xl p-4 flex items-center gap-4 transition-colors text-left group disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ backgroundColor: 'var(--bg-surface)' }}
          >
            <div className="h-14 w-14 rounded-full flex items-center justify-center text-2xl shrink-0 group-hover:scale-105 transition-transform" style={{ backgroundColor: 'rgba(191, 90, 242, 0.15)' }}>
              {game.icon}
            </div>
            <div className="flex-1 min-w-0">
              <h3 className="text-[15px] font-semibold" style={{ color: 'var(--text-primary)' }}>{game.name}</h3>
              <p className="text-[13px] mt-0.5" style={{ color: 'var(--text-secondary)' }}>{game.description}</p>
              <p className="text-[11px] mt-1" style={{ color: 'var(--text-tertiary)' }}>{game.players}</p>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

export default GameLobby;
