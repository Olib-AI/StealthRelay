import { useEffect, useCallback } from 'react';
import { Gamepad2, X, Eye } from 'lucide-react';
import { useGameStore } from '../stores/game.ts';
import { useConnectionStore } from '../stores/connection.ts';
import { usePoolStore } from '../stores/pool.ts';
import { transport } from '../transport/websocket.ts';
import type { GameInvitationResponse, GameControlPayload } from '../protocol/messages.ts';
import { base64Encode } from '../utils/base64.ts';

const textEncoder = new TextEncoder();

const GAME_NAMES: Record<string, string> = {
  connect_four: 'Connect Four',
  chain_reaction: 'Chain Reaction',
  chess: 'Chess',
  ludo: 'Ludo',
};

const AUTO_DISMISS_MS = 30000;

interface GameInvitationBannerProps {
  onNavigateToGames: () => void;
}

function GameInvitationBanner({ onNavigateToGames }: GameInvitationBannerProps) {
  const pendingInvitation = useGameStore((s) => s.pendingInvitation);
  const peers = usePoolStore((s) => s.peers);

  const handleDecline = useCallback(() => {
    const invitation = useGameStore.getState().pendingInvitation;
    const peerId = useConnectionStore.getState().localPeerId;
    if (!invitation || !peerId) {
      useGameStore.getState().clearInvitation();
      return;
    }

    const profile = usePoolStore.getState().userProfile;
    const response: GameInvitationResponse = {
      invitationID: invitation.invitationID,
      accepted: false,
      responderPeerID: peerId,
      responderName: profile.displayName,
    };

    const respData = base64Encode(textEncoder.encode(JSON.stringify(response)));
    const controlPayload: GameControlPayload = {
      controlType: 'invite_response',
      gameType: invitation.gameType as GameControlPayload['gameType'],
      sessionID: invitation.sessionID,
      data: respData,
    };

    transport.sendGameControl(controlPayload, [invitation.hostPeerID]);
    useGameStore.getState().clearInvitation();
  }, []);

  useEffect(() => {
    if (!pendingInvitation) return;
    const timer = setTimeout(() => {
      handleDecline();
    }, AUTO_DISMISS_MS);
    return () => clearTimeout(timer);
  }, [handleDecline, pendingInvitation]);

  const handleView = useCallback(() => {
    onNavigateToGames();
  }, [onNavigateToGames]);

  if (!pendingInvitation) return null;

  const hostPeer = peers.find((p) => p.peerId === pendingInvitation.hostPeerID);
  const gameName = GAME_NAMES[pendingInvitation.gameType] ?? pendingInvitation.gameType.replace(/_/g, ' ');

  return (
    <div className="absolute top-2 left-2 right-2 z-[60] pointer-events-none animate-slide-up">
      <div
        className="pointer-events-auto w-full rounded-2xl p-3 shadow-2xl border"
        style={{
          backgroundColor: 'rgba(88, 86, 214, 0.95)',
          backdropFilter: 'blur(20px)',
          borderColor: 'rgba(255, 255, 255, 0.15)',
        }}
      >
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl flex items-center justify-center shrink-0 bg-white/20">
            <Gamepad2 className="h-5 w-5 text-white" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[13px] font-bold text-white/90">Game Invitation</p>
            <p className="text-[12px] text-white/70 truncate">
              {hostPeer?.displayName ?? pendingInvitation.hostName} wants to play {gameName}
            </p>
          </div>
        </div>
        <div className="flex gap-2 mt-2.5">
          <button
            type="button"
            onClick={handleDecline}
            className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded-xl text-[13px] font-medium transition-colors"
            style={{ backgroundColor: 'rgba(255, 255, 255, 0.15)', color: 'rgba(255, 255, 255, 0.9)' }}
          >
            <X className="h-3.5 w-3.5" /> Decline
          </button>
          <button
            type="button"
            onClick={handleView}
            className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded-xl text-[13px] font-semibold transition-colors bg-white text-[#5856D6]"
          >
            <Eye className="h-3.5 w-3.5" /> View
          </button>
        </div>
      </div>
    </div>
  );
}

export default GameInvitationBanner;
