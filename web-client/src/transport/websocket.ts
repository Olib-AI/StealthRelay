import { v4 as uuidv4 } from 'uuid';
import { makeFrame } from '../protocol/frames.ts';
import type {
  ServerFrame,
  AuthChallengeData,
  JoinAcceptedData,
  JoinRejectedData,
  PeerJoinedData,
  PeerLeftData,
  RelayedData,
  ServerErrorData,
  KickedData,
  HeartbeatPongData,
  ServerHelloData,
  SessionResumedData,
} from '../protocol/frames.ts';
import type { PoolMessage, KeyExchangePayload, ProfileUpdatePayload, PeerInfoPayload, EncryptedChatMessage, GameControlPayload } from '../protocol/messages.ts';
import {
  HEARTBEAT_INTERVAL_MS,
  MAX_RECONNECT_ATTEMPTS,
  INITIAL_RECONNECT_DELAY_MS,
  MAX_RECONNECT_DELAY_MS,
  MAX_MESSAGE_SIZE,
  APPLE_EPOCH_OFFSET,
} from '../protocol/constants.ts';
import { useConnectionStore } from '../stores/connection.ts';
import { usePoolStore } from '../stores/pool.ts';
import type { Peer } from '../stores/pool.ts';
import { useChatStore } from '../stores/chat.ts';
import type { ChatMessage } from '../stores/chat.ts';
import { useGameStore } from '../stores/game.ts';
import type { ActiveGameType } from '../stores/game.ts';
import { getPublicKeyBase64 } from '../crypto/identity.ts';
import { parseInvitationUrl, computeJoinProof, isInvitationExpired } from '../crypto/invitation.ts';
import type { ParsedInvitation } from '../crypto/invitation.ts';
import { solvePowAsync } from '../crypto/pow.ts';
import { generateX25519KeyPair, getX25519PublicKeyBase64, deriveSharedKey, encryptMessage, decryptMessage, encryptBytes, decryptBytes, resetEncryptionSession } from '../crypto/encryption.ts';
import { base64Encode, base64Decode } from '../utils/base64.ts';
import { CallManager, type ActiveCall, type CallManagerDelegate } from '../calling/call-manager.ts';
import type { CallSignal } from '../calling/types.ts';
import { useCallStore } from '../stores/call.ts';
import type {
  GameInvitation,
  GameInvitationResponse,
  MultiplayerGameSession,
  ConnectFourState,
  ConnectFourAction,
  ChainReactionState,
  ChainReactionAction,
  ChessState,
  ChessAction,
  LudoBoardState,
  LudoAction,
  LudoPlayer,
  LudoTokenPosition,
  DiceRolledPayload,
  TokenMovedPayload,
  TurnChangedPayload,
} from '../protocol/messages.ts';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

class WebSocketTransport {
  private ws: WebSocket | null = null;
  private serverUrl: string | null = null;
  private sequenceNumber = 0;
  private invitation: ParsedInvitation | null = null;
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private powSolution: { challenge: string; solution: string } | null = null;
  private callManager: CallManager | null = null;

  async connect(invitationUrl: string): Promise<void> {
    this.cleanup();
    resetEncryptionSession();
    generateX25519KeyPair();

    const invitation = parseInvitationUrl(invitationUrl);
    if (isInvitationExpired(invitation)) {
      useConnectionStore.getState().setError('This invitation has expired.');
      useConnectionStore.getState().setStatus('failed');
      return;
    }

    this.invitation = invitation;
    this.serverUrl = invitation.serverAddress;
    this.sequenceNumber = 0;
    this.reconnectAttempt = 0;
    this.powSolution = null;

    useConnectionStore.getState().setServerUrl(this.serverUrl);
    useConnectionStore.getState().setStatus('connecting');

    this.openWebSocket();
  }

  private openWebSocket(): void {
    if (!this.serverUrl) return;

    // On secure pages, ws:// is blocked by mixed content policy.
    // In dev, route through Vite's WS proxy; in prod, upgrade to wss://.
    let url = this.serverUrl;
    if (window.location.protocol === 'https:' && url.startsWith('ws://')) {
      if (import.meta.env.DEV) {
        url = `wss://${window.location.host}/ws-proxy/${encodeURIComponent(url)}`;
      } else {
        url = 'wss://' + url.slice(5);
      }
    }

    try {
      this.ws = new WebSocket(url);
    } catch (err) {
      useConnectionStore.getState().setError(`Failed to connect: ${err instanceof Error ? err.message : 'Unknown error'}`);
      useConnectionStore.getState().setStatus('failed');
      return;
    }

    this.ws.onopen = () => {
      this.reconnectAttempt = 0;
      this.startHeartbeat();
    };

    this.ws.onmessage = (event: MessageEvent) => {
      if (typeof event.data === 'string') {
        this.handleMessage(event.data);
      }
    };

    this.ws.onclose = (event: CloseEvent) => {
      this.stopHeartbeat();
      const connState = useConnectionStore.getState();
      if (connState.status === 'connected' || connState.status === 'reconnecting') {
        this.attemptReconnect();
      } else if (connState.status !== 'idle' && connState.status !== 'disconnected') {
        if (!event.wasClean) {
          connState.setError('Connection closed unexpectedly');
          connState.setStatus('failed');
        }
      }
    };

    this.ws.onerror = () => {
      // onclose will fire after onerror
    };
  }

  private handleMessage(raw: string): void {
    let frame: ServerFrame;
    try {
      frame = JSON.parse(raw) as ServerFrame;
    } catch {
      return;
    }

    switch (frame.frame_type) {
      case 'auth_challenge':
        this.handleAuthChallenge(frame.data as AuthChallengeData);
        break;
      case 'server_hello':
        this.handleServerHello(frame.data as ServerHelloData);
        break;
      case 'join_accepted':
        this.handleJoinAccepted(frame.data as JoinAcceptedData);
        break;
      case 'join_rejected':
        this.handleJoinRejected(frame.data as JoinRejectedData);
        break;
      case 'peer_joined':
        this.handlePeerJoined(frame.data as PeerJoinedData);
        break;
      case 'peer_left':
        this.handlePeerLeft(frame.data as PeerLeftData);
        break;
      case 'relayed':
        this.handleRelayed(frame.data as RelayedData);
        break;
      case 'error':
        this.handleServerError(frame.data as ServerErrorData);
        break;
      case 'kicked':
        this.handleKicked(frame.data as KickedData);
        break;
      case 'heartbeat_pong':
        this.handleHeartbeatPong(frame.data as HeartbeatPongData);
        break;
      case 'session_resumed':
        this.handleSessionResumed(frame.data as SessionResumedData);
        break;
    }
  }

  private handleAuthChallenge(data: AuthChallengeData): void {
    useConnectionStore.getState().setAuthNonce(data.nonce);
    this.sendJoinRequest();
  }

  private handleServerHello(data: ServerHelloData): void {
    if (data.pow_challenge) {
      const challenge = data.pow_challenge;
      useConnectionStore.getState().setStatus('connecting');
      useConnectionStore.getState().setPowProgress(0);

      // Server sends challenge as base64 — convert to hex for the worker
      const challengeBytes = base64Decode(challenge.challenge);
      const challengeHex = Array.from(challengeBytes).map(b => b.toString(16).padStart(2, '0')).join('');

      solvePowAsync(
        challengeHex,
        challenge.difficulty,
        (nonce) => useConnectionStore.getState().setPowProgress(nonce),
      ).then((result) => {
        // Worker returns hex solution — convert to base64 for the server
        const solutionBytes = new Uint8Array(result.solution.match(/.{2}/g)!.map(b => parseInt(b, 16)));
        this.powSolution = {
          challenge: challenge.challenge,  // original base64 challenge
          solution: base64Encode(solutionBytes),  // base64-encoded 8-byte nonce
        };
        useConnectionStore.getState().setPowProgress(null);
        this.sendJoinRequest();
      }).catch((err) => {
        useConnectionStore.getState().setError(`PoW failed: ${err instanceof Error ? err.message : 'Unknown'}`);
        useConnectionStore.getState().setStatus('failed');
      });
    }
  }

  private sendJoinRequest(): void {
    if (!this.invitation || !this.ws || this.ws.readyState !== WebSocket.OPEN) return;

    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.getRandomValues(new Uint8Array(32));

    const proof = computeJoinProof(
      this.invitation.tokenSecret,
      this.invitation.tokenId,
      this.invitation.poolIdBytes,
      timestamp,
      nonce,
    );

    const profile = usePoolStore.getState().userProfile;

    const data = {
      token_id: base64Encode(this.invitation.tokenId),
      proof: base64Encode(proof),
      timestamp,
      nonce: base64Encode(nonce),
      client_public_key: getPublicKeyBase64(),
      display_name: profile.displayName,
      pow_solution: this.powSolution ?? null,
    };

    this.send('join_request', data);
    useConnectionStore.getState().setStatus('waiting_approval');
  }

  private handleJoinAccepted(data: JoinAcceptedData): void {
    useConnectionStore.getState().setJoinAccepted({
      sessionToken: data.session_token,
      peerId: data.peer_id,
      poolId: data.pool_info.pool_id,
    });

    usePoolStore.getState().setPoolInfo({
      poolId: data.pool_info.pool_id,
      name: data.pool_info.name,
      hostPeerId: data.pool_info.host_peer_id,
      maxPeers: data.pool_info.max_peers,
      currentPeers: data.pool_info.current_peers,
    });

    const peers: Peer[] = data.peers.map((p) => ({
      peerId: p.peer_id,
      displayName: p.display_name,
      publicKey: p.public_key,
      connectedAt: p.connected_at,
      avatarEmoji: '😀',
      avatarColorIndex: 0,
    }));
    usePoolStore.getState().setPeers(peers);

    // Send key exchange to all peers
    this.broadcastKeyExchange();
    // Send profile update
    this.broadcastProfileUpdate();
    // Send peer info
    this.broadcastPeerInfo();
  }

  private handleJoinRejected(data: JoinRejectedData): void {
    useConnectionStore.getState().setError(`Join rejected: ${data.reason}`);
    useConnectionStore.getState().setStatus('failed');
  }

  private handlePeerJoined(data: PeerJoinedData): void {
    const peer: Peer = {
      peerId: data.peer.peer_id,
      displayName: data.peer.display_name,
      publicKey: data.peer.public_key,
      connectedAt: data.peer.connected_at,
      avatarEmoji: '😀',
      avatarColorIndex: 0,
    };
    usePoolStore.getState().addPeer(peer);

    // Send key exchange to new peer
    this.sendKeyExchangeToPeer(data.peer.peer_id);
    // Send profile update to new peer
    this.sendProfileUpdateToPeer(data.peer.peer_id);
  }

  private handlePeerLeft(data: PeerLeftData): void {
    usePoolStore.getState().removePeer(data.peer_id);

    // If the peer was in an active game, end it
    const gameStore = useGameStore.getState();
    if (gameStore.isGameActive && gameStore.currentSession) {
      const wasInGame = gameStore.currentSession.players.some(p => p.id === data.peer_id);
      if (wasInGame) {
        gameStore.setSession({ ...gameStore.currentSession, state: 'finished' });
        // Mark game over in the active game state
        const localPeerId = useConnectionStore.getState().localPeerId;
        const localPlayer = gameStore.currentSession.players.find(p => p.id === localPeerId);
        if (gameStore.connectFourState && !gameStore.connectFourState.gameOver) {
          gameStore.setConnectFourState({ ...gameStore.connectFourState, gameOver: true, winnerIndex: localPlayer?.playerIndex });
        }
        if (gameStore.chainReactionState && !gameStore.chainReactionState.gameOver) {
          gameStore.setChainReactionState({ ...gameStore.chainReactionState, gameOver: true, winnerIndex: localPlayer?.playerIndex });
        }
        if (gameStore.chessState && !gameStore.chessState.gameOver) {
          gameStore.setChessState({ ...gameStore.chessState, gameOver: true, winnerIndex: localPlayer?.playerIndex, isCheckmate: false, isStalemate: false });
        }
        if (gameStore.ludoState && gameStore.ludoState.gamePhase !== 'finished') {
          gameStore.setLudoState({ ...gameStore.ludoState, gamePhase: 'finished', winnerPlayerIndex: localPlayer?.playerIndex ?? null });
        }
      }
    }
  }

  private handleRelayed(data: RelayedData): void {
    // ACK immediately
    this.send('ack', { sequence: data.sequence });

    try {
      const jsonStr = textDecoder.decode(base64Decode(data.data));
      const poolMsg = JSON.parse(jsonStr) as PoolMessage;
      this.processPoolMessage(poolMsg, data.from_peer_id);
    } catch {
      // Silently drop malformed messages
    }
  }

  private processPoolMessage(msg: PoolMessage, fromPeerId: string): void {
    switch (msg.type) {
      case 'key_exchange':
        this.handleKeyExchange(msg);
        break;
      case 'profile_update':
        this.handleProfileUpdate(msg);
        break;
      case 'peer_info':
        this.handlePeerInfoMessage(msg);
        break;
      case 'chat':
        this.handleChatMessage(msg, fromPeerId);
        break;
      case 'game_control':
        this.handleGameControl(msg);
        break;
      case 'game_state':
        this.handleGameState(msg);
        break;
      case 'game_action':
        this.handleGameAction(msg);
        break;
      case 'custom':
        this.handleCustomMessage(msg, fromPeerId);
        break;
      default:
        break;
    }
  }

  private handleKeyExchange(msg: PoolMessage): void {
    try {
      const payloadJson = textDecoder.decode(base64Decode(msg.payload));
      const payload = JSON.parse(payloadJson) as KeyExchangePayload;
      const peerPubKey = base64Decode(payload.publicKey);
      useChatStore.getState().setPeerX25519Key(payload.senderPeerID, peerPubKey);

      const symmetricKey = deriveSharedKey(peerPubKey);
      useChatStore.getState().setPeerSymmetricKey(payload.senderPeerID, symmetricKey);
    } catch {
      // Invalid key exchange
    }
  }

  private handleProfileUpdate(msg: PoolMessage): void {
    try {
      const payloadJson = textDecoder.decode(base64Decode(msg.payload));
      const payload = JSON.parse(payloadJson) as ProfileUpdatePayload;
      usePoolStore.getState().updatePeerProfile(payload.peerID, payload.profile);
    } catch {
      // Invalid profile update
    }
  }

  private handlePeerInfoMessage(msg: PoolMessage): void {
    try {
      const payloadJson = textDecoder.decode(base64Decode(msg.payload));
      const payload = JSON.parse(payloadJson) as PeerInfoPayload;
      if (payload.profile) {
        usePoolStore.getState().updatePeerProfile(payload.peerID, payload.profile);
      }
    } catch {
      // Invalid peer info
    }
  }

  private async handleChatMessage(msg: PoolMessage, fromPeerId: string): Promise<void> {
    try {
      const payloadJson = textDecoder.decode(base64Decode(msg.payload));
      // Try to parse as EncryptedChatMessage first (from PoolChat)
      let chatMsg: EncryptedChatMessage;
      try {
        chatMsg = JSON.parse(payloadJson) as EncryptedChatMessage;
      } catch {
        // Might be a simple ChatPayload
        const simple = JSON.parse(payloadJson) as { text: string };
        chatMsg = {
          id: msg.id,
          senderID: msg.senderID,
          senderName: msg.senderName,
          contentType: 'text',
          timestamp: msg.timestamp,
          text: simple.text,
          reactions: {},
          mentions: [],
        };
      }

      const appleTs = chatMsg.timestamp ?? msg.timestamp;
      const jsTimestamp = (appleTs + APPLE_EPOCH_OFFSET) * 1000;

      const message: ChatMessage = {
        id: chatMsg.id ?? msg.id,
        senderID: chatMsg.senderID ?? msg.senderID,
        senderName: chatMsg.senderName ?? msg.senderName,
        contentType: chatMsg.contentType ?? 'text',
        timestamp: jsTimestamp,
        text: chatMsg.text,
        emoji: chatMsg.emoji,
        pollData: chatMsg.pollData,
        reactions: chatMsg.reactions ?? {},
        replyTo: chatMsg.replyTo,
        mentions: chatMsg.mentions ?? [],
        senderAvatarEmoji: chatMsg.senderAvatarEmoji,
        senderAvatarColorIndex: chatMsg.senderAvatarColorIndex,
        isEncrypted: false,
        isPrivate: false,
      };

      // Determine if this is a private message by checking if it was targeted
      // For now, treat all chat messages as group (private messages come through targeted forwards)
      const localPeerId = useConnectionStore.getState().localPeerId;
      if (msg.senderID !== localPeerId) {
        // Try to decrypt if we have a key
        const symmetricKey = useChatStore.getState().peerSymmetricKeys[fromPeerId];
        if (symmetricKey && chatMsg.text) {
          try {
            const decrypted = await decryptMessage(chatMsg.text, symmetricKey);
            message.text = decrypted;
            message.isEncrypted = true;
          } catch {
            // Not encrypted or wrong key, keep original text
          }
        }
      }

      useChatStore.getState().addGroupMessage(message);
    } catch {
      // Invalid chat message
    }
  }

  private async handleCustomMessage(msg: PoolMessage, fromPeerId: string): Promise<void> {
    // iOS PoolChat sends encrypted messages as type "custom" with EncryptedChatPayload
    try {
      const payloadJson = textDecoder.decode(base64Decode(msg.payload));
      const payload = JSON.parse(payloadJson) as {
        messageType?: string;
        isPrivateChat?: boolean;
        encryptedData?: string;
        senderPeerID?: string;
        targetPeerID?: string;
      };

      if (payload.messageType === 'chat_message' && payload.encryptedData) {
        let isPrivate = payload.isPrivateChat === true;
        const symmetricKey = useChatStore.getState().peerSymmetricKeys[fromPeerId];

        let text: string | undefined = '[Encrypted message]';
        let decryptedMsg: EncryptedChatMessage | null = null;
        let didDecrypt = false;

        if (payload.encryptedData) {
          // First try: decrypt with peer's symmetric key (AES-GCM)
          if (symmetricKey) {
            try {
              const rawDecrypted = await decryptMessage(payload.encryptedData, symmetricKey);
              try {
                const parsed = JSON.parse(rawDecrypted) as Record<string, unknown>;
                // iOS wraps in PrivateChatPayload: { chatPayload: {..., text: "Hello"}, isPrivate }
                if (parsed.chatPayload && typeof parsed.chatPayload === 'object') {
                  const cp = parsed.chatPayload as EncryptedChatMessage & { messageID?: string };
                  decryptedMsg = { ...cp, id: cp.messageID ?? cp.id ?? msg.id };
                  text = cp.text;
                  isPrivate = (parsed.isPrivate as boolean) ?? false;
                } else if (parsed.text !== undefined) {
                  decryptedMsg = parsed as unknown as EncryptedChatMessage;
                  text = parsed.text as string;
                } else {
                  text = rawDecrypted;
                }
              } catch {
                text = rawDecrypted;
              }
              didDecrypt = true;
            } catch {
              // AES-GCM decryption failed
            }
          }

          // Second try: maybe it's just base64-encoded plaintext JSON (from web client or unencrypted)
          if (!didDecrypt) {
            try {
              const decoded = textDecoder.decode(base64Decode(payload.encryptedData));
              const parsed = JSON.parse(decoded) as Record<string, unknown>;

              // iOS PoolChat wraps in PrivateChatPayload: { chatPayload: RichChatPayload, isPrivate, targetPeerID }
              if (parsed.chatPayload && typeof parsed.chatPayload === 'object') {
                const cp = parsed.chatPayload as EncryptedChatMessage & { messageID?: string };
                decryptedMsg = {
                  ...cp,
                  id: cp.messageID ?? cp.id ?? msg.id,
                };
                text = cp.text;
                isPrivate = (parsed.isPrivate as boolean) ?? false;
                didDecrypt = true;
              } else if (parsed.text || parsed.contentType) {
                // Direct RichChatPayload (legacy)
                decryptedMsg = parsed as unknown as EncryptedChatMessage;
                text = parsed.text as string | undefined;
                didDecrypt = true;
              }
            } catch {
              // Not valid JSON either
            }
          }
        }

        const appleTs = msg.timestamp;
        const jsTimestamp = (appleTs + APPLE_EPOCH_OFFSET) * 1000;

        const message: ChatMessage = {
          id: decryptedMsg?.id ?? msg.id,
          senderID: msg.senderID,
          senderName: msg.senderName,
          contentType: decryptedMsg?.contentType ?? 'text',
          timestamp: jsTimestamp,
          text,
          imageData: decryptedMsg?.imageData,
          voiceData: decryptedMsg?.voiceData,
          voiceDuration: decryptedMsg?.voiceDuration,
          emoji: decryptedMsg?.emoji,
          pollData: decryptedMsg?.pollData,
          reactions: decryptedMsg?.reactions ?? {},
          replyTo: decryptedMsg?.replyTo,
          mentions: decryptedMsg?.mentions ?? [],
          senderAvatarEmoji: decryptedMsg?.senderAvatarEmoji,
          senderAvatarColorIndex: decryptedMsg?.senderAvatarColorIndex,
          isEncrypted: !!symmetricKey,
          isPrivate: isPrivate,
        };

        if (isPrivate) {
          useChatStore.getState().addPrivateMessage(fromPeerId, message);
        } else {
          useChatStore.getState().addGroupMessage(message);
        }
      } else if (payload.messageType === 'reaction' && payload.encryptedData) {
        const symmetricKey = useChatStore.getState().peerSymmetricKeys[fromPeerId];
        if (symmetricKey) {
          try {
            const decrypted = await decryptMessage(payload.encryptedData, symmetricKey);
            const reaction = JSON.parse(decrypted) as { messageID: string; emoji: string; peerID: string; isAdding: boolean };
            const chatState = useChatStore.getState();
            const reactionIdLower = reaction.messageID.toLowerCase();
            // Try group messages first
            const inGroup = chatState.groupMessages.some(m => m.id.toLowerCase() === reactionIdLower);
            if (inGroup) {
              chatState.addReaction(reaction.messageID, reaction.emoji, reaction.peerID, true);
            } else {
              // Search private messages
              for (const [peerId, msgs] of Object.entries(chatState.privateMessages)) {
                if (msgs.some(m => m.id.toLowerCase() === reactionIdLower)) {
                  chatState.addReaction(reaction.messageID, reaction.emoji, reaction.peerID, false, peerId);
                  break;
                }
              }
            }
          } catch {
            // Can't decrypt reaction
          }
        }
      } else if (payload.messageType === 'call_signal' && payload.encryptedData) {
        await this.handleIncomingCallSignal(payload.encryptedData, fromPeerId);
      } else if (payload.messageType === 'media_frame' && payload.encryptedData) {
        await this.handleIncomingMediaFrame(payload.encryptedData, fromPeerId);
      } else if (payload.messageType === 'poll_vote' && payload.encryptedData) {
        const symmetricKey = useChatStore.getState().peerSymmetricKeys[fromPeerId];
        if (symmetricKey) {
          try {
            const decrypted = await decryptMessage(payload.encryptedData, symmetricKey);
            const vote = JSON.parse(decrypted) as { messageID: string; option: string; voterID: string };
            const chatState = useChatStore.getState();
            const voteIdLower = vote.messageID.toLowerCase();
            const inGroup = chatState.groupMessages.some(m => m.id.toLowerCase() === voteIdLower);
            if (inGroup) {
              chatState.updatePollVote(vote.messageID, vote.option, vote.voterID, true);
            } else {
              for (const [peerId, msgs] of Object.entries(chatState.privateMessages)) {
                if (msgs.some(m => m.id.toLowerCase() === voteIdLower)) {
                  chatState.updatePollVote(vote.messageID, vote.option, vote.voterID, false, peerId);
                  break;
                }
              }
            }
          } catch {
            // Can't decrypt poll vote
          }
        }
      }
      // Ignore history_sync, clear_history, etc.
    } catch {
      // Invalid custom message
    }
  }

  private handleGameControl(msg: PoolMessage): void {
    try {
      const payloadJson = textDecoder.decode(base64Decode(msg.payload));
      const payload = JSON.parse(payloadJson) as GameControlPayload;

      switch (payload.controlType) {
        case 'invite': {
          if (payload.data) {
            const inviteJson = textDecoder.decode(base64Decode(payload.data));
            const invite = JSON.parse(inviteJson) as GameInvitation;
            useGameStore.getState().setPendingInvitation(invite);
          }
          break;
        }
        case 'invite_response': {
          if (payload.data) {
            const respJson = textDecoder.decode(base64Decode(payload.data));
            const resp = JSON.parse(respJson) as GameInvitationResponse;
            if (resp.accepted && payload.sessionID) {
              // Add the accepted player to the session
              const session = useGameStore.getState().currentSession;
              if (session && session.sessionID.toLowerCase() === (payload.sessionID ?? '').toLowerCase()) {
                const peer = usePoolStore.getState().peers.find(p => p.peerId === resp.responderPeerID);
                const newPlayer = {
                  id: resp.responderPeerID,
                  name: resp.responderName,
                  playerIndex: session.players.length,
                  isHost: false,
                  isReady: false,
                  colorIndex: peer?.avatarColorIndex ?? session.players.length,
                  profile: peer ? { displayName: peer.displayName, avatarEmoji: peer.avatarEmoji ?? '😀', avatarColorIndex: peer.avatarColorIndex ?? 0 } : undefined,
                };
                const updatedSession = { ...session, players: [...session.players, newPlayer] };
                useGameStore.getState().setSession(updatedSession);

                // Broadcast session update so the joiner gets the full player list
                const sessionData = base64Encode(textEncoder.encode(JSON.stringify(updatedSession)));
                const updatePayload: GameControlPayload = {
                  controlType: 'session_update',
                  gameType: session.gameType as GameControlPayload['gameType'],
                  sessionID: session.sessionID,
                  data: sessionData,
                };
                this.sendPoolMessage('game_control', updatePayload, null, true);
              }
            }
          }
          break;
        }
        case 'session_update': {
          if (payload.data) {
            const sessionJson = textDecoder.decode(base64Decode(payload.data));
            const session = JSON.parse(sessionJson) as MultiplayerGameSession;
            useGameStore.getState().setSession(session);
            if (session.state === 'playing') {
              useGameStore.getState().setGameActive(true);
              useGameStore.getState().setActiveGameType(payload.gameType as ActiveGameType);
            } else if (session.state === 'finished' || session.state === 'cancelled') {
              useGameStore.getState().setGameActive(false);
            }
          }
          break;
        }
        case 'start': {
          if (payload.data) {
            const sessionJson = textDecoder.decode(base64Decode(payload.data));
            const session = JSON.parse(sessionJson) as MultiplayerGameSession;
            useGameStore.getState().setSession(session);
          }
          useGameStore.getState().setGameActive(true);
          useGameStore.getState().setActiveGameType(payload.gameType as ActiveGameType);
          break;
        }
        case 'ready': {
          // Update player ready status in current session
          const session = useGameStore.getState().currentSession;
          if (session) {
            const players = session.players.map(p =>
              p.id === msg.senderID ? { ...p, isReady: true } : p
            );
            useGameStore.getState().setSession({ ...session, players });
          }
          break;
        }
        case 'forfeit': {
          const gameStore = useGameStore.getState();
          if (gameStore.currentSession) {
            gameStore.setSession({ ...gameStore.currentSession, state: 'finished' });
          }
          // Mark game over so the game-over overlay shows (don't hide the game immediately)
          const localPeerId = useConnectionStore.getState().localPeerId;
          const localPlayer = gameStore.currentSession?.players.find(p => p.id === localPeerId);
          if (gameStore.connectFourState && !gameStore.connectFourState.gameOver) {
            gameStore.setConnectFourState({ ...gameStore.connectFourState, gameOver: true, winnerIndex: localPlayer?.playerIndex });
          }
          if (gameStore.chainReactionState && !gameStore.chainReactionState.gameOver) {
            gameStore.setChainReactionState({ ...gameStore.chainReactionState, gameOver: true, winnerIndex: localPlayer?.playerIndex });
          }
          if (gameStore.chessState && !gameStore.chessState.gameOver) {
            gameStore.setChessState({ ...gameStore.chessState, gameOver: true, winnerIndex: localPlayer?.playerIndex, isCheckmate: false, isStalemate: false });
          }
          if (gameStore.ludoState && gameStore.ludoState.gamePhase !== 'finished') {
            gameStore.setLudoState({ ...gameStore.ludoState, gamePhase: 'finished', winnerPlayerIndex: localPlayer?.playerIndex ?? null });
          }
          break;
        }
        case 'rematch': {
          // Reset game state for rematch
          const session = useGameStore.getState().currentSession;
          if (session) {
            useGameStore.getState().setSession({ ...session, state: 'playing' });
            useGameStore.getState().setConnectFourState(null);
            useGameStore.getState().setChainReactionState(null);
            useGameStore.getState().setChessState(null);
            useGameStore.getState().setLudoState(null);
          }
          break;
        }
        case 'pause':
        case 'resume':
          break;
      }
    } catch {
      // Invalid game control
    }
  }

  private handleGameState(msg: PoolMessage): void {
    try {
      const payloadJson = textDecoder.decode(base64Decode(msg.payload));
      const state = JSON.parse(payloadJson) as Record<string, unknown>;

      const gameType = useGameStore.getState().activeGameType;
      if (gameType === 'connect_four') {
        useGameStore.getState().setConnectFourState(state as unknown as ConnectFourState);
      } else if (gameType === 'chain_reaction') {
        useGameStore.getState().setChainReactionState(state as unknown as ChainReactionState);
      } else if (gameType === 'chess') {
        useGameStore.getState().setChessState(state as unknown as ChessState);
      } else if (gameType === 'ludo') {
        // iOS sends LudoBroadcast via sendGameState.
        // LudoBroadcast has { type, timestamp, payload } where payload is base64-encoded inner data.
        // We need to unwrap and dispatch based on broadcast type.
        const incoming = state as Record<string, unknown>;
        if (incoming.type && incoming.payload !== undefined) {
          // This is a LudoBroadcast from iOS
          this.handleLudoBroadcast(incoming);
        } else if (incoming.players) {
          // This is a raw LudoBoardState (from web host or direct state sync)
          useGameStore.getState().setLudoState(this.normalizeLudoState(incoming));
        }
      }
    } catch {
      // Invalid game state
    }
  }

  private handleGameAction(msg: PoolMessage): void {
    try {
      const payloadJson = textDecoder.decode(base64Decode(msg.payload));
      const action = JSON.parse(payloadJson) as Record<string, unknown>;

      const gameType = useGameStore.getState().activeGameType;
      if (gameType === 'connect_four') {
        this.applyConnectFourAction(action as unknown as ConnectFourAction);
      } else if (gameType === 'chain_reaction') {
        this.applyChainReactionAction(action as unknown as ChainReactionAction);
      } else if (gameType === 'chess') {
        this.applyChessAction(action as unknown as ChessAction);
      } else if (gameType === 'ludo') {
        const incoming = action as Record<string, unknown>;
        if (
          typeof incoming.type === 'string' &&
          typeof incoming.playerID === 'string' &&
          typeof incoming.turnNumber === 'number' &&
          typeof incoming.timestamp === 'number'
        ) {
          useGameStore.getState().setLudoAction({
            type: incoming.type as LudoAction['type'],
            playerID: incoming.playerID,
            turnNumber: incoming.turnNumber,
            timestamp: incoming.timestamp,
            ...(typeof incoming.payload === 'string' ? { payload: incoming.payload } : {}),
          });
        } else if (incoming.type && incoming.payload !== undefined && typeof incoming.timestamp === 'number') {
          // Could be a LudoBroadcast routed through game_action
          this.handleLudoBroadcast(incoming);
        }
      }
    } catch {
      // Invalid game action
    }
  }

  /**
   * Normalize a LudoTokenPosition from iOS Swift enum encoding to web format.
   * Swift encodes enums with associated values as: {"board": {"step": 5}}
   * Web expects: { type: "board", step: 5 }
   */
  private normalizeLudoPosition(pos: unknown): LudoTokenPosition {
    if (!pos || typeof pos !== 'object') return { type: 'yard' };
    const obj = pos as Record<string, unknown>;
    // Already in web format
    if (typeof obj.type === 'string') return obj as unknown as LudoTokenPosition;
    // Swift enum format
    if ('yard' in obj) return { type: 'yard' };
    if ('home' in obj) return { type: 'home' };
    if ('board' in obj) {
      const inner = obj.board as Record<string, unknown> | undefined;
      return { type: 'board', step: (inner?.step as number) ?? 0 };
    }
    if ('homeColumn' in obj) {
      const inner = obj.homeColumn as Record<string, unknown> | undefined;
      return { type: 'homeColumn', step: (inner?.step as number) ?? 0 };
    }
    return { type: 'yard' };
  }

  /** Normalize all token positions and token structure in a LudoBoardState from iOS format */
  private normalizeLudoState(state: Record<string, unknown>): LudoBoardState {
    const s = state as unknown as LudoBoardState;
    if (!s.players) return s;
    return {
      ...s,
      players: s.players.map(p => ({
        ...p,
        // iOS LudoPlayer.tokenIndex is computed from id.tokenIndex — normalize
        playerIndex: p.playerIndex ?? (p as unknown as Record<string, unknown>).id as number ?? 0,
        tokens: (p.tokens ?? []).map(t => {
          const raw = t as unknown as Record<string, unknown>;
          // iOS LudoToken has { id: { playerIndex, tokenIndex }, position }
          // Web expects { tokenIndex, position }
          let tokenIndex = t.tokenIndex;
          if (tokenIndex === undefined || tokenIndex === null) {
            const tid = raw.id as Record<string, unknown> | undefined;
            tokenIndex = (tid?.tokenIndex as number) ?? 0;
          }
          return {
            ...t,
            tokenIndex,
            position: this.normalizeLudoPosition(t.position ?? raw.position),
          };
        }),
      })),
    };
  }

  /** Normalize a TokenMovedPayload from iOS */
  private normalizeTokenMovedPayload(payload: Record<string, unknown>): TokenMovedPayload {
    const p = payload as unknown as TokenMovedPayload;
    // iOS also serializes capturedToken as { playerIndex, tokenIndex } nested in LudoTokenID
    let capturedToken = p.capturedToken;
    if (capturedToken && (capturedToken as unknown as Record<string, unknown>).playerIndex === undefined) {
      capturedToken = null;
    }
    return {
      ...p,
      from: this.normalizeLudoPosition(p.from),
      to: this.normalizeLudoPosition(p.to),
      capturedToken,
    };
  }

  private handleLudoBroadcast(broadcast: Record<string, unknown>): void {
    const broadcastType = broadcast.type as string;
    const payloadRaw = broadcast.payload;

    // iOS encodes LudoBroadcast.payload as Swift Data, which serializes as base64 in JSON
    let innerPayload: Record<string, unknown> | null = null;
    if (typeof payloadRaw === 'string') {
      try {
        const decoded = textDecoder.decode(base64Decode(payloadRaw));
        innerPayload = JSON.parse(decoded);
      } catch { /* not base64 or not JSON */ }
    } else if (typeof payloadRaw === 'object' && payloadRaw !== null) {
      // Web host sends payload as direct object
      innerPayload = payloadRaw as Record<string, unknown>;
    }

    const gameStore = useGameStore.getState();

    switch (broadcastType) {
      case 'stateSync':
      case 'gameStarted': {
        // innerPayload is the full LudoBoardState
        if (innerPayload?.players) {
          gameStore.setLudoState(this.normalizeLudoState(innerPayload));
        }
        break;
      }
      case 'diceRolled': {
        // innerPayload is DiceRolledPayload — update lastDiceRoll on current state
        if (innerPayload && gameStore.ludoState) {
          const dp = innerPayload as unknown as DiceRolledPayload;
          gameStore.setLudoState({
            ...gameStore.ludoState,
            lastDiceRoll: dp.rollValue,
          });
        }
        break;
      }
      case 'tokenMoved': {
        // innerPayload is TokenMovedPayload — apply the move to local state
        if (innerPayload && gameStore.ludoState) {
          const mp = this.normalizeTokenMovedPayload(innerPayload);
          const players = gameStore.ludoState.players.map(p => {
            if (p.playerIndex !== mp.playerIndex) {
              // Handle capture — send captured token back to yard
              if (mp.capturedToken && p.playerIndex === mp.capturedToken.playerIndex) {
                return {
                  ...p,
                  tokens: p.tokens.map(t =>
                    t.tokenIndex === mp.capturedToken!.tokenIndex
                      ? { ...t, position: { type: 'yard' as const } }
                      : t
                  ),
                };
              }
              return p;
            }
            return {
              ...p,
              tokens: p.tokens.map(t =>
                t.tokenIndex === mp.tokenIndex
                  ? { ...t, position: mp.to }
                  : t
              ),
            };
          });
          gameStore.setLudoState({
            ...gameStore.ludoState,
            players,
            lastDiceRoll: null,
          });
        }
        break;
      }
      case 'turnChanged': {
        if (innerPayload && gameStore.ludoState) {
          const tc = innerPayload as unknown as TurnChangedPayload;
          gameStore.setLudoState({
            ...gameStore.ludoState,
            currentPlayerIndex: tc.currentPlayerIndex,
            turnNumber: tc.turnNumber,
            lastDiceRoll: null,
            consecutiveSixes: 0,
          });
        }
        break;
      }
      case 'playerFinished': {
        if (innerPayload && gameStore.ludoState) {
          const pf = innerPayload as { playerIndex: number; finishOrder: number[] };
          const players = gameStore.ludoState.players.map(p =>
            p.playerIndex === pf.playerIndex ? { ...p, isFinished: true } : p
          );
          gameStore.setLudoState({
            ...gameStore.ludoState,
            players,
            finishOrder: pf.finishOrder,
          });
        }
        break;
      }
      case 'gameEnded': {
        if (innerPayload && gameStore.ludoState) {
          const ge = innerPayload as { winnerPlayerIndex?: number; winnerTeamIndex?: number; finishOrder: number[] };
          gameStore.setLudoState({
            ...gameStore.ludoState,
            gamePhase: 'finished',
            winnerPlayerIndex: ge.winnerPlayerIndex ?? null,
            winnerTeamIndex: ge.winnerTeamIndex ?? null,
            finishOrder: ge.finishOrder ?? gameStore.ludoState.finishOrder,
          });
        }
        break;
      }
      case 'playerUpdate': {
        if (innerPayload && gameStore.ludoState) {
          const pu = innerPayload as { players?: LudoPlayer[] };
          if (pu.players) {
            gameStore.setLudoState({ ...gameStore.ludoState, players: pu.players });
          }
        }
        break;
      }
      default:
        break;
    }
  }

  private applyConnectFourAction(action: ConnectFourAction): void {
    const currentState = useGameStore.getState().connectFourState;
    if (!currentState) return;

    const cells = currentState.cells.map((c) => ({ ...c }));
    // Find lowest empty cell in column
    const columnCells = cells
      .filter((c) => c.column === action.column)
      .sort((a, b) => b.row - a.row);

    for (const cell of columnCells) {
      if (cell.ownerIndex === null) {
        cell.ownerIndex = action.playerIndex;
        break;
      }
    }

    const nextPlayer = action.playerIndex === 0 ? 1 : 0;
    const { gameOver, winnerIndex, winningCells } = checkConnectFourWin(cells);

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
  }

  private applyChainReactionAction(action: ChainReactionAction): void {
    const currentState = useGameStore.getState().chainReactionState;
    if (!currentState) return;

    const cells = currentState.cells.map((c) => ({ ...c }));
    const targetCell = cells.find((c) => c.id === action.cellID);
    if (!targetCell) return;

    targetCell.orbs += 1;
    targetCell.ownerIndex = action.playerIndex;

    // Process chain reactions
    processChainReactions(cells, 6, 6);

    const playerCount = useGameStore.getState().currentSession?.players.length ?? 2;
    const nextPlayer = (action.playerIndex + 1) % playerCount;
    const { gameOver, winnerIndex } = checkChainReactionWin(cells, currentState.moveCount + 1, playerCount);

    useGameStore.getState().setChainReactionState({
      ...currentState,
      cells,
      currentPlayerIndex: gameOver ? (winnerIndex ?? nextPlayer) : nextPlayer,
      moveCount: currentState.moveCount + 1,
      gameOver,
      winnerIndex,
      timestamp: action.timestamp,
    });
  }

  private applyChessAction(action: ChessAction): void {
    const currentState = useGameStore.getState().chessState;
    if (!currentState) return;

    // Transform from iOS coordinate system (row 0 = white rank 1) to web (row 0 = black rank 8)
    const webFromRow = 7 - action.fromRow;
    const webToRow = 7 - action.toRow;
    const from = webFromRow * 8 + action.fromCol;
    const to = webToRow * 8 + action.toCol;

    const board = [...currentState.board];
    const piece = board[from];
    if (!piece) return;

    const captured = board[to];
    const capturedPieces = {
      ...currentState.capturedPieces,
      white: [...currentState.capturedPieces.white],
      black: [...currentState.capturedPieces.black],
    };
    if (captured) {
      capturedPieces[piece.color === 'white' ? 'black' : 'white'].push(captured.type);
    }

    // En passant capture
    let enPassantSquare: number | null = null;
    if (piece.type === 'pawn' && to === currentState.enPassantSquare) {
      const capturedSq = piece.color === 'white' ? to + 8 : to - 8;
      const epCaptured = board[capturedSq];
      if (epCaptured) {
        capturedPieces[piece.color === 'white' ? 'black' : 'white'].push(epCaptured.type);
      }
      board[capturedSq] = null;
    }

    // Set en passant square for double pawn push
    if (piece.type === 'pawn' && Math.abs(from - to) === 16) {
      enPassantSquare = (from + to) / 2;
    }

    // Promotion
    const promotionType = action.promotionPiece as import('../protocol/messages.ts').ChessPieceType | undefined;
    board[to] = promotionType ? { type: promotionType, color: piece.color } : piece;
    board[from] = null;

    // Castling rook move
    if (piece.type === 'king' && Math.abs((from % 8) - (to % 8)) === 2) {
      if (to === 62) { board[61] = board[63] ?? null; board[63] = null; }
      else if (to === 58) { board[59] = board[56] ?? null; board[56] = null; }
      else if (to === 6) { board[5] = board[7] ?? null; board[7] = null; }
      else if (to === 2) { board[3] = board[0] ?? null; board[0] = null; }
    }

    // Update castling rights
    const cr = { ...currentState.castlingRights };
    if (piece.type === 'king') {
      if (piece.color === 'white') { cr.whiteKingside = false; cr.whiteQueenside = false; }
      else { cr.blackKingside = false; cr.blackQueenside = false; }
    }
    if (piece.type === 'rook') {
      if (from === 63) cr.whiteKingside = false;
      if (from === 56) cr.whiteQueenside = false;
      if (from === 7) cr.blackKingside = false;
      if (from === 0) cr.blackQueenside = false;
    }
    if (to === 63) cr.whiteKingside = false;
    if (to === 56) cr.whiteQueenside = false;
    if (to === 7) cr.blackKingside = false;
    if (to === 0) cr.blackQueenside = false;

    const nextPlayerIndex = action.playerIndex === 0 ? 1 : 0;

    useGameStore.getState().setChessState({
      ...currentState,
      board,
      currentPlayerIndex: nextPlayerIndex,
      moveCount: currentState.moveCount + 1,
      castlingRights: cr,
      enPassantSquare,
      moveHistory: [...currentState.moveHistory, action],
      capturedPieces,
      timestamp: action.timestamp,
    });
  }

  private handleServerError(data: ServerErrorData): void {
    if (data.code === 428) {
      // 428 can mean either "server unclaimed" or "proof-of-work required"
      const powMatch = data.message.match(/^proof-of-work required:\s*(.+)$/);
      if (powMatch?.[1]) {
        // PoW challenge embedded in error message — parse and solve it
        try {
          const challenge = JSON.parse(powMatch[1]) as { challenge: string; difficulty: number; timestamp: number };
          useConnectionStore.getState().setStatus('connecting');
          useConnectionStore.getState().setPowProgress(0);

          // The server sends challenge as base64 — convert to hex for the worker
          const challengeBytes = base64Decode(challenge.challenge);
          const challengeHex = Array.from(challengeBytes).map(b => b.toString(16).padStart(2, '0')).join('');

          solvePowAsync(
            challengeHex,
            challenge.difficulty,
            (nonce) => useConnectionStore.getState().setPowProgress(nonce),
          ).then((result) => {
            // Worker returns hex solution — convert to base64 for the server
            const solutionBytes = new Uint8Array(result.solution.match(/.{2}/g)!.map(b => parseInt(b, 16)));
            this.powSolution = {
              challenge: challenge.challenge,  // original base64 challenge
              solution: base64Encode(solutionBytes),  // base64-encoded 8-byte nonce
            };
            useConnectionStore.getState().setPowProgress(null);
            this.sendJoinRequest();
          }).catch((err) => {
            useConnectionStore.getState().setError(`PoW failed: ${err instanceof Error ? err.message : 'Unknown'}`);
            useConnectionStore.getState().setStatus('failed');
          });
        } catch {
          useConnectionStore.getState().setError('Failed to parse proof-of-work challenge.');
          useConnectionStore.getState().setStatus('failed');
        }
      } else {
        // Server is unclaimed
        useConnectionStore.getState().setError("This server hasn't been set up yet. Ask the server owner to complete setup first.");
        useConnectionStore.getState().setStatus('failed');
      }
    } else if (data.code === 429) {
      useConnectionStore.getState().setError('Rate limited. Please try again later.');
    } else {
      useConnectionStore.getState().setError(`Server error (${data.code}): ${data.message}`);
      if (data.code === 401 || data.code === 403) {
        useConnectionStore.getState().setStatus('failed');
      }
    }
  }

  private handleKicked(data: KickedData): void {
    useConnectionStore.getState().setError(`Kicked: ${data.reason}`);
    useConnectionStore.getState().setStatus('disconnected');
    this.cleanup();
  }

  private handleHeartbeatPong(data: HeartbeatPongData): void {
    // Heartbeat acknowledged by server. Could track latency via data.server_time.
    void data;
  }

  private handleSessionResumed(data: SessionResumedData): void {
    useConnectionStore.getState().setStatus('connected');
    for (const frame of data.missed_messages) {
      this.handleMessage(JSON.stringify(frame));
    }
  }

  private broadcastKeyExchange(): void {
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (!localPeerId) return;

    const payload: KeyExchangePayload = {
      publicKey: getX25519PublicKeyBase64(),
      senderPeerID: localPeerId,
    };
    this.sendPoolMessage('key_exchange', payload, null, true);
  }

  private sendKeyExchangeToPeer(peerId: string): void {
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (!localPeerId) return;

    const payload: KeyExchangePayload = {
      publicKey: getX25519PublicKeyBase64(),
      senderPeerID: localPeerId,
    };
    this.sendPoolMessage('key_exchange', payload, [peerId], true);
  }

  private broadcastProfileUpdate(): void {
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (!localPeerId) return;

    const profile = usePoolStore.getState().userProfile;
    const payload: ProfileUpdatePayload = {
      peerID: localPeerId,
      profile: {
        displayName: profile.displayName,
        avatarEmoji: profile.avatarEmoji,
        avatarColorIndex: profile.avatarColorIndex,
      },
    };
    this.sendPoolMessage('profile_update', payload, null, true);
  }

  private sendProfileUpdateToPeer(peerId: string): void {
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (!localPeerId) return;

    const profile = usePoolStore.getState().userProfile;
    const payload: ProfileUpdatePayload = {
      peerID: localPeerId,
      profile: {
        displayName: profile.displayName,
        avatarEmoji: profile.avatarEmoji,
        avatarColorIndex: profile.avatarColorIndex,
      },
    };
    this.sendPoolMessage('profile_update', payload, [peerId], true);
  }

  private broadcastPeerInfo(): void {
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (!localPeerId) return;

    const profile = usePoolStore.getState().userProfile;
    const payload: PeerInfoPayload = {
      peerID: localPeerId,
      displayName: profile.displayName,
      isHost: false,
      capabilities: ['chat', 'games'],
      profile: {
        displayName: profile.displayName,
        avatarEmoji: profile.avatarEmoji,
        avatarColorIndex: profile.avatarColorIndex,
      },
    };
    this.sendPoolMessage('peer_info', payload, null, true);
  }

  sendPoolMessage(
    type: string,
    payload: unknown,
    targetPeerIds: string[] | null,
    isReliable: boolean,
  ): void {
    const localPeerId = useConnectionStore.getState().localPeerId;
    const profile = usePoolStore.getState().userProfile;
    if (!localPeerId) return;

    const payloadJson = JSON.stringify(payload);
    const payloadBase64 = base64Encode(textEncoder.encode(payloadJson));

    const poolMsg: PoolMessage = {
      id: uuidv4(),
      type: type as PoolMessage['type'],
      senderID: localPeerId,
      senderName: profile.displayName,
      timestamp: Date.now() / 1000 - APPLE_EPOCH_OFFSET,
      payload: payloadBase64,
      isReliable,
    };

    const poolMsgJson = JSON.stringify(poolMsg);
    const dataBase64 = base64Encode(textEncoder.encode(poolMsgJson));

    const seq = this.sequenceNumber++;
    const sessionToken = useConnectionStore.getState().sessionToken;

    const forwardData: Record<string, unknown> = {
      data: dataBase64,
      target_peer_ids: targetPeerIds,
      sequence: seq,
    };
    if (sessionToken) {
      forwardData['session_token'] = sessionToken;
    }

    this.send('forward', forwardData);
  }

  async sendChatMessage(chatMessage: EncryptedChatMessage, targetPeerIds: string[] | null): Promise<void> {
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (!localPeerId) return;

    const isPrivate = targetPeerIds !== null && targetPeerIds.length > 0;

    // Build PrivateChatPayload matching iOS format
    const chatPayload: Record<string, unknown> = {
      messageID: chatMessage.id,
      senderID: chatMessage.senderID,
      senderName: chatMessage.senderName,
      contentType: chatMessage.contentType ?? 'text',
      timestamp: chatMessage.timestamp,
      text: chatMessage.text,
      reactions: chatMessage.reactions ?? {},
      mentions: chatMessage.mentions ?? [],
      isEncrypted: true,
      senderAvatarEmoji: chatMessage.senderAvatarEmoji,
      senderAvatarColorIndex: chatMessage.senderAvatarColorIndex,
    };
    if (chatMessage.imageData !== undefined) chatPayload.imageData = chatMessage.imageData;
    if (chatMessage.voiceData !== undefined) chatPayload.voiceData = chatMessage.voiceData;
    if (chatMessage.voiceDuration !== undefined) chatPayload.voiceDuration = chatMessage.voiceDuration;
    if (chatMessage.emoji !== undefined) chatPayload.emoji = chatMessage.emoji;
    if (chatMessage.pollData !== undefined) chatPayload.pollData = chatMessage.pollData;
    if (chatMessage.replyTo !== undefined) chatPayload.replyTo = chatMessage.replyTo;

    const privateChatPayload = {
      chatPayload,
      isPrivate,
      targetPeerID: isPrivate ? targetPeerIds?.[0] ?? null : null,
    };

    const plaintext = JSON.stringify(privateChatPayload);
    const peers = usePoolStore.getState().peers;
    const peerKeys = useChatStore.getState().peerSymmetricKeys;

    // Encrypt per-peer and send individually (matching iOS behavior)
    const targetPeers = isPrivate && targetPeerIds
      ? peers.filter(p => targetPeerIds.includes(p.peerId))
      : peers.filter(p => p.peerId !== localPeerId);

    for (const peer of targetPeers) {
      const symmetricKey = peerKeys[peer.peerId];
      let encryptedDataStr: string;

      if (symmetricKey) {
        encryptedDataStr = await encryptMessage(plaintext, symmetricKey);
      } else {
        // No key — send base64 encoded plaintext (peer can still read it)
        encryptedDataStr = base64Encode(textEncoder.encode(plaintext));
      }

      const encryptedPayload = {
        messageType: 'chat_message',
        senderPeerID: localPeerId,
        isPrivateChat: isPrivate,
        encryptedData: encryptedDataStr,
        targetPeerID: isPrivate ? peer.peerId : null,
      };

      this.sendPoolMessage('custom', encryptedPayload, [peer.peerId], true);
    }
  }

  async sendPollVote(messageID: string, option: string, voterID: string, targetPeerIds: string[] | null): Promise<void> {
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (!localPeerId) return;

    const pollVotePayload = { messageID, option, voterID };
    const plaintext = JSON.stringify(pollVotePayload);
    const peers = usePoolStore.getState().peers;
    const peerKeys = useChatStore.getState().peerSymmetricKeys;

    const targetPeers = targetPeerIds
      ? peers.filter(p => targetPeerIds.includes(p.peerId))
      : peers.filter(p => p.peerId !== localPeerId);

    for (const peer of targetPeers) {
      const symmetricKey = peerKeys[peer.peerId];
      let encryptedDataStr: string;

      if (symmetricKey) {
        encryptedDataStr = await encryptMessage(plaintext, symmetricKey);
      } else {
        encryptedDataStr = base64Encode(textEncoder.encode(plaintext));
      }

      const encryptedPayload = {
        messageType: 'poll_vote',
        senderPeerID: localPeerId,
        isPrivateChat: targetPeerIds !== null,
        encryptedData: encryptedDataStr,
        targetPeerID: targetPeerIds?.[0] ?? null,
      };

      this.sendPoolMessage('custom', encryptedPayload, [peer.peerId], true);
    }
  }

  async sendReaction(messageID: string, emoji: string, peerID: string, isAdding: boolean, targetPeerIds: string[] | null): Promise<void> {
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (!localPeerId) return;

    const reactionPayload = { messageID, emoji, peerID, isAdding };
    const plaintext = JSON.stringify(reactionPayload);
    const peers = usePoolStore.getState().peers;
    const peerKeys = useChatStore.getState().peerSymmetricKeys;

    const targetPeers = targetPeerIds
      ? peers.filter(p => targetPeerIds.includes(p.peerId))
      : peers.filter(p => p.peerId !== localPeerId);

    for (const peer of targetPeers) {
      const symmetricKey = peerKeys[peer.peerId];
      let encryptedDataStr: string;

      if (symmetricKey) {
        encryptedDataStr = await encryptMessage(plaintext, symmetricKey);
      } else {
        encryptedDataStr = base64Encode(textEncoder.encode(plaintext));
      }

      const encryptedPayload = {
        messageType: 'reaction',
        senderPeerID: localPeerId,
        isPrivateChat: targetPeerIds !== null,
        encryptedData: encryptedDataStr,
        targetPeerID: targetPeerIds?.[0] ?? null,
      };

      this.sendPoolMessage('custom', encryptedPayload, [peer.peerId], true);
    }
  }

  sendGameControl(payload: GameControlPayload, targetPeerIds: string[] | null): void {
    this.sendPoolMessage('game_control', payload, targetPeerIds, true);
  }

  sendGameAction(action: unknown, targetPeerIds: string[] | null): void {
    this.sendPoolMessage('game_action', action, targetPeerIds, true);
  }

  sendGameState(state: unknown, targetPeerIds: string[] | null): void {
    this.sendPoolMessage('game_state', state, targetPeerIds, true);
  }

  updateProfile(): void {
    if (useConnectionStore.getState().status === 'connected') {
      this.broadcastProfileUpdate();
    }
  }

  private send(frameType: string, data: unknown): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    const msg = makeFrame(frameType, data);
    if (msg.length > MAX_MESSAGE_SIZE) return;
    this.ws.send(msg);
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      this.send('heartbeat_ping', { timestamp: Math.floor(Date.now() / 1000) });
    }, HEARTBEAT_INTERVAL_MS);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer !== null) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempt >= MAX_RECONNECT_ATTEMPTS) {
      useConnectionStore.getState().setError('Failed to reconnect after multiple attempts.');
      useConnectionStore.getState().setStatus('failed');
      return;
    }

    if (this.invitation && isInvitationExpired(this.invitation)) {
      useConnectionStore.getState().setError('Invitation expired. Cannot reconnect.');
      useConnectionStore.getState().setStatus('failed');
      return;
    }

    useConnectionStore.getState().setStatus('reconnecting');
    const delay = Math.min(
      INITIAL_RECONNECT_DELAY_MS * Math.pow(2, this.reconnectAttempt),
      MAX_RECONNECT_DELAY_MS,
    );
    this.reconnectAttempt++;

    this.reconnectTimer = setTimeout(() => {
      this.openWebSocket();
    }, delay);
  }

  disconnect(): void {
    useConnectionStore.getState().setStatus('disconnected');
    this.cleanup();
    useConnectionStore.getState().reset();
    usePoolStore.getState().reset();
    useChatStore.getState().reset();
    useGameStore.getState().reset();
    resetEncryptionSession();
  }

  private cleanup(): void {
    this.stopHeartbeat();
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.onerror = null;
      this.ws.onmessage = null;
      this.ws.onopen = null;
      if (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING) {
        this.ws.close();
      }
      this.ws = null;
    }
  }

  // MARK: - Calling

  private ensureCallManager(): CallManager | null {
    if (this.callManager) return this.callManager;
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (!localPeerId) return null;
    const displayName = usePoolStore.getState().userProfile.displayName;
    const delegate: CallManagerDelegate = {
      sendSignal: (signal, peerIDs) => void this.sendCallSignal(signal, peerIDs),
      sendMediaFrame: (frame, peerIDs, reliable) => void this.sendMediaFrame(frame, peerIDs, reliable),
      onStateChange: (call: ActiveCall | null) => useCallStore.getState().setCall(call),
      onError: (msg) => useCallStore.getState().setError(msg),
    };
    this.callManager = new CallManager({ localPeerID: localPeerId, localDisplayName: displayName, delegate });
    return this.callManager;
  }

  /** Public: start an outgoing call from the UI. */
  startCall(args: { peerIDs: string[]; remoteDisplayName: string; isVideoCall: boolean }): void {
    const cm = this.ensureCallManager();
    if (!cm) return;
    cm.startCall(args);
  }

  /** Public: accept the current incoming call. */
  acceptCall(): void {
    this.callManager?.acceptIncoming();
  }

  /** Public: reject the current incoming call. */
  rejectCall(): void {
    this.callManager?.rejectIncoming();
  }

  /** Public: end the active or outgoing call. */
  hangup(): void {
    this.callManager?.endCall('normal');
  }

  /** Public: toggle the local microphone. */
  toggleMute(muted: boolean): void {
    this.callManager?.setAudioMuted(muted);
  }

  /** Public: toggle the local camera. Only meaningful in a video call. */
  toggleCamera(enabled: boolean): void {
    this.callManager?.setVideoEnabled(enabled);
  }

  /** Public: attach a canvas where the peer's decoded video should render. */
  attachRemoteVideoCanvas(peerID: string, canvas: HTMLCanvasElement | null): void {
    this.callManager?.attachRemoteCanvas(peerID, canvas);
  }

  /** Public: stream of the local camera, or null if no video call. */
  getLocalVideoStream(): MediaStream | null {
    return this.callManager?.getLocalVideoStream() ?? null;
  }

  /** Public: cycle the local capture rotation by +90° CW. Returns new value. */
  cycleLocalVideoRotation(): number {
    return this.callManager?.cycleLocalVideoRotation() ?? 0;
  }

  private async sendCallSignal(signal: CallSignal, peerIDs: string[]): Promise<void> {
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (!localPeerId) return;
    const peerKeys = useChatStore.getState().peerSymmetricKeys;
    const plaintext = JSON.stringify(signal);
    const isPrivateChat = peerIDs.length === 1;
    // Mirror iOS `sendEncryptedPayload` (PoolChatViewModel.swift:1852): drop
    // the local peer from the target list — we never hold a key for ourselves.
    const filtered = peerIDs.filter((id) => id !== localPeerId);
    for (const peerID of filtered) {
      const key = peerKeys[peerID];
      if (!key) {
        // Refuse to send call signals unencrypted. iOS rejects unencrypted
        // private payloads; sending plaintext here can silently never reach
        // the peer.
        useCallStore.getState().setError('No encryption key with peer yet — try again in a moment.');
        continue;
      }
      const encryptedDataStr = await encryptMessage(plaintext, key);
      const envelope = {
        messageType: 'call_signal',
        senderPeerID: localPeerId,
        isPrivateChat,
        encryptedData: encryptedDataStr,
        // Match iOS behaviour: only set targetPeerID for private chat.
        targetPeerID: isPrivateChat ? peerID : null,
      };
      this.sendPoolMessage('custom', envelope, [peerID], true);
    }
  }

  private async sendMediaFrame(frame: Uint8Array, peerIDs: string[], reliable: boolean): Promise<void> {
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (!localPeerId) return;
    const peerKeys = useChatStore.getState().peerSymmetricKeys;
    for (const peerID of peerIDs) {
      const key = peerKeys[peerID];
      if (!key) continue; // Refuse to send media to peers without an E2E key.
      // Encrypt RAW bytes — iOS expects the decrypted payload to be the
      // `MediaFrameCodec.pack` byte blob directly, not a base64 of it.
      const encryptedDataStr = await encryptBytes(frame, key);
      const envelope = {
        messageType: 'media_frame',
        senderPeerID: localPeerId,
        isPrivateChat: false,
        encryptedData: encryptedDataStr,
        targetPeerID: peerID,
      };
      this.sendPoolMessage('custom', envelope, [peerID], reliable);
    }
  }

  private async handleIncomingCallSignal(encryptedB64: string, fromPeerId: string): Promise<void> {
    const cm = this.ensureCallManager();
    if (!cm) return;
    const key = useChatStore.getState().peerSymmetricKeys[fromPeerId];
    let plaintext: string | null = null;
    if (key) {
      try { plaintext = await decryptMessage(encryptedB64, key); } catch { /* fall through */ }
    }
    if (plaintext === null) {
      try { plaintext = textDecoder.decode(base64Decode(encryptedB64)); } catch { return; }
    }
    let signal: CallSignal;
    try { signal = JSON.parse(plaintext) as CallSignal; } catch { return; }
    cm.handleSignal(signal, fromPeerId);
  }

  private async handleIncomingMediaFrame(encryptedB64: string, fromPeerId: string): Promise<void> {
    const cm = this.ensureCallManager();
    if (!cm) return;
    const key = useChatStore.getState().peerSymmetricKeys[fromPeerId];
    if (!key) return;
    let bytes: Uint8Array;
    try { bytes = await decryptBytes(encryptedB64, key); } catch { return; }
    cm.handleMediaFrameBytes(bytes, fromPeerId);
  }
}

function checkConnectFourWin(cells: { id: number; row: number; column: number; ownerIndex: number | null }[]): { gameOver: boolean; winnerIndex?: number; winningCells?: number[] } {
  const grid: (number | null)[][] = Array.from({ length: 6 }, () => Array.from({ length: 7 }, () => null));
  const idGrid: number[][] = Array.from({ length: 6 }, () => Array.from({ length: 7 }, () => 0));

  for (const cell of cells) {
    if (grid[cell.row]) {
      grid[cell.row]![cell.column] = cell.ownerIndex;
      idGrid[cell.row]![cell.column] = cell.id;
    }
  }

  const directions = [[0, 1], [1, 0], [1, 1], [1, -1]] as const;

  for (let r = 0; r < 6; r++) {
    for (let c = 0; c < 7; c++) {
      const owner = grid[r]?.[c];
      if (owner === null || owner === undefined) continue;

      for (const [dr, dc] of directions) {
        const winning: number[] = [idGrid[r]![c]!];
        let valid = true;

        for (let k = 1; k < 4; k++) {
          const nr = r + dr * k;
          const nc = c + dc * k;
          if (nr < 0 || nr >= 6 || nc < 0 || nc >= 7 || grid[nr]?.[nc] !== owner) {
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
  if (isFull) {
    return { gameOver: true };
  }

  return { gameOver: false };
}

function getCellCapacity(cellId: number, rows: number, cols: number): number {
  const row = Math.floor(cellId / cols);
  const col = cellId % cols;
  const isCorner = (row === 0 || row === rows - 1) && (col === 0 || col === cols - 1);
  const isEdge = row === 0 || row === rows - 1 || col === 0 || col === cols - 1;
  if (isCorner) return 2;
  if (isEdge) return 3;
  return 4;
}

function getAdjacentCells(cellId: number, rows: number, cols: number): number[] {
  const row = Math.floor(cellId / cols);
  const col = cellId % cols;
  const adjacent: number[] = [];
  if (row > 0) adjacent.push((row - 1) * cols + col);
  if (row < rows - 1) adjacent.push((row + 1) * cols + col);
  if (col > 0) adjacent.push(row * cols + col - 1);
  if (col < cols - 1) adjacent.push(row * cols + col + 1);
  return adjacent;
}

function processChainReactions(cells: { id: number; orbs: number; ownerIndex: number | null }[], rows: number, cols: number): void {
  let hasExplosion = true;
  let iterations = 0;
  const maxIterations = 1000;

  while (hasExplosion && iterations < maxIterations) {
    hasExplosion = false;
    iterations++;

    for (const cell of cells) {
      const capacity = getCellCapacity(cell.id, rows, cols);
      if (cell.orbs >= capacity) {
        hasExplosion = true;
        const owner = cell.ownerIndex;
        cell.orbs -= capacity;
        if (cell.orbs === 0) cell.ownerIndex = null;

        const adjacent = getAdjacentCells(cell.id, rows, cols);
        for (const adjId of adjacent) {
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

function checkChainReactionWin(cells: { id: number; orbs: number; ownerIndex: number | null }[], moveCount: number, playerCount: number): { gameOver: boolean; winnerIndex?: number } {
  // Need at least playerCount moves before win check
  if (moveCount < playerCount * 2) return { gameOver: false };

  const occupiedCells = cells.filter((c) => c.orbs > 0);
  if (occupiedCells.length === 0) return { gameOver: false };

  const owners = new Set(occupiedCells.map((c) => c.ownerIndex));
  if (owners.size === 1) {
    const winner = occupiedCells[0]?.ownerIndex;
    if (winner !== null && winner !== undefined) {
      return { gameOver: true, winnerIndex: winner };
    }
  }

  return { gameOver: false };
}

export const transport = new WebSocketTransport();
