import { v4 as uuidv4 } from 'uuid';
import { makeFrame } from '../protocol/frames.ts';
import type {
  ServerFrame,
  AuthChallengeData,
  JoinRejectedData,
  PeerJoinedData,
  PeerLeftData,
  RelayedData,
  ServerErrorData,
  KickedData,
  HeartbeatPongData,
  ServerHelloData,
  PoolHostStatusData,
} from '../protocol/frames.ts';
import type { PoolMessage, KeyExchangePayload, EncryptedChatMessage, GameControlPayload, ProfileUpdatePayload } from '../protocol/messages.ts';
import {
  classifyAppFrame,
  joinAcceptedMatches,
  parseDecryptedCallSignal,
  parseDecryptedChat,
  parseDecryptedPollVote,
  parseDecryptedReaction,
  parseHistorySync,
  parseJoinAccepted,
  parsePeerInfo,
} from '../protocol/inbound.ts';
import type { GameInvite, InboundAction } from '../protocol/inbound.ts';
import { CALLS_ENABLED, GAMES_ENABLED } from '../protocol/features.ts';
import { buildGameDecline, buildPoolMessage, buildPrivateChatPayload } from '../protocol/chat-wire.ts';
import type { EncryptedChatPayload, EncryptedMessageType } from '../protocol/chat-wire.ts';
import {
  HEARTBEAT_INTERVAL_MS,
  MAX_MESSAGE_SIZE,
} from '../protocol/constants.ts';
import { canAttemptJoin, joinRefusalText, reconnectDelayMs, serverErrorOutcome } from '../protocol/join-policy.ts';
import { shownName } from '../protocol/peer-names.ts';
import { useConnectionStore } from '../stores/connection.ts';
import { usePoolStore } from '../stores/pool.ts';
import { useChatStore } from '../stores/chat.ts';
import type { ChatMessage } from '../stores/chat.ts';
import { useGameStore } from '../stores/game.ts';
import type { ActiveGameType } from '../stores/game.ts';
import { loadOrCreatePoolIdentity, peekPoolIdentityJoined } from '../crypto/identity.ts';
import type { PoolIdentity } from '../crypto/identity.ts';
import { parseInvitationUrl, computeJoinProof, isInvitationExpired, memberRejoinTranscript, relayUrlFromInvitation } from '../crypto/invitation.ts';
import type { ParsedInvitation } from '../crypto/invitation.ts';
import { solvePowAsync } from '../crypto/pow.ts';
import type { PowTask } from '../crypto/pow.ts';
import { ChatEncryption } from '../crypto/encryption.ts';
import type { LocalDeviceSigner } from '../crypto/encryption.ts';
import { assertCryptoSupported, UNSUPPORTED_BROWSER_MESSAGE } from '../crypto/webcrypto.ts';
import { MAX_INBOUND_FRAME_BYTES, MemberTransportSecurity } from './pool-transport-security.ts';
import { base64Encode, base64Decode, base64DecodeStrict } from '../utils/base64.ts';
import { CallManager, type ActiveCall, type CallManagerDelegate } from '../calling/call-manager.ts';
import { appleTimestampNow } from '../calling/types.ts';
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

/** Same bound as the app's `maxPendingMessages`: messages waiting for a peer's key. */
const MAX_PENDING_E2E = 50;

const MAX_UNSENT_FRAMES = 256;

const POW_MAX_DIFFICULTY = 26;
const POW_CHALLENGE_LENGTH = 32;
const POW_TIME_BUDGET_MS = 90_000;

function kickedText(reason: string): string {
  switch (reason) {
    case 'pool closed':
    case 'pool_closed_host_offline':
      return 'The host closed this pool.';
    case 'rejoined_elsewhere':
      return 'You opened this pool in another tab or window, so this one has left it.';
    default:
      return 'The host removed you from this pool.';
  }
}

class WebSocketTransport {
  private ws: WebSocket | null = null;
  private serverUrl: string | null = null;
  private sequenceNumber = 0;
  private invitation: ParsedInvitation | null = null;
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private securityTimer: ReturnType<typeof setInterval> | null = null;
  private powSolution: { challenge: string; solution: string } | null = null;
  private powTask: PowTask | null = null;
  /** Game invitations already answered: the host may say it again. */
  private declinedInvitations = new Set<string>();
  private callManager: CallManager | null = null;
  private identity: PoolIdentity | null = null;
  private e2e: ChatEncryption | null = null;
  private security: MemberTransportSecurity | null = null;
  /** The relay let this identity in on this page. After that, a dropped connection rejoins. */
  private joinedThisSession = false;
  /** The relay has said the pool's host is gone: its return means rejoining (Security.md). */
  private hostWasOffline = false;
  /** Messages waiting for a peer's key. They wait: nothing leaves without E2E. */
  private pendingE2E: { messageType: EncryptedMessageType; plaintext: Uint8Array; isPrivateChat: boolean; peerId: string }[] = [];
  /** People we have already told the user about, so one bad key is one line in the chat. */
  private undecryptableNoticed = new Set<string>();
  private unreadableNoticed = new Set<string>();
  /** One history answer for each time we ask. A sync nobody asked for is ignored, as in the app. */
  private historyAsked = false;
  private historyPending = false;
  /** Sealed frames that came ready while the socket was down. */
  private unsentFrames: { data: Uint8Array; targetPeerIds: string[] | null }[] = [];
  /** Bumped by every connect and disconnect, so a slow step can tell it was overtaken. */
  private generation = 0;

  async connect(invitationUrl: string): Promise<void> {
    this.tearDownSession();
    const generation = ++this.generation;
    const connection = useConnectionStore.getState();

    let invitation: ParsedInvitation;
    try {
      invitation = parseInvitationUrl(invitationUrl);
    } catch (err) {
      this.failWith(err instanceof Error ? err.message : 'This invitation could not be read.');
      return;
    }
    connection.setStatus('connecting');
    try {
      await assertCryptoSupported();
    } catch {
      this.failWith(UNSUPPORTED_BROWSER_MESSAGE);
      return;
    }

    const serverUrl = relayUrlFromInvitation(invitation.serverAddress, import.meta.env.DEV);
    let identity: PoolIdentity;
    let e2e: ChatEncryption;
    try {
      identity = await loadOrCreatePoolIdentity(serverUrl, invitation.poolId);
      e2e = await ChatEncryption.create();
    } catch {
      this.failWith(UNSUPPORTED_BROWSER_MESSAGE);
      return;
    }
    if (generation !== this.generation) return;

    if (!canAttemptJoin({ expired: isInvitationExpired(invitation), joinedBefore: identity.joined })) {
      this.failWith('This invitation has expired. Ask the host for a new one.');
      return;
    }

    // The app keeps the host key from the first join and refuses another: a pool's host can't change.
    if (!identity.hostKeyMatches(invitation.transport.hostIdentityKey)) {
      this.failWith('This invitation names a different host than the one you joined this pool with, so it was refused. Nothing was sent. Ask the host for a new invitation.');
      return;
    }

    this.invitation = invitation;
    this.serverUrl = serverUrl;
    this.identity = identity;
    this.e2e = e2e;
    this.sequenceNumber = 0;
    this.reconnectAttempt = 0;
    this.powSolution = null;
    this.security = this.makeSecurity(invitation, identity);

    connection.setServerUrl(serverUrl);
    this.openWebSocket();
  }

  /** Whether this browser's key was already let in to that link's pool, so an expired link still gets it back. */
  async mayRejoinWith(invitation: ParsedInvitation): Promise<boolean> {
    try {
      return await peekPoolIdentityJoined(relayUrlFromInvitation(invitation.serverAddress, import.meta.env.DEV), invitation.poolId);
    } catch {
      return false;
    }
  }

  private makeSecurity(invitation: ParsedInvitation, identity: PoolIdentity): MemberTransportSecurity {
    return new MemberTransportSecurity({
      poolId: invitation.poolId,
      poolIdBytes: invitation.poolIdBytes,
      localPeerId: identity.peerId,
      identity: { publicKey: identity.publicKey, sign: identity.sign },
      // Its own copy of the invite key, which it clears once the host has enrolled this member.
      invite: { inviteKey: invitation.transport.inviteKey.slice(), hostIdentityKey: invitation.transport.hostIdentityKey },
      enrolled: identity.enrolled,
      onEnrolled: () => void identity.markEnrolled(),
      // Enrolled before or just now, nobody needs the invite key after a grant.
      onGranted: () => invitation.transport.inviteKey.fill(0),
      send: (data, targets) => this.forwardRaw(data, targets),
      deliver: (data, sender) => this.handleAppFrame(data, sender),
      onStatusChange: (status) => useConnectionStore.getState().setSecurity(status),
    });
  }

  private failWith(message: string): void {
    const connection = useConnectionStore.getState();
    connection.setStatus('failed');
    connection.setError(message);
  }

  private openWebSocket(): void {
    if (!this.serverUrl) return;

    // On secure pages, ws:// is blocked by mixed content policy.
    // In dev, route through Vite's WS proxy; in prod, upgrade to wss://.
    // `serverUrl` holds the relay's address only: the invitation's fragment never comes here.
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
      // Refused before parsing. Base64 inside JSON only ever shrinks when decoded, so this holds for the frame too.
      if (typeof event.data === 'string' && event.data.length <= MAX_INBOUND_FRAME_BYTES) {
        this.handleMessage(event.data);
      }
    };

    this.ws.onclose = (event: CloseEvent) => {
      this.stopHeartbeat();
      const connState = useConnectionStore.getState();
      this.stopSecurityTimer();
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
    // A frame from the relay is as untrusted as a peer's: one that fails drops, and nothing else does.
    try {
      const frame = JSON.parse(raw) as ServerFrame | null;
      if (frame && typeof frame === 'object' && frame.data && typeof frame.data === 'object') this.dispatchFrame(frame);
    } catch {
      // Dropped.
    }
  }

  private dispatchFrame(frame: ServerFrame): void {
    switch (frame.frame_type) {
      case 'auth_challenge':
        this.handleAuthChallenge(frame.data as AuthChallengeData);
        break;
      case 'server_hello':
        this.handleServerHello(frame.data as ServerHelloData);
        break;
      case 'join_accepted':
        this.handleJoinAccepted(frame.data);
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
      case 'pool_host_status':
        this.handlePoolHostStatus(frame.data as PoolHostStatusData);
        break;
      default:
        // Includes `session_resumed`: this client never asks to resume, so it can't be an answer.
        break;
    }
  }

  private handleAuthChallenge(data: AuthChallengeData): void {
    useConnectionStore.getState().setAuthNonce(data.nonce);
    if (this.joinedThisSession || this.identity?.joined) {
      void this.sendMemberRejoin();
    } else {
      this.sendJoinRequest();
    }
  }

  private handleServerHello(data: ServerHelloData): void {
    if (data.pow_challenge) this.solvePow(data.pow_challenge);
  }

  /** ProofOfWork in RelayWireCrypto.swift: a relay must not be able to pin a core for ever. */
  private solvePow(challenge: { challenge: string; difficulty: number }): void {
    if (this.powTask) return;
    const challengeBytes = base64DecodeStrict(challenge.challenge);
    if (!challengeBytes || challengeBytes.length !== POW_CHALLENGE_LENGTH || !(challenge.difficulty <= POW_MAX_DIFFICULTY)) {
      this.failWith('The relay server sent a proof-of-work challenge this client refuses. The server may be misconfigured.');
      return;
    }
    const generation = this.generation;
    useConnectionStore.getState().setStatus('connecting');
    useConnectionStore.getState().setPowProgress(0);

    // The worker works in hex; the server speaks base64.
    const challengeHex = Array.from(challengeBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const task = solvePowAsync(
      challengeHex,
      challenge.difficulty,
      (nonce) => useConnectionStore.getState().setPowProgress(nonce),
      POW_TIME_BUDGET_MS,
    );
    this.powTask = task;
    task.result.then((result) => {
      if (generation !== this.generation) return;
      const solutionBytes = new Uint8Array(result.solution.match(/.{2}/g)!.map(b => parseInt(b, 16)));
      this.powSolution = {
        challenge: challenge.challenge,  // original base64 challenge
        solution: base64Encode(solutionBytes),  // base64-encoded 8-byte nonce
      };
      useConnectionStore.getState().setPowProgress(null);
      this.sendJoinRequest();
    }).catch((err) => {
      if (generation !== this.generation) return;
      useConnectionStore.getState().setPowProgress(null);
      this.failWith(`PoW failed: ${err instanceof Error ? err.message : 'Unknown'}`);
    }).finally(() => {
      if (this.powTask === task) this.powTask = null;
    });
  }

  private sendJoinRequest(): void {
    if (!this.invitation || !this.identity || !this.ws || this.ws.readyState !== WebSocket.OPEN) return;

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
      client_public_key: this.identity.peerId,
      display_name: profile.displayName,
      pow_solution: this.powSolution ?? null,
    };

    this.send('join_request', data);
    useConnectionStore.getState().setStatus('waiting_approval');
    useConnectionStore.getState().setKeyHint(this.identity.peerId.slice(0, 8));
  }

  /** The host approved this identity before: the relay lets it back in with a signature. */
  private async sendMemberRejoin(): Promise<void> {
    if (!this.invitation || !this.identity) return;
    const generation = this.generation;
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const signature = await this.identity.sign(memberRejoinTranscript(this.invitation.poolIdBytes, timestamp, nonce));
    if (generation !== this.generation) return;
    this.send('member_rejoin', {
      pool_id: this.invitation.poolId,
      client_public_key: this.identity.peerId,
      timestamp,
      nonce: base64Encode(nonce),
      signature: base64Encode(signature),
      display_name: usePoolStore.getState().userProfile.displayName,
    });
  }

  private handleJoinAccepted(data: unknown): void {
    const { invitation, identity, security } = this;
    if (!invitation || !identity || !security) return;
    const accepted = parseJoinAccepted(data);
    if (!accepted) return;

    // The relay names the host by its identity key, so a relay claiming another host fails here.
    if (!joinAcceptedMatches(accepted, { poolId: invitation.poolId, localPeerId: identity.peerId }) || !security.connected(accepted.pool.hostPeerId)) {
      this.tearDownSession();
      this.failWith("This pool's host could not be verified: the invitation does not match the host on the server. Nothing was sent. Ask the host for a new invitation.");
      return;
    }

    this.joinedThisSession = true;
    this.historyAsked = false;
    this.historyPending = false;
    void identity.markJoined();
    void identity.pinHostKey(invitation.transport.hostIdentityKey);

    useConnectionStore.getState().setJoinAccepted({
      sessionToken: accepted.sessionToken,
      peerId: accepted.peerId,
      poolId: accepted.pool.poolId,
    });
    useConnectionStore.getState().setHostOffline(false);
    useConnectionStore.getState().setSecurity(security.status);
    this.hostWasOffline = false;
    this.startSecurityTimer();

    usePoolStore.getState().setPoolInfo(accepted.pool);
    usePoolStore.getState().setLocalIdentity(accepted.peerId, usePoolStore.getState().userProfile.displayName);
    usePoolStore.getState().setPeers(accepted.peers.map((peer) => ({ ...peer, avatarEmoji: '😀', avatarColorIndex: 0 })));

    // All of this waits inside the security layer until the host has given us the secret.
    this.broadcastKeyExchange();
    this.broadcastProfileUpdate();
    // What waited out a reconnect goes after our key: someone who saw us leave dropped theirs for us.
    void this.keyExchangeTail.then(() => security.settled()).then(() => this.flushUnsentFrames());
  }

  private handleJoinRejected(data: JoinRejectedData): void {
    this.tearDownSession();
    this.resetSessionStores();
    this.failWith(joinRefusalText(data.reason));
  }

  private handlePeerJoined(data: PeerJoinedData): void {
    const parsed = parsePeerInfo(data.peer);
    if (!parsed) return;
    usePoolStore.getState().addPeer({ ...parsed, avatarEmoji: '😀', avatarColorIndex: 0 });

    // Send key exchange to new peer
    this.sendKeyExchangeToPeer(parsed.peerId);
    // Send profile update to new peer
    this.sendProfileUpdateToPeer(parsed.peerId);
  }

  private handlePeerLeft(data: PeerLeftData): void {
    usePoolStore.getState().removePeer(data.peer_id);
    this.e2e?.removePeer(data.peer_id);
    useChatStore.getState().removePeerSymmetricKey(data.peer_id);
    this.pendingE2E = this.pendingE2E.filter((pending) => pending.peerId !== data.peer_id);

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

    if (typeof data.data !== 'string' || typeof data.from_peer_id !== 'string') return;
    const frame = base64DecodeStrict(data.data);
    if (frame) void this.security?.receive(frame, data.from_peer_id);
  }

  /** One app frame, out of the outer layer. `sender` is who the relay says sent it. */
  private async handleAppFrame(data: Uint8Array, sender: string): Promise<void> {
    const action = classifyAppFrame(data, sender, {
      hostPeerId: usePoolStore.getState().poolInfo?.hostPeerId ?? null,
      localPeerId: useConnectionStore.getState().localPeerId,
    });
    if (action) await this.runAction(action, sender);
  }

  private async runAction(action: InboundAction, fromPeerId: string): Promise<void> {
    switch (action.kind) {
      case 'key_exchange':
        await this.handleKeyExchange(action.payload, fromPeerId);
        break;
      case 'profile':
        usePoolStore.getState().updatePeerProfile(action.peerId, action.profile);
        break;
      case 'pool_closed':
        this.leaveWithReason('The host closed this pool.');
        break;
      case 'removed':
        this.leaveWithReason('The host removed you from this pool.');
        break;
      case 'encrypted':
        await this.handleEncrypted(action, fromPeerId);
        break;
      case 'game_invite':
        if (GAMES_ENABLED) return; // Not reachable: games validate invites before they turn on.
        this.declineGameInvite(action.invite, fromPeerId);
        break;
      case 'game_frame':
        if (GAMES_ENABLED) this.handleGameFrame(action.type, action.message as unknown as PoolMessage);
        break;
    }
  }

  /**
   * After the key exchange with the host, so what it sends can be read. ChatHistoryRequestPayload isn't
   * encrypted in the app either: it says nothing, and the frame around it is sealed.
   */
  private requestHistoryFrom(peerId: string): void {
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (this.historyAsked || !localPeerId || peerId !== usePoolStore.getState().poolInfo?.hostPeerId) return;
    this.historyAsked = true;
    this.historyPending = true;
    this.sendPoolMessage('custom', { requestID: uuidv4(), requestingPeerID: localPeerId }, [peerId], true);
  }

  private handleGameFrame(type: string, message: PoolMessage): void {
    if (type === 'game_control') this.handleGameControl(message);
    else if (type === 'game_state') this.handleGameState(message);
    else if (type === 'game_action') this.handleGameAction(message);
  }

  /** So the host isn't left waiting on an answer, and the person here knows why nothing happened. */
  private declineGameInvite(invite: GameInvite, fromPeerId: string): void {
    if (this.declinedInvitations.has(invite.invitationID)) return;
    this.declinedInvitations.add(invite.invitationID);
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (!localPeerId) return;
    this.sendPoolMessage('game_control', buildGameDecline(invite, localPeerId, usePoolStore.getState().userProfile.displayName), [fromPeerId], true);
    this.addSystemNotice(`${this.displayName(fromPeerId)} invited you to a game. Games aren't available on the web yet, so it was declined. Use the StealthOS app to play.`);
  }

  private async handleKeyExchange(payload: KeyExchangePayload, fromPeerId: string): Promise<void> {
    const e2e = this.e2e;
    if (!e2e) return;

    const result = await e2e.acceptKeyExchange(payload, fromPeerId);
    const name = this.displayName(fromPeerId);
    if (result.outcome === 'keyChanged') {
      this.addSystemNotice(`${name}'s security key changed. Compare your security code with them: open your private chat with them and tap the lock.`);
    } else if (result.outcome === 'replayRefused') {
      this.addSystemNotice(`Someone showed an old security key for ${name}. It was refused, and your chat with them is still protected.`);
    }
    if (!result.accepted) return;

    const key = e2e.keyFor(fromPeerId);
    if (key) useChatStore.getState().setPeerSymmetricKey(fromPeerId, key);
    useChatStore.getState().setPeerSecurity(fromPeerId, await e2e.securityInfo(fromPeerId));
    this.requestHistoryFrom(fromPeerId);
    this.undecryptableNoticed.delete(fromPeerId);

    // A peer that started over has lost our key, as a host that restarted has.
    if (result.shouldAnswer) this.sendKeyExchangeToPeer(fromPeerId);
    await this.flushPendingE2E(fromPeerId);
  }

  private leaveWithReason(reason: string): void {
    void this.identity?.forget();
    this.tearDownSession();
    this.resetSessionStores();
    this.failWith(reason);
  }

  private displayName(peerId: string): string {
    const peer = usePoolStore.getState().peers.find((candidate) => candidate.peerId === peerId);
    return peer ? shownName(peer) : 'Someone';
  }

  /** A line in the group chat that nobody sent. */
  private addSystemNotice(text: string): void {
    useChatStore.getState().addGroupMessage({
      id: uuidv4(),
      senderID: 'system',
      senderName: 'StealthOS',
      contentType: 'system',
      timestamp: Date.now(),
      text,
      reactions: {},
      mentions: [],
      isEncrypted: false,
      isPrivate: false,
    });
  }

  private async decryptFrom(combined: Uint8Array, peerId: string): Promise<Uint8Array | null> {
    if (!this.e2e) return null;
    const plaintext = await this.e2e.decrypt(combined, peerId);
    if (!plaintext && !this.undecryptableNoticed.has(peerId)) {
      this.undecryptableNoticed.add(peerId);
      this.addSystemNotice(`A message from ${this.displayName(peerId)} could not be decrypted, so it isn't shown.`);
    }
    return plaintext;
  }

  private async handleEncrypted(action: Extract<InboundAction, { kind: 'encrypted' }>, fromPeerId: string): Promise<void> {
    // Nothing here is ever taken in the clear: what doesn't decrypt under this peer's key doesn't exist.
    switch (action.messageType) {
      case 'chat_message':
        await this.handleEncryptedChat(action.encryptedData, action.timestampMillis, fromPeerId);
        break;
      case 'reaction':
        await this.handleEncryptedReaction(action.encryptedData, fromPeerId);
        break;
      case 'poll_vote':
        await this.handleEncryptedPollVote(action.encryptedData, fromPeerId);
        break;
      case 'call_signal':
        await this.handleIncomingCallSignal(action.encryptedData, fromPeerId);
        break;
      case 'media_frame':
        await this.handleIncomingMediaFrame(action.encryptedData, fromPeerId);
        break;
      case 'history_sync':
        await this.handleHistorySync(action.encryptedData, fromPeerId);
        break;
      default:
        // media_frame_v2 needs per-call keys; clear_history is not handled here.
        break;
    }
  }

  private async handleHistorySync(encryptedData: Uint8Array, fromPeerId: string): Promise<void> {
    // Only this pool's host, and only an answer to our asking.
    if (!this.historyPending || fromPeerId !== usePoolStore.getState().poolInfo?.hostPeerId) return;
    const plaintext = await this.decryptFrom(encryptedData, fromPeerId);
    const history = plaintext && parseHistorySync(plaintext, Date.now());
    if (!history) return;
    this.historyPending = false;
    const localPeerId = useConnectionStore.getState().localPeerId;
    useChatStore.getState().mergeHistory(history.map(({ timestampMillis, ...message }) => ({
      ...message,
      // The host's word on an author makes nothing this person's: their own lines show as anyone's.
      senderID: message.senderID === localPeerId ? 'history' : message.senderID,
      timestamp: timestampMillis,
      isEncrypted: true,
    })));
  }

  private async handleEncryptedChat(encryptedData: Uint8Array, timestamp: number, fromPeerId: string): Promise<void> {
    const plaintext = await this.decryptFrom(encryptedData, fromPeerId);
    if (!plaintext) return;
    const chat = parseDecryptedChat(plaintext);
    if (!chat) {
      if (!this.unreadableNoticed.has(fromPeerId)) {
        this.unreadableNoticed.add(fromPeerId);
        this.addSystemNotice(`A message from ${this.displayName(fromPeerId)} couldn't be read by this page, so it isn't shown.`);
      }
      return;
    }

    if (chat.senderAvatarEmoji !== undefined || chat.senderAvatarColorIndex !== undefined) {
      // Their own word, end to end. A first profile can come before the pool is protected, and is lost.
      usePoolStore.getState().updatePeerAvatar(fromPeerId, chat.senderAvatarEmoji, chat.senderAvatarColorIndex);
    }

    const message: ChatMessage = {
      ...chat,
      senderID: fromPeerId,
      // Who sent it is who the roster says, never what the message says.
      senderName: this.displayName(fromPeerId),
      timestamp,
      isEncrypted: true,
    };

    if (chat.isPrivate) {
      useChatStore.getState().addPrivateMessage(fromPeerId, message);
    } else {
      useChatStore.getState().addGroupMessage(message);
    }
  }

  private async handleEncryptedReaction(encryptedData: Uint8Array, fromPeerId: string): Promise<void> {
    const plaintext = await this.decryptFrom(encryptedData, fromPeerId);
    const reaction = plaintext && parseDecryptedReaction(plaintext);
    if (!reaction) return;
    const chatState = useChatStore.getState();
    const idLower = reaction.messageID.toLowerCase();
    // Who reacted is who the relay says sent this, never what it claims.
    if (chatState.groupMessages.some(m => m.id.toLowerCase() === idLower)) {
      chatState.addReaction(reaction.messageID, reaction.emoji, fromPeerId, true);
      return;
    }
    for (const [peerId, msgs] of Object.entries(chatState.privateMessages)) {
      if (msgs.some(m => m.id.toLowerCase() === idLower)) {
        chatState.addReaction(reaction.messageID, reaction.emoji, fromPeerId, false, peerId);
        return;
      }
    }
  }

  private async handleEncryptedPollVote(encryptedData: Uint8Array, fromPeerId: string): Promise<void> {
    const plaintext = await this.decryptFrom(encryptedData, fromPeerId);
    const vote = plaintext && parseDecryptedPollVote(plaintext);
    if (!vote) return;
    const chatState = useChatStore.getState();
    const idLower = vote.messageID.toLowerCase();
    // Who voted is who the relay says sent this, never what it claims.
    if (chatState.groupMessages.some(m => m.id.toLowerCase() === idLower)) {
      chatState.updatePollVote(vote.messageID, vote.option, fromPeerId, true);
      return;
    }
    for (const [peerId, msgs] of Object.entries(chatState.privateMessages)) {
      if (msgs.some(m => m.id.toLowerCase() === idLower)) {
        chatState.updatePollVote(vote.messageID, vote.option, fromPeerId, false, peerId);
        return;
      }
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
        try {
          this.solvePow(JSON.parse(powMatch[1]) as { challenge: string; difficulty: number });
        } catch {
          this.failWith('Failed to parse proof-of-work challenge.');
        }
      } else {
        this.failWith("This server hasn't been set up yet. Ask the server owner to complete setup first.");
      }
    } else if ((data.code === 403 && data.message === 'not_approved') || (data.code === 404 && data.message === 'pool_not_found')) {
      this.handleRejoinRefused(data.code);
    } else {
      const outcome = serverErrorOutcome(data.code, String(data.message), this.joinedThisSession);
      if (outcome.terminal) {
        this.tearDownSession();
        this.resetSessionStores();
        this.failWith(outcome.text ?? 'The connection to the relay ended.');
      }
    }
  }

  /** The relay no longer takes this identity. The word of the relay, and final (Security.md). */
  private handleRejoinRefused(code: number): void {
    const { identity, invitation, serverUrl } = this;
    const stillInvited = code === 403 && !this.joinedThisSession && invitation && !isInvitationExpired(invitation);
    if (!stillInvited || !invitation || !serverUrl) {
      this.leaveWithReason(code === 404
        ? 'This pool is no longer on the relay. Ask the host for a new invitation.'
        : "The relay no longer has you in this pool: the host removed you, or the relay restarted. Ask the host for a new invitation.");
      return;
    }
    // Someone returning with a live invitation asks the host again, as a new member.
    const generation = this.generation;
    void (async () => {
      await identity?.forget();
      const fresh = await loadOrCreatePoolIdentity(serverUrl, invitation.poolId);
      if (generation !== this.generation) return;
      this.identity = fresh;
      this.security?.destroy();
      this.security = this.makeSecurity(invitation, fresh);
      this.sendJoinRequest();
    })();
  }

  private handleKicked(data: KickedData): void {
    if (data.reason === 'rejoined_elsewhere') {
      // Another tab has this identity now, and it stays a member.
      this.tearDownSession();
      this.resetSessionStores();
      this.failWith(kickedText(data.reason));
      return;
    }
    this.leaveWithReason(kickedText(data.reason));
  }

  private handleHeartbeatPong(data: HeartbeatPongData): void {
    // Heartbeat acknowledged by server. Could track latency via data.server_time.
    void data;
  }

  private handlePoolHostStatus(data: PoolHostStatusData): void {
    if (typeof data.online !== 'boolean') return;
    useConnectionStore.getState().setHostOffline(!data.online);
    if (!data.online) {
      this.hostWasOffline = true;
      return;
    }
    if (!this.hostWasOffline) return;
    // A host that restarted knows nobody, and a relay names people to a host only as they arrive.
    // So arrive again: the ordinary rejoin, with the identity the relay already approved.
    this.hostWasOffline = false;
    if (this.joinedThisSession && useConnectionStore.getState().status === 'connected') {
      this.reconnectAttempt = 0;
      this.closeSocket();
      this.stopHeartbeat();
      this.stopSecurityTimer();
      this.attemptReconnect();
    }
  }

  private deviceSigner(): LocalDeviceSigner | null {
    const identity = this.identity;
    if (!identity) return null;
    return {
      publicKey: identity.device.publicKey(),
      sign: identity.device.sign,
      nextCounter: () => identity.nextContinuityCounter(),
    };
  }

  /** Everything is sent in order by the security layer; what's built here is built in order too. */
  private keyExchangeTail: Promise<void> = Promise.resolve();

  private sendKeyExchange(targets: string[] | null): void {
    const { e2e, invitation, identity } = this;
    if (!e2e || !invitation || !identity) return;
    this.keyExchangeTail = this.keyExchangeTail.then(async () => {
      const payload = await e2e.makeKeyExchange(identity.peerId, invitation.poolIdBytes, this.deviceSigner());
      this.sendPoolMessage('key_exchange', payload, targets, true);
    }).catch(() => {
      // Nothing to send this time. Peers ask again by sending theirs.
    });
  }

  private broadcastKeyExchange(): void {
    this.sendKeyExchange(null);
  }

  private sendKeyExchangeToPeer(peerId: string): void {
    this.sendKeyExchange([peerId]);
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

  sendPoolMessage(
    type: string,
    payload: unknown,
    targetPeerIds: string[] | null,
    isReliable: boolean,
  ): void {
    const localPeerId = useConnectionStore.getState().localPeerId;
    const profile = usePoolStore.getState().userProfile;
    if (!localPeerId) return;

    const poolMsg = buildPoolMessage(uuidv4(), type as PoolMessage['type'], localPeerId, profile.displayName, payload, isReliable);
    // Through the security layer, whatever the type: nothing goes to the relay in the clear.
    void this.security?.sendApp(textEncoder.encode(JSON.stringify(poolMsg)), targetPeerIds);
  }

  /** Hands the relay a frame the security layer has sealed, or one of its own control messages. */
  private forwardRaw(data: Uint8Array, targetPeerIds: string[] | null): void {
    // Sealed already, so it can wait out a reconnect. Receivers drop it after 5 minutes.
    if (useConnectionStore.getState().status !== 'connected' || this.ws?.readyState !== WebSocket.OPEN) {
      this.unsentFrames.push({ data, targetPeerIds });
      if (this.unsentFrames.length > MAX_UNSENT_FRAMES) this.unsentFrames.shift();
      return;
    }
    const seq = this.sequenceNumber++;
    const sessionToken = useConnectionStore.getState().sessionToken;

    const forwardData: Record<string, unknown> = {
      data: base64Encode(data),
      target_peer_ids: targetPeerIds,
      sequence: seq,
    };
    if (sessionToken) {
      forwardData['session_token'] = sessionToken;
    }

    this.send('forward', forwardData);
  }

  private flushUnsentFrames(): void {
    const frames = this.unsentFrames;
    this.unsentFrames = [];
    for (const { data, targetPeerIds } of frames) this.forwardRaw(data, targetPeerIds);
  }

  /** Encrypts for one peer and sends. No key yet: it waits for their key, never goes bare. */
  private async sendEncrypted(
    messageType: EncryptedMessageType,
    plaintext: Uint8Array,
    isPrivateChat: boolean,
    peerId: string,
    isReliable = true,
  ): Promise<void> {
    const localPeerId = useConnectionStore.getState().localPeerId;
    if (!localPeerId || !this.e2e) return;
    const sealed = await this.e2e.encrypt(plaintext, peerId);
    if (!sealed) {
      if (this.pendingE2E.length < MAX_PENDING_E2E) {
        this.pendingE2E.push({ messageType, plaintext, isPrivateChat, peerId });
      } else {
        this.addSystemNotice(`A message to ${this.displayName(peerId)} could not be sent: too many are waiting for their security key.`);
      }
      return;
    }
    const wrapped: EncryptedChatPayload = {
      encryptedData: base64Encode(sealed),
      senderPeerID: localPeerId,
      isPrivateChat,
      targetPeerID: isPrivateChat ? peerId : null,
      messageType,
    };
    this.sendPoolMessage('custom', wrapped, [peerId], isReliable);
  }

  private async flushPendingE2E(peerId: string): Promise<void> {
    const ready = this.pendingE2E.filter((pending) => pending.peerId === peerId);
    if (ready.length === 0) return;
    this.pendingE2E = this.pendingE2E.filter((pending) => pending.peerId !== peerId);
    for (const pending of ready) {
      await this.sendEncrypted(pending.messageType, pending.plaintext, pending.isPrivateChat, pending.peerId);
    }
  }

  private recipients(targetPeerIds: string[] | null): string[] {
    const localPeerId = useConnectionStore.getState().localPeerId;
    const peers = usePoolStore.getState().peers;
    return (targetPeerIds ? peers.filter((p) => targetPeerIds.includes(p.peerId)) : peers)
      .map((p) => p.peerId)
      .filter((id) => id !== localPeerId);
  }

  async sendChatMessage(chatMessage: EncryptedChatMessage, targetPeerIds: string[] | null): Promise<void> {
    const isPrivate = targetPeerIds !== null && targetPeerIds.length > 0;
    const plaintext = textEncoder.encode(JSON.stringify(
      buildPrivateChatPayload(chatMessage, isPrivate, targetPeerIds?.[0] ?? null),
    ));
    // Encrypted per peer and sent individually, as the app does.
    for (const peerId of this.recipients(targetPeerIds)) {
      await this.sendEncrypted('chat_message', plaintext, isPrivate, peerId);
    }
  }

  async sendPollVote(messageID: string, option: string, voterID: string, targetPeerIds: string[] | null): Promise<void> {
    const plaintext = textEncoder.encode(JSON.stringify({ messageID, option, voterID }));
    for (const peerId of this.recipients(targetPeerIds)) {
      await this.sendEncrypted('poll_vote', plaintext, targetPeerIds !== null, peerId);
    }
  }

  async sendReaction(messageID: string, emoji: string, peerID: string, isAdding: boolean, targetPeerIds: string[] | null): Promise<void> {
    const plaintext = textEncoder.encode(JSON.stringify({ messageID, emoji, peerID, isAdding }));
    for (const peerId of this.recipients(targetPeerIds)) {
      await this.sendEncrypted('reaction', plaintext, targetPeerIds !== null, peerId);
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
    if (msg.length > MAX_MESSAGE_SIZE) {
      this.addSystemNotice('That message is too large to send through this relay.');
      return;
    }
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

  private startSecurityTimer(): void {
    this.stopSecurityTimer();
    this.securityTimer = setInterval(() => void this.security?.tick(), 1000);
  }

  private stopSecurityTimer(): void {
    if (this.securityTimer !== null) {
      clearInterval(this.securityTimer);
      this.securityTimer = null;
    }
  }

  private attemptReconnect(): void {
    // An approved member rejoins with its key. The invitation's expiry only binds someone who has
    // not been let in yet.
    if (!this.joinedThisSession && this.invitation && isInvitationExpired(this.invitation)) {
      useConnectionStore.getState().setError('Invitation expired. Cannot reconnect.');
      useConnectionStore.getState().setStatus('failed');
      return;
    }

    useConnectionStore.getState().setStatus('reconnecting');
    const delay = reconnectDelayMs(this.reconnectAttempt);
    this.reconnectAttempt++;

    this.reconnectTimer = setTimeout(() => {
      this.openWebSocket();
    }, delay);
  }

  /** The person chose to leave: nothing about this pool stays, as with the app's Leave Pool. */
  disconnect(): void {
    void this.identity?.forget();
    this.tearDownSession();
    this.resetSessionStores();
  }

  private resetSessionStores(): void {
    usePoolStore.getState().reset();
    useChatStore.getState().reset();
    useGameStore.getState().reset();
  }

  /** Ends the connection and drops every key in memory for it. */
  private tearDownSession(): void {
    this.generation++;
    this.powTask?.cancel();
    this.powTask = null;
    this.stopHeartbeat();
    this.stopSecurityTimer();
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.closeSocket();
    this.security?.destroy();
    this.security = null;
    this.e2e = null;
    this.identity = null;
    this.invitation?.transport.inviteKey.fill(0);
    this.invitation?.tokenSecret.fill(0);
    this.invitation = null;
    this.serverUrl = null;
    this.powSolution = null;
    this.joinedThisSession = false;
    this.hostWasOffline = false;
    this.pendingE2E = [];
    this.unsentFrames = [];
    this.undecryptableNoticed.clear();
    this.unreadableNoticed.clear();
    this.historyAsked = false;
    this.historyPending = false;
    this.declinedInvitations.clear();
    useConnectionStore.getState().reset();
  }

  private closeSocket(): void {
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
    if (!CALLS_ENABLED) return;
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
    const plaintext = textEncoder.encode(JSON.stringify(signal));
    const isPrivateChat = peerIDs.length === 1;
    // Mirror iOS `sendEncryptedPayload`: we never hold a key for ourselves.
    for (const peerID of peerIDs.filter((id) => id !== localPeerId)) {
      await this.sendEncrypted('call_signal', plaintext, isPrivateChat, peerID);
    }
  }

  private async sendMediaFrame(frame: Uint8Array, peerIDs: string[], reliable: boolean): Promise<void> {
    if (!CALLS_ENABLED) return;
    for (const peerID of peerIDs) {
      if (!this.e2e?.keyFor(peerID)) continue; // Refuse to send media to peers without an E2E key.
      // Encrypt RAW bytes: iOS expects the decrypted payload to be the
      // `MediaFrameCodec.pack` byte blob directly, not a base64 of it.
      await this.sendEncrypted('media_frame', frame, false, peerID, reliable);
    }
  }

  private async handleIncomingCallSignal(encrypted: Uint8Array, fromPeerId: string): Promise<void> {
    const plaintext = await this.decryptFrom(encrypted, fromPeerId);
    const signal = plaintext && parseDecryptedCallSignal(plaintext);
    if (!signal) return;

    if (!CALLS_ENABLED) {
      if (signal.signalType !== 'offer') return;
      // Decline so the caller isn't left ringing, and say why here.
      await this.sendCallSignal({
        callID: signal.callID,
        signalType: 'reject',
        callerPeerID: signal.callerPeerID,
        callerDisplayName: signal.callerDisplayName,
        calleePeerIDs: signal.calleePeerIDs,
        isVideoCall: signal.isVideoCall,
        timestamp: appleTimestampNow(),
        mediaControl: null,
      }, [fromPeerId]);
      this.addSystemNotice(`${this.displayName(fromPeerId)} tried to call you. Calls aren't available on the web yet, so the call was declined. Use the StealthOS app for calls.`);
      return;
    }
    this.ensureCallManager()?.handleSignal(signal as unknown as CallSignal, fromPeerId);
  }

  private async handleIncomingMediaFrame(encrypted: Uint8Array, fromPeerId: string): Promise<void> {
    if (!CALLS_ENABLED) return;
    const cm = this.ensureCallManager();
    if (!cm) return;
    const bytes = await this.decryptFrom(encrypted, fromPeerId);
    if (bytes) cm.handleMediaFrameBytes(bytes, fromPeerId);
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
