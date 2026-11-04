// Everything a peer or the relay sends is untrusted, even once it has decrypted: a member holds real
// keys. This is the one place it becomes typed data. Nothing here throws, and nothing that fails a
// check reaches the UI's state. Field shapes follow PoolMessage.swift, RichChatMessage.swift and
// ServerFrame.swift; a field of the wrong type refuses the whole message, as `JSONDecoder` does.

import { base64DecodeStrict } from '../utils/base64.ts';
import { APPLE_EPOCH_OFFSET } from './constants.ts';
import type { KeyExchangePayload } from './messages.ts';
import type { EncryptedMessageType } from './chat-wire.ts';

export const MAX_DISPLAY_NAME = 128;
const MAX_TEXT_CHARS = 200_000;
const MAX_EMOJI_CHARS = 32;
const MAX_POLL_OPTIONS = 32;
const MAX_POLL_TEXT = 1_000;
const MAX_ID_LIST = 256;

const UUID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;
// Control characters and the ones that reorder text, so a name can't overwrite what is around it.
const UNSAFE_NAME_CHARS = /[\p{Cc}‎‏‪-‮⁦-⁩]/gu;
const decoder = new TextDecoder('utf-8', { fatal: true });

type Json = Record<string, unknown>;

function isObject(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(decoder.decode(bytes));
  } catch {
    return undefined;
  }
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

function isBase64(value: unknown): value is string {
  return typeof value === 'string' && value.length % 4 === 0 && BASE64_PATTERN.test(value);
}

function isStringArray(value: unknown, maxLength: number = MAX_ID_LIST): value is string[] {
  return Array.isArray(value) && value.length <= maxLength && value.every((item) => typeof item === 'string');
}

/** Usable as a key of a plain object: not `__proto__`, `constructor` and the like. */
export function isSafeKey(key: string): boolean {
  return !(key in {});
}

function absent(value: unknown): value is undefined | null {
  return value === undefined || value === null;
}

export function sanitizeDisplayName(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const cleaned = value.replace(UNSAFE_NAME_CHARS, '').trim();
  if (cleaned.length === 0) return null;
  return Array.from(cleaned).slice(0, MAX_DISPLAY_NAME).join('');
}

export interface ValidProfile {
  displayName: string;
  avatarEmoji: string;
  avatarColorIndex: number;
}

export function parseProfile(value: unknown): ValidProfile | null {
  if (!isObject(value)) return null;
  const displayName = sanitizeDisplayName(value.displayName);
  const { avatarEmoji, avatarColorIndex } = value;
  if (!displayName || typeof avatarEmoji !== 'string' || avatarEmoji.length > MAX_EMOJI_CHARS) return null;
  if (!Number.isInteger(avatarColorIndex)) return null;
  return { displayName, avatarEmoji, avatarColorIndex: (avatarColorIndex as number) >= 0 && (avatarColorIndex as number) < 8 ? (avatarColorIndex as number) : 0 };
}

// --- Chat, after decryption

export type ChatContentType = 'text' | 'image' | 'voice' | 'emoji' | 'poll';

/** What a peer may send. `system` is not on it: those lines come from this client alone. */
const PEER_CONTENT_TYPES: ReadonlySet<string> = new Set<ChatContentType>(['text', 'image', 'voice', 'emoji', 'poll']);

export interface ValidPoll {
  question: string;
  options: string[];
  votes: Record<string, string[]>;
  allowVoteChange: boolean;
}

export interface ValidChat {
  id: string;
  contentType: ChatContentType;
  isPrivate: boolean;
  text?: string;
  imageData?: string;
  voiceData?: string;
  voiceDuration?: number;
  emoji?: string;
  pollData?: ValidPoll;
  reactions: Record<string, string[]>;
  replyTo?: { messageID: string; senderName: string; previewText: string };
  mentions: string[];
  senderAvatarEmoji?: string;
  senderAvatarColorIndex?: number;
}

function parseIdMap(value: unknown): Record<string, string[]> | null {
  if (absent(value)) return {};
  if (!isObject(value)) return null;
  const entries = Object.entries(value);
  if (entries.length > MAX_ID_LIST) return null;
  const out: [string, string[]][] = [];
  for (const [key, ids] of entries) {
    if (!isSafeKey(key) || key.length > MAX_POLL_TEXT || !isStringArray(ids)) return null;
    out.push([key, ids]);
  }
  return Object.fromEntries(out);
}

function parsePoll(value: unknown): ValidPoll | null {
  if (!isObject(value)) return null;
  const { question, options, allowVoteChange } = value;
  if (typeof question !== 'string' || question.length > MAX_POLL_TEXT) return null;
  if (!isStringArray(options, MAX_POLL_OPTIONS) || !options.every((option) => option.length <= MAX_POLL_TEXT && isSafeKey(option))) return null;
  if (!absent(allowVoteChange) && typeof allowVoteChange !== 'boolean') return null;
  const votes = parseIdMap(value.votes);
  if (!votes) return null;
  return { question, options, votes, allowVoteChange: allowVoteChange ?? true };
}

/** A decrypted `chat_message`: PrivateChatPayload, or a bare RichChatPayload. `null` if anything is off. */
export function parseDecryptedChat(plaintext: Uint8Array): ValidChat | null {
  const parsed = parseJson(plaintext);
  if (!isObject(parsed)) return null;
  const wrapped = isObject(parsed.chatPayload);
  const chat = wrapped ? (parsed.chatPayload as Json) : parsed;
  if (wrapped && !absent(parsed.isPrivate) && typeof parsed.isPrivate !== 'boolean') return null;
  return validateChat(chat, wrapped && parsed.isPrivate === true, false);
}

const MAX_HISTORY_MESSAGES = 1000;

export interface ValidHistoryMessage extends ValidChat {
  senderID: string;
  senderName: string;
  timestampMillis: number;
}

/**
 * A decrypted `history_sync`: ChatHistorySyncPayload. A sync carries no media, so a photo or voice note
 * comes as its type alone and is shown as not available, and whatever media a sender attached anyway is
 * dropped. Nothing has happened yet, whatever it says, and nobody posts as the app. All of it is only as
 * good as the host, which is the only one a caller may take this from. `null` if it isn't a group sync.
 */
export function parseHistorySync(plaintext: Uint8Array, nowMillis: number): ValidHistoryMessage[] | null {
  const parsed = parseJson(plaintext);
  if (!isObject(parsed) || parsed.isGroupChat !== true || !Array.isArray(parsed.messages)) return null;
  const out: ValidHistoryMessage[] = [];
  for (const entry of parsed.messages.slice(0, MAX_HISTORY_MESSAGES)) {
    if (!isObject(entry) || typeof entry.senderID !== 'string') continue;
    const chat = validateChat({ ...entry, imageData: undefined, voiceData: undefined }, false, true);
    if (!chat) continue;
    out.push({
      ...chat,
      senderID: entry.senderID,
      senderName: sanitizeDisplayName(entry.senderName) ?? 'Someone',
      timestampMillis: Math.min(timestampMillis(entry.timestamp), nowMillis),
    });
  }
  return out;
}

function validateChat(chat: Json, isPrivate: boolean, mediaMayBeMissing: boolean): ValidChat | null {
  const id = chat.messageID ?? chat.id;
  const { contentType, text, imageData, voiceData, voiceDuration, emoji, senderAvatarEmoji, senderAvatarColorIndex } = chat;
  if (!isUuid(id)) return null;
  if (typeof contentType !== 'string' || !PEER_CONTENT_TYPES.has(contentType)) return null;
  if (!absent(text) && typeof text !== 'string') return null;
  if (!absent(imageData) && !isBase64(imageData)) return null;
  if (!absent(voiceData) && !isBase64(voiceData)) return null;
  if (!absent(voiceDuration) && !(typeof voiceDuration === 'number' && Number.isFinite(voiceDuration) && voiceDuration >= 0)) return null;
  if (!absent(emoji) && !(typeof emoji === 'string' && emoji.length <= MAX_EMOJI_CHARS)) return null;
  if (!absent(senderAvatarEmoji) && !(typeof senderAvatarEmoji === 'string' && senderAvatarEmoji.length <= MAX_EMOJI_CHARS)) return null;
  if (!absent(senderAvatarColorIndex) && !Number.isInteger(senderAvatarColorIndex)) return null;

  const reactions = parseIdMap(chat.reactions);
  if (!reactions) return null;
  const mentions = absent(chat.mentions) ? [] : chat.mentions;
  if (!isStringArray(mentions)) return null;

  const pollData = absent(chat.pollData) ? undefined : parsePoll(chat.pollData);
  if (pollData === null) return null;

  let replyTo: ValidChat['replyTo'];
  if (!absent(chat.replyTo)) {
    const reply = chat.replyTo;
    if (!isObject(reply) || !isUuid(reply.messageID) || typeof reply.senderName !== 'string' || typeof reply.previewText !== 'string') return null;
    replyTo = {
      messageID: reply.messageID,
      senderName: sanitizeDisplayName(reply.senderName) ?? 'Someone',
      previewText: reply.previewText.slice(0, MAX_POLL_TEXT),
    };
  }

  // The content has to be what the type says it is.
  if (contentType === 'text' && typeof text !== 'string') return null;
  if (contentType === 'image' && typeof imageData !== 'string' && !mediaMayBeMissing) return null;
  if (contentType === 'voice' && typeof voiceData !== 'string' && !mediaMayBeMissing) return null;
  if (contentType === 'emoji' && typeof emoji !== 'string') return null;
  if (contentType === 'poll' && !pollData) return null;

  return {
    id,
    contentType: contentType as ChatContentType,
    isPrivate,
    text: typeof text === 'string' ? text.slice(0, MAX_TEXT_CHARS) : undefined,
    imageData: imageData as string | undefined ?? undefined,
    voiceData: voiceData as string | undefined ?? undefined,
    voiceDuration: voiceDuration as number | undefined ?? undefined,
    emoji: emoji as string | undefined ?? undefined,
    pollData,
    reactions,
    replyTo,
    mentions,
    senderAvatarEmoji: senderAvatarEmoji as string | undefined ?? undefined,
    senderAvatarColorIndex: senderAvatarColorIndex as number | undefined ?? undefined,
  };
}

export interface ValidReaction {
  messageID: string;
  emoji: string;
  isAdding: boolean;
}

export function parseDecryptedReaction(plaintext: Uint8Array): ValidReaction | null {
  const parsed = parseJson(plaintext);
  if (!isObject(parsed) || !isUuid(parsed.messageID)) return null;
  const { emoji, isAdding } = parsed;
  if (typeof emoji !== 'string' || emoji.length === 0 || emoji.length > MAX_EMOJI_CHARS || !isSafeKey(emoji) || typeof isAdding !== 'boolean') return null;
  return { messageID: parsed.messageID, emoji, isAdding };
}

export interface ValidPollVote {
  messageID: string;
  option: string;
}

export function parseDecryptedPollVote(plaintext: Uint8Array): ValidPollVote | null {
  const parsed = parseJson(plaintext);
  if (!isObject(parsed) || !isUuid(parsed.messageID)) return null;
  const { option } = parsed;
  if (typeof option !== 'string' || option.length > MAX_POLL_TEXT || !isSafeKey(option)) return null;
  return { messageID: parsed.messageID, option };
}

export interface ValidCallSignal {
  callID: string;
  signalType: string;
  callerPeerID: string;
  callerDisplayName: string;
  calleePeerIDs: string[];
  isVideoCall: boolean;
}

export function parseDecryptedCallSignal(plaintext: Uint8Array): ValidCallSignal | null {
  const parsed = parseJson(plaintext);
  if (!isObject(parsed) || !isUuid(parsed.callID)) return null;
  const { signalType, callerPeerID, callerDisplayName, calleePeerIDs, isVideoCall } = parsed;
  if (typeof signalType !== 'string' || typeof callerPeerID !== 'string' || typeof callerDisplayName !== 'string') return null;
  if (!isStringArray(calleePeerIDs) || typeof isVideoCall !== 'boolean') return null;
  return { callID: parsed.callID, signalType, callerPeerID, callerDisplayName, calleePeerIDs, isVideoCall };
}

// --- A pool message, out of the outer layer

export interface PeerContext {
  /** Who the relay says the pool's host is. */
  hostPeerId: string | null;
  localPeerId: string | null;
}

export interface GameInvite {
  invitationID: string;
  gameType: string;
  sessionID: string;
}

export type InboundAction =
  | { kind: 'key_exchange'; payload: KeyExchangePayload }
  | { kind: 'profile'; peerId: string; profile: ValidProfile }
  | { kind: 'pool_closed' }
  | { kind: 'removed' }
  | { kind: 'encrypted'; messageType: EncryptedMessageType; encryptedData: Uint8Array; timestampMillis: number; messageId: string }
  | { kind: 'game_invite'; invite: GameInvite }
  | { kind: 'game_frame'; type: string; message: Json };

const ENCRYPTED_TYPES: ReadonlySet<string> = new Set<EncryptedMessageType>([
  'chat_message', 'reaction', 'poll_vote', 'history_sync', 'clear_history', 'call_signal', 'media_frame', 'media_frame_v2',
]);

function payloadObject(message: Json): Json | null {
  if (typeof message.payload !== 'string') return null;
  const bytes = base64DecodeStrict(message.payload);
  if (!bytes) return null;
  const parsed = parseJson(bytes);
  return isObject(parsed) ? parsed : null;
}

function classifyGameControl(message: Json, payload: Json, sender: string, context: PeerContext): InboundAction | null {
  if (payload.controlType !== 'invite') return { kind: 'game_frame', type: 'game_control', message };
  if (typeof payload.gameType !== 'string' || !/^[a-z_]{1,32}$/.test(payload.gameType)) return null;
  if (typeof payload.data !== 'string') return null;
  const inner = base64DecodeStrict(payload.data);
  const invitation = inner && parseJson(inner);
  if (!isObject(invitation) || !isUuid(invitation.invitationID) || !isUuid(invitation.sessionID)) return null;
  // An invitation speaks for its sender, and only to whom it names.
  if (invitation.hostPeerID !== sender) return null;
  if (!absent(invitation.targetPeerID) && invitation.targetPeerID !== context.localPeerId) return null;
  return { kind: 'game_invite', invite: { invitationID: invitation.invitationID, gameType: payload.gameType, sessionID: invitation.sessionID } };
}

/**
 * One app frame. `sender` is who the relay says sent it, which the outer layer's AAD has already
 * held the frame to. There are no mesh hops on a relay, so a message naming anyone else is a lie.
 * `null` means drop it.
 */
export function classifyAppFrame(data: Uint8Array, sender: string, context: PeerContext): InboundAction | null {
  const message = parseJson(data);
  if (!isObject(message) || typeof message.type !== 'string' || message.senderID !== sender) return null;
  const fromHost = context.hostPeerId !== null && sender === context.hostPeerId;

  switch (message.type) {
    case 'key_exchange': {
      const payload = payloadObject(message);
      // A key exchange speaks for its sender alone.
      if (!payload || payload.senderPeerID !== sender || typeof payload.publicKey !== 'string') return null;
      return { kind: 'key_exchange', payload: payload as unknown as KeyExchangePayload };
    }
    case 'profile_update': {
      const payload = payloadObject(message);
      // Only from its owner, as ConnectionPoolManager.injectReceivedMessage requires.
      if (!payload || payload.peerID !== sender) return null;
      const profile = parseProfile(payload.profile);
      return profile ? { kind: 'profile', peerId: sender, profile } : null;
    }
    case 'peer_info': {
      // A roster entry counts only if the relay says the host sent it.
      if (!fromHost) return null;
      const payload = payloadObject(message);
      if (!payload || typeof payload.peerID !== 'string') return null;
      const profile = parseProfile(payload.profile);
      return profile ? { kind: 'profile', peerId: payload.peerID, profile } : null;
    }
    case 'system': {
      // A removal or pool close counts only if the relay says the host sent it.
      if (!fromHost) return null;
      const payload = payloadObject(message);
      if (!payload) return null;
      if (payload.event === 'pool_closed') return { kind: 'pool_closed' };
      if (payload.event === 'removed_from_pool' && context.localPeerId !== null && payload.targetPeerID === context.localPeerId) return { kind: 'removed' };
      return null;
    }
    case 'custom': {
      const payload = payloadObject(message);
      if (!payload || payload.senderPeerID !== sender || typeof payload.encryptedData !== 'string') return null;
      if (typeof payload.messageType !== 'string' || !ENCRYPTED_TYPES.has(payload.messageType)) return null;
      const encryptedData = base64DecodeStrict(payload.encryptedData);
      if (!encryptedData) return null;
      return {
        kind: 'encrypted',
        messageType: payload.messageType as EncryptedMessageType,
        encryptedData,
        timestampMillis: timestampMillis(message.timestamp),
        messageId: typeof message.id === 'string' ? message.id : '',
      };
    }
    case 'game_control': {
      const payload = payloadObject(message);
      return payload ? classifyGameControl(message, payload, sender, context) : null;
    }
    case 'game_state':
    case 'game_action':
      return { kind: 'game_frame', type: message.type, message };
    default:
      // Includes `chat`: Pool Chat refuses unencrypted chat, and so does this client.
      return null;
  }
}

/** A `Date` on the wire: seconds since 2001. Anything else is now. */
function timestampMillis(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return Date.now();
  const millis = (value + APPLE_EPOCH_OFFSET) * 1000;
  return Math.abs(millis) <= 8.64e15 ? millis : Date.now();
}

// --- What the relay says

export interface ValidPeer {
  peerId: string;
  displayName: string;
  publicKey: string;
  connectedAt: number;
}

export function parsePeerInfo(value: unknown): ValidPeer | null {
  if (!isObject(value) || typeof value.peer_id !== 'string') return null;
  return {
    peerId: value.peer_id,
    displayName: sanitizeDisplayName(value.display_name) ?? 'Someone',
    publicKey: typeof value.public_key === 'string' ? value.public_key : '',
    connectedAt: typeof value.connected_at === 'number' ? value.connected_at : 0,
  };
}

export interface ValidJoinAccepted {
  sessionToken: string;
  peerId: string;
  peers: ValidPeer[];
  pool: { poolId: string; name: string; hostPeerId: string; maxPeers: number; currentPeers: number };
}

export function parseJoinAccepted(value: unknown): ValidJoinAccepted | null {
  if (!isObject(value) || typeof value.session_token !== 'string' || typeof value.peer_id !== 'string') return null;
  if (!Array.isArray(value.peers) || !isObject(value.pool_info)) return null;
  const info = value.pool_info;
  if (typeof info.pool_id !== 'string' || typeof info.host_peer_id !== 'string') return null;
  const peers: ValidPeer[] = [];
  for (const entry of value.peers) {
    const peer = parsePeerInfo(entry);
    if (peer) peers.push(peer);
  }
  return {
    sessionToken: value.session_token,
    peerId: value.peer_id,
    peers,
    pool: {
      poolId: info.pool_id,
      name: sanitizeDisplayName(info.name) ?? 'Pool',
      hostPeerId: info.host_peer_id,
      maxPeers: typeof info.max_peers === 'number' ? info.max_peers : 0,
      currentPeers: typeof info.current_peers === 'number' ? info.current_peers : 0,
    },
  };
}

/** The relay's word held against the invitation and our own key, before anything is sent or believed. */
export function joinAcceptedMatches(accepted: ValidJoinAccepted, expected: { poolId: string; localPeerId: string }): boolean {
  return accepted.pool.poolId.toLowerCase() === expected.poolId.toLowerCase() && accepted.peerId === expected.localPeerId;
}
