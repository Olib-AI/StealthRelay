// What a peer or the relay can put in front of the UI, and who may say what. Everything that reaches
// the stores goes through src/protocol/inbound.ts, which must never throw.
import test from 'node:test';
import assert from 'node:assert/strict';
import { V } from './helpers.ts';
import { base64Encode } from '../src/utils/base64.ts';
import {
  classifyAppFrame,
  isSafeKey,
  joinAcceptedMatches,
  parseDecryptedCallSignal,
  parseDecryptedChat,
  parseDecryptedPollVote,
  parseDecryptedReaction,
  parseJoinAccepted,
  parsePeerInfo,
  parseProfile,
  sanitizeDisplayName,
} from '../src/protocol/inbound.ts';
import type { PeerContext } from '../src/protocol/inbound.ts';
import { capMessages, MAX_CHAT_BYTES, MAX_MESSAGES_PER_CHAT, useChatStore } from '../src/stores/chat.ts';
import type { ChatMessage } from '../src/stores/chat.ts';

const utf8 = (text: string) => new TextEncoder().encode(text);
const ID = '6ba7b810-9dad-41d1-80b4-00c04fd430c8';
const HOST = 'host-peer';
const ME = 'me-peer';
const OTHER = 'other-peer';
const context: PeerContext = { hostPeerId: HOST, localPeerId: ME };

function chat(extra: Record<string, unknown>): Uint8Array {
  return utf8(JSON.stringify({ chatPayload: { messageID: ID, contentType: 'text', text: 'hi', reactions: {}, mentions: [], ...extra }, isPrivate: false }));
}

function message(type: string, sender: string, payload: unknown, extra: Record<string, unknown> = {}): Uint8Array {
  return utf8(JSON.stringify({ id: ID, type, senderID: sender, senderName: 'x', timestamp: 815000000, payload: base64Encode(utf8(JSON.stringify(payload))), isReliable: true, ...extra }));
}

test('a good message passes, as a control for the refusals below', () => {
  const parsed = parseDecryptedChat(chat({}))!;
  assert.equal(parsed.text, 'hi');
  assert.equal(parsed.id, ID);
  assert.equal(parsed.isPrivate, false);
});

test('fields of the wrong type refuse the message: the page-blanking payloads', () => {
  const bad: Record<string, unknown>[] = [
    { text: {} },
    { text: 5 },
    { messageID: 7 },
    { messageID: 'not-a-uuid' },
    { messageID: undefined, id: {} },
    { contentType: 'image', imageData: 1 },
    { contentType: 'image', imageData: 'not base64!' },
    { contentType: 'image', imageData: null },
    { contentType: 'voice', voiceData: {} },
    { contentType: 'voice', voiceData: 'AAAA', voiceDuration: 'long' },
    { contentType: 'voice', voiceData: 'AAAA', voiceDuration: -1 },
    { contentType: 'emoji', emoji: {} },
    { contentType: 'emoji', emoji: 'x'.repeat(33) },
    { contentType: 'poll', pollData: { question: 'q', options: 'not-an-array', votes: {}, allowVoteChange: true } },
    { contentType: 'poll', pollData: { question: {}, options: [], votes: {} } },
    { contentType: 'poll', pollData: { question: 'q', options: [1], votes: {} } },
    { contentType: 'poll', pollData: { question: 'q', options: ['constructor'], votes: {} } },
    { contentType: 'poll', pollData: { question: 'q', options: ['a'], votes: { a: 'x' } } },
    { contentType: 'poll', pollData: { question: 'q', options: ['a'], votes: {}, allowVoteChange: 1 } },
    { contentType: 'poll', pollData: null },
    { reactions: 5 },
    { reactions: { x: 'y' } },
    { reactions: { x: [1] } },
    { mentions: 'x' },
    { mentions: [1] },
    { replyTo: 'x' },
    { replyTo: { messageID: 1, senderName: 'a', previewText: 'b' } },
    { replyTo: { messageID: ID, senderName: {}, previewText: 'b' } },
    { senderAvatarEmoji: {} },
    { senderAvatarColorIndex: 'x' },
    { contentType: {} },
    { contentType: 'image', imageData: 'AAAA', text: {} },
  ];
  for (const extra of bad) {
    assert.equal(parseDecryptedChat(chat(extra)), null, JSON.stringify(extra));
  }
  for (const junk of ['null', '[]', '1', '"x"', '{', '', '{"chatPayload":5}']) {
    assert.equal(parseDecryptedChat(utf8(junk)), null, junk);
  }
  assert.equal(parseDecryptedChat(new Uint8Array([0xff, 0xfe])), null, 'not UTF-8');
  assert.equal(parseDecryptedChat(utf8(JSON.stringify({ chatPayload: { messageID: ID, contentType: 'text', text: 'x' }, isPrivate: 'yes' }))), null);
});

test('a peer can\'t send a system line, or any type not on the list', () => {
  for (const contentType of ['system', 'SYSTEM', 'html', '', 'toString']) {
    assert.equal(parseDecryptedChat(chat({ contentType })), null, contentType);
  }
  assert.equal(parseDecryptedChat(chat({ contentType: undefined })), null, 'the type is required');
});

test('content has to be what the type says', () => {
  assert.equal(parseDecryptedChat(chat({ text: undefined })), null);
  assert.equal(parseDecryptedChat(chat({ contentType: 'image', text: undefined })), null);
  assert.equal(parseDecryptedChat(chat({ contentType: 'voice', text: undefined })), null);
  assert.equal(parseDecryptedChat(chat({ contentType: 'emoji', text: undefined })), null);
  assert.equal(parseDecryptedChat(chat({ contentType: 'poll', text: undefined })), null);
});

test('object keys that would reach Object.prototype are refused', () => {
  assert.equal(isSafeKey('__proto__'), false);
  assert.equal(isSafeKey('constructor'), false);
  assert.equal(isSafeKey('👍'), true);
  assert.equal(parseDecryptedChat(utf8(`{"chatPayload":{"messageID":"${ID}","contentType":"text","text":"x","reactions":{"__proto__":["a"]}}}`)), null);
  assert.equal(parseDecryptedChat(chat({ reactions: { constructor: ['a'] } })), null);
  assert.equal(parseDecryptedReaction(utf8(JSON.stringify({ messageID: ID, emoji: 'constructor', isAdding: true }))), null);
  assert.equal(parseDecryptedPollVote(utf8(JSON.stringify({ messageID: ID, option: '__proto__' }))), null);
});

test('reactions, votes and call signals are held to their shapes', () => {
  assert.equal(parseDecryptedReaction(utf8(JSON.stringify({ messageID: 7, emoji: 'x', isAdding: true }))), null);
  assert.equal(parseDecryptedReaction(utf8(JSON.stringify({ messageID: ID, emoji: {}, isAdding: true }))), null);
  assert.equal(parseDecryptedReaction(utf8(JSON.stringify({ messageID: ID, emoji: '', isAdding: true }))), null);
  assert.equal(parseDecryptedReaction(utf8(JSON.stringify({ messageID: ID, emoji: 'x', isAdding: 1 }))), null);
  assert.equal(parseDecryptedPollVote(utf8(JSON.stringify({ messageID: 7, option: 'a' }))), null);
  assert.equal(parseDecryptedPollVote(utf8(JSON.stringify({ messageID: ID, option: {} }))), null);
  assert.equal(parseDecryptedCallSignal(utf8('null')), null);
  assert.equal(parseDecryptedCallSignal(utf8(JSON.stringify({ callID: 1 }))), null);
  assert.equal(parseDecryptedCallSignal(utf8(JSON.stringify({ callID: ID, signalType: 'offer', callerPeerID: 'a', callerDisplayName: {}, calleePeerIDs: [], isVideoCall: false }))), null);
});

test('names and profiles', () => {
  assert.equal(sanitizeDisplayName({}), null);
  assert.equal(sanitizeDisplayName('   '), null);
  assert.equal(sanitizeDisplayName('a‮b\nc\u0000'), 'abc');
  assert.equal(sanitizeDisplayName('x'.repeat(100))?.length, 64);
  assert.equal(parseProfile({ displayName: {}, avatarEmoji: 'x', avatarColorIndex: 0 }), null);
  assert.equal(parseProfile({ displayName: 'a', avatarEmoji: 5, avatarColorIndex: 0 }), null);
  assert.equal(parseProfile({ displayName: 'a', avatarEmoji: 'x', avatarColorIndex: 'x' }), null);
  assert.equal(parseProfile({ displayName: 'a', avatarEmoji: 'x', avatarColorIndex: 1.5 }), null);
  assert.equal(parseProfile(null), null);
  assert.equal(parseProfile({ displayName: 'a', avatarEmoji: 'x', avatarColorIndex: 99 })?.avatarColorIndex, 0);
  assert.deepEqual(parseProfile({ displayName: 'a', avatarEmoji: 'x', avatarColorIndex: 2 }), { displayName: 'a', avatarEmoji: 'x', avatarColorIndex: 2 });
});

test('a message naming another sender is dropped, whatever its type', () => {
  for (const type of ['key_exchange', 'profile_update', 'custom', 'peer_info', 'system', 'game_control', 'game_state', 'game_action']) {
    assert.equal(classifyAppFrame(message(type, OTHER, { senderPeerID: HOST, peerID: HOST, publicKey: 'AAAA' }), HOST, context), null, type);
  }
});

test('a key exchange speaks for its sender alone', () => {
  const good = { publicKey: 'AAAA', senderPeerID: OTHER };
  assert.equal(classifyAppFrame(message('key_exchange', OTHER, good), OTHER, context)?.kind, 'key_exchange');
  assert.equal(classifyAppFrame(message('key_exchange', OTHER, { ...good, senderPeerID: HOST }), OTHER, context), null);
  assert.equal(classifyAppFrame(message('key_exchange', OTHER, { senderPeerID: OTHER, publicKey: 5 }), OTHER, context), null);
});

test('a profile comes from its owner only, and is validated', () => {
  const profile = { displayName: 'A', avatarEmoji: 'x', avatarColorIndex: 1 };
  assert.deepEqual(classifyAppFrame(message('profile_update', OTHER, { peerID: OTHER, profile }), OTHER, context), { kind: 'profile', peerId: OTHER, profile });
  assert.equal(classifyAppFrame(message('profile_update', OTHER, { peerID: HOST, profile }), OTHER, context), null);
  assert.equal(classifyAppFrame(message('profile_update', OTHER, { peerID: OTHER, profile: { ...profile, displayName: {} } }), OTHER, context), null);
  assert.equal(classifyAppFrame(message('profile_update', OTHER, null), OTHER, context), null, 'a null payload');
});

test('roster entries and pool events count only from the host', () => {
  const profile = { displayName: 'A', avatarEmoji: 'x', avatarColorIndex: 1 };
  assert.equal(classifyAppFrame(message('peer_info', HOST, { peerID: OTHER, profile }), HOST, context)?.kind, 'profile');
  assert.equal(classifyAppFrame(message('peer_info', OTHER, { peerID: OTHER, profile }), OTHER, context), null);
  assert.equal(classifyAppFrame(message('system', HOST, { event: 'pool_closed' }), HOST, context)?.kind, 'pool_closed');
  assert.equal(classifyAppFrame(message('system', OTHER, { event: 'pool_closed' }), OTHER, context), null);
  assert.equal(classifyAppFrame(message('system', HOST, { event: 'removed_from_pool', targetPeerID: ME }), HOST, context)?.kind, 'removed');
  assert.equal(classifyAppFrame(message('system', OTHER, { event: 'removed_from_pool', targetPeerID: ME }), OTHER, context), null);
  assert.equal(classifyAppFrame(message('system', HOST, { event: 'removed_from_pool', targetPeerID: OTHER }), HOST, context), null, 'someone else\'s removal');
  assert.equal(classifyAppFrame(message('system', HOST, { text: 'plain words' }), HOST, context), null);
  // With no host known, nobody is the host.
  const noHost = { hostPeerId: null, localPeerId: ME };
  assert.equal(classifyAppFrame(message('system', HOST, { event: 'pool_closed' }), HOST, noHost), null);
});

test('encrypted payloads name their sender and a known type, and nothing else is taken', () => {
  const body = { encryptedData: 'AAAA', senderPeerID: OTHER, isPrivateChat: false, messageType: 'chat_message' };
  assert.equal(classifyAppFrame(message('custom', OTHER, body), OTHER, context)?.kind, 'encrypted');
  assert.equal(classifyAppFrame(message('custom', OTHER, { ...body, senderPeerID: HOST }), OTHER, context), null);
  assert.equal(classifyAppFrame(message('custom', OTHER, { ...body, messageType: 'nope' }), OTHER, context), null);
  assert.equal(classifyAppFrame(message('custom', OTHER, { ...body, encryptedData: '***' }), OTHER, context), null);
  assert.equal(classifyAppFrame(message('custom', OTHER, { ...body, encryptedData: 5 }), OTHER, context), null);
  assert.equal(classifyAppFrame(message('chat', OTHER, { text: 'plaintext' }), OTHER, context), null, 'unencrypted chat');
  assert.equal(classifyAppFrame(message('relay', OTHER, {}), OTHER, context), null);
});

test('malformed frames are dropped and never throw', () => {
  for (const junk of ['null', '1', '[]', '"x"', '{', '', '{"type":5}', `{"type":"custom","senderID":"${OTHER}"}`, `{"type":"custom","senderID":"${OTHER}","payload":"***"}`, `{"type":"custom","senderID":"${OTHER}","payload":5}`]) {
    assert.equal(classifyAppFrame(utf8(junk), OTHER, context), null, junk);
  }
  assert.equal(classifyAppFrame(new Uint8Array([0xff]), OTHER, context), null);
});

test('a bad timestamp is now, not a crash', () => {
  const body = { encryptedData: 'AAAA', senderPeerID: OTHER, messageType: 'chat_message' };
  for (const timestamp of ['x', null, {}, 1e308]) {
    const action = classifyAppFrame(message('custom', OTHER, body, { timestamp }), OTHER, context);
    assert.ok(action?.kind === 'encrypted' && Number.isFinite(action.timestampMillis) && Math.abs(Date.now() - action.timestampMillis) < 5000, String(timestamp));
  }
  const action = classifyAppFrame(message('custom', OTHER, body, { timestamp: 0 }), OTHER, context);
  assert.ok(action?.kind === 'encrypted' && action.timestampMillis === 978307200000);
});

test('game invitations: only the sender\'s own, only to us; other game frames stay frames', () => {
  const data = (extra: Record<string, unknown>) => base64Encode(utf8(JSON.stringify({ invitationID: ID, sessionID: ID, hostPeerID: OTHER, ...extra })));
  const invite = (extra: Record<string, unknown> = {}, gameType: unknown = 'connect_four') => message('game_control', OTHER, { controlType: 'invite', gameType, data: data(extra) });
  assert.deepEqual(classifyAppFrame(invite(), OTHER, context), { kind: 'game_invite', invite: { invitationID: ID, gameType: 'connect_four', sessionID: ID } });
  assert.equal(classifyAppFrame(invite({ targetPeerID: ME }), OTHER, context)?.kind, 'game_invite');
  assert.equal(classifyAppFrame(invite({ targetPeerID: 'someone' }), OTHER, context), null);
  assert.equal(classifyAppFrame(invite({ hostPeerID: HOST }), OTHER, context), null);
  assert.equal(classifyAppFrame(invite({ invitationID: 7 }), OTHER, context), null);
  assert.equal(classifyAppFrame(invite({}, {}), OTHER, context), null);
  assert.equal(classifyAppFrame(invite({}, 'Bad Type!'), OTHER, context), null);
  assert.equal(classifyAppFrame(message('game_control', OTHER, { controlType: 'session_update' }), OTHER, context)?.kind, 'game_frame');
});

test('what the relay says is validated too', () => {
  const good = { session_token: 't', peer_id: ME, peers: [{ peer_id: HOST, display_name: 'H', public_key: 'k', connected_at: 1 }, { nope: 1 }], pool_info: { pool_id: ID, name: {}, host_peer_id: HOST, max_peers: 8, current_peers: 2 } };
  const accepted = parseJoinAccepted(good)!;
  assert.equal(accepted.peers.length, 1, 'a bad row is dropped');
  assert.equal(accepted.pool.name, 'Pool');
  assert.equal(parseJoinAccepted(null), null);
  assert.equal(parseJoinAccepted({ ...good, peers: 'x' }), null);
  assert.equal(parseJoinAccepted({ ...good, pool_info: { pool_id: 1 } }), null);
  assert.equal(parsePeerInfo({ peer_id: 'p', display_name: {} })?.displayName, 'Someone');
  assert.equal(parsePeerInfo(5), null);
  assert.equal(joinAcceptedMatches(accepted, { poolId: ID.toUpperCase(), localPeerId: ME }), true);
  assert.equal(joinAcceptedMatches(accepted, { poolId: '00000000-0000-4000-8000-000000000000', localPeerId: ME }), false, 'another pool');
  assert.equal(joinAcceptedMatches(accepted, { poolId: ID, localPeerId: 'not-me' }), false, 'another identity');
});

function stored(id: string, weight = 1): ChatMessage {
  return { id, senderID: 'a', senderName: 'a', contentType: 'text', timestamp: 0, text: 'x'.repeat(weight), reactions: {}, mentions: [], isEncrypted: true, isPrivate: false };
}

test('a chat keeps a bounded number of messages and bytes, newest first', () => {
  const many = Array.from({ length: MAX_MESSAGES_PER_CHAT + 50 }, (_, i) => stored(String(i)));
  const capped = capMessages(many);
  assert.equal(capped.length, MAX_MESSAGES_PER_CHAT);
  assert.equal(capped.at(-1)!.id, String(many.length - 1));
  const heavy = Array.from({ length: 5 }, (_, i) => stored(String(i), MAX_CHAT_BYTES / 2));
  const trimmed = capMessages(heavy);
  assert.ok(trimmed.length <= 2);
  assert.equal(trimmed.at(-1)!.id, '4');
  const store = useChatStore.getState();
  for (let i = 0; i < MAX_MESSAGES_PER_CHAT + 5; i++) store.addGroupMessage(stored(`g${i}`));
  assert.equal(useChatStore.getState().groupMessages.length, MAX_MESSAGES_PER_CHAT);
  for (let i = 0; i < MAX_MESSAGES_PER_CHAT + 5; i++) store.addPrivateMessage('p', stored(`p${i}`));
  assert.equal(useChatStore.getState().privateMessages['p']!.length, MAX_MESSAGES_PER_CHAT);
  store.reset();
});

test('votes only for what a poll offers; reactors are bounded', () => {
  const store = useChatStore.getState();
  store.reset();
  const poll: ChatMessage = { ...stored(ID), contentType: 'poll', pollData: { question: 'q', options: ['a'], votes: { a: [] }, allowVoteChange: true } };
  store.addGroupMessage(poll);
  store.updatePollVote(ID, 'b', 'v', true);
  assert.deepEqual(useChatStore.getState().groupMessages[0]!.pollData!.votes, { a: [] });
  store.updatePollVote(ID, 'a', 'v', true);
  assert.deepEqual(useChatStore.getState().groupMessages[0]!.pollData!.votes, { a: ['v'] });
  for (let i = 0; i < 150; i++) store.addReaction(ID, 'x', `peer${i}`, true);
  assert.equal(useChatStore.getState().groupMessages[0]!.reactions['x']!.length, 100);
  store.reset();
});

test('vectors loaded', () => { assert.ok(V.wire); });
