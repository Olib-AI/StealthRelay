// Each of these failed in a run against the real app before it was fixed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { canAttemptJoin, joinRefusalText, notProtectedText, reconnectDelayMs, serverErrorOutcome } from '../src/protocol/join-policy.ts';
import { b64, makeProtectedMember, V } from './helpers.ts';
import { foldName, mixesScripts, PeerNameBook, shownName } from '../src/protocol/peer-names.ts';
import { parseHistorySync } from '../src/protocol/inbound.ts';
import { resolveReply } from '../src/protocol/reply.ts';
import { effectiveView } from '../src/view-state.ts';
import { useChatStore } from '../src/stores/chat.ts';
import type { ChatMessage } from '../src/stores/chat.ts';

const ID = '6ba7b810-9dad-41d1-80b4-00c04fd430c8';
const OTHER_ID = '7ba7b810-9dad-41d1-80b4-00c04fd430c8';
const utf8 = (text: string) => new TextEncoder().encode(text);

test('a used or expired link ends the wait, with words, before anyone is let in', () => {
  const used = serverErrorOutcome(404, 'invitation not found or expired', false);
  assert.equal(used.terminal, true, 'it used to wait for the host for ever');
  assert.match(used.text!, /no longer valid/);
  assert.match(used.text!, /new one/);
  for (const [code, message] of [[503, 'pool_full'], [503, 'too many pending join requests for this pool, try again later'], [400, 'display name too long'], [403, 'proof-of-work verification failed'], [429, 'rate limited'], [401, 'rejoin signature invalid'], [500, 'whatever']] as const) {
    const outcome = serverErrorOutcome(code, message, false);
    assert.equal(outcome.terminal, true, message);
    assert.ok(outcome.text && !outcome.text.includes(message) && !outcome.text.includes('—'), message);
  }
});

test('once in, a passing server error doesn\'t end the session', () => {
  assert.equal(serverErrorOutcome(429, 'rate limited', true).terminal, false);
  assert.equal(serverErrorOutcome(400, 'something', true).terminal, false);
  assert.equal(serverErrorOutcome(401, 'session token', true).terminal, true);
});

test('a refusal from the join path reads as words, not codes', () => {
  assert.match(joinRefusalText('invitation_ended'), /no longer valid/);
  assert.match(joinRefusalText('host_offline_unavailable'), /host is offline/);
  assert.match(joinRefusalText('rejected by host'), /host declined/);
  assert.match(joinRefusalText('Rejected by host'), /host declined/);
  assert.match(joinRefusalText('something new'), /couldn't join/);
  assert.ok(!joinRefusalText('something new').includes('something new'));
});

test('an expired link still lets an approved member back, and nobody else in', () => {
  assert.equal(canAttemptJoin({ expired: false, joinedBefore: false }), true);
  assert.equal(canAttemptJoin({ expired: true, joinedBefore: false }), false);
  assert.equal(canAttemptJoin({ expired: true, joinedBefore: true }), true);
});

test('reconnecting backs off to 5 minutes, as the app does, and doesn\'t give up', () => {
  assert.equal(reconnectDelayMs(0), 1000);
  assert.equal(reconnectDelayMs(1), 2000);
  assert.equal(reconnectDelayMs(4), 16000);
  assert.equal(reconnectDelayMs(9), 300000);
  assert.equal(reconnectDelayMs(50), 300000);
  assert.equal(reconnectDelayMs(5000), 300000);
});

test('names fold the way they read', () => {
  assert.equal(foldName('Alexandria of the Long Valley'), foldName('alexandria  OF the long valley'));
  assert.equal(foldName('Kíra'), foldName('Kira'));
  assert.equal(foldName('Кira'), foldName('kira'), 'Cyrillic К');
  assert.equal(foldName('bob (N8XmwXCO)'), foldName('Bob'), 'a tag dressed up in a name is left out');
  assert.equal(foldName('al1ce'), foldName('alice'));
  assert.equal(foldName('a​nna'), foldName('anna'));
  assert.notEqual(foldName('Ann'), foldName('Anna'));
  assert.equal(mixesScripts('Кira'), true);
  assert.equal(mixesScripts('Anna Иванова'), false);
  assert.equal(mixesScripts('田中 Tom'), false);
});

test('anyone sharing a name shows the start of their key; the local person never does', () => {
  const book = new PeerNameBook();
  book.hold('Alexandria', 'me-id-000000');
  assert.equal(book.tag('me-id-000000', 'Alexandria', 'me-id-000000'), null);
  book.hold('Alexandria', 'gCS8ElkiAAAA');
  assert.equal(book.tag('gCS8ElkiAAAA', 'Alexandria', 'me-id-000000'), 'gCS8Elki');
  book.hold('Webby', 'IM3dwZcfAAAA');
  assert.equal(book.tag('IM3dwZcfAAAA', 'Webby', 'me-id-000000'), null, 'a name nobody else holds has no tag');
  assert.equal(book.tag('NEWNEWNEWNEW', 'Кira', 'me-id-000000'), 'NEWNEWNE', 'mixing scripts in one word');
  // Someone who has left still counts: a name doesn't come free for someone else in this pool.
  book.hold('Hana', 'first-holder');
  book.hold('Hana', 'second-holder');
  assert.equal(book.tag('second-holder', 'Hana', 'me-id-000000'), 'second-h');
  assert.equal(shownName({ displayName: 'Hana', nameTag: 'second-h' }), 'Hana (second-h)');
  assert.equal(shownName({ displayName: 'Hana' }), 'Hana');
});

function history(messages: unknown[], isGroupChat = true): Uint8Array {
  return utf8(JSON.stringify({ messages, isGroupChat }));
}
const base = { messageID: ID, senderID: 'p', senderName: 'P', contentType: 'text', timestamp: 815000000, text: 'old', reactions: {}, mentions: [], isEncrypted: true };

test('history: media-less messages come through as what they are; bad ones and system lines don\'t', () => {
  const parsed = parseHistorySync(history([
    base,
    { ...base, messageID: OTHER_ID, contentType: 'image', text: undefined },
    { ...base, messageID: '8ba7b810-9dad-41d1-80b4-00c04fd430c8', contentType: 'voice', text: undefined, voiceDuration: 3 },
    { ...base, messageID: '9ba7b810-9dad-41d1-80b4-00c04fd430c8', contentType: 'system', text: 'I am the app' },
    { ...base, messageID: 7 },
    { ...base, messageID: 'aba7b810-9dad-41d1-80b4-00c04fd430c8', text: {} },
  ]), Date.now())!;
  assert.deepEqual(parsed.map((m) => m.contentType), ['text', 'image', 'voice']);
  assert.equal(parsed[1]!.imageData, undefined);
  assert.equal(parsed[0]!.senderName, 'P');
  assert.equal(parseHistorySync(history([base], false), Date.now()), null, 'only group history');
  assert.equal(parseHistorySync(utf8('null'), Date.now()), null);
  assert.equal(parseHistorySync(utf8('{"messages":5,"isGroupChat":true}'), Date.now()), null);
  assert.ok(parseHistorySync(history(Array.from({ length: 5000 }, () => base)), Date.now())!.length <= 1000);
});

test('history: media a sender attached anyway is dropped, a name is cleaned, and nothing is from the future', () => {
  const now = 1_800_000_000_000;
  const [m] = parseHistorySync(history([{ ...base, contentType: 'image', imageData: 'AAAA', senderName: 'a‮b', timestamp: 2_000_000_000 }]), now)!;
  assert.equal(m!.imageData, undefined);
  assert.equal(m!.senderName, 'ab');
  assert.equal(m!.timestampMillis, now);
});

function stored(id: string, timestamp: number): ChatMessage {
  return { id, senderID: 'a', senderName: 'a', contentType: 'text', timestamp, text: id, reactions: {}, mentions: [], isEncrypted: true, isPrivate: false };
}

test('history merges in order, by ID, without counting as unread', () => {
  const store = useChatStore.getState();
  store.reset();
  store.addGroupMessage(stored(ID, 200));
  const unread = useChatStore.getState().unreadGroup;
  store.mergeHistory([stored(OTHER_ID, 100), stored(ID.toUpperCase(), 100)]);
  const state = useChatStore.getState();
  assert.deepEqual(state.groupMessages.map((m) => m.id), [OTHER_ID, ID]);
  assert.equal(state.unreadGroup, unread);
  assert.equal(state.groupMessages[0]!.isHistory, true);
  store.reset();
});

test('a reply shows this device\'s copy of what it quotes, or says it isn\'t there', () => {
  const message = { ...stored(ID, 1), senderName: 'Real Name', text: 'what was really said' };
  const quote = { messageID: ID.toUpperCase(), senderName: 'Forged', previewText: 'what was never said' };
  assert.deepEqual(resolveReply(quote, [message]), { senderName: 'Real Name', text: 'what was really said' });
  assert.equal(resolveReply({ ...quote, messageID: OTHER_ID }, [message]), null);
  assert.deepEqual(resolveReply(quote, [{ ...message, text: undefined, contentType: 'image' }]), { senderName: 'Real Name', text: 'Photo' });
  assert.deepEqual(resolveReply(quote, [{ ...message, text: undefined, contentType: 'voice' }]), { senderName: 'Real Name', text: 'Voice message' });
});

test('a dropped connection keeps the pool on screen, instead of the join page', () => {
  const none = { isGameActive: false, activeGameType: null };
  assert.equal(effectiveView('join', 'reconnecting', none), 'lobby', 'someone who never left the lobby');
  assert.equal(effectiveView('chat', 'reconnecting', none), 'chat');
  assert.equal(effectiveView('join', 'connected', none), 'lobby');
  assert.equal(effectiveView('chat', 'failed', none), 'join');
  assert.equal(effectiveView('chat', 'disconnected', none), 'join');
  assert.equal(effectiveView('lobby', 'waiting_approval', none), 'join');
  assert.equal(effectiveView('game_lobby', 'connected', { isGameActive: true, activeGameType: 'chess' }), 'chess');
});

test('behind the announced epoch, a frame waits for that key: under the old one the host drops it after 30 s', async () => {
  const h = await makeProtectedMember();
  const epochOf = (frame: { data: Uint8Array }) => new DataView(frame.data.buffer, frame.data.byteOffset).getUint32(4);
  const appFrames = () => h.sent.filter((frame) => new TextDecoder().decode(frame.data.subarray(0, 4)) === 'SWO2');

  await h.member.sendApp(utf8('before'), null);
  await h.member.settled();
  assert.deepEqual(appFrames().map(epochOf), [V.rotation.epoch - 1], 'sent under the key it has');

  await h.member.receive(b64(V.rotation.announcementWire[0]), V.hostPeerID);
  await h.member.settled();
  await h.member.sendApp(utf8('while behind'), null);
  await h.member.settled();
  assert.equal(appFrames().length, 1, 'held: this used to go out under the old key and be lost');

  h.clock.now += 1000;
  await h.member.receive(b64(V.rotation.grantWire), V.hostPeerID);
  await h.member.settled();
  assert.deepEqual(appFrames().map(epochOf), [V.rotation.epoch - 1, V.rotation.epoch], 'the new key is here: it goes');
});

test('the refusal says why only while it is true: nobody on an older version, no such claim', () => {
  assert.match(notProtectedText(1), /someone here uses an older version/);
  assert.match(notProtectedText(1), /nothing is being sent or received/);
  const nobody = notProtectedText(0);
  assert.doesNotMatch(nobody, /older version/);
  assert.match(nobody, /nothing is being sent or received/);
});
