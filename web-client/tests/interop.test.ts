// Proves this client speaks the app's protocol, against vectors from the real Swift code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { V, b64, hex, importAes, importEd25519, importX25519, makeMember, makeProtectedMember } from './helpers.ts';
import { base64Encode } from '../src/utils/base64.ts';
import { hexEncode } from '../src/utils/hex.ts';
import { computeJoinProof, memberRejoinTranscript, parseInvitationUrl, parseTransportFragment } from '../src/crypto/invitation.ts';
import { decodeCard, decodeCardQRText } from '../src/crypto/sealed-card.ts';
import { ed25519Verify } from '../src/crypto/webcrypto.ts';
import { aesGcmOpenCombined } from '../src/crypto/webcrypto.ts';
import { announcementTranscript, decodeControlMessage, grantTranscript, requestTranscript } from '../src/transport/control-message.ts';
import { encodeHeader, openOuterFrame, outerAad, parseHeader, sealOuterFrame } from '../src/transport/outer-frame.ts';
import { bindingStatement, ChatEncryption, continuityStatement, deriveChatKey } from '../src/crypto/encryption.ts';
import { buildPoolMessage, buildPrivateChatPayload } from '../src/protocol/chat-wire.ts';
import type { KeyExchangePayload, PoolMessage } from '../src/protocol/messages.ts';

const poolIdBytes = hex((V.poolID as string).replace(/-/g, ''));

test('parses the real invitation, fragment and all', () => {
  const parsed = parseInvitationUrl(V.inviteURL);
  assert.equal(parsed.poolId.toUpperCase(), V.poolID);
  assert.equal(hexEncode(parsed.transport.inviteKey), V.fragment.inviteKey);
  assert.equal(hexEncode(parsed.transport.hostIdentityKey), V.fragment.hostKey);
  assert.equal(parsed.serverAddress, 'wss://relay.example:9090');
  const direct = parseTransportFragment(V.fragment.fragment);
  assert.equal(hexEncode(direct.inviteKey), V.fragment.inviteKey);
});

test('opens a Swift invite card, fragment intact, as a file or a QR code', () => {
  const bytes = hex(V.card.bytes);
  assert.equal(decodeCard(bytes), V.inviteURL);
  assert.equal(decodeCard(decodeCardQRText(`stcard1:${base64Encode(bytes)}`)!), V.inviteURL);
  assert.equal(hexEncode(parseInvitationUrl(decodeCard(bytes)).transport.inviteKey), V.fragment.inviteKey);
});

test('join proof and rejoin transcript match Swift', async () => {
  const j = V.joinProof;
  const proof = computeJoinProof(hex(j.tokenSecret), hex(j.tokenID), poolIdBytes, j.timestamp, hex(j.nonce));
  assert.equal(hexEncode(proof), j.proof);
  const transcript = memberRejoinTranscript(poolIdBytes, j.timestamp, hex(j.nonce));
  assert.equal(hexEncode(transcript), V.rejoin.transcript);
  assert.ok(await ed25519Verify(hex(V.memberPublic), hex(V.rejoin.signature), transcript));
});

test('a first key request is byte-identical to the Swift one', async () => {
  const h = await makeMember();
  assert.equal(h.member.connected(V.hostPeerID), true);
  await h.member.settled();
  assert.equal(h.sent.length, 1);
  assert.deepEqual(h.sent[0]!.targets, [V.hostPeerID]);
  const ours = decodeControlMessage(h.sent[0]!.data)!;
  const swift = decodeControlMessage(b64(V.firstJoin.requestWire))!;
  assert.equal(hexEncode(requestTranscript(ours, poolIdBytes)!), V.firstJoin.requestTranscript);
  assert.equal(hexEncode(requestTranscript(swift, poolIdBytes)!), V.firstJoin.requestTranscript);
  // CryptoKit's Ed25519 is hedged, so signatures differ run to run: each has to verify.
  const transcript = hex(V.firstJoin.requestTranscript);
  assert.ok(await ed25519Verify(hex(V.memberPublic), ours.memberSignature!, transcript));
  assert.ok(await ed25519Verify(hex(V.memberPublic), swift.memberSignature!, transcript));
  assert.deepEqual(ours.inviteProof, swift.inviteProof);
  assert.deepEqual(ours.inviteKeyID, hex(V.fragment.keyID));
});

test('takes the Swift host\'s grant and announcement, and clears the invite key', async () => {
  const h = await makeProtectedMember();
  assert.deepEqual(h.member.status, { kind: 'protected', epoch: 1, excludedPeers: [] });
  assert.ok(h.inviteKey.every((byte) => byte === 0), 'invite key cleared once enrolled');
});

test('grant and announcement transcripts match Swift', () => {
  const grant = decodeControlMessage(b64(V.firstJoin.grantWire))!;
  assert.equal(hexEncode(grantTranscript(grant, poolIdBytes)!), V.firstJoin.grantTranscript);
  const announce = decodeControlMessage(b64(V.firstJoin.announcementsWire[0]))!;
  assert.equal(hexEncode(announcementTranscript(announce, poolIdBytes)!), V.firstJoin.announcementTranscript);
});

test('opens the Swift host\'s frames, and holds frames sent before it can seal', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  // Frames arriving before the grant wait for it.
  for (const wire of V.frames.fromHost as string[]) await h.member.receive(b64(wire), V.hostPeerID);
  assert.equal(h.delivered.length, 0);
  // Outgoing frames wait too.
  await h.member.sendApp(new TextEncoder().encode('held'), null);
  assert.equal(h.sent.length, 1, 'only the key request went out');

  await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
  for (const wire of V.firstJoin.announcementsWire as string[]) await h.member.receive(b64(wire), V.hostPeerID);
  await h.member.settled();
  assert.deepEqual(h.delivered.map((d) => d.text), V.frames.plaintexts);
  assert.ok(h.delivered.every((d) => d.sender === V.hostPeerID));
  assert.equal(h.sent.length, 2, 'the held frame went out once it could be sealed');
  assert.equal(new TextDecoder().decode(h.sent[1]!.data.subarray(0, 4)), 'SWO2');
});

test('outer frame layout matches Swift, both ways', async () => {
  const f = V.frames;
  const key = await importAes(hex(f.frameKey));
  const wire = b64(f.fixedWire);
  const header = parseHeader(wire)!;
  assert.equal(hexEncode(encodeHeader(header)), f.fixedHeader);
  assert.equal(hexEncode(outerAad(encodeHeader(header), poolIdBytes, V.hostPeerID)), f.aad);
  const opened = await openOuterFrame(wire, key, poolIdBytes, V.hostPeerID);
  assert.equal(new TextDecoder().decode(opened!.plaintext), f.fixedPlain);
  const resealed = await sealOuterFrame(new TextEncoder().encode(f.fixedPlain), key, header, poolIdBytes, V.hostPeerID);
  assert.deepEqual(resealed, wire, 'same key, header and plaintext give the same bytes');
});

test('derives the same frame key as Swift from the secret', async () => {
  const h = await makeProtectedMember();
  await h.member.sendApp(new TextEncoder().encode('from web'), null);
  const key = await importAes(hex(V.frames.frameKey));
  const opened = await openOuterFrame(h.sent.at(-1)!.data, key, poolIdBytes, V.memberPeerID);
  assert.equal(new TextDecoder().decode(opened!.plaintext), 'from web');
});

test('follows the host through a rotation', async () => {
  const h = await makeProtectedMember();
  await h.member.receive(b64(V.rotation.announcementWire[0]), V.hostPeerID);
  await h.member.settled();
  const request = decodeControlMessage(h.sent.at(-1)!.data)!;
  assert.equal(request.kind, 'keyRequest');
  assert.equal(request.inviteKeyID, undefined, 'an enrolled member asks without the invite key');
  assert.equal(request.inviteProof, undefined);
  assert.equal(hexEncode(requestTranscript(request, poolIdBytes)!), V.rotation.requestTranscript);
  assert.deepEqual(h.member.status, { kind: 'protected', epoch: 1, excludedPeers: [] });

  h.clock.now += 1000;
  await h.member.receive(b64(V.rotation.grantWire), V.hostPeerID);
  assert.deepEqual(h.member.status, { kind: 'protected', epoch: 2, excludedPeers: [] });
  await h.member.receive(b64(V.rotation.frameWire), V.hostPeerID);
  assert.equal(h.delivered.at(-1)!.text, 'under epoch two');
});

test('inner E2E: derives the same key as Swift and reads its message', async () => {
  const e = V.e2e;
  const web = await importX25519(hex(e.webChatSeed), hex(e.webChatPublic));
  const key = await deriveChatKey(web.privateKey, web.publicKey, hex(e.hostChatPublic));
  const msg = JSON.parse(e.customMessage) as PoolMessage;
  const wrapped = JSON.parse(new TextDecoder().decode(b64(msg.payload))) as { encryptedData: string; messageType: string; senderPeerID: string };
  assert.equal(wrapped.messageType, 'chat_message');
  assert.equal(wrapped.senderPeerID, V.hostPeerID);
  const plain = await aesGcmOpenCombined(key, b64(wrapped.encryptedData));
  assert.equal(new TextDecoder().decode(plain!), e.plainPayload);
  const parsed = JSON.parse(e.plainPayload);
  assert.equal(parsed.chatPayload.text, e.chatText);
});

test('inner E2E: binding and continuity statements match Swift, and their signatures verify', async () => {
  const e = V.e2e;
  const binding = bindingStatement(V.hostPeerID, poolIdBytes, hex(e.hostChatPublic), hex(e.signingPublic));
  assert.equal(hexEncode(binding), e.bindingStatement);
  assert.ok(await ed25519Verify(hex(e.signingPublic), hex(e.binding), binding));
  const continuity = continuityStatement(V.hostPeerID, hex(e.hostChatPublic), hex(e.continuityKey), Number(e.continuityCounter), hex(e.signingPublic));
  assert.equal(hexEncode(continuity), e.continuityStatement);
  assert.ok(await ed25519Verify(hex(e.continuityKey), hex(e.continuityProof), continuity));
});

test('accepts the Swift key exchange', async () => {
  const e = V.e2e;
  const chat = await ChatEncryption.create(await importX25519(hex(e.webChatSeed), hex(e.webChatPublic)));
  const msg = JSON.parse(e.keyExchangeMessage) as PoolMessage;
  const payload = JSON.parse(new TextDecoder().decode(b64(msg.payload))) as KeyExchangePayload;
  assert.equal(payload.senderPeerID, V.hostPeerID);
  const result = await chat.acceptKeyExchange(payload, V.hostPeerID);
  assert.deepEqual(result, { outcome: 'newPeer', accepted: true, shouldAnswer: true });
  assert.ok(chat.keyFor(V.hostPeerID));
});

// Everything the Swift side checks in its `verify` step. Set STEALTH_TS_OUTPUT to write it.
test('writes what this client produces, for the Swift side to verify', async (t) => {
  const path = process.env['STEALTH_TS_OUTPUT'];
  if (!path) { t.skip('STEALTH_TS_OUTPUT not set'); return; }
  const e = V.e2e;
  const now = Date.now();
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const signingKey = await importEd25519(hex(V.memberSeed));
  const h = await makeMember({ now: () => now, newNonce: () => nonce });
  h.member.connected(V.hostPeerID);
  await h.member.settled();

  const chat = await ChatEncryption.create(await importX25519(hex(e.webChatSeed), hex(e.webChatPublic)));
  const payload = await chat.makeKeyExchange(V.memberPeerID, poolIdBytes, {
    publicKey: hex(V.memberPublic),
    sign: async (m) => new Uint8Array(await crypto.subtle.sign('Ed25519', signingKey, new Uint8Array(m))),
    nextCounter: async () => 1_900_000_000_999,
  });
  const keyExchange = buildPoolMessage(crypto.randomUUID(), 'key_exchange', V.memberPeerID, 'Webby', payload, true, now);

  await chat.acceptKeyExchange({ publicKey: base64Encode(hex(e.hostChatPublic)), senderPeerID: V.hostPeerID }, V.hostPeerID);
  const text = 'hello from the web';
  const plain = buildPrivateChatPayload({
    id: crypto.randomUUID(), senderID: V.memberPeerID, senderName: 'Webby', contentType: 'text',
    timestamp: now / 1000 - 978307200, text, reactions: {}, mentions: [],
  }, false, null);
  const sealed = await chat.encrypt(new TextEncoder().encode(JSON.stringify(plain)), V.hostPeerID);
  const custom = buildPoolMessage(crypto.randomUUID(), 'custom', V.memberPeerID, 'Webby', {
    encryptedData: base64Encode(sealed!), senderPeerID: V.memberPeerID, isPrivateChat: false, targetPeerID: null, messageType: 'chat_message',
  }, true, now);

  const outerKey = await importAes(hex(V.frames.frameKey));
  const outerWire = await sealOuterFrame(new TextEncoder().encode('outer from web'), outerKey, {
    epoch: 1, session: 42n, counter: 1n, timestampMillis: now, nonce: crypto.getRandomValues(new Uint8Array(12)),
  }, poolIdBytes, V.memberPeerID);

  writeFileSync(path, JSON.stringify({
    nowMillis: now,
    memberPeerID: V.memberPeerID,
    requestWire: base64Encode(h.sent[0]!.data),
    outerSecret: V.firstJoin.secret, outerWire: base64Encode(outerWire), outerPlain: 'outer from web',
    keyExchangeMessage: JSON.stringify(keyExchange),
    customMessage: JSON.stringify(custom),
    chatText: text,
  }));
});
