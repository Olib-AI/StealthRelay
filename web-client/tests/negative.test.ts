// What this client must refuse: wrong keys, tampering, bad signatures, replays, downgrades.
import test from 'node:test';
import assert from 'node:assert/strict';
import { V, b64, canReadPool, hex, importAes, importEd25519, importX25519, makeMember, makeProtectedMember } from './helpers.ts';
import { base64Encode } from '../src/utils/base64.ts';
import { InvitationError, parseInvitationUrl, parseTransportFragment, relayUrlFromInvitation } from '../src/crypto/invitation.ts';
import { decodeControlMessage, encodeControlMessage, grantTranscript, requestTranscript, secretAad } from '../src/transport/control-message.ts';
import type { ControlMessage } from '../src/transport/control-message.ts';
import { be32, concatBytes } from '../src/utils/bytes.ts';
import { MAX_INBOUND_FRAME_BYTES, MAX_PENDING_RECEIVE_BYTES, MAX_PENDING_RECEIVE_STEPS, MAX_QUEUED_BYTES_PER_SENDER, MAX_QUEUED_BYTES_TOTAL } from '../src/transport/pool-transport-security.ts';
import { openOuterFrame, sealOuterFrame } from '../src/transport/outer-frame.ts';
import { ChatEncryption, continuityStatement, deriveChatKey } from '../src/crypto/encryption.ts';
import { aesGcmOpenCombined, aesGcmSealCombined, generateEd25519, generateX25519, hkdfToAesKey, sha256, UnsupportedBrowserError, x25519SharedSecret } from '../src/crypto/webcrypto.ts';
import { loadOrCreatePoolIdentity, memoryIdentityStore, wipeLegacyIdentity } from '../src/crypto/identity.ts';
import type { KeyExchangePayload } from '../src/protocol/messages.ts';

const poolIdBytes = hex((V.poolID as string).replace(/-/g, ''));
const utf8 = (text: string) => new TextEncoder().encode(text);
const plaintextFrame = utf8(JSON.stringify({ id: 'x', type: 'custom', senderID: V.hostPeerID, senderName: 'Host', timestamp: 0, payload: '', isReliable: true }));

function expectInvitationError(url: string, code: InvitationError['code']) {
  assert.throws(() => parseInvitationUrl(url), (err: unknown) => err instanceof InvitationError && err.code === code);
}

test('a malformed fragment is a clear error, never a parser crash', () => {
  const base = (V.inviteURL as string).split('#')[0]!;
  const good = V.fragment.fragment as string;
  expectInvitationError(`${base}#nonsense`, 'bad_fragment');
  expectInvitationError(`${base}#v1.${good.slice(3)}`, 'bad_fragment');
  expectInvitationError(`${base}#v2.`, 'bad_fragment');
  expectInvitationError(`${base}#v2.${good.slice(3, 20)}`, 'bad_fragment');
  expectInvitationError(`${base}#${good}AA`, 'bad_fragment');
  expectInvitationError(`${base}#v2.${good.slice(3, -1)}!`, 'bad_fragment');
  expectInvitationError(`${base}#${good}#again`, 'bad_fragment');
  // Well-formed, with a version byte of a later format.
  const later = new Uint8Array(65).fill(7);
  const b64url = base64Encode(later).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  assert.throws(() => parseTransportFragment(`v2.${b64url}`), (err: unknown) => err instanceof InvitationError && err.code === 'unsupported_fragment');
});

test('no fragment is refused: this client has no plaintext mode to fall back to', () => {
  const base = (V.inviteURL as string).split('#')[0]!;
  expectInvitationError(base, 'no_fragment');
  expectInvitationError(`${base}#`, 'no_fragment');
});

test('damaged invitations are clear errors', () => {
  expectInvitationError('https://example.com', 'not_an_invitation');
  expectInvitationError('stealth://invite/', 'damaged');
  expectInvitationError('stealth://invite/!!!!', 'damaged');
  expectInvitationError(`stealth://invite/${base64Encode(utf8('{"id":[1]}')).replace(/=/g, '')}#${V.fragment.fragment}`, 'damaged');
  expectInvitationError(`stealth://invite/${base64Encode(utf8('not json')).replace(/=/g, '')}#${V.fragment.fragment}`, 'damaged');
  for (const code of ['not_an_invitation', 'damaged', 'bad_fragment', 'no_fragment'] as const) {
    assert.ok(!new InvitationError(code).message.includes('—'));
  }
});

test('an invitation address is never talked to in the clear', () => {
  assert.equal(relayUrlFromInvitation('wss://r.example', false), 'wss://r.example');
  assert.equal(relayUrlFromInvitation('ws://r.example:9090/x', false), 'wss://r.example:9090/x');
  assert.equal(relayUrlFromInvitation('r.example:9090', false), 'wss://r.example:9090');
  assert.equal(relayUrlFromInvitation('ws://127.0.0.1:9090', false), 'ws://127.0.0.1:9090');
  assert.equal(relayUrlFromInvitation('ws://r.example:9090', true), 'ws://r.example:9090');
});

test('a relay naming another host: nothing is sent, ever', async () => {
  const h = await makeMember();
  assert.equal(h.member.connected(base64Encode(new Uint8Array(32).fill(9))), false);
  assert.equal(h.member.status.kind, 'hostIdentityMismatch');
  await h.member.sendApp(utf8('secret'), null);
  await h.member.tick();
  assert.equal(h.sent.length, 0);
  assert.equal((h.member as unknown as { outboundQueue: unknown[] }).outboundQueue.length, 0, 'not even kept for later');
});

test('a control path a real grant does pass: the checks below are not passing by default', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
  assert.equal(await canReadPool(h), true);
});

test('a key grant not signed by the invitation\'s host is refused, and nothing opens', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  const forged = decodeControlMessage(b64(V.firstJoin.grantWire))!;
  forged.hostSignature = new Uint8Array(64).fill(1);
  await h.member.receive(encodeControlMessage(forged), V.hostPeerID);
  assert.equal(await canReadPool(h), false);
  assert.equal(h.member.status.kind, 'securing');
});

test('a tampered grant is refused: every signed field', async () => {
  const fields = ['requestHash', 'hostEphemeral', 'sealedSecret'] as const;
  for (const field of fields) {
    const h = await makeMember();
    h.member.connected(V.hostPeerID);
    await h.member.settled();
    const grant = decodeControlMessage(b64(V.firstJoin.grantWire))!;
    grant[field]![0]! ^= 1;
    await h.member.receive(encodeControlMessage(grant), V.hostPeerID);
    assert.equal(await canReadPool(h), false, `tampered ${field}`);
    assert.equal(h.member.status.kind, 'securing', `tampered ${field}`);
  }
});

test('a grant signed over another epoch or time is refused', async () => {
  for (const change of [{ epoch: 9 }, { timestampMillis: V.nowMillis + 1 }]) {
    const h = await makeMember();
    h.member.connected(V.hostPeerID);
    await h.member.settled();
    const grant = { ...decodeControlMessage(b64(V.firstJoin.grantWire))!, ...change };
    await h.member.receive(encodeControlMessage(grant), V.hostPeerID);
    assert.equal(await canReadPool(h), false, JSON.stringify(change));
  }
});

test('a grant with the wrong request hash but a good signature is refused', async () => {
  // Signed by the real host key, so only the hash check stands in the way.
  const signing = await importEd25519(hex(V.hostSeed));
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  const grant = decodeControlMessage(b64(V.firstJoin.grantWire))!;
  grant.requestHash = new Uint8Array(32).fill(5);
  grant.hostSignature = new Uint8Array(await crypto.subtle.sign('Ed25519', signing, new Uint8Array(grantTranscript(grant, poolIdBytes)!)));
  await h.member.receive(encodeControlMessage(grant), V.hostPeerID);
  assert.equal(await canReadPool(h), false);
});

test('a grant whose secret is not 32 bytes is refused', async () => {
  // A host that did everything else right: properly sealed for this request, properly signed.
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  const request = decodeControlMessage(h.sent[0]!.data)!;
  const requestHash = await sha256(requestTranscript(request, poolIdBytes)!);
  const ephemeral = await generateX25519();
  const shared = await x25519SharedSecret(ephemeral.privateKey, request.memberEphemeral!);
  const info = concatBytes(utf8('STEALTH_WS_TRANSPORT_KEY_V2'), be32(1), hex(V.fragment.inviteKey));
  const sealingKey = await hkdfToAesKey(shared, requestHash, info);
  const grant: ControlMessage = {
    kind: 'keyGrant', poolID: V.poolID, timestampMillis: V.nowMillis, epoch: 1, requestHash,
    hostEphemeral: ephemeral.publicKey,
    sealedSecret: await aesGcmSealCombined(sealingKey, new Uint8Array(16).fill(1), secretAad(poolIdBytes, 1)),
  };
  const signing = await importEd25519(hex(V.hostSeed));
  grant.hostSignature = new Uint8Array(await crypto.subtle.sign('Ed25519', signing, new Uint8Array(grantTranscript(grant, poolIdBytes)!)));
  await h.member.receive(encodeControlMessage(grant), V.hostPeerID);
  for (const wire of V.firstJoin.announcementsWire as string[]) await h.member.receive(b64(wire), V.hostPeerID);
  assert.equal(h.member.status.kind, 'securing', 'no key came of it');
  assert.equal(h.inviteKey.every((byte) => byte === 0), false, 'and the invite key is kept for a real grant');
});

test('a control message over the size limit is refused, whatever it says', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  const json = JSON.parse(new TextDecoder().decode(b64(V.firstJoin.grantWire).subarray(4)));
  json.padding = 'x'.repeat(17 * 1024);
  await h.member.receive(concatBytes(utf8('SWK2'), utf8(JSON.stringify(json))), V.hostPeerID);
  assert.equal(await canReadPool(h), false);
});

test('a control message with a field of the wrong type is refused outright', () => {
  const base = { kind: 'keyGrant', poolID: V.poolID, timestampMillis: 1 };
  const decode = (extra: Record<string, unknown>) => decodeControlMessage(concatBytes(utf8('SWK2'), utf8(JSON.stringify({ ...base, ...extra }))));
  assert.ok(decode({}), 'the control case');
  for (const bad of [{ nonce: 5 }, { nonce: '***' }, { epoch: 'x' }, { epoch: -1 }, { epoch: 2 ** 32 }, { protected: 'yes' }, { memberPeerID: 5 }, { removedPeerIDs: 'x' }, { removedPeerIDs: [1] }, { legacyPeerIDs: {} }, { timestampMillis: 'x' }, { timestampMillis: 1.5 }, { poolID: 5 }, { kind: 'nope' }]) {
    assert.equal(decode(bad), null, JSON.stringify(bad));
  }
});

test('a grant from anyone but the host is ignored, and nothing opens', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  await h.member.receive(b64(V.firstJoin.grantWire), 'someone-else');
  assert.equal(await canReadPool(h), false);
});

test('a grant sealed for another invite key opens nothing', async () => {
  const h = await makeMember({ invite: { inviteKey: new Uint8Array(32).fill(0xee), hostIdentityKey: hex(V.hostPublic) } });
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
  assert.equal(await canReadPool(h), false);
});

test('a grant answering an old request is refused', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  // The next request has another nonce and so another hash: the old grant no longer answers it.
  h.clock.now += 6000;
  await h.member.tick();
  await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
  assert.equal(await canReadPool(h), false);
});

test('a replayed grant changes nothing', async () => {
  const h = await makeProtectedMember();
  await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
  assert.deepEqual(h.member.status, { kind: 'protected', epoch: 1, excludedPeers: [] });
});

test('a stale or future grant is refused', async () => {
  for (const shift of [301_000, -61_000]) {
    const h = await makeMember();
    h.member.connected(V.hostPeerID);
    await h.member.settled();
    h.clock.now += shift;
    await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
    h.clock.now -= shift;
    assert.equal(await canReadPool(h), false, `shift ${shift}`);
  }
});

test('a stale or future announcement is refused', async () => {
  for (const shift of [301_000, -61_000]) {
    const h = await makeMember();
    h.member.connected(V.hostPeerID);
    await h.member.settled();
    await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
    h.clock.now += shift;
    for (const wire of V.firstJoin.announcementsWire as string[]) await h.member.receive(b64(wire), V.hostPeerID);
    assert.equal(h.member.status.kind, 'securing', `shift ${shift}`);
  }
});

test('a control message naming another pool is ignored', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  const grant = decodeControlMessage(b64(V.firstJoin.grantWire))!;
  grant.poolID = '00000000-0000-4000-8000-000000000000';
  await h.member.receive(encodeControlMessage(grant), V.hostPeerID);
  assert.equal(await canReadPool(h), false);
});

test('a replayed older announcement can\'t undo a newer one', async () => {
  const h = await makeProtectedMember();
  await h.member.receive(b64(V.signedOff), V.hostPeerID); // at T + 5 s, refused as a downgrade
  assert.equal(h.member.status.kind, 'downgradeRefused');
  await h.member.receive(b64(V.signedOn2), V.hostPeerID); // at T + 6 s, with a legacy peer named
  assert.deepEqual(h.member.status, { kind: 'protected', epoch: 1, excludedPeers: ['someone'] });
  // The same "off" again, and one before it: nothing moves.
  await h.member.receive(b64(V.signedOff), V.hostPeerID);
  assert.deepEqual(h.member.status, { kind: 'protected', epoch: 1, excludedPeers: ['someone'] });
  await h.member.receive(b64(V.firstJoin.announcementsWire[0]), V.hostPeerID);
  assert.deepEqual(h.member.status, { kind: 'protected', epoch: 1, excludedPeers: ['someone'] }, 'older word leaves the list alone');
});

test('only the invite key the invitation holds is proved, and only until a grant', async () => {
  const h = await makeProtectedMember();
  assert.ok(h.inviteKey.every((byte) => byte === 0));
  const enrolled = await makeMember({ enrolled: true, onGranted: () => undefined });
  enrolled.member.connected(V.hostPeerID);
  await enrolled.member.settled();
  assert.equal(decodeControlMessage(enrolled.sent[0]!.data)!.inviteProof, undefined);
});

test('an enrolled member\'s grant clears the invite key too, and tells the owner', async () => {
  let granted = 0;
  const h = await makeMember({ enrolled: false, onGranted: () => { granted += 1; } });
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
  assert.equal(granted, 1);
  assert.ok(h.inviteKey.every((byte) => byte === 0));
});

test('malformed control messages are dropped', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  for (const junk of ['SWK2', 'SWK2{', 'SWK2[]', 'SWK2{"kind":"keyGrant"}', `SWK2{"kind":"keyGrant","poolID":"${V.poolID}","timestampMillis":1,"nonce":"***"}`]) {
    await h.member.receive(utf8(junk), V.hostPeerID);
  }
  await h.member.receive(new Uint8Array(20_000).fill(0x53), V.hostPeerID);
  assert.equal(h.member.status.kind, 'securing');
});

test('forged announcements are refused', async () => {
  const h = await makeProtectedMember();
  await h.member.receive(b64(V.forgedOff), V.hostPeerID);
  assert.equal(h.member.status.kind, 'protected');
  await h.member.receive(b64(V.signedOff), 'someone-else');
  assert.equal(h.member.status.kind, 'protected');
  await h.member.settled();
  assert.equal(await canReadPool(h), true, 'and the pool still works');
});

test('downgrade: a signed "protection off" for a protected pool is refused, and frames stay sealed', async () => {
  const h = await makeProtectedMember();
  await h.member.receive(b64(V.signedOff), V.hostPeerID);
  assert.equal(h.member.status.kind, 'downgradeRefused');
  await h.member.sendApp(utf8('still secret'), null);
  const frame = h.sent.at(-1)!.data;
  assert.equal(new TextDecoder().decode(frame.subarray(0, 4)), 'SWO2');
  assert.ok(!new TextDecoder().decode(frame).includes('still secret'));
  await h.member.receive(plaintextFrame, V.hostPeerID);
  assert.equal(h.delivered.length, 0);
});

test('a pool the host never protected: nothing is sent or taken in the clear', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  await h.member.receive(b64(V.signedOff), V.hostPeerID);
  assert.deepEqual(h.member.status, { kind: 'hostNotProtected', legacyPeers: ['someone'] });
  await h.member.sendApp(utf8('held'), null);
  assert.equal(h.sent.length, 1, 'only the key request');
  await h.member.receive(plaintextFrame, V.hostPeerID);
  assert.equal(h.delivered.length, 0);
});

test('holding a key isn\'t enough to send: not before the host says protected, not when it says off', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
  await h.member.sendApp(utf8('held'), null);
  assert.equal(h.sent.length, 1, 'granted, no announcement yet: only the key request has gone');
  await h.member.receive(b64(V.signedOff), V.hostPeerID);
  assert.equal(h.member.status.kind, 'hostNotProtected');
  await h.member.sendApp(utf8('still held'), null);
  assert.equal(h.sent.length, 1, 'never protected, so nothing goes');
  await h.member.receive(b64(V.signedOn2), V.hostPeerID);
  assert.equal(h.sent.length, 3, 'protection on: both go, sealed');
  assert.ok(h.sent.slice(1).every((f) => new TextDecoder().decode(f.data.subarray(0, 4)) === 'SWO2'));
});

test('plaintext frames are dropped in every state', async () => {
  const securing = await makeMember();
  securing.member.connected(V.hostPeerID);
  await securing.member.receive(plaintextFrame, V.hostPeerID);
  assert.equal(securing.delivered.length, 0);
  const secured = await makeProtectedMember();
  await secured.member.receive(plaintextFrame, V.hostPeerID);
  assert.equal(secured.delivered.length, 0);
});

test('outer frames: wrong key, tampering and a wrong claimed sender all fail', async () => {
  const key = await importAes(hex(V.frames.frameKey));
  const wrong = await importAes(new Uint8Array(32).fill(1));
  const wire = b64(V.frames.fixedWire);
  assert.equal(await openOuterFrame(wire, wrong, poolIdBytes, V.hostPeerID), null);
  assert.equal(await openOuterFrame(wire, key, poolIdBytes, V.memberPeerID), null);
  assert.equal(await openOuterFrame(wire, key, new Uint8Array(16), V.hostPeerID), null);
  for (const offset of [4, 8, 16, 24, 32, 44, wire.length - 1]) {
    const tampered = wire.slice();
    tampered[offset]! ^= 1;
    assert.equal(await openOuterFrame(tampered, key, poolIdBytes, V.hostPeerID), null, `offset ${offset}`);
  }
  assert.equal(await openOuterFrame(wire.subarray(0, 50), key, poolIdBytes, V.hostPeerID), null);
});

test('a frame re-attributed by the relay is refused', async () => {
  const h = await makeProtectedMember();
  await h.member.receive(b64(V.frames.fromHost[0]), 'some-other-member');
  assert.equal(h.delivered.length, 0);
});

test('replay: a frame is taken once', async () => {
  const h = await makeProtectedMember();
  const wire = b64(V.frames.fromHost[0]);
  await h.member.receive(wire, V.hostPeerID);
  await h.member.receive(wire, V.hostPeerID);
  assert.equal(h.delivered.length, 1);
});

test('frames too old or too far ahead are refused', async () => {
  for (const shift of [301_000, -61_000]) {
    const h = await makeProtectedMember();
    h.clock.now += shift;
    await h.member.receive(b64(V.frames.fromHost[0]), V.hostPeerID);
    assert.equal(h.delivered.length, 0, `shift ${shift}`);
  }
});

async function afterRotation() {
  const h = await makeProtectedMember();
  await h.member.receive(b64(V.rotation.announcementWire[0]), V.hostPeerID);
  await h.member.settled();
  h.clock.now += 1000;
  await h.member.receive(b64(V.rotation.grantWire), V.hostPeerID);
  return h;
}

test('after a rotation the previous epoch is good for 30 s, and never from the removed member', async () => {
  const h = await afterRotation();
  const key = await importAes(hex(V.frames.frameKey));
  const frame = (sender: string, counter: bigint, ts: number) => sealOuterFrame(utf8(`old from ${sender}`), key, {
    epoch: 1, session: 7n, counter, timestampMillis: ts, nonce: crypto.getRandomValues(new Uint8Array(12)),
  }, poolIdBytes, sender);

  await h.member.receive(await frame(V.hostPeerID, 1n, h.clock.now), V.hostPeerID);
  assert.equal(h.delivered.length, 1, 'within the grace period');
  await h.member.receive(await frame(V.rotation.removed, 2n, h.clock.now), V.rotation.removed);
  assert.equal(h.delivered.length, 1, 'never from the removed member');
  h.clock.now += 31_000;
  await h.member.receive(await frame(V.hostPeerID, 3n, h.clock.now), V.hostPeerID);
  assert.equal(h.delivered.length, 1, 'not after the grace period');
});

test('the key request retries until answered, without showing the invite key once enrolled', async () => {
  const h = await makeMember({ enrolled: true });
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  assert.equal(decodeControlMessage(h.sent[0]!.data)!.inviteKeyID, undefined);
  await h.member.tick();
  assert.equal(h.sent.length, 1, 'no retry before 5 s');
  h.clock.now += 5100;
  await h.member.tick();
  assert.equal(h.sent.length, 2);
  assert.equal(decodeControlMessage(h.sent[1]!.data)!.inviteKeyID, undefined);
  h.clock.now += 5100;
  await h.member.tick();
  assert.ok(decodeControlMessage(h.sent[2]!.data)!.inviteKeyID, 'a host that can\'t place us gets the invitation');
});

test('after destroy, nothing moves', async () => {
  const h = await makeProtectedMember();
  const before = h.sent.length;
  h.member.destroy();
  await h.member.sendApp(utf8('x'), null);
  await h.member.receive(b64(V.frames.fromHost[0]), V.hostPeerID);
  assert.equal(h.sent.length, before);
  assert.equal(h.delivered.length, 0);
  assert.equal((h.member as unknown as { outboundQueue: unknown[] }).outboundQueue.length, 0, 'nothing is kept');
});

// --- Inner E2E

async function pair() {
  const e = V.e2e;
  const web = await ChatEncryption.create(await importX25519(hex(e.webChatSeed), hex(e.webChatPublic)));
  return { web, peer: 'peer' };
}

test('E2E: the wrong key and tampering fail', async () => {
  const e = V.e2e;
  const web = await importX25519(hex(e.webChatSeed), hex(e.webChatPublic));
  const { key: right } = await deriveChatKey(web.privateKey, web.publicKey, hex(e.hostChatPublic));
  const wrongPeer = await generateX25519();
  const { key: wrong } = await deriveChatKey(web.privateKey, web.publicKey, wrongPeer.publicKey);
  const msg = JSON.parse(e.customMessage) as { payload: string };
  const wrapped = JSON.parse(new TextDecoder().decode(b64(msg.payload))) as { encryptedData: string };
  const sealed = b64(wrapped.encryptedData);
  assert.equal(await aesGcmOpenCombined(wrong, sealed), null);
  const tampered = sealed.slice();
  tampered[sealed.length - 1]! ^= 1;
  assert.equal(await aesGcmOpenCombined(right, tampered), null);
});

test('E2E: nothing is encrypted without a key, and no key means no plaintext', async () => {
  const { web } = await pair();
  assert.equal(await web.encrypt(utf8('x'), 'nobody'), null);
  assert.equal(await web.decrypt(new Uint8Array(40), 'nobody'), null);
});

test('E2E: bad keys are refused', async () => {
  const { web, peer } = await pair();
  const refuse = async (publicKey: string) => {
    const result = await web.acceptKeyExchange({ publicKey, senderPeerID: peer }, peer);
    assert.equal(result.outcome, 'invalid');
    assert.equal(web.keyFor(peer), undefined);
  };
  await refuse(base64Encode(new Uint8Array(31)));
  await refuse(base64Encode(new Uint8Array(32)));
  await refuse(base64Encode(web.publicKey)); // reflection
  await refuse('***');
  // A small-order point: WebCrypto gives all zeros, or refuses it outright.
  const small = new Uint8Array(32);
  small[0] = 1;
  await refuse(base64Encode(small));
});

interface Device {
  device: Awaited<ReturnType<typeof generateEd25519>>;
}

async function exchange(device: Device['device'], chatKey: Uint8Array, peerId: string, counter: number): Promise<KeyExchangePayload> {
  const statement = continuityStatement(peerId, chatKey, device.publicKey, counter, null);
  const proof = new Uint8Array(await crypto.subtle.sign('Ed25519', device.privateKey, new Uint8Array(statement)));
  return { publicKey: base64Encode(chatKey), senderPeerID: peerId, continuityKey: base64Encode(device.publicKey), continuityProof: base64Encode(proof), continuityCounter: counter };
}

test('E2E TOFU: a new key warns, unless the same device vouches for it at a higher counter', async () => {
  const { web, peer } = await pair();
  const device = await generateEd25519();
  const first = (await generateX25519()).publicKey;
  assert.equal((await web.acceptKeyExchange(await exchange(device, first, peer, 100), peer)).outcome, 'newPeer');
  assert.equal((await web.acceptKeyExchange(await exchange(device, first, peer, 100), peer)).outcome, 'unchanged');

  const second = (await generateX25519()).publicKey;
  const same = await web.acceptKeyExchange(await exchange(device, second, peer, 200), peer);
  assert.deepEqual(same, { outcome: 'sameDevice', accepted: true, shouldAnswer: true });

  // No proof at all: taken, with the warning.
  const third = (await generateX25519()).publicKey;
  assert.equal((await web.acceptKeyExchange({ publicKey: base64Encode(third), senderPeerID: peer }, peer)).outcome, 'keyChanged');
});

test('E2E TOFU: a bad proof counts as no proof, so it gets the warning, not the trust', async () => {
  const { web, peer } = await pair();
  const device = await generateEd25519();
  const first = (await generateX25519()).publicKey;
  await web.acceptKeyExchange(await exchange(device, first, peer, 100), peer);
  const second = (await generateX25519()).publicKey;
  const forged = await exchange(device, second, peer, 200);
  forged.continuityProof = base64Encode(new Uint8Array(64).fill(3));
  assert.equal((await web.acceptKeyExchange(forged, peer)).outcome, 'keyChanged');
});

test('E2E TOFU: an older key with its older proof is refused while the peer is here', async () => {
  const { web, peer } = await pair();
  const device = await generateEd25519();
  const older = (await generateX25519()).publicKey;
  const newer = (await generateX25519()).publicKey;
  const replay = await exchange(device, older, peer, 100);
  await web.acceptKeyExchange(replay, peer);
  await web.acceptKeyExchange(await exchange(device, newer, peer, 200), peer);
  const keyBefore = web.keyFor(peer);
  const result = await web.acceptKeyExchange(replay, peer);
  assert.deepEqual(result, { outcome: 'replayRefused', accepted: false, shouldAnswer: false });
  assert.equal(web.keyFor(peer), keyBefore, 'the key in use stays');
});

test('E2E TOFU: once they left, a lower rank gets the warning, not a refusal', async () => {
  const { web, peer } = await pair();
  const device = await generateEd25519();
  const older = (await generateX25519()).publicKey;
  const newer = (await generateX25519()).publicKey;
  await web.acceptKeyExchange(await exchange(device, newer, peer, 200), peer);
  web.removePeer(peer);
  const result = await web.acceptKeyExchange(await exchange(device, older, peer, 100), peer);
  assert.equal(result.outcome, 'keyChanged');
  assert.equal(result.accepted, true);
});

// --- Keys at rest

test('identity keys can\'t be read back, and are per relay and pool', async () => {
  const store = memoryIdentityStore();
  const a = await loadOrCreatePoolIdentity('wss://r', V.poolID, store);
  const again = await loadOrCreatePoolIdentity('wss://r', V.poolID, store);
  const other = await loadOrCreatePoolIdentity('wss://r', '00000000-0000-4000-8000-000000000000', store);
  assert.equal(a.peerId, again.peerId);
  assert.notEqual(a.peerId, other.peerId);
  const record = await store.get(Object.getOwnPropertyDescriptor(a, 'account')!.value as string);
  assert.equal(record!.signingPrivate.extractable, false);
  assert.equal(record!.devicePrivate.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('pkcs8', record!.signingPrivate));
  assert.ok(!Object.values(record!).some((value) => value instanceof Uint8Array && value.length === 64));
});

test('the continuity counter only goes up, whatever the clock does', async () => {
  const id = await loadOrCreatePoolIdentity('wss://r', V.poolID, memoryIdentityStore());
  const first = await id.nextContinuityCounter(2_000_000);
  const second = await id.nextContinuityCounter(1_000_000);
  assert.ok(second > first);
  assert.ok(Number.isSafeInteger(second));
});

test('leaving forgets the identity', async () => {
  const store = memoryIdentityStore();
  const a = await loadOrCreatePoolIdentity('wss://r', V.poolID, store);
  await a.forget();
  const b = await loadOrCreatePoolIdentity('wss://r', V.poolID, store);
  assert.notEqual(a.peerId, b.peerId);
});

test('the raw key earlier versions kept in localStorage is wiped', () => {
  const items = new Map([['stealth_ed25519_private_key', 'secret'], ['stealth_user_profile', '{}']]);
  const fake = { removeItem: (k: string) => items.delete(k) };
  Object.defineProperty(globalThis, 'localStorage', { value: fake, configurable: true });
  wipeLegacyIdentity();
  assert.equal(items.has('stealth_ed25519_private_key'), false);
  assert.equal(items.has('stealth_user_profile'), true);
  Reflect.deleteProperty(globalThis, 'localStorage');
});

test('the host key is pinned across joins', async () => {
  const store = memoryIdentityStore();
  const first = await loadOrCreatePoolIdentity('wss://r', V.poolID, store);
  const realHost = hex(V.hostPublic);
  const otherHost = new Uint8Array(32).fill(7);
  assert.equal(first.hostKeyMatches(otherHost), true, 'nothing is pinned until a join is verified');
  await first.pinHostKey(realHost);
  assert.equal(first.hostKeyMatches(realHost), true);
  assert.equal(first.hostKeyMatches(otherHost), false);
  const again = await loadOrCreatePoolIdentity('wss://r', V.poolID, store);
  assert.equal(again.hostKeyMatches(otherHost), false, 'it survives a reload');
  await again.pinHostKey(otherHost);
  assert.equal(again.hostKeyMatches(otherHost), false, 'a later pin moves nothing');
  await again.forget();
  const fresh = await loadOrCreatePoolIdentity('wss://r', V.poolID, store);
  assert.equal(fresh.hostKeyMatches(otherHost), true, 'leaving the pool ends it');
});

// --- Limits on what can queue

async function highEpochFrame(epoch: number, size: number, sender = 'junk'): Promise<Uint8Array> {
  const key = await importAes(new Uint8Array(32).fill(3));
  return sealOuterFrame(new Uint8Array(size), key, { epoch, session: 11n, counter: BigInt(size + epoch), timestampMillis: V.nowMillis, nonce: new Uint8Array(12) }, poolIdBytes, sender);
}

test('an oversized inbound frame is refused, even a properly sealed one', async () => {
  const h = await makeProtectedMember();
  const key = await importAes(hex(V.frames.frameKey));
  const seal = (size: number, counter: bigint) => sealOuterFrame(new Uint8Array(size), key, { epoch: 1, session: 13n, counter, timestampMillis: V.nowMillis, nonce: crypto.getRandomValues(new Uint8Array(12)) }, poolIdBytes, V.hostPeerID);
  await h.member.receive(await seal(MAX_INBOUND_FRAME_BYTES, 1n), V.hostPeerID);
  assert.equal(h.delivered.length, 0);
  await h.member.receive(await seal(1024, 2n), V.hostPeerID);
  assert.equal(h.delivered.length, 1, 'the control case');
});

test('frames for epochs past newest + 1 don\'t queue', async () => {
  const h = await makeProtectedMember();
  await h.member.receive(await highEpochFrame(2, 100), 'a');
  const queue = () => (h.member as unknown as { inboundQueue: unknown[] }).inboundQueue.length;
  assert.equal(queue(), 1, 'the next epoch waits');
  await h.member.receive(await highEpochFrame(3, 100), 'a');
  await h.member.receive(await highEpochFrame(0xffffffff, 100), 'a');
  assert.equal(queue(), 1, 'nothing further ahead does');
});

test('queued bytes are capped per sender and in total, and junk can\'t push out what is queued', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  const inner = h.member as unknown as { inboundQueue: { sender: string }[]; queuedBytesTotal: number };
  const real = await sealOuterFrame(utf8('real'), await importAes(new Uint8Array(32).fill(4)), { epoch: 1, session: 12n, counter: 1n, timestampMillis: V.nowMillis, nonce: new Uint8Array(12) }, poolIdBytes, V.hostPeerID);
  await h.member.receive(real, V.hostPeerID);
  const chunk = 1024 * 1024;
  for (let i = 0; i < 10; i++) await h.member.receive(await highEpochFrame(1, chunk + i), 'junk');
  const junk = inner.inboundQueue.filter((entry) => entry.sender === 'junk').length;
  assert.ok(junk * chunk <= MAX_QUEUED_BYTES_PER_SENDER, `one sender got ${junk} MiB`);
  assert.ok(inner.inboundQueue.some((entry) => entry.sender === V.hostPeerID), 'the real frame is still there');
  for (let sender = 0; sender < 12; sender++) {
    for (let i = 0; i < 5; i++) await h.member.receive(await highEpochFrame(1, chunk + i, `junk-${sender}`), `junk-${sender}`);
  }
  assert.ok(inner.queuedBytesTotal <= MAX_QUEUED_BYTES_TOTAL);
  assert.ok(inner.inboundQueue.some((entry) => entry.sender === V.hostPeerID), 'still there');
});

test('the line of frames waiting for their turn is bounded', async () => {
  const h = await makeProtectedMember();
  const frame = new Uint8Array(1024);
  const pending: Promise<void>[] = [];
  for (let i = 0; i < MAX_PENDING_RECEIVE_STEPS + 500; i++) pending.push(h.member.receive(frame, V.hostPeerID));
  const inner = h.member as unknown as { pendingReceiveSteps: number };
  assert.ok(inner.pendingReceiveSteps <= MAX_PENDING_RECEIVE_STEPS);
  await Promise.all(pending);
  await h.member.settled();
  assert.equal(inner.pendingReceiveSteps, 0, 'and it drains');
  const big = new Uint8Array(2 * 1024 * 1024);
  const burst: Promise<void>[] = [];
  for (let i = 0; i < 40; i++) burst.push(h.member.receive(big, V.hostPeerID));
  assert.ok((h.member as unknown as { pendingReceiveBytes: number }).pendingReceiveBytes <= MAX_PENDING_RECEIVE_BYTES);
  await Promise.all(burst);
});

test('one frame that fails doesn\'t take the queue with it', async () => {
  let calls = 0;
  const h = await makeMember({ deliver: () => { calls += 1; if (calls === 1) throw new Error('boom'); } });
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  for (const wire of V.frames.fromHost as string[]) await h.member.receive(b64(wire), V.hostPeerID);
  await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
  for (const wire of V.firstJoin.announcementsWire as string[]) await h.member.receive(b64(wire), V.hostPeerID);
  await h.member.settled();
  assert.equal(calls, 2, 'the second frame was still delivered');
});

// --- The relay's address

test('an address that only looks local is not talked to in the clear', () => {
  assert.equal(relayUrlFromInvitation('ws://127.0.0.1@evil.com/', false), 'wss://127.0.0.1@evil.com/');
  assert.equal(relayUrlFromInvitation('ws://127.evil.com:9090', false), 'wss://127.evil.com:9090');
  assert.equal(relayUrlFromInvitation('ws://localhost.evil.com', false), 'wss://localhost.evil.com');
  assert.equal(relayUrlFromInvitation('ws://not a url', false), 'wss://not a url');
  assert.equal(relayUrlFromInvitation('ws://localhost:9090', false), 'ws://localhost:9090');
  assert.equal(relayUrlFromInvitation('ws://LOCALHOST:9090', false), 'ws://LOCALHOST:9090', 'the URL parser decides, not the spelling');
  assert.equal(relayUrlFromInvitation('ws://[::1]:9090', false), 'ws://[::1]:9090');
  assert.equal(relayUrlFromInvitation('ws://127.1.2.3:9090/x', false), 'ws://127.1.2.3:9090/x');
});

test('the unsupported-browser error says what to do', () => {
  assert.match(new UnsupportedBrowserError().message, /Update to a current version/);
});
