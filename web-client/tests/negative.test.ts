// What this client must refuse: wrong keys, tampering, bad signatures, replays, downgrades.
import test from 'node:test';
import assert from 'node:assert/strict';
import { V, b64, hex, importAes, importX25519, makeMember, makeProtectedMember } from './helpers.ts';
import { base64Encode } from '../src/utils/base64.ts';
import { InvitationError, parseInvitationUrl, parseTransportFragment, relayUrlFromInvitation } from '../src/crypto/invitation.ts';
import { decodeControlMessage, encodeControlMessage } from '../src/transport/control-message.ts';
import { openOuterFrame, sealOuterFrame } from '../src/transport/outer-frame.ts';
import { ChatEncryption, continuityStatement, deriveChatKey } from '../src/crypto/encryption.ts';
import { aesGcmOpenCombined, generateEd25519, generateX25519, UnsupportedBrowserError } from '../src/crypto/webcrypto.ts';
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
});

test('a key grant not signed by the invitation\'s host is refused', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  const forged = decodeControlMessage(b64(V.firstJoin.grantWire))!;
  forged.hostSignature = new Uint8Array(64).fill(1);
  await h.member.receive(encodeControlMessage(forged), V.hostPeerID);
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
    for (const wire of V.firstJoin.announcementsWire as string[]) await h.member.receive(b64(wire), V.hostPeerID);
    await h.member.settled();
    assert.equal(h.member.status.kind, 'securing', `tampered ${field}`);
  }
});

test('a grant from anyone but the host is ignored', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  await h.member.receive(b64(V.firstJoin.grantWire), 'someone-else');
  for (const wire of V.firstJoin.announcementsWire as string[]) await h.member.receive(b64(wire), V.hostPeerID);
  await h.member.settled();
  assert.equal(h.member.status.kind, 'securing');
});

test('a grant sealed for another invite key opens nothing', async () => {
  const h = await makeMember({ invite: { inviteKey: new Uint8Array(32).fill(0xee), hostIdentityKey: hex(V.hostPublic) } });
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
  for (const wire of V.firstJoin.announcementsWire as string[]) await h.member.receive(b64(wire), V.hostPeerID);
  await h.member.settled();
  assert.equal(h.member.status.kind, 'securing');
});

test('a grant answering an old request is refused', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  // The next request has another nonce and so another hash: the old grant no longer answers it.
  h.clock.now += 6000;
  await h.member.tick();
  await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
  for (const wire of V.firstJoin.announcementsWire as string[]) await h.member.receive(b64(wire), V.hostPeerID);
  await h.member.settled();
  assert.equal(h.member.status.kind, 'securing');
});

test('a replayed grant changes nothing', async () => {
  const h = await makeProtectedMember();
  await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
  assert.deepEqual(h.member.status, { kind: 'protected', epoch: 1, excludedPeers: [] });
});

test('stale and future control messages are refused', async () => {
  for (const shift of [301_000, -61_000]) {
    const h = await makeMember();
    h.member.connected(V.hostPeerID);
    await h.member.settled();
    h.clock.now += shift;
    await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
    await h.member.settled();
    assert.equal(h.member.status.kind, 'securing', `shift ${shift}`);
  }
});

test('a control message for another pool is ignored', async () => {
  const h = await makeMember();
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  const grant = decodeControlMessage(b64(V.firstJoin.grantWire))!;
  grant.poolID = '00000000-0000-4000-8000-000000000000';
  await h.member.receive(encodeControlMessage(grant), V.hostPeerID);
  assert.equal(h.member.status.kind, 'securing');
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
  const right = await deriveChatKey(web.privateKey, web.publicKey, hex(e.hostChatPublic));
  const wrongPeer = await generateX25519();
  const wrong = await deriveChatKey(web.privateKey, web.publicKey, wrongPeer.publicKey);
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

test('the unsupported-browser error says what to do', () => {
  assert.match(new UnsupportedBrowserError().message, /Update to a current version/);
});
