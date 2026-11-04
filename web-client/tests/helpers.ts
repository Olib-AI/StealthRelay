import { readFileSync } from 'node:fs';
import { hexDecode } from '../src/utils/hex.ts';
import { base64DecodeStrict } from '../src/utils/base64.ts';
import { concatBytes, raw } from '../src/utils/bytes.ts';
import type { RawPublicKeyPair } from '../src/crypto/webcrypto.ts';
import { MemberTransportSecurity } from '../src/transport/pool-transport-security.ts';
import type { MemberTransportSecurityOptions, OuterLayerStatus } from '../src/transport/pool-transport-security.ts';

/** Generated from the real Swift code by a scratch tool outside this repo. Test keys only. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const V: any = JSON.parse(readFileSync(new URL('./vectors/swift-vectors.json', import.meta.url), 'utf8'));

export const hex = hexDecode;
export function b64(text: string): Uint8Array {
  const out = base64DecodeStrict(text);
  if (!out) throw new Error('bad base64 in vector');
  return out;
}

const ED25519_PKCS8 = hexDecode('302e020100300506032b657004220420');
const X25519_PKCS8 = hexDecode('302e020100300506032b656e04220420');

export function importEd25519(seed: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('pkcs8', raw(concatBytes(ED25519_PKCS8, seed)), 'Ed25519', false, ['sign']);
}

export async function importX25519(seed: Uint8Array, publicKey: Uint8Array): Promise<RawPublicKeyPair> {
  const privateKey = await crypto.subtle.importKey('pkcs8', raw(concatBytes(X25519_PKCS8, seed)), 'X25519', false, ['deriveBits']);
  return { privateKey, publicKey };
}

export function importAes(key: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw(key), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export interface Harness {
  member: MemberTransportSecurity;
  sent: { data: Uint8Array; targets: string[] | null }[];
  delivered: { text: string; sender: string }[];
  statuses: OuterLayerStatus[];
  clock: { now: number };
  inviteKey: Uint8Array;
}

/** A member on the vector identity and clock. Its first request matches Swift's first join byte for byte. */
export async function makeMember(overrides: Partial<MemberTransportSecurityOptions> = {}): Promise<Harness> {
  const signing = await importEd25519(hex(V.memberSeed));
  const ephemeral = await importX25519(hex(V.memberEphSeed), hex(V.memberEphPublic));
  const sent: Harness['sent'] = [];
  const delivered: Harness['delivered'] = [];
  const statuses: OuterLayerStatus[] = [];
  const clock = { now: V.nowMillis as number };
  const inviteKey = hex(V.fragment.inviteKey);
  const nonces = [hex(V.firstJoin.nonce), hex(V.rotation.nonce)];
  const member = new MemberTransportSecurity({
    poolId: V.poolID,
    poolIdBytes: hex((V.poolID as string).replace(/-/g, '')),
    localPeerId: V.memberPeerID,
    identity: {
      publicKey: hex(V.memberPublic),
      sign: async (message) => new Uint8Array(await crypto.subtle.sign('Ed25519', signing, raw(message))),
    },
    invite: { inviteKey, hostIdentityKey: hex(V.hostPublic) },
    enrolled: false,
    now: () => clock.now,
    newEphemeral: async () => ephemeral,
    newNonce: () => nonces.shift() ?? crypto.getRandomValues(new Uint8Array(32)),
    send: (data, targets) => sent.push({ data, targets }),
    deliver: (data, sender) => { delivered.push({ text: new TextDecoder().decode(data), sender }); },
    onStatusChange: (status) => statuses.push(status),
    ...overrides,
  });
  return { member, sent, delivered, statuses, clock, inviteKey };
}

/** Connected, granted and told the pool is protected: the state of a normal first join. */
export async function makeProtectedMember(overrides: Partial<MemberTransportSecurityOptions> = {}): Promise<Harness> {
  const h = await makeMember(overrides);
  h.member.connected(V.hostPeerID);
  await h.member.settled();
  await h.member.receive(b64(V.firstJoin.grantWire), V.hostPeerID);
  for (const wire of V.firstJoin.announcementsWire as string[]) await h.member.receive(b64(wire), V.hostPeerID);
  await h.member.settled();
  return h;
}
