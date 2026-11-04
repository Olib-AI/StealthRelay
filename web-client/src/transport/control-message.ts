// Control messages that distribute the pool transport secret: a byte-exact port of
// LocalPackages/ConnectionPool/Sources/Transport/OuterLayer/TransportControlMessage.swift.
// They travel through the relay as `"SWK2" || JSON`, so every field is public or sealed.
//
//   request      = lp("STEALTH_WS_KEY_REQUEST_V2") || poolID(16) || i64 timestampMillis
//                  || lp(memberPeerID) || memberIdentityKey(32) || memberEphemeral(32)
//                  || nonce(32) || lp(inviteKeyID or empty)
//   grant        = lp("STEALTH_WS_KEY_GRANT_V2") || poolID(16) || SHA-256(request)
//                  || u32 epoch || hostEphemeral(32) || lp(sealedSecret) || i64 timestampMillis
//   announcement = lp("STEALTH_WS_ANNOUNCE_V2") || poolID(16) || i64 timestampMillis
//                  || u32 epoch || u8 protected || u32 count || lp(removed)...
//                  || u32 count || lp(legacy)...

import { base64DecodeStrict, base64Encode } from '../utils/base64.ts';
import { be32, be64, concatBytes, lengthPrefixed, utf8 } from '../utils/bytes.ts';
import { hkdfToAesKey } from '../crypto/webcrypto.ts';

export type ControlKind = 'keyRequest' | 'keyGrant' | 'announcement';

export interface ControlMessage {
  kind: ControlKind;
  poolID: string;
  timestampMillis: number;
  memberPeerID?: string;
  memberIdentityKey?: Uint8Array;
  memberEphemeral?: Uint8Array;
  nonce?: Uint8Array;
  inviteKeyID?: Uint8Array;
  inviteProof?: Uint8Array;
  memberSignature?: Uint8Array;
  requestHash?: Uint8Array;
  hostEphemeral?: Uint8Array;
  sealedSecret?: Uint8Array;
  epoch?: number;
  hostSignature?: Uint8Array;
  protected?: boolean;
  removedPeerIDs?: string[];
  legacyPeerIDs?: string[];
}

const MAGIC = utf8('SWK2');
const MAX_CONTROL_SIZE = 16 * 1024;
const BYTE_FIELDS = [
  'memberIdentityKey', 'memberEphemeral', 'nonce', 'inviteKeyID', 'inviteProof', 'memberSignature',
  'requestHash', 'hostEphemeral', 'sealedSecret', 'hostSignature',
] as const;

export function isControlFrame(data: Uint8Array): boolean {
  return data.length >= 4 && data[0] === MAGIC[0] && data[1] === MAGIC[1] && data[2] === MAGIC[2] && data[3] === MAGIC[3];
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

/** Like `JSONDecoder`, a field of the wrong type refuses the whole message. */
export function decodeControlMessage(data: Uint8Array): ControlMessage | null {
  if (!isControlFrame(data) || data.length > MAX_CONTROL_SIZE) return null;
  let json: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data.subarray(4)));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    json = parsed as Record<string, unknown>;
  } catch {
    return null;
  }
  const { kind, poolID, timestampMillis, epoch, memberPeerID, removedPeerIDs, legacyPeerIDs } = json;
  if (kind !== 'keyRequest' && kind !== 'keyGrant' && kind !== 'announcement') return null;
  if (typeof poolID !== 'string' || !Number.isSafeInteger(timestampMillis)) return null;
  const message: ControlMessage = { kind, poolID, timestampMillis: timestampMillis as number };

  for (const field of BYTE_FIELDS) {
    const value = json[field];
    if (value === undefined || value === null) continue;
    if (typeof value !== 'string') return null;
    const bytes = base64DecodeStrict(value);
    if (!bytes) return null;
    message[field] = bytes;
  }
  if (epoch !== undefined && epoch !== null) {
    if (!Number.isInteger(epoch) || (epoch as number) < 0 || (epoch as number) > 0xffffffff) return null;
    message.epoch = epoch as number;
  }
  if (memberPeerID !== undefined && memberPeerID !== null) {
    if (typeof memberPeerID !== 'string') return null;
    message.memberPeerID = memberPeerID;
  }
  if (json.protected !== undefined && json.protected !== null) {
    if (typeof json.protected !== 'boolean') return null;
    message.protected = json.protected;
  }
  if (removedPeerIDs !== undefined && removedPeerIDs !== null) {
    if (!isStringArray(removedPeerIDs)) return null;
    message.removedPeerIDs = removedPeerIDs;
  }
  if (legacyPeerIDs !== undefined && legacyPeerIDs !== null) {
    if (!isStringArray(legacyPeerIDs)) return null;
    message.legacyPeerIDs = legacyPeerIDs;
  }
  return message;
}

export function encodeControlMessage(message: ControlMessage): Uint8Array {
  const json: Record<string, unknown> = { ...message };
  for (const field of BYTE_FIELDS) {
    const value = message[field];
    if (value) json[field] = base64Encode(value);
  }
  return concatBytes(MAGIC, utf8(JSON.stringify(json)));
}

function header(label: string, poolId: Uint8Array): Uint8Array {
  return concatBytes(lengthPrefixed(utf8(label)), poolId);
}

/** `null` if a required field is missing or the wrong size. */
export function requestTranscript(message: ControlMessage, poolId: Uint8Array): Uint8Array | null {
  const { memberPeerID, memberIdentityKey, memberEphemeral, nonce, inviteKeyID } = message;
  if (message.kind !== 'keyRequest' || memberPeerID === undefined) return null;
  if (memberIdentityKey?.length !== 32 || memberEphemeral?.length !== 32 || nonce?.length !== 32) return null;
  return concatBytes(
    header('STEALTH_WS_KEY_REQUEST_V2', poolId),
    be64(message.timestampMillis),
    lengthPrefixed(utf8(memberPeerID)),
    memberIdentityKey,
    memberEphemeral,
    nonce,
    lengthPrefixed(inviteKeyID ?? new Uint8Array(0)),
  );
}

export function grantTranscript(message: ControlMessage, poolId: Uint8Array): Uint8Array | null {
  const { requestHash, epoch, hostEphemeral, sealedSecret } = message;
  if (message.kind !== 'keyGrant' || epoch === undefined || !sealedSecret) return null;
  if (requestHash?.length !== 32 || hostEphemeral?.length !== 32) return null;
  return concatBytes(
    header('STEALTH_WS_KEY_GRANT_V2', poolId),
    requestHash,
    be32(epoch),
    hostEphemeral,
    lengthPrefixed(sealedSecret),
    be64(message.timestampMillis),
  );
}

export function announcementTranscript(message: ControlMessage, poolId: Uint8Array): Uint8Array | null {
  if (message.kind !== 'announcement' || message.epoch === undefined || message.protected === undefined) return null;
  const parts: Uint8Array[] = [
    header('STEALTH_WS_ANNOUNCE_V2', poolId),
    be64(message.timestampMillis),
    be32(message.epoch),
    new Uint8Array([message.protected ? 1 : 0]),
  ];
  for (const list of [message.removedPeerIDs ?? [], message.legacyPeerIDs ?? []]) {
    parts.push(be32(list.length));
    for (const id of list) parts.push(lengthPrefixed(utf8(id)));
  }
  return concatBytes(...parts);
}

/**
 * The key a grant's secret is sealed under:
 * HKDF-SHA256(X25519 output, salt = SHA-256(request), info = "STEALTH_WS_TRANSPORT_KEY_V2" || u32 epoch || inviteKey-or-empty).
 */
export function deriveSealingKey(
  sharedSecret: Uint8Array,
  requestHash: Uint8Array,
  epoch: number,
  inviteKey: Uint8Array | null,
): Promise<CryptoKey> {
  const info = concatBytes(utf8('STEALTH_WS_TRANSPORT_KEY_V2'), be32(epoch), inviteKey ?? new Uint8Array(0));
  return hkdfToAesKey(sharedSecret, requestHash, info, ['decrypt']).finally(() => info.fill(0));
}

export function secretAad(poolId: Uint8Array, epoch: number): Uint8Array {
  return concatBytes(poolId, be32(epoch));
}
