import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { base64UrlDecode } from '../utils/base64.ts';
import { hexEncode } from '../utils/hex.ts';
import { bytesToUuid } from '../utils/uuid.ts';

export interface TokenWire {
  id: number[];
  secret: number[];
  pool: number[];
  fp: number[];
  exp: number;
  max: number;
  addr: string;
  sig: string;
}

export interface ParsedInvitation {
  tokenId: Uint8Array;
  tokenIdHex: string;
  tokenSecret: Uint8Array;
  poolIdBytes: Uint8Array;
  poolId: string;
  hostFingerprint: Uint8Array;
  expiry: number;
  maxUses: number;
  serverAddress: string;
  signature: string;
}

const INVITE_PREFIX = 'stealth://invite/';

function numberArrayToUint8Array(arr: number[]): Uint8Array {
  return new Uint8Array(arr);
}

export function parseInvitationUrl(url: string): ParsedInvitation {
  const trimmed = url.trim();

  let payload: string;
  if (trimmed.startsWith(INVITE_PREFIX)) {
    payload = trimmed.slice(INVITE_PREFIX.length);
  } else {
    throw new Error('Invalid invitation URL: must start with stealth://invite/');
  }

  const jsonBytes = base64UrlDecode(payload);
  const jsonStr = new TextDecoder().decode(jsonBytes);
  const wire: TokenWire = JSON.parse(jsonStr) as TokenWire;

  if (!wire.id || !wire.secret || !wire.pool || !wire.addr) {
    throw new Error('Invalid invitation: missing required fields');
  }

  const tokenId = numberArrayToUint8Array(wire.id);
  const tokenSecret = numberArrayToUint8Array(wire.secret);
  const poolIdBytes = numberArrayToUint8Array(wire.pool);
  const hostFingerprint = numberArrayToUint8Array(wire.fp);

  if (tokenId.length !== 16) throw new Error('Invalid token ID length');
  if (tokenSecret.length !== 32) throw new Error('Invalid token secret length');
  if (poolIdBytes.length !== 16) throw new Error('Invalid pool ID length');

  return {
    tokenId,
    tokenIdHex: hexEncode(tokenId),
    tokenSecret,
    poolIdBytes,
    poolId: bytesToUuid(poolIdBytes),
    hostFingerprint,
    expiry: wire.exp,
    maxUses: wire.max,
    serverAddress: wire.addr,
    signature: wire.sig,
  };
}

export function isInvitationExpired(invitation: ParsedInvitation): boolean {
  return Date.now() / 1000 > invitation.expiry;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function int64BigEndian(value: number): Uint8Array {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setBigUint64(0, BigInt(Math.floor(value)));
  return new Uint8Array(buf);
}

const TEXT_ENCODER = new TextEncoder();

export function computeJoinProof(
  tokenSecret: Uint8Array,
  tokenId: Uint8Array,
  poolIdBytes: Uint8Array,
  timestamp: number,
  nonce: Uint8Array,
): Uint8Array {
  const infoPrefix = TEXT_ENCODER.encode('STEALTH_INVITE_V1');
  const info = concat(infoPrefix, tokenId);
  const vk = hkdf(sha256, tokenSecret, poolIdBytes, info, 32);

  const joinPrefix = TEXT_ENCODER.encode('JOIN');
  const tsBytes = int64BigEndian(timestamp);
  const msg = concat(joinPrefix, poolIdBytes, tsBytes, nonce);

  return hmac(sha256, vk, msg);
}
