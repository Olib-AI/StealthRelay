import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { base64UrlDecodeStrict } from '../utils/base64.ts';
import { be64, concatBytes, utf8 } from '../utils/bytes.ts';
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

/**
 * What the host adds to an invitation as a URL fragment (TransportInviteSecret.swift):
 * `#v2.<base64url(0x02 || inviteKey(32) || hostIdentityKey(32))>`. The relay builds the rest of the
 * invitation and never sees this part. `inviteKey` is secret: it stays in memory only, and the
 * security layer clears it as soon as the host has enrolled this member.
 */
export interface TransportInvite {
  inviteKey: Uint8Array;
  hostIdentityKey: Uint8Array;
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
  transport: TransportInvite;
}

export type InvitationErrorCode =
  | 'not_an_invitation'
  | 'damaged'
  | 'bad_fragment'
  | 'unsupported_fragment'
  | 'no_fragment';

const INVITATION_ERROR_TEXT: Record<InvitationErrorCode, string> = {
  not_an_invitation: 'This is not a StealthOS invitation. An invitation starts with stealth://invite/.',
  damaged: 'This invitation is damaged or incomplete. Copy it again, or ask the host for a new one.',
  bad_fragment: "This invitation's security key is damaged, so it can't be trusted. Copy it again, or ask the host for a new one.",
  unsupported_fragment: 'This invitation uses a security format this page does not know yet. Reload the page and try again.',
  no_fragment: 'This invitation has no security key, so this pool could not be protected. Make sure you copied all of it, including the part after the #. Otherwise ask the host for a new invitation from a current version of StealthOS.',
};

export class InvitationError extends Error {
  readonly code: InvitationErrorCode;
  constructor(code: InvitationErrorCode) {
    super(INVITATION_ERROR_TEXT[code]);
    this.name = 'InvitationError';
    this.code = code;
  }
}

const INVITE_PREFIX = 'stealth://invite/';
const FRAGMENT_PREFIX = 'v2.';
const FRAGMENT_VERSION = 0x02;
const FRAGMENT_LENGTH = 65;

/**
 * Parses the fragment's value (without the `#`). A fragment that is present but malformed is
 * refused, so a tampered link can't pass for one with no fragment.
 */
export function parseTransportFragment(fragment: string): TransportInvite {
  if (!fragment.startsWith(FRAGMENT_PREFIX)) throw new InvitationError('bad_fragment');
  const bytes = base64UrlDecodeStrict(fragment.slice(FRAGMENT_PREFIX.length));
  if (!bytes || bytes.length !== FRAGMENT_LENGTH) throw new InvitationError('bad_fragment');
  if (bytes[0] !== FRAGMENT_VERSION) throw new InvitationError('unsupported_fragment');
  return { inviteKey: bytes.slice(1, 33), hostIdentityKey: bytes.slice(33, 65) };
}

function byteArray(value: unknown, length: number): Uint8Array {
  if (!Array.isArray(value) || value.length !== length) throw new InvitationError('damaged');
  for (const item of value) {
    if (!Number.isInteger(item) || (item as number) < 0 || (item as number) > 255) throw new InvitationError('damaged');
  }
  return Uint8Array.from(value as number[]);
}

/** @throws InvitationError, always with text fit to show to the person who pasted the link. */
export function parseInvitationUrl(url: string): ParsedInvitation {
  const trimmed = url.trim();
  if (!trimmed.startsWith(INVITE_PREFIX)) throw new InvitationError('not_an_invitation');

  const rest = trimmed.slice(INVITE_PREFIX.length);
  const hash = rest.indexOf('#');
  const payload = hash === -1 ? rest : rest.slice(0, hash);
  const fragment = hash === -1 ? '' : rest.slice(hash + 1);

  const jsonBytes = base64UrlDecodeStrict(payload);
  if (!jsonBytes || jsonBytes.length === 0) throw new InvitationError('damaged');
  let wire: Partial<TokenWire> | null;
  try {
    wire = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(jsonBytes)) as Partial<TokenWire> | null;
  } catch {
    throw new InvitationError('damaged');
  }
  if (!wire || typeof wire !== 'object') throw new InvitationError('damaged');
  if (typeof wire.addr !== 'string' || wire.addr.length === 0 || typeof wire.exp !== 'number') {
    throw new InvitationError('damaged');
  }

  // Same lengths as RemotePoolService.parseInvitationURL.
  const tokenId = byteArray(wire.id, 16);
  const tokenSecret = byteArray(wire.secret, 32);
  const poolIdBytes = byteArray(wire.pool, 16);
  const hostFingerprint = byteArray(wire.fp, 8);

  if (fragment.length === 0) throw new InvitationError('no_fragment');
  const transport = parseTransportFragment(fragment);

  return {
    tokenId,
    tokenIdHex: hexEncode(tokenId),
    tokenSecret,
    poolIdBytes,
    poolId: bytesToUuid(poolIdBytes),
    hostFingerprint,
    expiry: wire.exp,
    maxUses: typeof wire.max === 'number' ? wire.max : 0,
    serverAddress: wire.addr,
    signature: typeof wire.sig === 'string' ? wire.sig : '',
    transport,
  };
}

export function isInvitationExpired(invitation: ParsedInvitation): boolean {
  return Date.now() / 1000 > invitation.expiry;
}

/** The URL's real host, not whatever text comes first: `ws://127.0.0.1@evil.com` is evil.com. */
function isLoopbackUrl(address: string): boolean {
  let host: string;
  try {
    host = new URL(address).hostname;
  } catch {
    return false;
  }
  return host === 'localhost' || host === '[::1]' || /^127(\.\d{1,3}){3}$/.test(host);
}

/**
 * The relay's address, as RemotePoolService.parseInvitationURL treats it: an address from an
 * invitation is never talked to in cleartext. `ws://` and a bare `host:port` become `wss://`. Only a
 * relay on this machine stays on `ws://`, or any `ws://` in a development build.
 */
export function relayUrlFromInvitation(address: string, allowCleartext: boolean): string {
  if (address.startsWith('wss://')) return address;
  if (address.startsWith('ws://')) {
    return allowCleartext || isLoopbackUrl(address) ? address : `wss://${address.slice('ws://'.length)}`;
  }
  return `wss://${address}`;
}

export function computeJoinProof(
  tokenSecret: Uint8Array,
  tokenId: Uint8Array,
  poolIdBytes: Uint8Array,
  timestamp: number,
  nonce: Uint8Array,
): Uint8Array {
  const info = concatBytes(utf8('STEALTH_INVITE_V1'), tokenId);
  const vk = hkdf(sha256, tokenSecret, poolIdBytes, info, 32);
  const msg = concatBytes(utf8('JOIN'), poolIdBytes, be64(Math.floor(timestamp)), nonce);
  return hmac(sha256, vk, msg);
}

/** `"STEALTH_MEMBER_REJOIN_V1:" || pool_id(16) || timestamp i64 BE || nonce`. */
export function memberRejoinTranscript(poolIdBytes: Uint8Array, timestamp: number, nonce: Uint8Array): Uint8Array {
  return concatBytes(utf8('STEALTH_MEMBER_REJOIN_V1:'), poolIdBytes, be64(timestamp), nonce);
}
