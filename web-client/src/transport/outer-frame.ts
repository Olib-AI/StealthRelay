// The outer layer's frame: a byte-exact port of
// LocalPackages/ConnectionPool/Sources/Transport/OuterLayer/OuterFrameV2.swift and
// Sources/Security/SlidingReplayWindow.swift.
//
//   0   4  "SWO2"
//   4   4  epoch            u32 BE
//   8   8  sender session   random per sender connection
//  16   8  counter          u64 BE, strictly increasing per session
//  24   8  timestamp        i64 BE, sender clock, milliseconds since 1970
//  32  12  nonce            random
//  44   n  AES-256-GCM ciphertext of the app frame
// 44+n 16  tag
//
// key = HKDF-SHA256(ikm = pool transport secret, salt = poolID(16), info = "STEALTH_WS_OUTER_V2" || epoch BE)
// AAD = bytes 0..<44 || poolID(16) || u32 BE len || sender peer ID (UTF-8)

import { be32, be64, concatBytes, raw, utf8 } from '../utils/bytes.ts';
import { hkdfToAesKey } from '../crypto/webcrypto.ts';

export const HEADER_LENGTH = 44;
export const TAG_LENGTH = 16;
export const MAX_AGE_MS = 300_000;
export const MAX_FUTURE_SKEW_MS = 60_000;

const MAGIC = utf8('SWO2');

export interface OuterHeader {
  epoch: number;
  session: bigint;
  counter: bigint;
  timestampMillis: number;
  nonce: Uint8Array;
}

export function isOuterFrame(data: Uint8Array): boolean {
  return data.length >= 4 && data[0] === MAGIC[0] && data[1] === MAGIC[1] && data[2] === MAGIC[2] && data[3] === MAGIC[3];
}

export function encodeHeader(header: OuterHeader): Uint8Array {
  const session = new Uint8Array(8);
  new DataView(session.buffer).setBigUint64(0, header.session);
  const counter = new Uint8Array(8);
  new DataView(counter.buffer).setBigUint64(0, header.counter);
  return concatBytes(MAGIC, be32(header.epoch), session, counter, be64(header.timestampMillis), header.nonce);
}

/** Parses the header without authenticating it. `null` for anything malformed. */
export function parseHeader(data: Uint8Array): OuterHeader | null {
  if (data.length < HEADER_LENGTH + TAG_LENGTH || !isOuterFrame(data)) return null;
  const view = new DataView(data.buffer, data.byteOffset, HEADER_LENGTH);
  return {
    epoch: view.getUint32(4),
    session: view.getBigUint64(8),
    counter: view.getBigUint64(16),
    timestampMillis: Number(view.getBigInt64(24)),
    nonce: data.slice(32, 44),
  };
}

export function outerAad(header: Uint8Array, poolId: Uint8Array, senderPeerId: string): Uint8Array {
  const sender = utf8(senderPeerId);
  return concatBytes(header, poolId, be32(sender.length), sender);
}

/** The frame key for an epoch. `secret` is the caller's to clear. */
export function deriveFrameKey(secret: Uint8Array, poolId: Uint8Array, epoch: number): Promise<CryptoKey> {
  return hkdfToAesKey(secret, poolId, concatBytes(utf8('STEALTH_WS_OUTER_V2'), be32(epoch)));
}

export async function sealOuterFrame(
  plaintext: Uint8Array,
  key: CryptoKey,
  header: OuterHeader,
  poolId: Uint8Array,
  senderPeerId: string,
): Promise<Uint8Array> {
  const encoded = encodeHeader(header);
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: raw(header.nonce), additionalData: raw(outerAad(encoded, poolId, senderPeerId)) },
    key,
    raw(plaintext),
  );
  return concatBytes(encoded, new Uint8Array(sealed));
}

/** Authenticates and decrypts. `null` for any failure. */
export async function openOuterFrame(
  data: Uint8Array,
  key: CryptoKey,
  poolId: Uint8Array,
  senderPeerId: string,
): Promise<{ header: OuterHeader; plaintext: Uint8Array } | null> {
  const header = parseHeader(data);
  if (!header) return null;
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: raw(header.nonce),
        additionalData: raw(outerAad(data.subarray(0, HEADER_LENGTH), poolId, senderPeerId)),
      },
      key,
      raw(data.subarray(HEADER_LENGTH)),
    );
    return { header, plaintext: new Uint8Array(plaintext) };
  } catch {
    return null;
  }
}

const WINDOW_WIDTH = 1n << 16n;

/** Accepts each counter at most once, and older ones only within the window (RFC 6479 style). */
export class SlidingReplayWindow {
  private readonly bits = new Uint8Array(Number(WINDOW_WIDTH) / 8);
  private top = 0n;
  private started = false;

  wouldAccept(counter: bigint): boolean {
    if (!this.started || counter > this.top) return true;
    if (this.top - counter >= WINDOW_WIDTH) return false;
    return !this.isSet(counter);
  }

  accept(counter: bigint): boolean {
    if (!this.wouldAccept(counter)) return false;
    if (!this.started) {
      this.started = true;
      this.top = counter;
    } else if (counter > this.top) {
      this.advance(counter);
    }
    this.write(counter, true);
    return true;
  }

  private isSet(counter: bigint): boolean {
    const bit = Number(counter % WINDOW_WIDTH);
    return (this.bits[bit >> 3]! & (1 << (bit & 7))) !== 0;
  }

  private write(counter: bigint, value: boolean): void {
    const bit = Number(counter % WINDOW_WIDTH);
    if (value) this.bits[bit >> 3]! |= 1 << (bit & 7);
    else this.bits[bit >> 3]! &= ~(1 << (bit & 7));
  }

  private advance(counter: bigint): void {
    if (counter - this.top >= WINDOW_WIDTH) {
      this.bits.fill(0);
    } else {
      for (let k = this.top + 1n; k <= counter; k++) this.write(k, false);
    }
    this.top = counter;
  }
}

const MAX_SESSIONS = 512;

/** Per-(sender, session) replay windows plus freshness. */
export class OuterFrameReplayGuard {
  private readonly windows = new Map<string, SlidingReplayWindow>();

  private static key(sender: string, session: bigint): string {
    return `${session}:${sender}`;
  }

  isFresh(header: OuterHeader, nowMillis: number): boolean {
    const age = nowMillis - header.timestampMillis;
    return age <= MAX_AGE_MS && age >= -MAX_FUTURE_SKEW_MS;
  }

  wouldAccept(header: OuterHeader, sender: string): boolean {
    return this.windows.get(OuterFrameReplayGuard.key(sender, header.session))?.wouldAccept(header.counter) ?? true;
  }

  accept(header: OuterHeader, sender: string): boolean {
    const key = OuterFrameReplayGuard.key(sender, header.session);
    let window = this.windows.get(key);
    if (!window) {
      window = new SlidingReplayWindow();
      this.windows.set(key, window);
      if (this.windows.size > MAX_SESSIONS) {
        const oldest = this.windows.keys().next().value;
        if (oldest !== undefined) this.windows.delete(oldest);
      }
    }
    return window.accept(header.counter);
  }
}
