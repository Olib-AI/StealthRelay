// SealedInviteCard — TypeScript mirror of
// LocalPackages/ConnectionPool/Sources/Crypto/SealedInviteCard.swift.
// Byte layout MUST stay identical to the Swift implementation.

export const STCARD_MAGIC = new Uint8Array([0x53, 0x54, 0x43, 0x44]); // "STCD"
export const STCARD_VERSION = 0x01;
export const STCARD_FILE_EXTENSION = 'stcard';
export const STCARD_UTI = 'com.olibai.stealthos.card';
export const STCARD_MIME = 'application/vnd.stealthos.card';

/** Marker prefix for QR-encoded cards carried as base64 text. */
export const STCARD_QR_TEXT_PREFIX = 'stcard1:';

/** Decode a `stcard1:base64...` QR text payload to raw card bytes. */
export function decodeCardQRText(text: string): Uint8Array | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith(STCARD_QR_TEXT_PREFIX)) return null;
  const b64 = trimmed.slice(STCARD_QR_TEXT_PREFIX.length).trim();
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

const MAX_URL_LEN = 8 * 1024;

export type CardErrorCode =
  | 'truncated'
  | 'badMagic'
  | 'unsupportedVersion'
  | 'urlTooLarge'
  | 'malformedURL';

export class CardError extends Error {
  readonly code: CardErrorCode;
  constructor(code: CardErrorCode, message?: string) {
    super(message ?? code);
    this.name = 'CardError';
    this.code = code;
  }
}

export function encodeCard(url: string): Uint8Array {
  const urlBytes = new TextEncoder().encode(url);
  if (urlBytes.length > MAX_URL_LEN || urlBytes.length > 0xffff) {
    throw new CardError('urlTooLarge');
  }
  const out = new Uint8Array(7 + urlBytes.length);
  out.set(STCARD_MAGIC, 0);
  out[4] = STCARD_VERSION;
  out[5] = (urlBytes.length >> 8) & 0xff;
  out[6] = urlBytes.length & 0xff;
  out.set(urlBytes, 7);
  return out;
}

export function decodeCard(data: Uint8Array): string {
  if (data.length < 7) throw new CardError('truncated');
  for (let i = 0; i < STCARD_MAGIC.length; i++) {
    if (data[i] !== STCARD_MAGIC[i]) throw new CardError('badMagic');
  }
  if (data[4] !== STCARD_VERSION) {
    throw new CardError('unsupportedVersion', `version=${data[4]}`);
  }
  const len = (data[5]! << 8) | data[6]!;
  if (len > MAX_URL_LEN) throw new CardError('urlTooLarge');
  if (data.length < 7 + len) throw new CardError('truncated');
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(data.slice(7, 7 + len));
  } catch {
    throw new CardError('malformedURL');
  }
}
