// WebCrypto primitives. Private keys are created non-extractable, and symmetric keys are derived
// into non-extractable CryptoKeys, so script on the page can use them but never read them.

import { raw, utf8, concatBytes, isAllZero } from '../utils/bytes.ts';

export const UNSUPPORTED_BROWSER_MESSAGE =
  "This browser can't secure a StealthOS pool. Update to a current version of Chrome, Edge, Firefox or Safari and open the page over HTTPS, then try again.";

export class UnsupportedBrowserError extends Error {
  constructor() {
    super(UNSUPPORTED_BROWSER_MESSAGE);
    this.name = 'UnsupportedBrowserError';
  }
}

let support: Promise<boolean> | null = null;

async function probeSupport(): Promise<boolean> {
  try {
    if (!globalThis.crypto?.subtle) return false; // Not a secure context, or a very old browser.
    const message = utf8('probe');
    const signing = await generateEd25519();
    const signature = await crypto.subtle.sign('Ed25519', signing.privateKey, raw(message));
    if (!(await ed25519Verify(signing.publicKey, new Uint8Array(signature), message))) return false;
    const a = await generateX25519();
    const b = await generateX25519();
    const shared = await x25519SharedSecret(a.privateKey, b.publicKey);
    return shared.length === 32;
  } catch {
    return false;
  }
}

/** Everything the pool protocol needs: Ed25519 and X25519 in WebCrypto. Checked once. */
export async function assertCryptoSupported(): Promise<void> {
  support ??= probeSupport();
  if (!(await support)) throw new UnsupportedBrowserError();
}

export interface RawPublicKeyPair {
  privateKey: CryptoKey;
  publicKey: Uint8Array;
}

export async function generateEd25519(): Promise<RawPublicKeyPair> {
  const pair = (await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)) };
}

export async function generateX25519(): Promise<RawPublicKeyPair> {
  const pair = (await crypto.subtle.generateKey('X25519', false, ['deriveBits'])) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)) };
}

export async function ed25519Sign(privateKey: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, raw(message)));
}

/** `false` for a bad signature and for a key or signature of the wrong shape. Never throws. */
export async function ed25519Verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): Promise<boolean> {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey('raw', raw(publicKey), 'Ed25519', false, ['verify']);
    return await crypto.subtle.verify('Ed25519', key, raw(signature), raw(message));
  } catch {
    return false;
  }
}

/** The 32-byte X25519 output. Throws for a degenerate peer key (all-zero output). */
export async function x25519SharedSecret(privateKey: CryptoKey, peerPublicKey: Uint8Array): Promise<Uint8Array> {
  const peer = await crypto.subtle.importKey('raw', raw(peerPublicKey), 'X25519', false, []);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: peer }, privateKey, 256));
  if (isAllZero(bits)) throw new Error('degenerate key agreement');
  return bits;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', raw(data)));
}

export async function hmacSha256(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey('raw', raw(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', imported, raw(message)));
}

/**
 * HKDF-SHA256 into a non-extractable AES-256-GCM key. The caller clears `ikm` afterwards: what
 * goes into WebCrypto is a copy, and the key that comes out can't be read back.
 */
export async function hkdfToAesKey(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  usages: KeyUsage[] = ['encrypt', 'decrypt'],
): Promise<CryptoKey> {
  const source = raw(ikm);
  const infoCopy = raw(info);
  try {
    const base = await crypto.subtle.importKey('raw', source, 'HKDF', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: raw(salt), info: infoCopy },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      usages,
    );
  } finally {
    source.fill(0);
    infoCopy.fill(0); // Can hold the invite key.
  }
}

/**
 * The same HKDF output as `hkdfToAesKey`, as a non-extractable HMAC-SHA256 key. Used once, for the
 * safety code the app computes over the shared chat key (`sharedKeyFingerprint`).
 */
export async function hkdfToHmacKey(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array): Promise<CryptoKey> {
  const source = raw(ikm);
  try {
    const base = await crypto.subtle.importKey('raw', source, 'HKDF', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: raw(salt), info: raw(info) },
      base,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign'],
    );
  } finally {
    source.fill(0);
  }
}

/** AES-256-GCM with a fresh random nonce: `nonce(12) || ciphertext || tag(16)`, CryptoKit's `combined`. */
export async function aesGcmSealCombined(key: CryptoKey, plaintext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt(
    aad ? { name: 'AES-GCM', iv, additionalData: raw(aad) } : { name: 'AES-GCM', iv },
    key,
    raw(plaintext),
  );
  return concatBytes(iv, new Uint8Array(sealed));
}

/** Opens a `combined` box. `null` for anything malformed or tampered with. */
export async function aesGcmOpenCombined(key: CryptoKey, combined: Uint8Array, aad?: Uint8Array): Promise<Uint8Array | null> {
  if (combined.length < 12 + 16) return null;
  const iv = raw(combined.subarray(0, 12));
  try {
    const opened = await crypto.subtle.decrypt(
      aad ? { name: 'AES-GCM', iv, additionalData: raw(aad) } : { name: 'AES-GCM', iv },
      key,
      raw(combined.subarray(12)),
    );
    return new Uint8Array(opened);
  } catch {
    return null;
  }
}
