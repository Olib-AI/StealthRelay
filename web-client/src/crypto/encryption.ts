import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64Encode, base64Decode } from '../utils/base64.ts';

let sessionX25519PrivateKey: Uint8Array | null = null;
let sessionX25519PublicKey: Uint8Array | null = null;

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

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i]! < b[i]!) return -1;
    if (a[i]! > b[i]!) return 1;
  }
  return a.length - b.length;
}

export function generateX25519KeyPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = crypto.getRandomValues(new Uint8Array(32));
  const publicKey = x25519.getPublicKey(privateKey);
  sessionX25519PrivateKey = privateKey;
  sessionX25519PublicKey = publicKey;
  return { privateKey, publicKey };
}

export function getX25519PublicKey(): Uint8Array {
  if (!sessionX25519PublicKey) {
    generateX25519KeyPair();
  }
  return sessionX25519PublicKey!;
}

export function getX25519PublicKeyBase64(): string {
  return base64Encode(getX25519PublicKey());
}

export function deriveSharedKey(peerPublicKey: Uint8Array): Uint8Array {
  if (!sessionX25519PrivateKey || !sessionX25519PublicKey) {
    throw new Error('X25519 keypair not initialized');
  }
  const sharedSecret = x25519.getSharedSecret(sessionX25519PrivateKey, peerPublicKey);
  const myPubKey = sessionX25519PublicKey;

  const sorted = compareBytes(myPubKey, peerPublicKey) <= 0
    ? [myPubKey, peerPublicKey] as const
    : [peerPublicKey, myPubKey] as const;

  const salt = sha256(concat(sorted[0], sorted[1]));
  const info = concat(
    new TextEncoder().encode('E2E-Encryption-v1'),
    sorted[0],
    sorted[1],
  );
  return hkdf(sha256, sharedSecret, salt, info, 32);
}

function toRawBuffer(bytes: Uint8Array): ArrayBuffer {
  // Copy to a fresh ArrayBuffer to avoid SharedArrayBuffer type issues
  // and ensure we get exactly the bytes we want, not a larger backing buffer
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  return buf;
}

export async function encryptMessage(plaintext: string, keyBytes: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey('raw', toRawBuffer(keyBytes), 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  const combined = concat(iv, new Uint8Array(ciphertext));
  return base64Encode(combined);
}

export async function decryptMessage(encryptedBase64: string, keyBytes: Uint8Array): Promise<string> {
  const combined = base64Decode(encryptedBase64);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const key = await crypto.subtle.importKey('raw', toRawBuffer(keyBytes), 'AES-GCM', false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}

export function resetEncryptionSession(): void {
  sessionX25519PrivateKey = null;
  sessionX25519PublicKey = null;
}
