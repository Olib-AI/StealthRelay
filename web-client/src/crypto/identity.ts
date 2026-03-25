import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { base64Encode, base64Decode } from '../utils/base64.ts';

const STORAGE_KEY = 'stealth_ed25519_private_key';

ed.hashes.sha512 = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

let cachedPrivateKey: Uint8Array | null = null;
let cachedPublicKey: Uint8Array | null = null;

function loadOrGenerateKeyPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  if (cachedPrivateKey && cachedPublicKey) {
    return { privateKey: cachedPrivateKey, publicKey: cachedPublicKey };
  }

  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored) {
    const privateKey = base64Decode(stored);
    if (privateKey.length === 32) {
      const publicKey = ed.getPublicKey(privateKey);
      cachedPrivateKey = privateKey;
      cachedPublicKey = publicKey;
      return { privateKey, publicKey };
    }
  }

  const privateKey = ed.utils.randomSecretKey();
  const publicKey = ed.getPublicKey(privateKey);
  localStorage.setItem(STORAGE_KEY, base64Encode(privateKey));
  cachedPrivateKey = privateKey;
  cachedPublicKey = publicKey;
  return { privateKey, publicKey };
}

export function getIdentityKeyPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  return loadOrGenerateKeyPair();
}

export function getPublicKeyBase64(): string {
  const { publicKey } = loadOrGenerateKeyPair();
  return base64Encode(publicKey);
}

export function signMessage(message: Uint8Array): Uint8Array {
  const { privateKey } = loadOrGenerateKeyPair();
  return ed.sign(message, privateKey);
}
