// Pool Chat's end-to-end layer: a port of LocalPackages/PoolChat/Sources/Services/ChatEncryptionService.swift
// and the key exchange of ConnectionPool's KeyExchangePayload. Per peer pair:
// X25519, then HKDF-SHA256(salt = SHA-256(both keys, sorted), info = "E2E-Encryption-v1" || both keys, sorted),
// then AES-256-GCM as `nonce(12) || ciphertext || tag(16)`, in base64 inside the JSON.

import { base64DecodeStrict, base64Encode } from '../utils/base64.ts';
import { be64, bytesEqual, compareBytes, concatBytes, isAllZero, lengthPrefixed, raw, utf8 } from '../utils/bytes.ts';
import type { KeyExchangePayload } from '../protocol/messages.ts';
import {
  aesGcmOpenCombined,
  aesGcmSealCombined,
  ed25519Sign,
  ed25519Verify,
  generateEd25519,
  generateX25519,
  hkdfToAesKey,
  hkdfToHmacKey,
  sha256,
  x25519SharedSecret,
} from './webcrypto.ts';
import type { RawPublicKeyPair } from './webcrypto.ts';

/** `u32 len || label || u32 len || peerID || poolID(16) || X25519(32) || Ed25519(32)`. */
export function bindingStatement(peerId: string, poolIdBytes: Uint8Array, chatKey: Uint8Array, signingKey: Uint8Array): Uint8Array {
  return concatBytes(
    lengthPrefixed(utf8('STEALTH_ENVELOPE_SIGNING_KEY_V2')),
    lengthPrefixed(utf8(peerId)),
    poolIdBytes,
    chatKey,
    signingKey,
  );
}

/** PoolDeviceIdentity.continuityStatement. */
export function continuityStatement(
  peerId: string,
  chatKey: Uint8Array,
  deviceKey: Uint8Array,
  counter: number,
  signingKey: Uint8Array | null,
): Uint8Array {
  return concatBytes(
    lengthPrefixed(utf8('STEALTH_POOL_CHAT_CONTINUITY_V3')),
    lengthPrefixed(utf8(peerId)),
    chatKey,
    deviceKey,
    be64(counter),
    lengthPrefixed(signingKey ?? new Uint8Array(0)),
  );
}

/** First 8 bytes, uppercase hex pairs joined by ':', the format of the app's codes. */
function formatCode(bytes: Uint8Array): string {
  return Array.from(bytes.subarray(0, 8), (b) => b.toString(16).toUpperCase().padStart(2, '0')).join(':');
}

/** ChatEncryptionService.fingerprint: what the app shows as a person's key. */
export async function keyFingerprint(publicKey: Uint8Array): Promise<string> {
  return formatCode(await sha256(publicKey));
}

export interface ChatKeys {
  key: CryptoKey;
  /** ChatEncryptionService.sharedKeyFingerprint: HMAC-SHA256(chat key, "fingerprint-check"). */
  safetyCode: string;
}

export async function deriveChatKey(privateKey: CryptoKey, ownPublicKey: Uint8Array, peerPublicKey: Uint8Array): Promise<ChatKeys> {
  const shared = await x25519SharedSecret(privateKey, peerPublicKey);
  const [first, second] = compareBytes(ownPublicKey, peerPublicKey) <= 0
    ? [ownPublicKey, peerPublicKey]
    : [peerPublicKey, ownPublicKey];
  const salt = await sha256(concatBytes(first, second));
  const info = concatBytes(utf8('E2E-Encryption-v1'), first, second);
  try {
    const key = await hkdfToAesKey(shared, salt, info);
    const hmac = await hkdfToHmacKey(shared, salt, info);
    const code = await crypto.subtle.sign('HMAC', hmac, raw(utf8('fingerprint-check')));
    return { key, safetyCode: formatCode(new Uint8Array(code)) };
  } finally {
    shared.fill(0);
  }
}

export type PeerKeyOutcome =
  /** First key seen for this peer. */
  | 'newPeer'
  /** The key we already have, said again. */
  | 'unchanged'
  /** A new key, signed by the device key that signed the old one: the same device in a new session. */
  | 'sameDevice'
  /** A new key with no proof for it. Accepted, and the person is told. */
  | 'keyChanged'
  /** An older key with its older proof: someone showing it again. Refused; the key in use stays. */
  | 'replayRefused'
  /** Not a usable key. Refused. */
  | 'invalid';

export interface KeyExchangeResult {
  outcome: PeerKeyOutcome;
  accepted: boolean;
  /** There was no key for this peer before, or it just changed: they need ours (again). */
  shouldAnswer: boolean;
}

interface Vouch {
  deviceKey: Uint8Array;
  counter: number;
}

export interface PeerSecurityInfo {
  safetyCode: string;
  theirKey: string;
  yourKey: string;
}

export interface LocalDeviceSigner {
  publicKey: Uint8Array;
  sign: (message: Uint8Array) => Promise<Uint8Array>;
  nextCounter: () => Promise<number>;
}

export class ChatEncryption {
  private readonly keyAgreement: RawPublicKeyPair;
  private readonly signing: RawPublicKeyPair;
  private readonly peerKeys = new Map<string, CryptoKey>();
  private readonly safetyCodes = new Map<string, string>();
  private readonly knownPeerKeys = new Map<string, Uint8Array>();
  private readonly knownDeviceKeys = new Map<string, Uint8Array>();
  private readonly lastVouched = new Map<string, { deviceKey: Uint8Array; counter: number; chatKey: Uint8Array }>();
  private readonly departed = new Set<string>();

  private constructor(keyAgreement: RawPublicKeyPair, signing: RawPublicKeyPair) {
    this.keyAgreement = keyAgreement;
    this.signing = signing;
  }

  /** Fresh keys, per session as in the app: forward secrecy for what is said in it. */
  static async create(keyAgreement?: RawPublicKeyPair): Promise<ChatEncryption> {
    return new ChatEncryption(keyAgreement ?? (await generateX25519()), await generateEd25519());
  }

  get publicKey(): Uint8Array {
    return this.keyAgreement.publicKey;
  }

  /** Our key exchange: the X25519 key, the session's Ed25519 key bound to it, and the device's word. */
  async makeKeyExchange(localPeerId: string, poolIdBytes: Uint8Array, device: LocalDeviceSigner | null): Promise<KeyExchangePayload> {
    const chatKey = this.keyAgreement.publicKey;
    const signingKey = this.signing.publicKey;
    const binding = await ed25519Sign(this.signing.privateKey, bindingStatement(localPeerId, poolIdBytes, chatKey, signingKey));
    const payload: KeyExchangePayload = {
      publicKey: base64Encode(chatKey),
      senderPeerID: localPeerId,
      signingPublicKey: base64Encode(signingKey),
      signingKeyBinding: base64Encode(binding),
    };
    if (device) {
      const counter = await device.nextCounter();
      const statement = continuityStatement(localPeerId, chatKey, device.publicKey, counter, signingKey);
      payload.continuityKey = base64Encode(device.publicKey);
      payload.continuityProof = base64Encode(await device.sign(statement));
      payload.continuityCounter = counter;
    }
    return payload;
  }

  private async vouch(payload: KeyExchangePayload, peerId: string, chatKey: Uint8Array): Promise<Vouch | null> {
    const { continuityKey, continuityProof, continuityCounter, signingPublicKey } = payload;
    if (typeof continuityKey !== 'string' || typeof continuityProof !== 'string' || !Number.isSafeInteger(continuityCounter)) return null;
    const deviceKey = base64DecodeStrict(continuityKey);
    const proof = base64DecodeStrict(continuityProof);
    const signingKey = typeof signingPublicKey === 'string' ? base64DecodeStrict(signingPublicKey) : null;
    if (!deviceKey || !proof || (typeof signingPublicKey === 'string' && !signingKey)) return null;
    const statement = continuityStatement(peerId, chatKey, deviceKey, continuityCounter!, signingKey);
    return (await ed25519Verify(deviceKey, proof, statement)) ? { deviceKey, counter: continuityCounter! } : null;
  }

  /**
   * ChatEncryptionService.performKeyExchange with its TOFU. `peerId` is who the relay says sent it;
   * the caller has already held the payload's own claim against that.
   */
  async acceptKeyExchange(payload: KeyExchangePayload, peerId: string): Promise<KeyExchangeResult> {
    const refused = (outcome: PeerKeyOutcome): KeyExchangeResult => ({ outcome, accepted: false, shouldAnswer: false });
    if (typeof payload.publicKey !== 'string') return refused('invalid');
    const chatKey = base64DecodeStrict(payload.publicKey);
    if (!chatKey || chatKey.length !== 32 || isAllZero(chatKey)) return refused('invalid');
    if (bytesEqual(chatKey, this.keyAgreement.publicKey)) return refused('invalid'); // reflection

    const hadKeyBefore = this.peerKeys.has(peerId);
    const vouch = await this.vouch(payload, peerId, chatKey);
    const existing = this.knownPeerKeys.get(peerId);
    const existingDevice = this.knownDeviceKeys.get(peerId);
    const last = this.lastVouched.get(peerId);
    const hasDeparted = this.departed.has(peerId);

    // An older proof from the same device key, for another chat key, is an old key shown again.
    let rankFellBack = false;
    if (vouch && last && bytesEqual(last.deviceKey, vouch.deviceKey) && vouch.counter <= last.counter && !bytesEqual(last.chatKey, chatKey)) {
      if (!hasDeparted) return refused('replayRefused');
      rankFellBack = true;
    }

    // Derive before recording anything, so a key the platform rejects changes no state.
    let derived: ChatKeys;
    try {
      derived = await deriveChatKey(this.keyAgreement.privateKey, this.keyAgreement.publicKey, chatKey);
    } catch {
      return refused('invalid');
    }

    this.departed.delete(peerId);
    let outcome: PeerKeyOutcome;
    if (!existing) {
      outcome = 'newPeer';
      this.knownPeerKeys.set(peerId, chatKey);
      if (vouch) this.knownDeviceKeys.set(peerId, vouch.deviceKey);
      this.recordVouch(vouch, chatKey, peerId);
    } else if (bytesEqual(existing, chatKey)) {
      outcome = 'unchanged';
      if (vouch && existingDevice && bytesEqual(existingDevice, vouch.deviceKey)) this.recordVouch(vouch, chatKey, peerId);
    } else {
      const sameDevice = !rankFellBack && !!existingDevice && !!vouch && bytesEqual(existingDevice, vouch.deviceKey);
      outcome = sameDevice ? 'sameDevice' : 'keyChanged';
      this.knownPeerKeys.set(peerId, chatKey);
      if (vouch) this.knownDeviceKeys.set(peerId, vouch.deviceKey);
      else this.knownDeviceKeys.delete(peerId);
      this.recordVouch(vouch, chatKey, peerId);
    }
    if (rankFellBack && vouch) {
      this.lastVouched.set(peerId, { deviceKey: vouch.deviceKey, counter: vouch.counter, chatKey });
    }

    this.peerKeys.set(peerId, derived.key);
    this.safetyCodes.set(peerId, derived.safetyCode);
    return { outcome, accepted: true, shouldAnswer: !hadKeyBefore || (existing !== undefined && !bytesEqual(existing, chatKey)) };
  }

  /** Only ever moves a device key's record forward. */
  private recordVouch(vouch: Vouch | null, chatKey: Uint8Array, peerId: string): void {
    if (!vouch) return;
    const last = this.lastVouched.get(peerId);
    if (last && bytesEqual(last.deviceKey, vouch.deviceKey) && vouch.counter < last.counter) return;
    this.lastVouched.set(peerId, { deviceKey: vouch.deviceKey, counter: vouch.counter, chatKey });
  }

  keyFor(peerId: string): CryptoKey | undefined {
    return this.peerKeys.get(peerId);
  }

  /** What the security-code screen shows. `null` until the key exchange with them has finished. */
  async securityInfo(peerId: string): Promise<PeerSecurityInfo | null> {
    const safetyCode = this.safetyCodes.get(peerId);
    const theirKey = this.knownPeerKeys.get(peerId);
    if (!safetyCode || !theirKey || !this.peerKeys.has(peerId)) return null;
    return { safetyCode, theirKey: await keyFingerprint(theirKey), yourKey: await keyFingerprint(this.keyAgreement.publicKey) };
  }

  /** Their session ended. What they showed so far says nothing about their next key's rank. */
  removePeer(peerId: string): void {
    this.peerKeys.delete(peerId);
    this.safetyCodes.delete(peerId);
    this.departed.add(peerId);
  }

  /** `null` when there is no key for this peer: the caller holds the message, never sends it bare. */
  async encrypt(data: Uint8Array, peerId: string): Promise<Uint8Array | null> {
    const key = this.peerKeys.get(peerId);
    return key ? aesGcmSealCombined(key, data) : null;
  }

  /** `null` for no key, or for anything that does not authenticate. */
  async decrypt(combined: Uint8Array, peerId: string): Promise<Uint8Array | null> {
    const key = this.peerKeys.get(peerId);
    return key ? aesGcmOpenCombined(key, combined) : null;
  }
}
