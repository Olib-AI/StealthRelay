// The member side of the outer layer: a port of
// LocalPackages/ConnectionPool/Sources/Transport/OuterLayer/PoolTransportSecurity.swift, with one
// deliberate difference. The app can run a pool with no outer layer when a 1.4.x peer is involved.
// This client cannot: it has no plaintext path at all. An invitation without the fragment is
// refused, a signed "protection off" holds traffic instead of sending it in the clear, and frames
// that are not sealed are dropped. See `status`.

import { base64Encode } from '../utils/base64.ts';
import { bytesEqual, randomBytes } from '../utils/bytes.ts';
import { aesGcmOpenCombined, ed25519Verify, generateX25519, hmacSha256, sha256, x25519SharedSecret } from '../crypto/webcrypto.ts';
import type { RawPublicKeyPair } from '../crypto/webcrypto.ts';
import type { TransportInvite } from '../crypto/invitation.ts';
import {
  announcementTranscript,
  decodeControlMessage,
  deriveSealingKey,
  encodeControlMessage,
  grantTranscript,
  isControlFrame,
  requestTranscript,
  secretAad,
} from './control-message.ts';
import type { ControlMessage } from './control-message.ts';
import {
  deriveFrameKey,
  isOuterFrame,
  openOuterFrame,
  OuterFrameReplayGuard,
  parseHeader,
  sealOuterFrame,
} from './outer-frame.ts';

const CONTROL_MAX_AGE_MS = 300_000;
const CONTROL_MAX_FUTURE_MS = 60_000;
const PREVIOUS_EPOCH_GRACE_MS = 30_000;
const REQUEST_RETRY_MS = 5_000;
const MAX_QUEUED_FRAMES = 256;

/** The relay's own `max_message_size`, and more than any frame it can legitimately relay decodes to. */
export const MAX_INBOUND_FRAME_BYTES = 2 * 1024 * 1024;
/** Frames waiting for a key: unauthenticated until then, so a share per sender and a total, in bytes. */
export const MAX_QUEUED_BYTES_PER_SENDER = 4 * 1024 * 1024;
export const MAX_QUEUED_BYTES_TOTAL = 16 * 1024 * 1024;
/** Frames waiting for their turn in line. Past this they are dropped, not lined up for ever. */
export const MAX_PENDING_RECEIVE_BYTES = 32 * 1024 * 1024;
export const MAX_PENDING_RECEIVE_STEPS = 4096;
/**
 * The app keeps its secret, so an enrolled member always asks without the invite key. This client
 * keeps none across a reload, and a request a host can't place gets no answer, so after this many
 * silent tries it also shows the invite key, if it still holds a live invitation.
 */
const ENROLLED_TRIES_BEFORE_INVITE = 2;

export type OuterLayerStatus =
  /** Waiting for the host to deliver the secret. App frames are held. */
  | { kind: 'securing' }
  /** Every frame is sealed. The people listed run 1.4.x and can't read or send pool traffic. */
  | { kind: 'protected'; epoch: number; excludedPeers: string[] }
  /** The host says this pool has never been protected, because of 1.4.x peers. Traffic is held. */
  | { kind: 'hostNotProtected'; legacyPeers: string[] }
  /** The host announced "protection off" for a protected pool. Refused: frames stay sealed. */
  | { kind: 'downgradeRefused' }
  /** The relay's host is not the host the invitation names. Nothing is sent or accepted. */
  | { kind: 'hostIdentityMismatch' };

type Mode = 'securing' | 'protected' | 'hostNotProtected' | 'downgradeRefused' | 'identityMismatch';

export interface MemberIdentityKeys {
  publicKey: Uint8Array;
  sign: (message: Uint8Array) => Promise<Uint8Array>;
}

export interface MemberTransportSecurityOptions {
  poolId: string;
  poolIdBytes: Uint8Array;
  localPeerId: string;
  identity: MemberIdentityKeys;
  invite: TransportInvite;
  /** Whether the host enrolled this identity on an earlier connection. */
  enrolled: boolean;
  onEnrolled?: () => void;
  /** Any grant has opened: an invite key is no longer needed by anyone. */
  onGranted?: () => void;
  now?: () => number;
  /** Test seams, so a run can be compared byte for byte with the Swift side's. */
  newEphemeral?: () => Promise<RawPublicKeyPair>;
  newNonce?: () => Uint8Array;
  send: (data: Uint8Array, targets: string[] | null) => void;
  deliver: (data: Uint8Array, sender: string) => Promise<void> | void;
  onStatusChange?: (status: OuterLayerStatus) => void;
}

interface EpochKey {
  epoch: number;
  frameKey: CryptoKey;
}

interface Outstanding {
  transcript: Uint8Array;
  ephemeral: CryptoKey;
  sentAt: number;
  /** The invite key this request proved. The grant is sealed under it too. */
  inviteKey: Uint8Array | null;
}

function randomSession(): bigint {
  const bytes = randomBytes(8);
  const value = new DataView(bytes.buffer).getBigUint64(0);
  return value === 0n ? 1n : value; // `UInt64.random(in: 1...UInt64.max)`
}

export class MemberTransportSecurity {
  private readonly options: MemberTransportSecurityOptions;
  private readonly now: () => number;
  private readonly session = randomSession();
  private readonly replayGuard = new OuterFrameReplayGuard();
  private readonly hostIdentityKey: Uint8Array;
  private inviteKey: Uint8Array | null;
  private enrolled: boolean;

  private counter = 0n;
  private keys: EpochKey[] = [];
  private mode: Mode = 'securing';
  private hostPeerId: string | null = null;
  private outstanding: Outstanding | null = null;
  private unansweredRequests = 0;
  private lastAnnouncementMillis = Number.NEGATIVE_INFINITY;
  private legacyPeers: string[] = [];
  private announcedEpoch = 0;
  private oldEpochsValidUntil: number | null = null;
  private readonly removedPeers = new Set<string>();
  private outboundQueue: { data: Uint8Array; targets: string[] | null }[] = [];
  private inboundQueue: { data: Uint8Array; sender: string }[] = [];
  private queuedBytesTotal = 0;
  private readonly queuedBytesBySender = new Map<string, number>();
  private pendingReceiveBytes = 0;
  private pendingReceiveSteps = 0;
  private lastStatusKey = '';
  private destroyed = false;

  /** Everything runs in order, one step at a time: sealing and opening are async. */
  private tail: Promise<void> = Promise.resolve();

  constructor(options: MemberTransportSecurityOptions) {
    this.options = options;
    this.now = options.now ?? Date.now;
    this.hostIdentityKey = options.invite.hostIdentityKey;
    this.inviteKey = options.invite.inviteKey;
    this.enrolled = options.enrolled;
  }

  get status(): OuterLayerStatus {
    switch (this.mode) {
      case 'securing':
        return { kind: 'securing' };
      case 'protected':
        return this.keys.length === 0
          ? { kind: 'securing' }
          : { kind: 'protected', epoch: this.latestEpoch(), excludedPeers: [...this.legacyPeers] };
      case 'hostNotProtected':
        return { kind: 'hostNotProtected', legacyPeers: [...this.legacyPeers] };
      case 'downgradeRefused':
        return { kind: 'downgradeRefused' };
      case 'identityMismatch':
        return { kind: 'hostIdentityMismatch' };
    }
  }

  private publishStatus(): void {
    const status = this.status;
    const key = JSON.stringify(status);
    if (key !== this.lastStatusKey) {
      this.lastStatusKey = key;
      this.options.onStatusChange?.(status);
    }
  }

  private enqueue(step: () => Promise<void>): Promise<void> {
    this.tail = this.tail.then(async () => {
      if (!this.destroyed) await step();
    }).catch(() => {
      // A step that fails has dropped its frame. It must not stop the ones after it.
    });
    return this.tail;
  }

  /** Lets everything queued so far finish. */
  settled(): Promise<void> {
    return this.tail;
  }

  /**
   * The relay accepted this member and named the host. The relay names hosts by their identity
   * key, so this is where the invitation's host key is held against what the relay says.
   *
   * @returns `false` when they differ. The caller must leave: nothing has been sent.
   */
  connected(hostPeerId: string): boolean {
    this.hostPeerId = hostPeerId;
    if (base64Encode(this.hostIdentityKey) !== hostPeerId) {
      this.mode = 'identityMismatch';
      this.publishStatus();
      return false;
    }
    void this.enqueue(() => this.sendKeyRequest());
    this.publishStatus();
    return true;
  }

  /** Sends an app frame (`null` = broadcast): sealed, or held until it can be. Never in the clear. */
  sendApp(data: Uint8Array, targets: string[] | null): Promise<void> {
    return this.enqueue(() => this.sendAppNow(data, targets));
  }

  private async sendAppNow(data: Uint8Array, targets: string[] | null): Promise<void> {
    if (this.mode === 'identityMismatch') return;
    const latest = this.keys[this.keys.length - 1];
    const canSeal = latest && (this.mode === 'protected' || this.mode === 'downgradeRefused');
    if (!canSeal) {
      this.outboundQueue.push({ data, targets });
      if (this.outboundQueue.length > MAX_QUEUED_FRAMES) this.outboundQueue.shift();
      return;
    }
    this.counter += 1n;
    const sealed = await sealOuterFrame(
      data,
      latest.frameKey,
      {
        epoch: latest.epoch,
        session: this.session,
        counter: this.counter,
        timestampMillis: Math.round(this.now()),
        nonce: randomBytes(12),
      },
      this.options.poolIdBytes,
      this.options.localPeerId,
    );
    this.options.send(sealed, targets);
  }

  /** Handles one relayed frame. App plaintext goes to `deliver`. */
  receive(data: Uint8Array, sender: string): Promise<void> {
    if (data.length > MAX_INBOUND_FRAME_BYTES) return Promise.resolve();
    if (
      this.pendingReceiveSteps >= MAX_PENDING_RECEIVE_STEPS ||
      this.pendingReceiveBytes + data.length > MAX_PENDING_RECEIVE_BYTES
    ) {
      return Promise.resolve();
    }
    this.pendingReceiveSteps += 1;
    this.pendingReceiveBytes += data.length;
    return this.enqueue(async () => {
      try {
        await this.receiveNow(data, sender);
      } finally {
        this.pendingReceiveSteps -= 1;
        this.pendingReceiveBytes -= data.length;
      }
    });
  }

  private async receiveNow(data: Uint8Array, sender: string): Promise<void> {
    if (sender === this.options.localPeerId) return; // the relay never echoes our own frames
    if (isControlFrame(data)) {
      const message = decodeControlMessage(data);
      if (message && message.poolID.toLowerCase() === this.options.poolId.toLowerCase()) {
        await this.handleControl(message, sender);
      }
      return;
    }
    if (isOuterFrame(data)) await this.receiveOuter(data, sender);
    // Anything else is a plaintext frame. This client has no use for one.
  }

  private latestEpoch(): number {
    return this.keys[this.keys.length - 1]?.epoch ?? this.announcedEpoch;
  }

  private frameKeyForReceiving(epoch: number, sender: string): CryptoKey | null {
    const entry = this.keys.find((key) => key.epoch === epoch);
    if (!entry) return null;
    if (epoch < this.latestEpoch()) {
      // Only for a short while after a rotation, and never from someone it removed.
      if (this.oldEpochsValidUntil === null || this.now() >= this.oldEpochsValidUntil) return null;
      if (this.removedPeers.has(sender)) return null;
    }
    return entry.frameKey;
  }

  private async receiveOuter(data: Uint8Array, sender: string): Promise<void> {
    const header = parseHeader(data);
    if (!header || !this.replayGuard.isFresh(header, this.now()) || !this.replayGuard.wouldAccept(header, sender)) return;
    const frameKey = this.frameKeyForReceiving(header.epoch, sender);
    if (!frameKey) {
      this.queueForLater(data, sender, header.epoch);
      return;
    }
    const opened = await openOuterFrame(data, frameKey, this.options.poolIdBytes, sender);
    if (!opened || !this.replayGuard.accept(opened.header, sender)) return;
    await this.options.deliver(opened.plaintext, sender);
  }

  /**
   * A frame under an epoch we have no key for yet may be a rotation we haven't caught up with. Only
   * the next epoch can be, so nothing further ahead waits. Nobody can have authenticated this frame,
   * so what is full stays as it is: one sender can't push out what another sent.
   */
  private queueForLater(data: Uint8Array, sender: string, epoch: number): void {
    const newest = this.keys.reduce((max, key) => Math.max(max, key.epoch), this.announcedEpoch);
    if (epoch > newest + 1) return;
    if (this.keys.length > 0 && epoch <= this.latestEpoch()) return; // An old epoch we have let go of.
    const fromSender = this.queuedBytesBySender.get(sender) ?? 0;
    if (
      this.inboundQueue.length >= MAX_QUEUED_FRAMES ||
      fromSender + data.length > MAX_QUEUED_BYTES_PER_SENDER ||
      this.queuedBytesTotal + data.length > MAX_QUEUED_BYTES_TOTAL
    ) {
      return;
    }
    this.inboundQueue.push({ data, sender });
    this.queuedBytesBySender.set(sender, fromSender + data.length);
    this.queuedBytesTotal += data.length;
  }

  private isFresh(millis: number): boolean {
    const age = this.now() - millis;
    return age <= CONTROL_MAX_AGE_MS && age >= -CONTROL_MAX_FUTURE_MS;
  }

  private async sendKeyRequest(): Promise<void> {
    if (this.hostPeerId === null || this.mode === 'identityMismatch') return;
    const ephemeral = await (this.options.newEphemeral ?? generateX25519)();
    const message: ControlMessage = {
      kind: 'keyRequest',
      poolID: this.options.poolId.toUpperCase(),
      timestampMillis: Math.round(this.now()),
      memberPeerID: this.options.localPeerId,
      memberIdentityKey: this.options.identity.publicKey,
      memberEphemeral: ephemeral.publicKey,
      nonce: this.options.newNonce?.() ?? randomBytes(32),
    };
    const inviteKey = !this.enrolled || this.unansweredRequests >= ENROLLED_TRIES_BEFORE_INVITE ? this.inviteKey : null;
    this.unansweredRequests += 1;
    if (inviteKey) {
      message.inviteKeyID = (await sha256(inviteKey)).slice(0, 8);
    }
    const transcript = requestTranscript(message, this.options.poolIdBytes);
    if (!transcript) return;
    message.memberSignature = await this.options.identity.sign(transcript);
    if (inviteKey) {
      message.inviteProof = await hmacSha256(inviteKey, transcript);
    }
    this.outstanding = { transcript, ephemeral: ephemeral.privateKey, sentAt: this.now(), inviteKey };
    this.options.send(encodeControlMessage(message), [this.hostPeerId]);
  }

  private async handleControl(message: ControlMessage, sender: string): Promise<void> {
    // Only the host speaks here, under the key the invitation named, and only recently.
    if (sender !== this.hostPeerId || this.mode === 'identityMismatch') return;
    if (!this.isFresh(message.timestampMillis) || !message.hostSignature) return;
    if (message.kind === 'keyGrant') await this.handleGrant(message);
    else if (message.kind === 'announcement') await this.handleAnnouncement(message);
  }

  private async handleGrant(message: ControlMessage): Promise<void> {
    const transcript = grantTranscript(message, this.options.poolIdBytes);
    if (!transcript || !(await ed25519Verify(this.hostIdentityKey, message.hostSignature!, transcript))) return;
    const pending = this.outstanding;
    if (!pending) return;
    const requestHash = await sha256(pending.transcript);
    if (!message.requestHash || !bytesEqual(message.requestHash, requestHash)) return;
    const { epoch, hostEphemeral, sealedSecret } = message;
    if (epoch === undefined || !hostEphemeral || !sealedSecret) return;

    let shared: Uint8Array;
    try {
      shared = await x25519SharedSecret(pending.ephemeral, hostEphemeral);
    } catch {
      return;
    }
    const sealingKey = await deriveSealingKey(shared, requestHash, epoch, pending.inviteKey);
    shared.fill(0);
    const secret = await aesGcmOpenCombined(sealingKey, sealedSecret, secretAad(this.options.poolIdBytes, epoch));
    if (!secret) return;
    if (secret.length !== 32) {
      secret.fill(0);
      return;
    }
    const frameKey = await deriveFrameKey(secret, this.options.poolIdBytes, epoch);
    secret.fill(0);

    this.outstanding = null;
    this.unansweredRequests = 0;
    const previousLatest = this.keys.reduce<number | null>((max, key) => (max === null || key.epoch > max ? key.epoch : max), null);
    this.keys = [...this.keys.filter((key) => key.epoch !== epoch), { epoch, frameKey }]
      .sort((a, b) => a.epoch - b.epoch)
      .slice(-2);
    if (!this.enrolled) {
      this.enrolled = true;
      this.options.onEnrolled?.();
    }
    this.inviteKey?.fill(0);
    this.inviteKey = null;
    this.options.onGranted?.();
    if (previousLatest !== null && epoch > previousLatest) {
      this.oldEpochsValidUntil = this.now() + PREVIOUS_EPOCH_GRACE_MS;
    }
    await this.drainQueues();
  }

  private async handleAnnouncement(message: ControlMessage): Promise<void> {
    const transcript = announcementTranscript(message, this.options.poolIdBytes);
    if (!transcript || !(await ed25519Verify(this.hostIdentityKey, message.hostSignature!, transcript))) return;
    if (message.timestampMillis <= this.lastAnnouncementMillis) return;
    const { epoch, protected: isProtected } = message;
    if (epoch === undefined || isProtected === undefined) return;

    this.lastAnnouncementMillis = message.timestampMillis;
    for (const peer of message.removedPeerIDs ?? []) this.removedPeers.add(peer);
    this.legacyPeers = [...(message.legacyPeerIDs ?? [])].sort();
    this.announcedEpoch = epoch;

    if (isProtected) {
      this.mode = 'protected';
      if (!this.keys.some((key) => key.epoch === epoch) && this.outstanding === null) {
        await this.sendKeyRequest();
      }
    } else if (this.mode === 'protected' || this.mode === 'downgradeRefused') {
      // Once protected, never again in the clear, whoever signed it.
      this.mode = 'downgradeRefused';
    } else {
      this.mode = 'hostNotProtected';
    }
    await this.drainQueues();
  }

  private async drainQueues(): Promise<void> {
    const canSend = (this.mode === 'protected' || this.mode === 'downgradeRefused') && this.keys.length > 0;
    if (canSend && this.outboundQueue.length > 0) {
      const queued = this.outboundQueue;
      this.outboundQueue = [];
      for (const { data, targets } of queued) await this.sendAppNow(data, targets);
    }
    if (this.mode !== 'securing' && this.inboundQueue.length > 0) {
      const queued = this.inboundQueue;
      this.inboundQueue = [];
      this.queuedBytesTotal = 0;
      this.queuedBytesBySender.clear();
      for (const { data, sender } of queued) {
        const header = parseHeader(data);
        if (header && this.frameKeyForReceiving(header.epoch, sender) === null) continue; // still no key: drop rather than loop
        try {
          await this.receiveNow(data, sender);
        } catch {
          // One bad frame must not take the rest of the queue with it.
        }
      }
    }
    this.publishStatus();
  }

  /** Call about once a second: asks again if the host has not answered. */
  tick(): Promise<void> {
    return this.enqueue(async () => {
      if (this.hostPeerId === null || this.mode === 'identityMismatch') return;
      const needsKey =
        this.mode === 'securing' ||
        (this.mode === 'hostNotProtected' && this.keys.length === 0) ||
        (this.mode === 'protected' && this.announcedEpoch > 0 && !this.keys.some((key) => key.epoch === this.announcedEpoch));
      if (needsKey && (this.outstanding === null || this.now() - this.outstanding.sentAt > REQUEST_RETRY_MS)) {
        await this.sendKeyRequest();
      }
    });
  }

  /** Drops every key and clears the invite key. */
  destroy(): void {
    this.destroyed = true;
    this.inviteKey?.fill(0);
    this.inviteKey = null;
    this.keys = [];
    this.outstanding = null;
    this.outboundQueue = [];
    this.inboundQueue = [];
    this.queuedBytesTotal = 0;
    this.queuedBytesBySender.clear();
  }
}
