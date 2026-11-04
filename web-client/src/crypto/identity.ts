// A member's keys in one pool, as RemoteMemberIdentity.swift and PoolDeviceIdentity.swift scope them:
// one per (relay, pool), so nothing links a person's pools to each other. The app keeps them in the
// Keychain. Here they are non-extractable CryptoKeys in IndexedDB: this page can sign with them and
// nothing can read them, including this page. Where IndexedDB is unavailable (some private windows)
// they last as long as the tab, and a reload asks the host again.

import { base64Encode } from '../utils/base64.ts';
import { hexEncode } from '../utils/hex.ts';
import { bytesEqual, randomBytes, utf8 } from '../utils/bytes.ts';
import { ed25519Sign, generateEd25519, sha256 } from './webcrypto.ts';

/** Where earlier versions kept one raw private key for every pool. */
const LEGACY_LOCAL_STORAGE_KEY = 'stealth_ed25519_private_key';

const DB_NAME = 'stealth_pool_keys';
const STORE_NAME = 'identities';

/** Everything here is either non-extractable or public. Pool secrets are never stored. */
interface IdentityRecord {
  signingPrivate: CryptoKey;
  signingPublic: Uint8Array;
  devicePrivate: CryptoKey;
  devicePublic: Uint8Array;
  /** Added to the time, so two pools' members can't line up what this browser sends. */
  counterOffset: number;
  counterHighWater: number;
  /** The host approved this key: the relay knows it and takes a `member_rejoin`. */
  joined: boolean;
  /** The host enrolled this key for the transport secret. */
  enrolled: boolean;
  /** The host key this pool was first joined under, once the relay agreed. It never changes. */
  hostIdentityKey?: Uint8Array;
}

export interface IdentityStore {
  get(account: string): Promise<IdentityRecord | undefined>;
  put(account: string, record: IdentityRecord): Promise<void>;
  delete(account: string): Promise<void>;
}

class MemoryIdentityStore implements IdentityStore {
  private readonly items = new Map<string, IdentityRecord>();
  async get(account: string) { return this.items.get(account); }
  async put(account: string, record: IdentityRecord) { this.items.set(account, record); }
  async delete(account: string) { this.items.delete(account); }
}

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB request failed'));
  });
}

class IndexedDbIdentityStore implements IdentityStore {
  private db: Promise<IDBDatabase> | null = null;

  private open(): Promise<IDBDatabase> {
    this.db ??= new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        req.result.createObjectStore(STORE_NAME);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error('IndexedDB open failed'));
    });
    return this.db;
  }

  async get(account: string): Promise<IdentityRecord | undefined> {
    const db = await this.open();
    return request(db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).get(account)) as Promise<IdentityRecord | undefined>;
  }

  async put(account: string, record: IdentityRecord): Promise<void> {
    const db = await this.open();
    await request(db.transaction(STORE_NAME, 'readwrite').objectStore(STORE_NAME).put(record, account));
  }

  async delete(account: string): Promise<void> {
    const db = await this.open();
    await request(db.transaction(STORE_NAME, 'readwrite').objectStore(STORE_NAME).delete(account));
  }
}

/** Falls back to memory for good on the first failure, so a key is never half stored. */
class ResilientIdentityStore implements IdentityStore {
  private readonly memory = new MemoryIdentityStore();
  private durable: IdentityStore | null;

  constructor(durable: IdentityStore | null) {
    this.durable = durable;
  }

  private async attempt<T>(step: (store: IdentityStore) => Promise<T>): Promise<T> {
    if (this.durable) {
      try {
        return await step(this.durable);
      } catch {
        this.durable = null;
      }
    }
    return step(this.memory);
  }

  get(account: string) { return this.attempt((store) => store.get(account)); }
  put(account: string, record: IdentityRecord) { return this.attempt((store) => store.put(account, record)); }
  delete(account: string) { return this.attempt((store) => store.delete(account)); }
}

const defaultStore: IdentityStore = new ResilientIdentityStore(
  typeof indexedDB === 'undefined' ? null : new IndexedDbIdentityStore(),
);

export function memoryIdentityStore(): IdentityStore {
  return new MemoryIdentityStore();
}

/** Removes the raw key earlier versions left in localStorage. Run once at startup. */
export function wipeLegacyIdentity(): void {
  try {
    localStorage.removeItem(LEGACY_LOCAL_STORAGE_KEY);
  } catch {
    // Storage blocked: there is nothing we can read there either.
  }
}

export class PoolIdentity {
  private readonly account: string;
  private readonly record: IdentityRecord;
  private readonly store: IdentityStore;

  constructor(account: string, record: IdentityRecord, store: IdentityStore) {
    this.account = account;
    this.record = record;
    this.store = store;
  }

  get publicKey(): Uint8Array {
    return this.record.signingPublic;
  }

  /** The relay names members by the base64 of their identity key. */
  get peerId(): string {
    return base64Encode(this.record.signingPublic);
  }

  get joined(): boolean {
    return this.record.joined;
  }

  get enrolled(): boolean {
    return this.record.enrolled;
  }

  sign = (message: Uint8Array): Promise<Uint8Array> => ed25519Sign(this.record.signingPrivate, message);

  /** The pool's device key, which signs nothing but this session's chat key. */
  readonly device = {
    publicKey: (): Uint8Array => this.record.devicePublic,
    sign: (message: Uint8Array): Promise<Uint8Array> => ed25519Sign(this.record.devicePrivate, message),
  };

  /**
   * `false` when an invitation names another host than the one this identity joined under, as
   * PoolTransportSecurity does with its stored record. A pool's host key can't legitimately change:
   * the relay binds a pool to it.
   */
  hostKeyMatches(hostKey: Uint8Array): boolean {
    const pinned = this.record.hostIdentityKey;
    return pinned === undefined || bytesEqual(pinned, hostKey);
  }

  /** Remembers the host once the relay has named the same one as the invitation. */
  async pinHostKey(hostKey: Uint8Array): Promise<void> {
    if (this.record.hostIdentityKey) return;
    this.record.hostIdentityKey = hostKey.slice();
    await this.store.put(this.account, this.record);
  }

  /** Only ever goes up, whatever the clock does, so an older proof can be refused. */
  async nextContinuityCounter(now: number = Date.now()): Promise<number> {
    const next = Math.max(now + this.record.counterOffset, this.record.counterHighWater + 1);
    this.record.counterHighWater = next;
    await this.store.put(this.account, this.record);
    return next;
  }

  async markJoined(): Promise<void> {
    if (this.record.joined) return;
    this.record.joined = true;
    await this.store.put(this.account, this.record);
  }

  async markEnrolled(): Promise<void> {
    if (this.record.enrolled) return;
    this.record.enrolled = true;
    await this.store.put(this.account, this.record);
  }

  /** Leaving the pool, or the relay saying this key is no longer in it. */
  async forget(): Promise<void> {
    await this.store.delete(this.account);
  }
}

function randomCounterOffset(): number {
  // Up to 2^40, as PoolDeviceIdentity.continuityCounterOffset: about 34 years in milliseconds.
  return randomBytes(5).reduce((acc, byte) => acc * 256 + byte, 0);
}

async function accountFor(serverUrl: string, poolId: string): Promise<string> {
  return hexEncode(await sha256(utf8(`${serverUrl}:${poolId.toLowerCase()}`)));
}

export async function loadOrCreatePoolIdentity(
  serverUrl: string,
  poolId: string,
  store: IdentityStore = defaultStore,
): Promise<PoolIdentity> {
  const account = await accountFor(serverUrl, poolId);
  const existing = await store.get(account);
  if (existing) return new PoolIdentity(account, existing, store);

  const signing = await generateEd25519();
  const device = await generateEd25519();
  const record: IdentityRecord = {
    signingPrivate: signing.privateKey,
    signingPublic: signing.publicKey,
    devicePrivate: device.privateKey,
    devicePublic: device.publicKey,
    counterOffset: randomCounterOffset(),
    counterHighWater: 0,
    joined: false,
    enrolled: false,
  };
  await store.put(account, record);
  return new PoolIdentity(account, record, store);
}
