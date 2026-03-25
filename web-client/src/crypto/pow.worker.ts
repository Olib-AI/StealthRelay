import { sha256 } from '@noble/hashes/sha2.js';

function hexDecode(hex: string): Uint8Array {
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    result[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return result;
}

function hexEncode(bytes: Uint8Array): string {
  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    result += bytes[i]!.toString(16).padStart(2, '0');
  }
  return result;
}

function leadingZeroBits(hash: Uint8Array): number {
  let count = 0;
  for (let i = 0; i < hash.length; i++) {
    const byte = hash[i]!;
    if (byte === 0) {
      count += 8;
    } else {
      count += Math.clz32(byte) - 24;
      break;
    }
  }
  return count;
}

function bigint64BigEndian(value: bigint): Uint8Array {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setBigUint64(0, value);
  return new Uint8Array(buf);
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

function solvePoW(challengeHex: string, difficulty: number): string {
  const prefix = new TextEncoder().encode('STEALTH_POW');
  const challenge = hexDecode(challengeHex);
  let nonce = 0n;

  while (true) {
    const nonceBytes = bigint64BigEndian(nonce);
    const input = concat(prefix, challenge, nonceBytes);
    const hash = sha256(input);
    if (leadingZeroBits(hash) >= difficulty) {
      return hexEncode(nonceBytes);
    }
    nonce++;
    if (nonce % 100000n === 0n) {
      self.postMessage({ type: 'progress', nonce: Number(nonce) });
    }
  }
}

self.onmessage = (e: MessageEvent<{ challenge: string; difficulty: number }>) => {
  const { challenge, difficulty } = e.data;
  const solution = solvePoW(challenge, difficulty);
  self.postMessage({ type: 'solution', solution });
};
