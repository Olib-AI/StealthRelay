// Wire-format pack/unpack for media frames.
// Wire format: [4-byte big-endian header length] [JSON header] [codec payload].
// Matches LocalPackages/PoolChat/Sources/Calling/Models/MediaFrame.swift.

import type { MediaFrameHeader, CallMediaType } from './types.ts';
import { MAX_FRAGMENT_PAYLOAD_BYTES } from './types.ts';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

export function packFrame(header: MediaFrameHeader, payload: Uint8Array): Uint8Array {
  const headerJSON = textEncoder.encode(JSON.stringify(header));
  const out = new Uint8Array(4 + headerJSON.length + payload.length);
  // 4-byte big-endian length
  const len = headerJSON.length;
  out[0] = (len >>> 24) & 0xff;
  out[1] = (len >>> 16) & 0xff;
  out[2] = (len >>> 8) & 0xff;
  out[3] = len & 0xff;
  out.set(headerJSON, 4);
  out.set(payload, 4 + headerJSON.length);
  return out;
}

export type UnpackedFrame = {
  header: MediaFrameHeader;
  payload: Uint8Array;
};

export function unpackFrame(data: Uint8Array): UnpackedFrame | null {
  if (data.length < 4) return null;
  const headerLen =
    (data[0]! << 24) | (data[1]! << 16) | (data[2]! << 8) | data[3]!;
  // Guard against malicious or corrupted frames.
  if (headerLen < 0 || headerLen > 64 * 1024) return null;
  const headerEnd = 4 + headerLen;
  if (data.length < headerEnd) return null;
  let header: MediaFrameHeader;
  try {
    const json = textDecoder.decode(data.slice(4, headerEnd));
    header = JSON.parse(json) as MediaFrameHeader;
  } catch {
    return null;
  }
  return { header, payload: data.slice(headerEnd) };
}

/**
 * Split a payload into one or more fragments matching iOS's algorithm.
 * Audio always lands as a single 1/1 fragment. Video larger than
 * `MAX_FRAGMENT_PAYLOAD_BYTES` splits into ≤ 255 chunks.
 */
export function fragmentFrame(args: {
  callID: string;
  senderPeerID: string;
  mediaType: CallMediaType;
  sequence: number;
  timestamp: number;
  isKeyFrame: boolean;
  payload: Uint8Array;
}): Uint8Array[] {
  const { callID, senderPeerID, mediaType, sequence, timestamp, isKeyFrame, payload } = args;
  if (payload.length <= MAX_FRAGMENT_PAYLOAD_BYTES) {
    return [
      packFrame(
        {
          callID,
          senderPeerID,
          mediaType,
          sequence,
          timestamp,
          fragmentIndex: 0,
          totalFragments: 1,
          isKeyFrame,
        },
        payload,
      ),
    ];
  }
  const totalFragments = Math.min(
    255,
    Math.ceil(payload.length / MAX_FRAGMENT_PAYLOAD_BYTES),
  );
  const out: Uint8Array[] = [];
  for (let i = 0; i < totalFragments; i++) {
    const start = i * MAX_FRAGMENT_PAYLOAD_BYTES;
    const end = Math.min(start + MAX_FRAGMENT_PAYLOAD_BYTES, payload.length);
    out.push(
      packFrame(
        {
          callID,
          senderPeerID,
          mediaType,
          sequence,
          timestamp,
          fragmentIndex: i,
          totalFragments,
          isKeyFrame,
        },
        payload.slice(start, end),
      ),
    );
  }
  return out;
}

/**
 * Reassembles fragmented frames keyed by (sequence). Holds incomplete frames
 * for `holdMs` then evicts.
 */
export class FragmentReassembler {
  private pending = new Map<
    number,
    { fragments: (Uint8Array | undefined)[]; received: number; total: number; firstSeenAt: number }
  >();

  private readonly holdMs: number;
  private readonly maxPending: number;

  constructor(holdMs = 200, maxPending = 5) {
    this.holdMs = holdMs;
    this.maxPending = maxPending;
  }

  /** Returns the reassembled payload + header when complete, otherwise null. */
  ingest(unpacked: UnpackedFrame): { header: MediaFrameHeader; payload: Uint8Array } | null {
    const { header, payload } = unpacked;
    if (header.totalFragments <= 1) return { header, payload };

    let entry = this.pending.get(header.sequence);
    if (!entry) {
      entry = {
        fragments: new Array(header.totalFragments),
        received: 0,
        total: header.totalFragments,
        firstSeenAt: performance.now(),
      };
      this.pending.set(header.sequence, entry);
      this.evictStale();
    }
    if (entry.fragments[header.fragmentIndex] !== undefined) {
      // Duplicate fragment — ignore.
      return null;
    }
    entry.fragments[header.fragmentIndex] = payload;
    entry.received++;
    if (entry.received < entry.total) return null;

    let totalLen = 0;
    for (const f of entry.fragments) totalLen += f?.length ?? 0;
    const merged = new Uint8Array(totalLen);
    let off = 0;
    for (const f of entry.fragments) {
      if (f) {
        merged.set(f, off);
        off += f.length;
      }
    }
    this.pending.delete(header.sequence);
    return { header, payload: merged };
  }

  private evictStale(): void {
    const now = performance.now();
    for (const [seq, entry] of this.pending) {
      if (now - entry.firstSeenAt > this.holdMs) {
        this.pending.delete(seq);
      }
    }
    if (this.pending.size > this.maxPending) {
      // Drop oldest.
      const oldest = [...this.pending.entries()].sort(
        (a, b) => a[1].firstSeenAt - b[1].firstSeenAt,
      )[0];
      if (oldest) this.pending.delete(oldest[0]);
    }
  }

  reset(): void {
    this.pending.clear();
  }
}
