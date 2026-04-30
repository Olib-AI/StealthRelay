// H.264 AVCC helpers.
//
// iOS `VideoCallService.swift` writes keyframes as a sequence of length-
// prefixed NAL units in this exact order:
//
//   [4-byte BE length][SPS NAL][4-byte BE length][PPS NAL][4-byte BE length][IDR NAL]
//
// Non-keyframes carry only the slice NAL units (also length-prefixed).
// To stay byte-compatible we mirror that layout in both directions.

const NAL_TYPE_MASK = 0x1f;
const NAL_TYPE_SPS = 7;
const NAL_TYPE_PPS = 8;

/** Read a 4-byte big-endian length at `offset`. */
function readU32BE(buf: Uint8Array, offset: number): number {
  return (
    (buf[offset]! * 0x1000000) +
    (buf[offset + 1]! << 16) +
    (buf[offset + 2]! << 8) +
    buf[offset + 3]!
  );
}

function writeU32BE(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = (value >>> 24) & 0xff;
  buf[offset + 1] = (value >>> 16) & 0xff;
  buf[offset + 2] = (value >>> 8) & 0xff;
  buf[offset + 3] = value & 0xff;
}

/** Parse an avcC config record into its raw SPS and PPS NAL units. */
export function parseAvcCDescription(description: Uint8Array): {
  sps: Uint8Array;
  pps: Uint8Array;
  lengthSize: number;
} {
  // [0]=version, [1]=profile, [2]=profile_compat, [3]=level,
  // [4]=0xFC | (lengthSizeMinusOne), [5]=0xE0 | numSPS
  const lengthSize = (description[4]! & 0x03) + 1;
  const numSPS = description[5]! & 0x1f;
  let off = 6;
  let sps: Uint8Array | null = null;
  for (let i = 0; i < numSPS; i++) {
    const len = (description[off]! << 8) | description[off + 1]!;
    off += 2;
    if (sps === null) sps = description.slice(off, off + len);
    off += len;
  }
  const numPPS = description[off]!;
  off++;
  let pps: Uint8Array | null = null;
  for (let i = 0; i < numPPS; i++) {
    const len = (description[off]! << 8) | description[off + 1]!;
    off += 2;
    if (pps === null) pps = description.slice(off, off + len);
    off += len;
  }
  if (!sps || !pps) throw new Error('avcC missing SPS or PPS');
  return { sps, pps, lengthSize };
}

/** Build an avcC config record from raw SPS/PPS NALs. */
export function buildAvcCDescription(sps: Uint8Array, pps: Uint8Array): Uint8Array {
  // SPS: byte 0 is NAL header, bytes 1-3 are profile / profile_compat / level.
  const profile = sps[1] ?? 0x42;
  const profileCompat = sps[2] ?? 0xe0;
  const level = sps[3] ?? 0x1e;
  const out = new Uint8Array(7 + 2 + sps.length + 1 + 2 + pps.length);
  let off = 0;
  out[off++] = 0x01; // configurationVersion
  out[off++] = profile;
  out[off++] = profileCompat;
  out[off++] = level;
  out[off++] = 0xff; // 0xFC | (lengthSize - 1) = 0xFF for 4-byte length prefix
  out[off++] = 0xe1; // 0xE0 | 1 SPS
  out[off++] = (sps.length >> 8) & 0xff;
  out[off++] = sps.length & 0xff;
  out.set(sps, off);
  off += sps.length;
  out[off++] = 0x01; // 1 PPS
  out[off++] = (pps.length >> 8) & 0xff;
  out[off++] = pps.length & 0xff;
  out.set(pps, off);
  off += pps.length;
  return out;
}

/** Prepend `[len][SPS][len][PPS]` to a keyframe's slice NALs. Matches iOS. */
export function prependParameterSets(
  slice: Uint8Array,
  sps: Uint8Array,
  pps: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(4 + sps.length + 4 + pps.length + slice.length);
  let off = 0;
  writeU32BE(out, off, sps.length);
  off += 4;
  out.set(sps, off);
  off += sps.length;
  writeU32BE(out, off, pps.length);
  off += 4;
  out.set(pps, off);
  off += pps.length;
  out.set(slice, off);
  return out;
}

/**
 * Force `nal_ref_idc = 11` on every length-prefixed NAL in `data` whose
 * type is in `types`. Mutates in place. Use to defang the WebCodecs habit
 * of emitting parameter sets and IDR slices with ref_idc=01, which Apple
 * VideoToolbox treats as discardable.
 */
export function setRefIdcHigh(data: Uint8Array, types: ReadonlySet<number>): void {
  let off = 0;
  while (off + 4 <= data.length) {
    const len = readU32BE(data, off);
    if (len <= 0 || off + 4 + len > data.length) break;
    const headerOff = off + 4;
    const nalType = data[headerOff]! & NAL_TYPE_MASK;
    if (types.has(nalType)) {
      data[headerOff] = (data[headerOff]! & 0x9f) | 0x60;
    }
    off = headerOff + len;
  }
}

/**
 * Walk length-prefixed NALs at the front of `data` and pluck SPS/PPS if
 * present. Returns the parameter sets and the body containing the remaining
 * NALs (typically the IDR slice + any aux NALs).
 */
export function extractParameterSets(data: Uint8Array): {
  sps?: Uint8Array;
  pps?: Uint8Array;
  body: Uint8Array;
} {
  let off = 0;
  let sps: Uint8Array | undefined;
  let pps: Uint8Array | undefined;
  while (off + 4 <= data.length) {
    const len = readU32BE(data, off);
    if (len <= 0 || off + 4 + len > data.length) break;
    const nalHeader = data[off + 4]!;
    const nalType = nalHeader & NAL_TYPE_MASK;
    if (nalType === NAL_TYPE_SPS && !sps) {
      sps = data.slice(off + 4, off + 4 + len);
      off += 4 + len;
      continue;
    }
    if (nalType === NAL_TYPE_PPS && !pps) {
      pps = data.slice(off + 4, off + 4 + len);
      off += 4 + len;
      continue;
    }
    break; // First non-PS NAL — stop and treat the rest as body.
  }
  return { sps, pps, body: data.slice(off) };
}
