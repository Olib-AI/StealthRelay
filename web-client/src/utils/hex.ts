const HEX_CHARS = '0123456789abcdef';

export function hexEncode(bytes: Uint8Array): string {
  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    result += HEX_CHARS[b >> 4]!;
    result += HEX_CHARS[b & 0x0f]!;
  }
  return result;
}

export function hexDecode(hex: string): Uint8Array {
  const clean = hex.replace(/\s/g, '');
  if (clean.length % 2 !== 0) {
    throw new Error('Invalid hex string: odd length');
  }
  const result = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    const hi = parseInt(clean[i]!, 16);
    const lo = parseInt(clean[i + 1]!, 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) {
      throw new Error(`Invalid hex character at position ${i}`);
    }
    result[i / 2] = (hi << 4) | lo;
  }
  return result;
}
