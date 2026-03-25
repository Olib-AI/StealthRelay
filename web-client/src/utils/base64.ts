const STANDARD_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function buildLookup(chars: string): Uint8Array {
  const lookup = new Uint8Array(128);
  for (let i = 0; i < chars.length; i++) {
    lookup[chars.charCodeAt(i)]! = i;
  }
  return lookup;
}

const STANDARD_LOOKUP = buildLookup(STANDARD_CHARS);
const URL_LOOKUP = buildLookup(URL_CHARS);

export function base64Encode(bytes: Uint8Array): string {
  let result = '';
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i]!;
    const b1 = i + 1 < len ? bytes[i + 1]! : 0;
    const b2 = i + 2 < len ? bytes[i + 2]! : 0;
    result += STANDARD_CHARS[(b0 >> 2)!]!;
    result += STANDARD_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)]!;
    result += i + 1 < len ? STANDARD_CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)]! : '=';
    result += i + 2 < len ? STANDARD_CHARS[b2 & 0x3f]! : '=';
  }
  return result;
}

function decodeBase64(str: string, lookup: Uint8Array): Uint8Array {
  let stripped = str.replace(/[=\s]/g, '');
  const misalign = stripped.length % 4;
  if (misalign === 2) stripped += 'AA';
  else if (misalign === 3) stripped += 'A';

  const len = stripped.length;
  const outLen = (len * 3) / 4 - (misalign === 2 ? 2 : misalign === 3 ? 1 : 0);
  const result = new Uint8Array(outLen);
  let j = 0;
  for (let i = 0; i < len; i += 4) {
    const a = lookup[stripped.charCodeAt(i)]!;
    const b = lookup[stripped.charCodeAt(i + 1)]!;
    const c = lookup[stripped.charCodeAt(i + 2)]!;
    const d = lookup[stripped.charCodeAt(i + 3)]!;
    if (j < outLen) result[j++] = (a << 2) | (b >> 4);
    if (j < outLen) result[j++] = ((b & 0x0f) << 4) | (c >> 2);
    if (j < outLen) result[j++] = ((c & 0x03) << 6) | d;
  }
  return result;
}

export function base64Decode(str: string): Uint8Array {
  return decodeBase64(str, STANDARD_LOOKUP);
}

export function base64UrlDecode(str: string): Uint8Array {
  return decodeBase64(str, URL_LOOKUP);
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let result = '';
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i]!;
    const b1 = i + 1 < len ? bytes[i + 1]! : 0;
    const b2 = i + 2 < len ? bytes[i + 2]! : 0;
    result += URL_CHARS[(b0 >> 2)!]!;
    result += URL_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)]!;
    if (i + 1 < len) result += URL_CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)]!;
    if (i + 2 < len) result += URL_CHARS[b2 & 0x3f]!;
  }
  return result;
}
