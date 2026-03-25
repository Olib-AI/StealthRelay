import { hexEncode, hexDecode } from './hex.ts';

export function uuidToBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, '');
  if (hex.length !== 32) {
    throw new Error(`Invalid UUID: ${uuid}`);
  }
  return hexDecode(hex);
}

export function bytesToUuid(bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    throw new Error(`Invalid UUID bytes: expected 16, got ${bytes.length}`);
  }
  const hex = hexEncode(bytes);
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}
