import { APPLE_EPOCH_OFFSET } from '../protocol/constants.ts';

/** Returns Apple reference date timestamp (seconds since Jan 1, 2001) */
export function appleTimestamp(): number {
  return Date.now() / 1000 - APPLE_EPOCH_OFFSET;
}
