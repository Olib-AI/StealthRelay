/**
 * Calls need the per-call media keys of MediaEncryptionService (v2), which this client does not have
 * yet. Its v1 media would pass as an older StealthOS, so it stays off: incoming calls are declined and
 * the person is told, here and on the caller's side.
 */
export const CALLS_ENABLED = false as boolean;

/**
 * Games have not been shown to work against the app since 1.5.0, and game state is not validated the
 * way chat is (see inbound.ts). Until both change they stay off: an invitation is declined and the
 * person told, and game frames are dropped. Validate them before turning this on.
 */
export const GAMES_ENABLED = false as boolean;
