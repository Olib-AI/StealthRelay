// What the relay's answers mean for someone joining, in words fit to show.

const INVITATION_ENDED = 'This invitation is no longer valid: it has expired, been used up, or the host withdrew it. Ask the host for a new one.';
const TRY_AGAIN = "The relay couldn't take this request. Try again in a moment. If it keeps happening, ask the host for a new invitation.";

export interface ServerErrorOutcome {
  /** This ends the attempt or the session. Nothing else is coming, so don't keep waiting. */
  terminal: boolean;
  text: string | null;
}

/**
 * An `error` frame other than the proof-of-work challenge and a refused rejoin. The relay answers a join
 * it refuses with one of these and nothing more, so before someone is in, every one of them ends the wait.
 */
export function serverErrorOutcome(code: number, message: string, joined: boolean): ServerErrorOutcome {
  if (joined) {
    if (code === 401 || code === 403) return { terminal: true, text: 'The relay no longer accepts this connection. Ask the host for a new invitation.' };
    return { terminal: false, text: null };
  }
  if (code === 404) return { terminal: true, text: INVITATION_ENDED };
  if (code === 429) return { terminal: true, text: 'Too many attempts. Wait a moment and try again.' };
  if (message === 'pool_full') return { terminal: true, text: 'This pool is full.' };
  if (code === 503) return { terminal: true, text: 'Too many people are waiting to join this pool. Try again in a moment.' };
  return { terminal: true, text: TRY_AGAIN };
}

/** A `join_rejected` frame. */
export function joinRefusalText(reason: unknown): string {
  switch (typeof reason === 'string' ? reason.toLowerCase() : '') {
    case 'invitation_ended':
      return INVITATION_ENDED;
    case 'host_offline_unavailable':
      return "The host is offline, so they can't let you in right now. Try again when they're back.";
    case 'rejected by host':
      return 'The host declined this request.';
    default:
      return "You couldn't join this pool. Ask the host for a new invitation.";
  }
}

/**
 * An expired link has nothing left to offer a newcomer. Someone the host has already let in doesn't need
 * it: the relay takes them back on their key, and refuses them if they were removed.
 */
export function canAttemptJoin(state: { expired: boolean; joinedBefore: boolean }): boolean {
  return !state.expired || state.joinedBefore;
}

const FIRST_RETRY_MS = 1000;
const LONGEST_RETRY_MS = 300_000;

/** The app's reconnect: growing gaps, up to 5 minutes, for as long as the person stays. */
export function reconnectDelayMs(attempt: number): number {
  if (attempt >= 20) return LONGEST_RETRY_MS;
  return Math.min(FIRST_RETRY_MS * 2 ** attempt, LONGEST_RETRY_MS);
}

/** Why a pool the host never protected holds everything. Older versions are named only while one is here. */
export function notProtectedText(olderVersionPeople: number): string {
  return olderVersionPeople > 0
    ? "The host hasn't turned on protection for this pool, because someone here uses an older version of StealthOS. The web client only takes part in protected pools, so nothing is being sent or received until they update."
    : "The host hasn't turned on protection for this pool yet. The web client only takes part in protected pools, so nothing is being sent or received until it's on.";
}
