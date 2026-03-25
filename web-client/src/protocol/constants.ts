export const MAX_MESSAGE_SIZE = 2097152;
export const HEARTBEAT_INTERVAL_MS = 15000;
export const MAX_RECONNECT_ATTEMPTS = 5;
export const INITIAL_RECONNECT_DELAY_MS = 1000;
export const MAX_RECONNECT_DELAY_MS = 30000;
export const APPLE_EPOCH_OFFSET = 978307200;

export const AVATAR_EMOJIS = [
  '😀', '😎', '🥳', '🤓', '😈', '👻', '🤖', '👽',
  '🦊', '🐱', '🐶', '🐼', '🦁', '🐯', '🐵', '🦄',
  '🎮', '🎯', '🎲', '🎸', '🎨', '🚀', '⚡️', '🔥',
  '🌟', '🌈', '🌙', '☀️', '🌸', '🍀', '💎', '🎭',
] as const;

export const AVATAR_COLORS = [
  '#3B82F6', '#22C55E', '#F97316', '#A855F7',
  '#EC4899', '#06B6D4', '#EAB308', '#EF4444',
] as const;

export type PoolMessageType =
  | 'chat'
  | 'game_state'
  | 'game_action'
  | 'game_control'
  | 'system'
  | 'ping'
  | 'pong'
  | 'peer_info'
  | 'profile_update'
  | 'key_exchange'
  | 'relay'
  | 'custom';
