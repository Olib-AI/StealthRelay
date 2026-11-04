// What Pool Chat puts on the wire, byte-compatible with PoolMessage.swift (ConnectionPool) and
// RichChatMessage.swift (PoolChat). `Date` is seconds since 2001, `Data` is base64.

import { base64Encode } from '../utils/base64.ts';
import { utf8 } from '../utils/bytes.ts';
import { APPLE_EPOCH_OFFSET } from './constants.ts';
import type { EncryptedChatMessage, PoolMessage } from './messages.ts';

export type EncryptedMessageType =
  | 'chat_message'
  | 'reaction'
  | 'poll_vote'
  | 'history_sync'
  | 'clear_history'
  | 'call_signal'
  | 'media_frame'
  | 'media_frame_v2';

export interface EncryptedChatPayload {
  encryptedData: string;
  senderPeerID: string;
  isPrivateChat: boolean;
  targetPeerID: string | null;
  messageType: EncryptedMessageType;
}

/** PrivateChatPayload { chatPayload: RichChatPayload, isPrivate, targetPeerID }. */
export function buildPrivateChatPayload(
  message: EncryptedChatMessage,
  isPrivate: boolean,
  targetPeerId: string | null,
): Record<string, unknown> {
  const chatPayload: Record<string, unknown> = {
    messageID: message.id,
    senderID: message.senderID,
    senderName: message.senderName,
    contentType: message.contentType ?? 'text',
    timestamp: message.timestamp,
    text: message.text,
    reactions: message.reactions ?? {},
    mentions: message.mentions ?? [],
    isEncrypted: true,
    senderAvatarEmoji: message.senderAvatarEmoji,
    senderAvatarColorIndex: message.senderAvatarColorIndex,
  };
  if (message.imageData !== undefined) chatPayload.imageData = message.imageData;
  if (message.voiceData !== undefined) chatPayload.voiceData = message.voiceData;
  if (message.voiceDuration !== undefined) chatPayload.voiceDuration = message.voiceDuration;
  if (message.emoji !== undefined) chatPayload.emoji = message.emoji;
  if (message.pollData !== undefined) chatPayload.pollData = message.pollData;
  if (message.replyTo !== undefined) chatPayload.replyTo = message.replyTo;
  return { chatPayload, isPrivate, targetPeerID: isPrivate ? targetPeerId : null };
}

export function buildPoolMessage(
  id: string,
  type: PoolMessage['type'],
  senderId: string,
  senderName: string,
  payload: unknown,
  isReliable: boolean,
  nowMillis: number = Date.now(),
): PoolMessage {
  return {
    id,
    type,
    senderID: senderId,
    senderName,
    timestamp: nowMillis / 1000 - APPLE_EPOCH_OFFSET,
    payload: base64Encode(utf8(JSON.stringify(payload))),
    isReliable,
  };
}
