import { create } from 'zustand';
import type { PeerSecurityInfo } from '../crypto/encryption.ts';

/** What one conversation keeps. A peer can send as much as it likes; this page keeps this much. */
export const MAX_MESSAGES_PER_CHAT = 500;
export const MAX_CHAT_BYTES = 64 * 1024 * 1024;
/** Same as the app's `StoredMessageChange.maximumReactors`. */
const MAX_REACTORS_PER_MESSAGE = 100;

function messageWeight(message: ChatMessage): number {
  return (message.text?.length ?? 0) + (message.imageData?.length ?? 0) + (message.voiceData?.length ?? 0);
}

/** Drops the oldest messages past either limit. */
export function capMessages(messages: ChatMessage[]): ChatMessage[] {
  let kept = messages.length > MAX_MESSAGES_PER_CHAT ? messages.slice(-MAX_MESSAGES_PER_CHAT) : messages;
  let bytes = kept.reduce((sum, message) => sum + messageWeight(message), 0);
  if (bytes > MAX_CHAT_BYTES) {
    let start = 0;
    while (bytes > MAX_CHAT_BYTES && start < kept.length - 1) {
      bytes -= messageWeight(kept[start]!);
      start += 1;
    }
    kept = kept.slice(start);
  }
  return kept;
}

export interface ChatMessage {
  id: string;
  senderID: string;
  senderName: string;
  contentType: 'text' | 'image' | 'voice' | 'emoji' | 'system' | 'poll';
  timestamp: number;
  text?: string;
  emoji?: string;
  imageData?: string;
  voiceData?: string;
  voiceDuration?: number;
  pollData?: {
    question: string;
    options: string[];
    votes: Record<string, string[]>;
    allowVoteChange: boolean;
  };
  reactions: Record<string, string[]>;
  replyTo?: { messageID: string; senderName: string; previewText: string };
  mentions: string[];
  senderAvatarEmoji?: string;
  senderAvatarColorIndex?: number;
  isEncrypted: boolean;
  isPrivate: boolean;
}

interface ChatState {
  groupMessages: ChatMessage[];
  privateMessages: Record<string, ChatMessage[]>;
  unreadGroup: number;
  unreadPrivate: Record<string, number>;
  /** Non-extractable AES-GCM keys, one per peer the key exchange has finished with. */
  peerSymmetricKeys: Record<string, CryptoKey>;
  /** Safety code and key fingerprints per peer, for the security-code screen. */
  peerSecurity: Record<string, PeerSecurityInfo>;
  currentView: 'group' | 'private';
  selectedPrivatePeerId: string | null;
  replyingTo: ChatMessage | null;
  addGroupMessage: (msg: ChatMessage) => void;
  addPrivateMessage: (peerId: string, msg: ChatMessage) => void;
  markGroupRead: () => void;
  markPrivateRead: (peerId: string) => void;
  setPeerSymmetricKey: (peerId: string, key: CryptoKey) => void;
  removePeerSymmetricKey: (peerId: string) => void;
  setPeerSecurity: (peerId: string, info: PeerSecurityInfo | null) => void;
  clearMessages: () => void;
  setCurrentView: (view: 'group' | 'private') => void;
  setSelectedPrivatePeerId: (peerId: string | null) => void;
  setReplyingTo: (msg: ChatMessage | null) => void;
  addReaction: (messageId: string, emoji: string, peerId: string, isGroup: boolean, privatePeerId?: string) => void;
  updatePollVote: (messageId: string, option: string, peerId: string, isGroup: boolean, privatePeerId?: string) => void;
  reset: () => void;
}

function addReactionToMessages(messages: ChatMessage[], messageId: string, emoji: string, peerId: string): ChatMessage[] {
  const normalizedId = messageId.toLowerCase();
  return messages.map((m) => {
    if (m.id.toLowerCase() !== normalizedId) return m;
    const reactions = { ...m.reactions };
    const existing = reactions[emoji] ?? [];
    const reactorCount = Object.values(reactions).reduce((sum, ids) => sum + ids.length, 0);
    if (!existing.includes(peerId) && reactorCount >= MAX_REACTORS_PER_MESSAGE) return m;
    if (existing.includes(peerId)) {
      const filtered = existing.filter((id) => id !== peerId);
      if (filtered.length === 0) {
        delete reactions[emoji];
      } else {
        reactions[emoji] = filtered;
      }
    } else {
      reactions[emoji] = [...existing, peerId];
    }
    return { ...m, reactions };
  });
}

function updatePollInMessages(messages: ChatMessage[], messageId: string, option: string, peerId: string): ChatMessage[] {
  const normalizedId = messageId.toLowerCase();
  return messages.map((m) => {
    if (m.id.toLowerCase() !== normalizedId || !m.pollData) return m;
    if (!m.pollData.options.includes(option)) return m; // Only what the poll offers.
    const votes = { ...m.pollData.votes };
    // Remove previous votes if not allowed to change
    for (const [opt, voters] of Object.entries(votes)) {
      if (opt !== option && voters.includes(peerId)) {
        votes[opt] = voters.filter((id) => id !== peerId);
      }
    }
    const optionVotes = votes[option] ?? [];
    if (optionVotes.includes(peerId)) {
      votes[option] = optionVotes.filter((id) => id !== peerId);
    } else {
      votes[option] = [...optionVotes, peerId];
    }
    return { ...m, pollData: { ...m.pollData, votes } };
  });
}

export const useChatStore = create<ChatState>((set) => ({
  groupMessages: [],
  privateMessages: {},
  unreadGroup: 0,
  unreadPrivate: {},
  peerSymmetricKeys: {},
  peerSecurity: {},
  currentView: 'group',
  selectedPrivatePeerId: null,
  replyingTo: null,
  addGroupMessage: (msg) =>
    set((state) => ({
      groupMessages: capMessages([...state.groupMessages, msg]),
      unreadGroup: state.unreadGroup + 1,
    })),
  addPrivateMessage: (peerId, msg) =>
    set((state) => ({
      privateMessages: {
        ...state.privateMessages,
        [peerId]: capMessages([...(state.privateMessages[peerId] ?? []), msg]),
      },
      unreadPrivate: {
        ...state.unreadPrivate,
        [peerId]: (state.unreadPrivate[peerId] ?? 0) + 1,
      },
    })),
  markGroupRead: () => set({ unreadGroup: 0 }),
  markPrivateRead: (peerId) =>
    set((state) => ({
      unreadPrivate: { ...state.unreadPrivate, [peerId]: 0 },
    })),
  setPeerSymmetricKey: (peerId, key) =>
    set((state) => ({
      peerSymmetricKeys: { ...state.peerSymmetricKeys, [peerId]: key },
    })),
  removePeerSymmetricKey: (peerId) =>
    set((state) => {
      const remaining = { ...state.peerSymmetricKeys };
      delete remaining[peerId];
      const security = { ...state.peerSecurity };
      delete security[peerId];
      return { peerSymmetricKeys: remaining, peerSecurity: security };
    }),
  setPeerSecurity: (peerId, info) =>
    set((state) => {
      const security = { ...state.peerSecurity };
      if (info) security[peerId] = info;
      else delete security[peerId];
      return { peerSecurity: security };
    }),
  clearMessages: () => set({ groupMessages: [], privateMessages: {}, unreadGroup: 0, unreadPrivate: {}, replyingTo: null }),
  setCurrentView: (currentView) => set({ currentView }),
  setSelectedPrivatePeerId: (selectedPrivatePeerId) => set({ selectedPrivatePeerId }),
  setReplyingTo: (replyingTo) => set({ replyingTo }),
  addReaction: (messageId, emoji, peerId, isGroup, privatePeerId) =>
    set((state) => {
      if (isGroup) {
        return { groupMessages: addReactionToMessages(state.groupMessages, messageId, emoji, peerId) };
      }
      if (privatePeerId) {
        const msgs = state.privateMessages[privatePeerId] ?? [];
        return {
          privateMessages: {
            ...state.privateMessages,
            [privatePeerId]: addReactionToMessages(msgs, messageId, emoji, peerId),
          },
        };
      }
      return state;
    }),
  updatePollVote: (messageId, option, peerId, isGroup, privatePeerId) =>
    set((state) => {
      if (isGroup) {
        return { groupMessages: updatePollInMessages(state.groupMessages, messageId, option, peerId) };
      }
      if (privatePeerId) {
        const msgs = state.privateMessages[privatePeerId] ?? [];
        return {
          privateMessages: {
            ...state.privateMessages,
            [privatePeerId]: updatePollInMessages(msgs, messageId, option, peerId),
          },
        };
      }
      return state;
    }),
  reset: () =>
    set({
      groupMessages: [],
      privateMessages: {},
      unreadGroup: 0,
      unreadPrivate: {},
      peerSymmetricKeys: {},
      peerSecurity: {},
      currentView: 'group',
      selectedPrivatePeerId: null,
      replyingTo: null,
    }),
}));
