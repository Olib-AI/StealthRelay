import { create } from 'zustand';

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
  peerSymmetricKeys: Record<string, Uint8Array>;
  peerX25519Keys: Record<string, Uint8Array>;
  currentView: 'group' | 'private';
  selectedPrivatePeerId: string | null;
  replyingTo: ChatMessage | null;
  addGroupMessage: (msg: ChatMessage) => void;
  addPrivateMessage: (peerId: string, msg: ChatMessage) => void;
  markGroupRead: () => void;
  markPrivateRead: (peerId: string) => void;
  setPeerSymmetricKey: (peerId: string, key: Uint8Array) => void;
  setPeerX25519Key: (peerId: string, key: Uint8Array) => void;
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
  peerX25519Keys: {},
  currentView: 'group',
  selectedPrivatePeerId: null,
  replyingTo: null,
  addGroupMessage: (msg) =>
    set((state) => ({
      groupMessages: [...state.groupMessages, msg],
      unreadGroup: state.unreadGroup + 1,
    })),
  addPrivateMessage: (peerId, msg) =>
    set((state) => ({
      privateMessages: {
        ...state.privateMessages,
        [peerId]: [...(state.privateMessages[peerId] ?? []), msg],
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
  setPeerX25519Key: (peerId, key) =>
    set((state) => ({
      peerX25519Keys: { ...state.peerX25519Keys, [peerId]: key },
    })),
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
      peerX25519Keys: {},
      currentView: 'group',
      selectedPrivatePeerId: null,
      replyingTo: null,
    }),
}));
