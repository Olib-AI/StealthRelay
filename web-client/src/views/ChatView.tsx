import { useRef, useEffect, useCallback } from 'react';
import { ArrowLeft, Lock, Users, User, MessageSquare } from 'lucide-react';
import { v4 as uuidv4 } from 'uuid';
import { useChatStore } from '../stores/chat.ts';
import type { ChatMessage } from '../stores/chat.ts';
import { useConnectionStore } from '../stores/connection.ts';
import { usePoolStore } from '../stores/pool.ts';
import { transport } from '../transport/websocket.ts';

import { appleTimestamp } from '../utils/time.ts';
import type { EncryptedChatMessage } from '../protocol/messages.ts';
import MessageBubble from '../components/MessageBubble.tsx';
import ChatInput from '../components/ChatInput.tsx';
import PeerAvatar from '../components/PeerAvatar.tsx';

interface ChatViewProps {
  onBack: () => void;
}

function ChatView({ onBack }: ChatViewProps) {
  const currentView = useChatStore((s) => s.currentView);
  const setCurrentView = useChatStore((s) => s.setCurrentView);
  const groupMessages = useChatStore((s) => s.groupMessages);
  const privateMessages = useChatStore((s) => s.privateMessages);
  const selectedPrivatePeerId = useChatStore((s) => s.selectedPrivatePeerId);
  const setSelectedPrivatePeerId = useChatStore((s) => s.setSelectedPrivatePeerId);
  const unreadPrivate = useChatStore((s) => s.unreadPrivate);
  const unreadGroup = useChatStore((s) => s.unreadGroup);
  const markGroupRead = useChatStore((s) => s.markGroupRead);
  const markPrivateRead = useChatStore((s) => s.markPrivateRead);
  const peerSymmetricKeys = useChatStore((s) => s.peerSymmetricKeys);
  const localPeerId = useConnectionStore((s) => s.localPeerId);
  const peers = usePoolStore((s) => s.peers);
  const userProfile = usePoolStore((s) => s.userProfile);
  const totalPrivateUnread = Object.values(unreadPrivate).reduce((sum, n) => sum + n, 0);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const currentMessages: ChatMessage[] =
    currentView === 'group'
      ? groupMessages
      : selectedPrivatePeerId
        ? (privateMessages[selectedPrivatePeerId] ?? [])
        : [];

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [currentMessages.length]);

  useEffect(() => {
    if (currentView === 'group') {
      markGroupRead();
    } else if (selectedPrivatePeerId) {
      markPrivateRead(selectedPrivatePeerId);
    }
  }, [currentView, selectedPrivatePeerId, markGroupRead, markPrivateRead, currentMessages.length]);

  const handleSendMessage = useCallback(async (text: string, replyTo?: { messageID: string; senderName: string; previewText: string }) => {
    if (!localPeerId) return;

    const timestamp = appleTimestamp();

    const chatMessage: EncryptedChatMessage = {
      id: uuidv4(),
      senderID: localPeerId,
      senderName: userProfile.displayName,
      contentType: 'text',
      timestamp,
      text,
      reactions: {},
      replyTo,
      mentions: [],
      senderAvatarEmoji: userProfile.avatarEmoji,
      senderAvatarColorIndex: userProfile.avatarColorIndex,
    };

    if (currentView === 'group') {
      // Try to encrypt for each peer, but send as group message
      // For group chat, we send the plaintext version (E2E is per-peer)
      transport.sendChatMessage(chatMessage, null);

      // Add to local store immediately
      const localMsg: ChatMessage = {
        id: chatMessage.id,
        senderID: localPeerId,
        senderName: userProfile.displayName,
        contentType: 'text',
        timestamp: Date.now(),
        text,
        reactions: {},
        replyTo,
        mentions: [],
        senderAvatarEmoji: userProfile.avatarEmoji,
        senderAvatarColorIndex: userProfile.avatarColorIndex,
        isEncrypted: false,
        isPrivate: false,
      };
      useChatStore.getState().addGroupMessage(localMsg);
    } else if (selectedPrivatePeerId) {
      // Private message: sendChatMessage handles encryption at the transport layer
      transport.sendChatMessage(chatMessage, [selectedPrivatePeerId]);

      const localMsg: ChatMessage = {
        id: chatMessage.id,
        senderID: localPeerId,
        senderName: userProfile.displayName,
        contentType: 'text',
        timestamp: Date.now(),
        text,
        reactions: {},
        replyTo,
        mentions: [],
        senderAvatarEmoji: userProfile.avatarEmoji,
        senderAvatarColorIndex: userProfile.avatarColorIndex,
        isEncrypted: !!peerSymmetricKeys[selectedPrivatePeerId],
        isPrivate: true,
      };
      useChatStore.getState().addPrivateMessage(selectedPrivatePeerId, localMsg);
    }
  }, [localPeerId, userProfile, currentView, selectedPrivatePeerId, peerSymmetricKeys]);

  const handleSendVoice = useCallback(async (voiceData: string, voiceDuration: number) => {
    if (!localPeerId) return;

    const chatMessage: EncryptedChatMessage = {
      id: uuidv4(),
      senderID: localPeerId,
      senderName: userProfile.displayName,
      contentType: 'voice',
      timestamp: appleTimestamp(),
      voiceData,
      voiceDuration,
      reactions: {},
      mentions: [],
      senderAvatarEmoji: userProfile.avatarEmoji,
      senderAvatarColorIndex: userProfile.avatarColorIndex,
    };

    const targets = currentView === 'group' ? null : selectedPrivatePeerId ? [selectedPrivatePeerId] : null;
    transport.sendChatMessage(chatMessage, targets);

    const localMsg: ChatMessage = {
      id: chatMessage.id,
      senderID: localPeerId,
      senderName: userProfile.displayName,
      contentType: 'voice',
      timestamp: Date.now(),
      voiceData,
      voiceDuration,
      reactions: {},
      mentions: [],
      senderAvatarEmoji: userProfile.avatarEmoji,
      senderAvatarColorIndex: userProfile.avatarColorIndex,
      isEncrypted: currentView === 'private' && selectedPrivatePeerId ? !!peerSymmetricKeys[selectedPrivatePeerId] : false,
      isPrivate: currentView === 'private',
    };

    if (currentView === 'group') {
      useChatStore.getState().addGroupMessage(localMsg);
    } else if (selectedPrivatePeerId) {
      useChatStore.getState().addPrivateMessage(selectedPrivatePeerId, localMsg);
    }
  }, [localPeerId, userProfile, currentView, selectedPrivatePeerId, peerSymmetricKeys]);

  const handleSendImage = useCallback(async (imageData: string, caption?: string) => {
    if (!localPeerId) return;

    const chatMessage: EncryptedChatMessage = {
      id: uuidv4(),
      senderID: localPeerId,
      senderName: userProfile.displayName,
      contentType: 'image',
      timestamp: appleTimestamp(),
      imageData,
      text: caption,
      reactions: {},
      mentions: [],
      senderAvatarEmoji: userProfile.avatarEmoji,
      senderAvatarColorIndex: userProfile.avatarColorIndex,
    };

    const targets = currentView === 'group' ? null : selectedPrivatePeerId ? [selectedPrivatePeerId] : null;
    transport.sendChatMessage(chatMessage, targets);

    const localMsg: ChatMessage = {
      id: chatMessage.id,
      senderID: localPeerId,
      senderName: userProfile.displayName,
      contentType: 'image',
      timestamp: Date.now(),
      imageData,
      text: caption,
      reactions: {},
      mentions: [],
      senderAvatarEmoji: userProfile.avatarEmoji,
      senderAvatarColorIndex: userProfile.avatarColorIndex,
      isEncrypted: currentView === 'private' && selectedPrivatePeerId ? !!peerSymmetricKeys[selectedPrivatePeerId] : false,
      isPrivate: currentView === 'private',
    };

    if (currentView === 'group') {
      useChatStore.getState().addGroupMessage(localMsg);
    } else if (selectedPrivatePeerId) {
      useChatStore.getState().addPrivateMessage(selectedPrivatePeerId, localMsg);
    }
  }, [localPeerId, userProfile, currentView, selectedPrivatePeerId, peerSymmetricKeys]);

  const handleSendPoll = useCallback((question: string, options: string[], allowVoteChange: boolean) => {
    if (!localPeerId) return;

    const chatMessage: EncryptedChatMessage = {
      id: uuidv4(),
      senderID: localPeerId,
      senderName: userProfile.displayName,
      contentType: 'poll',
      timestamp: appleTimestamp(),
      pollData: { question, options, votes: {}, allowVoteChange },
      reactions: {},
      mentions: [],
      senderAvatarEmoji: userProfile.avatarEmoji,
      senderAvatarColorIndex: userProfile.avatarColorIndex,
    };

    transport.sendChatMessage(chatMessage, currentView === 'group' ? null : selectedPrivatePeerId ? [selectedPrivatePeerId] : null);

    const localMsg: ChatMessage = {
      id: chatMessage.id,
      senderID: localPeerId,
      senderName: userProfile.displayName,
      contentType: 'poll',
      timestamp: Date.now(),
      pollData: { question, options, votes: {}, allowVoteChange },
      reactions: {},
      mentions: [],
      senderAvatarEmoji: userProfile.avatarEmoji,
      senderAvatarColorIndex: userProfile.avatarColorIndex,
      isEncrypted: false,
      isPrivate: currentView === 'private',
    };

    if (currentView === 'group') {
      useChatStore.getState().addGroupMessage(localMsg);
    } else if (selectedPrivatePeerId) {
      useChatStore.getState().addPrivateMessage(selectedPrivatePeerId, localMsg);
    }
  }, [localPeerId, userProfile, currentView, selectedPrivatePeerId]);

  const otherPeers = peers.filter((p) => p.peerId !== localPeerId);

  return (
    <div className="flex-1 flex flex-col min-h-0">
      {/* Top bar */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[#38383A] bg-[#1C1C1E]">
        <button type="button" onClick={onBack} className="text-[#007AFF] transition-colors">
          <ArrowLeft className="h-5 w-5" />
        </button>

        <div className="flex-1 flex items-center gap-2">
          {currentView === 'group' ? (
            <>
              <Users className="h-4 w-4 text-[#007AFF]" />
              <span className="text-[17px] font-semibold text-white">Group Chat</span>
            </>
          ) : selectedPrivatePeerId ? (
            <>
              {(() => {
                const peer = peers.find((p) => p.peerId === selectedPrivatePeerId);
                return peer ? (
                  <>
                    <PeerAvatar emoji={peer.avatarEmoji} colorIndex={peer.avatarColorIndex} size="sm" />
                    <span className="text-[17px] font-semibold text-white">{peer.displayName}</span>
                    {peerSymmetricKeys[selectedPrivatePeerId] && (
                      <Lock className="h-3 w-3 text-[#30D158]" />
                    )}
                  </>
                ) : (
                  <span className="text-[17px] font-semibold text-white">Private Chat</span>
                );
              })()}
            </>
          ) : (
            <>
              <User className="h-4 w-4 text-[#BF5AF2]" />
              <span className="text-[17px] font-semibold text-white">Private Messages</span>
            </>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex bg-[#1C1C1E] px-2 py-1.5 gap-1">
        <button
          type="button"
          onClick={() => { setCurrentView('group'); setSelectedPrivatePeerId(null); }}
          className={`flex-1 py-2 text-[13px] font-medium rounded-lg transition-colors relative ${currentView === 'group' ? 'bg-[rgba(0,122,255,0.1)] text-[#007AFF]' : 'text-[rgba(235,235,245,0.6)]'}`}
        >
          Group Chat
          {currentView !== 'group' && unreadGroup > 0 && (
            <span className="absolute top-1 right-2 min-w-[18px] h-[18px] px-1 rounded-full bg-[#FF453A] text-white text-[11px] font-bold flex items-center justify-center">
              {unreadGroup > 99 ? '99+' : unreadGroup}
            </span>
          )}
        </button>
        <button
          type="button"
          onClick={() => setCurrentView('private')}
          className={`flex-1 py-2 text-[13px] font-medium rounded-lg transition-colors relative ${currentView === 'private' ? 'bg-[rgba(0,122,255,0.1)] text-[#007AFF]' : 'text-[rgba(235,235,245,0.6)]'}`}
        >
          Private Messages
          {currentView !== 'private' && totalPrivateUnread > 0 && (
            <span className="absolute top-1 right-2 min-w-[18px] h-[18px] px-1 rounded-full bg-[#FF453A] text-white text-[11px] font-bold flex items-center justify-center">
              {totalPrivateUnread > 99 ? '99+' : totalPrivateUnread}
            </span>
          )}
        </button>
      </div>

      {/* Private peer list (when no peer selected) */}
      {currentView === 'private' && !selectedPrivatePeerId && (
        <div className="flex-1 overflow-y-auto bg-black">
          {otherPeers.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full" style={{ color: 'rgba(235, 235, 245, 0.3)' }}>
              <User className="h-8 w-8 mb-2 opacity-50" />
              <p className="text-[15px]">No peers to message</p>
            </div>
          )}
          {otherPeers.map((peer, index) => {
            const unread = unreadPrivate[peer.peerId] ?? 0;
            const lastMsg = privateMessages[peer.peerId]?.slice(-1)[0];
            return (
              <button
                key={peer.peerId}
                type="button"
                onClick={() => setSelectedPrivatePeerId(peer.peerId)}
                className={`w-full flex items-center gap-3 px-4 py-2.5 transition-colors ${index < otherPeers.length - 1 ? 'border-b border-[#38383A]' : ''}`}
              >
                <PeerAvatar emoji={peer.avatarEmoji} colorIndex={peer.avatarColorIndex} size="sm" />
                <div className="flex-1 min-w-0 text-left">
                  <div className="flex items-center justify-between">
                    <span className="text-[15px] font-medium text-white truncate">{peer.displayName}</span>
                    {unread > 0 && (
                      <span className="h-5 min-w-5 px-1.5 rounded-full bg-[#FF453A] text-white text-[10px] font-bold flex items-center justify-center">
                        {unread}
                      </span>
                    )}
                  </div>
                  {lastMsg && (
                    <p className="text-[12px] truncate mt-0.5" style={{ color: 'rgba(235, 235, 245, 0.3)' }}>{lastMsg.text ?? '...'}</p>
                  )}
                </div>
                {peerSymmetricKeys[peer.peerId] && (
                  <Lock className="h-3 w-3 text-[#30D158] shrink-0" />
                )}
              </button>
            );
          })}
        </div>
      )}

      {/* Messages area */}
      {(currentView === 'group' || (currentView === 'private' && selectedPrivatePeerId)) && (
        <>
          <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3 bg-black">
            {currentMessages.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full" style={{ color: 'rgba(235, 235, 245, 0.3)' }}>
                <MessageSquare className="h-8 w-8 mb-2 opacity-50" />
                <p className="text-[15px]">No messages yet</p>
                <p className="text-[12px] mt-1">Start the conversation</p>
              </div>
            )}
            {currentMessages.map((msg) => (
              <MessageBubble key={msg.id} message={msg} isGroup={currentView === 'group'} />
            ))}
            <div ref={messagesEndRef} />
          </div>

          <ChatInput
            onSendMessage={handleSendMessage}
            onSendPoll={handleSendPoll}
            onSendVoice={handleSendVoice}
            onSendImage={handleSendImage}
          />
        </>
      )}
    </div>
  );
}

export default ChatView;
