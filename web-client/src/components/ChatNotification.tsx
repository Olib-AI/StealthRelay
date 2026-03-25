import { useState, useEffect, useRef } from 'react';
import { MessageSquare, User } from 'lucide-react';
import { useChatStore } from '../stores/chat.ts';
import type { ChatMessage } from '../stores/chat.ts';
import { usePoolStore } from '../stores/pool.ts';
import { useConnectionStore } from '../stores/connection.ts';
import PeerAvatar from './PeerAvatar.tsx';

interface Toast {
  id: string;
  message: ChatMessage;
  isPrivate: boolean;
  peerId?: string;
}

interface ChatNotificationProps {
  currentView: string;
  onNavigateToChat?: (view: 'group' | 'private', peerId?: string) => void;
}

function ChatNotification({ currentView, onNavigateToChat }: ChatNotificationProps) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const peers = usePoolStore((s) => s.peers);

  // Subscribe to store changes outside React render cycle
  useEffect(() => {
    let prevGroupCount = useChatStore.getState().groupMessages.length;
    const prevPrivateCounts: Record<string, number> = {};
    for (const [pid, msgs] of Object.entries(useChatStore.getState().privateMessages)) {
      prevPrivateCounts[pid] = msgs.length;
    }

    const unsub = useChatStore.subscribe((state, prevState) => {
      const localPeerId = useConnectionStore.getState().localPeerId;
      const chatTab = state.currentView;
      const selectedPeer = state.selectedPrivatePeerId;
      const isOnChat = currentView === 'chat';
      const isViewingGroup = isOnChat && chatTab === 'group';
      const isViewingPrivate = isOnChat && chatTab === 'private';

      // Check group messages
      const groupCount = state.groupMessages.length;
      if (groupCount > prevGroupCount) {
        const newMsg = state.groupMessages[groupCount - 1];
        if (newMsg && newMsg.senderID !== 'system' && newMsg.senderID !== localPeerId && !isViewingGroup) {
          const id = newMsg.id + '-toast';
          setToasts((prev) => {
            if (prev.some((t) => t.id === id)) return prev;
            return [...prev, { id, message: newMsg, isPrivate: false }].slice(-3);
          });
          setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 4000);
        }
      }
      prevGroupCount = groupCount;

      // Check private messages
      for (const [peerId, msgs] of Object.entries(state.privateMessages)) {
        const prev = prevPrivateCounts[peerId] ?? 0;
        const curr = msgs.length;
        if (curr > prev) {
          const newMsg = msgs[curr - 1];
          const isViewingThisChat = isViewingPrivate && selectedPeer === peerId;
          if (newMsg && newMsg.senderID !== localPeerId && !isViewingThisChat) {
            const id = newMsg.id + '-toast';
            setToasts((prev) => {
              if (prev.some((t) => t.id === id)) return prev;
              return [...prev, { id, message: newMsg, isPrivate: true, peerId }].slice(-3);
            });
            setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 4000);
          }
        }
        prevPrivateCounts[peerId] = curr;
      }
    });

    return unsub;
  }, [currentView]);

  function handleToastClick(toast: Toast) {
    setToasts((prev) => prev.filter((t) => t.id !== toast.id));
    onNavigateToChat?.(toast.isPrivate ? 'private' : 'group', toast.peerId);
  }

  if (toasts.length === 0) return null;

  return (
    <div className="absolute top-2 left-2 right-2 z-50 flex flex-col gap-1.5 pointer-events-none">
      {toasts.map((toast) => {
        const peer = peers.find((p) => p.peerId === toast.message.senderID);
        const avatarEmoji = toast.message.senderAvatarEmoji ?? peer?.avatarEmoji ?? '😀';
        const colorIndex = toast.message.senderAvatarColorIndex ?? peer?.avatarColorIndex ?? 0;
        const senderName = peer?.displayName ?? toast.message.senderName;
        const previewText = toast.message.text
          ? toast.message.text.slice(0, 50) + (toast.message.text.length > 50 ? '...' : '')
          : toast.message.contentType === 'image' ? '📷 Photo'
          : toast.message.contentType === 'voice' ? '🎤 Voice message'
          : toast.message.contentType === 'poll' ? '📊 Poll'
          : 'New message';

        return (
          <button
            key={toast.id}
            type="button"
            onClick={() => handleToastClick(toast)}
            className="pointer-events-auto w-full flex items-center gap-2.5 px-3 py-2.5 rounded-2xl animate-slide-up shadow-2xl border border-[#007AFF]/30"
            style={{ backgroundColor: 'rgba(0, 30, 60, 0.92)', backdropFilter: 'blur(20px)' }}
          >
            <PeerAvatar emoji={avatarEmoji} colorIndex={colorIndex} size="sm" />
            <div className="flex-1 min-w-0 text-left">
              <div className="flex items-center gap-1.5">
                <span className="text-[13px] font-semibold text-white truncate">{senderName}</span>
                {toast.isPrivate ? (
                  <User className="h-3 w-3 text-[#BF5AF2] shrink-0" />
                ) : (
                  <MessageSquare className="h-3 w-3 text-[#007AFF] shrink-0" />
                )}
              </div>
              <p className="text-[12px] truncate" style={{ color: 'rgba(235, 235, 245, 0.6)' }}>{previewText}</p>
            </div>
          </button>
        );
      })}
    </div>
  );
}

export default ChatNotification;
