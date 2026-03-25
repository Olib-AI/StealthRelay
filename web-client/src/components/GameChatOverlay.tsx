import { useState, useEffect, useRef, useCallback } from 'react';
import { MessageSquare, X, Send } from 'lucide-react';
import { v4 as uuidv4 } from 'uuid';
import { useChatStore } from '../stores/chat.ts';
import type { ChatMessage } from '../stores/chat.ts';
import { useConnectionStore } from '../stores/connection.ts';
import { usePoolStore } from '../stores/pool.ts';
import { transport } from '../transport/websocket.ts';
import { appleTimestamp } from '../utils/time.ts';
import { AVATAR_COLORS } from '../protocol/constants.ts';
import type { EncryptedChatMessage } from '../protocol/messages.ts';

const QUICK_REACTIONS = ['GG', 'Nice!', '\u{1F602}', '\u{1F389}', '\u{1F44D}', '\u{1F914}'] as const;
const MAX_VISIBLE_MESSAGES = 20;
const TOAST_DURATION_MS = 3000;
const DRAG_THRESHOLD_PX = 5;
const VIEWPORT_MARGIN = 20;
const BUBBLE_SIZE = 44;
const PANEL_WIDTH = 280;
const PANEL_HEIGHT = 320;

interface ToastData {
  id: string;
  senderEmoji: string;
  senderName: string;
  text: string;
}

function GameChatOverlay() {
  const [isOpen, setIsOpen] = useState(false);
  const [pos, setPos] = useState({ x: 0, y: 0 });
  const [posInitialized, setPosInitialized] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [toast, setToast] = useState<ToastData | null>(null);
  const [pulseKey, setPulseKey] = useState(0);
  const [inputText, setInputText] = useState('');

  const dragStartRef = useRef<{ x: number; y: number; posX: number; posY: number } | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevMessageCountRef = useRef(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const groupMessages = useChatStore((s) => s.groupMessages);
  const localPeerId = useConnectionStore((s) => s.localPeerId);
  const userProfile = usePoolStore((s) => s.userProfile);
  const peers = usePoolStore((s) => s.peers);

  // Initialize position on mount
  useEffect(() => {
    setPos({
      x: window.innerWidth - BUBBLE_SIZE - 40,
      y: window.innerHeight - BUBBLE_SIZE - 80,
    });
    setPosInitialized(true);
  }, []);

  // Filter to only text/emoji messages for display
  const chatMessages = groupMessages.filter(
    (m) => m.contentType === 'text' || m.contentType === 'emoji',
  );

  const visibleMessages = chatMessages.slice(-MAX_VISIBLE_MESSAGES);

  // Track new messages for unread count, toast, and pulse
  useEffect(() => {
    const currentCount = chatMessages.length;
    if (currentCount > prevMessageCountRef.current && prevMessageCountRef.current > 0) {
      const newMessages = chatMessages.slice(prevMessageCountRef.current);
      for (const msg of newMessages) {
        if (msg.senderID === localPeerId) continue;

        if (!isOpen) {
          setUnreadCount((c) => c + 1);
          setPulseKey((k) => k + 1);

          // Show toast for the latest message
          if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
          const displayText = (msg.contentType === 'emoji' ? msg.emoji : msg.text) ?? '';
          setToast({
            id: msg.id,
            senderEmoji: msg.senderAvatarEmoji ?? '\u{1F600}',
            senderName: msg.senderName,
            text: displayText.length > 40 ? displayText.slice(0, 40) + '\u2026' : displayText,
          });
          toastTimerRef.current = setTimeout(() => setToast(null), TOAST_DURATION_MS);
        }
      }
    }
    prevMessageCountRef.current = currentCount;
  }, [chatMessages.length, chatMessages, isOpen, localPeerId]);

  // Reset unread when panel opens
  useEffect(() => {
    if (isOpen) {
      setUnreadCount(0);
      setToast(null);
      if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    }
  }, [isOpen]);

  // Auto-scroll to bottom when new message arrives and panel is open
  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [visibleMessages.length, isOpen]);

  // Clamp position on window resize
  useEffect(() => {
    function handleResize() {
      setPos((prev) => ({
        x: Math.min(prev.x, window.innerWidth - BUBBLE_SIZE - VIEWPORT_MARGIN),
        y: Math.min(prev.y, window.innerHeight - BUBBLE_SIZE - VIEWPORT_MARGIN),
      }));
    }
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Drag handlers
  const handlePointerDown = useCallback((e: React.PointerEvent) => {
    dragStartRef.current = { x: e.clientX, y: e.clientY, posX: pos.x, posY: pos.y };
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  }, [pos.x, pos.y]);

  const handlePointerMove = useCallback((e: React.PointerEvent) => {
    const start = dragStartRef.current;
    if (!start) return;

    const dx = e.clientX - start.x;
    const dy = e.clientY - start.y;
    const distance = Math.sqrt(dx * dx + dy * dy);

    if (distance >= DRAG_THRESHOLD_PX) {
      setIsDragging(true);
    }

    const newX = Math.max(VIEWPORT_MARGIN, Math.min(start.posX + dx, window.innerWidth - BUBBLE_SIZE - VIEWPORT_MARGIN));
    const newY = Math.max(VIEWPORT_MARGIN, Math.min(start.posY + dy, window.innerHeight - BUBBLE_SIZE - VIEWPORT_MARGIN));
    setPos({ x: newX, y: newY });
  }, []);

  const handlePointerUp = useCallback(() => {
    const wasDragging = isDragging;
    dragStartRef.current = null;
    setIsDragging(false);

    if (!wasDragging) {
      setIsOpen((prev) => !prev);
    }
  }, [isDragging]);

  // Send message
  const sendMessage = useCallback((text: string) => {
    if (!text.trim() || !localPeerId) return;

    const chatMessage: EncryptedChatMessage = {
      id: uuidv4(),
      senderID: localPeerId,
      senderName: userProfile.displayName,
      contentType: 'text',
      timestamp: appleTimestamp(),
      text: text.trim(),
      reactions: {},
      mentions: [],
      senderAvatarEmoji: userProfile.avatarEmoji,
      senderAvatarColorIndex: userProfile.avatarColorIndex,
    };

    transport.sendChatMessage(chatMessage, null);

    const localMsg: ChatMessage = {
      id: chatMessage.id,
      senderID: localPeerId,
      senderName: userProfile.displayName,
      contentType: 'text',
      timestamp: Date.now(),
      text: text.trim(),
      reactions: {},
      mentions: [],
      senderAvatarEmoji: userProfile.avatarEmoji,
      senderAvatarColorIndex: userProfile.avatarColorIndex,
      isEncrypted: false,
      isPrivate: false,
    };
    useChatStore.getState().addGroupMessage(localMsg);
  }, [localPeerId, userProfile]);

  const handleSendClick = useCallback(() => {
    sendMessage(inputText);
    setInputText('');
    inputRef.current?.focus();
  }, [inputText, sendMessage]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage(inputText);
      setInputText('');
    }
  }, [inputText, sendMessage]);

  const handleQuickReaction = useCallback((reaction: string) => {
    sendMessage(reaction);
  }, [sendMessage]);

  const handleToastClick = useCallback(() => {
    setToast(null);
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    setIsOpen(true);
  }, []);

  // Determine panel position: above or below bubble
  const panelAbove = pos.y > PANEL_HEIGHT + 12;
  const panelLeft = Math.min(
    Math.max(VIEWPORT_MARGIN, pos.x + BUBBLE_SIZE / 2 - PANEL_WIDTH / 2),
    window.innerWidth - PANEL_WIDTH - VIEWPORT_MARGIN,
  );
  const panelTop = panelAbove ? pos.y - PANEL_HEIGHT - 12 : pos.y + BUBBLE_SIZE + 12;

  function getSenderColor(msg: ChatMessage): string {
    if (msg.senderID === localPeerId) return '#64D2FF'; // iOS cyan
    const colorIndex = msg.senderAvatarColorIndex;
    if (colorIndex !== undefined) {
      return AVATAR_COLORS[colorIndex] ?? '#FF9F0A'; // orange fallback
    }
    return '#FF9F0A'; // orange for remote
  }

  // Don't render until position is initialized to avoid flash at 0,0
  if (!posInitialized) return null;

  const unreadDisplay = unreadCount > 99 ? '99+' : String(unreadCount);

  return (
    <>
      {/* Toast notification */}
      {toast && !isOpen && (
        <button
          type="button"
          onClick={handleToastClick}
          className="fixed z-[41] right-4 top-4 max-w-[240px] rounded-full px-3 py-2 flex items-center gap-2 shadow-lg shadow-black/30 animate-fade-in cursor-pointer transition-colors"
          style={{ backgroundColor: 'rgba(0, 0, 0, 0.85)', backdropFilter: 'blur(20px)' }}
        >
          <span className="text-sm shrink-0">{toast.senderEmoji}</span>
          <div className="min-w-0">
            <span className="text-xs font-medium text-orange-400">{toast.senderName}</span>
            <p className="text-xs text-slate-300 truncate">{toast.text}</p>
          </div>
        </button>
      )}

      {/* Chat panel */}
      {isOpen && (
        <div
          className="fixed z-[41] rounded-2xl shadow-xl shadow-black/40 flex flex-col overflow-hidden"
          style={{ backgroundColor: 'rgba(0, 0, 0, 0.85)', backdropFilter: 'blur(20px)' }}
          style={{
            width: PANEL_WIDTH,
            height: PANEL_HEIGHT,
            left: panelLeft,
            top: panelTop,
          }}
        >
          {/* Header */}
          <div className="flex items-center gap-2 px-3 py-2 border-b border-white/10 shrink-0">
            <MessageSquare className="h-4 w-4 text-[#64D2FF]" />
            <span className="text-[13px] font-semibold text-white flex-1">Game Chat</span>
            <button
              type="button"
              onClick={() => setIsOpen(false)}
              className="transition-colors p-0.5" style={{ color: 'rgba(235, 235, 245, 0.6)' }}
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>

          {/* Message list */}
          <div className="flex-1 overflow-y-auto px-3 py-2 space-y-1.5 min-h-0">
            {visibleMessages.length === 0 && (
              <p className="text-[12px] text-center mt-8" style={{ color: 'rgba(235, 235, 245, 0.3)' }}>No messages yet</p>
            )}
            {visibleMessages.map((msg) => {
              const isLocal = msg.senderID === localPeerId;
              const peer = !isLocal ? peers.find((p) => p.peerId === msg.senderID) : null;
              const emoji = msg.senderAvatarEmoji ?? peer?.avatarEmoji ?? '\u{1F600}';
              const name = isLocal ? userProfile.displayName : (peer?.displayName ?? msg.senderName);
              const displayText = msg.contentType === 'emoji' ? msg.emoji : msg.text;

              return (
                <div key={msg.id} className="flex items-start gap-1.5">
                  <span className="text-sm shrink-0 mt-0.5">{emoji}</span>
                  <div className="min-w-0">
                    <span
                      className="text-[10px] font-semibold"
                      style={{ color: getSenderColor(msg) }}
                    >
                      {name}
                    </span>
                    <p className="text-xs text-slate-200 break-words leading-relaxed">{displayText}</p>
                  </div>
                </div>
              );
            })}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick reactions */}
          <div className="flex gap-1.5 px-3 py-1.5 border-t border-white/10 overflow-x-auto shrink-0 no-scrollbar">
            {QUICK_REACTIONS.map((reaction) => (
              <button
                key={reaction}
                type="button"
                onClick={() => handleQuickReaction(reaction)}
                className="shrink-0 px-2 py-0.5 bg-white/10 hover:bg-white/20 rounded-full text-[12px] text-white transition-colors"
              >
                {reaction}
              </button>
            ))}
          </div>

          {/* Input bar */}
          <div className="flex items-center gap-1.5 px-3 py-2 border-t border-white/10 shrink-0">
            <input
              ref={inputRef}
              type="text"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Message..."
              className="flex-1 bg-white/10 rounded-[20px] px-2.5 py-1.5 text-[13px] text-white placeholder-[rgba(235,235,245,0.3)] outline-none focus:ring-1 focus:ring-[#64D2FF]/50"
            />
            <button
              type="button"
              onClick={handleSendClick}
              disabled={!inputText.trim()}
              className="p-1.5 rounded-lg transition-colors disabled:opacity-30"
              style={{ color: inputText.trim() ? '#007AFF' : 'rgba(235, 235, 245, 0.3)' }}
            >
              <Send className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      {/* Bubble button */}
      <div
        key={pulseKey}
        className={`fixed z-40 select-none touch-none ${pulseKey > 0 ? 'animate-bubble-pulse' : ''}`}
        style={{ left: pos.x, top: pos.y }}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
      >
        <div
          className={`h-11 w-11 rounded-full flex items-center justify-center shadow-lg shadow-black/30 cursor-grab transition-transform ${
            isDragging ? 'scale-110 cursor-grabbing' : 'hover:scale-105'
          }`}
          style={{ backgroundColor: 'rgba(0, 0, 0, 0.7)', backdropFilter: 'blur(12px)' }}
        >
          <MessageSquare className="h-[18px] w-[18px] text-white" />
        </div>

        {/* Unread badge */}
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 h-5 min-w-5 px-1 rounded-full bg-[#FF453A] text-white text-[10px] font-bold flex items-center justify-center">
            {unreadDisplay}
          </span>
        )}
      </div>
    </>
  );
}

export default GameChatOverlay;
