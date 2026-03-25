import { Lock, Reply, SmilePlus, Play, Pause, X } from 'lucide-react';
import type { ChatMessage } from '../stores/chat.ts';
import { useConnectionStore } from '../stores/connection.ts';
import { usePoolStore } from '../stores/pool.ts';
import { useChatStore } from '../stores/chat.ts';
import PeerAvatar from './PeerAvatar.tsx';
import { useState, useRef, useEffect, useMemo } from 'react';

const REACTION_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🔥', '🎉', '👏'];

function base64ToDataUrl(base64: string, mimeType: string): string {
  return `data:${mimeType};base64,${base64}`;
}

function detectAudioMimeType(base64: string): string {
  // Check first bytes for file signatures
  // ftyp = MP4/M4A, OggS = Ogg/Opus, 1a45dfa3 = WebM
  if (base64.startsWith('AAAA') || base64.startsWith('AAAAGG') || base64.startsWith('AAAAI')) {
    return 'audio/mp4';
  }
  if (base64.startsWith('T2dn')) {
    return 'audio/ogg';
  }
  if (base64.startsWith('GkXf')) {
    return 'audio/webm';
  }
  // Default to mp4 (iOS sends m4a which is mp4 container)
  return 'audio/mp4';
}

function detectImageMimeType(base64: string): string {
  if (base64.startsWith('/9j/')) return 'image/jpeg';
  if (base64.startsWith('iVBOR')) return 'image/png';
  if (base64.startsWith('R0lGOD')) return 'image/gif';
  if (base64.startsWith('UklGR')) return 'image/webp';
  return 'image/jpeg';
}

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}:${s.toString().padStart(2, '0')}`;
}

interface VoicePlayerProps {
  voiceData: string;
  voiceDuration?: number;
  isSelf: boolean;
}

function VoicePlayer({ voiceData, voiceDuration, isSelf }: VoicePlayerProps) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(voiceDuration ?? 0);
  const audioRef = useRef<HTMLAudioElement | null>(null);

  // Use data URL — immune to React strict mode double-mount and revocation race conditions
  const audioDataUrl = useMemo(() => {
    const mimeType = detectAudioMimeType(voiceData);
    return `data:${mimeType};base64,${voiceData}`;
  }, [voiceData]);

  useEffect(() => {
    const audio = new Audio(audioDataUrl);
    audioRef.current = audio;

    function handleTimeUpdate() {
      setCurrentTime(audio.currentTime);
    }
    function handleLoadedMetadata() {
      if (audio.duration && isFinite(audio.duration)) {
        setDuration(audio.duration);
      }
    }
    function handleEnded() {
      setIsPlaying(false);
      setCurrentTime(0);
    }

    audio.addEventListener('timeupdate', handleTimeUpdate);
    audio.addEventListener('loadedmetadata', handleLoadedMetadata);
    audio.addEventListener('ended', handleEnded);

    return () => {
      audio.removeEventListener('timeupdate', handleTimeUpdate);
      audio.removeEventListener('loadedmetadata', handleLoadedMetadata);
      audio.removeEventListener('ended', handleEnded);
      audio.pause();
      audioRef.current = null;
    };
  }, [audioDataUrl]);

  function togglePlay() {
    const audio = audioRef.current;
    if (!audio) return;
    if (isPlaying) {
      audio.pause();
      setIsPlaying(false);
    } else {
      audio.play().then(() => setIsPlaying(true)).catch(() => setIsPlaying(false));
    }
  }

  const progress = duration > 0 ? (currentTime / duration) * 100 : 0;

  return (
    <div className="flex items-center gap-2 min-w-[180px]">
      <button
        type="button"
        onClick={togglePlay}
        className="h-8 w-8 rounded-full flex items-center justify-center shrink-0 transition-colors"
        style={{ backgroundColor: isSelf ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.1)' }}
      >
        {isPlaying ? <Pause className="h-3.5 w-3.5" style={{ color: 'inherit' }} /> : <Play className="h-3.5 w-3.5 ml-0.5" style={{ color: 'inherit' }} />}
      </button>
      <div className="flex-1 flex flex-col gap-0.5">
        <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: isSelf ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.1)' }}>
          <div
            className="h-full rounded-full transition-all duration-100"
            style={{ width: `${progress}%`, backgroundColor: isSelf ? 'rgba(255,255,255,0.8)' : '#007AFF' }}
          />
        </div>
        <span className="text-[10px] opacity-60">
          {isPlaying || currentTime > 0 ? formatDuration(currentTime) : formatDuration(duration)}
        </span>
      </div>
    </div>
  );
}

interface ImageLightboxProps {
  src: string;
  onClose: () => void;
}

function ImageLightbox({ src, onClose }: ImageLightboxProps) {
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm animate-fade-in"
      onClick={onClose}
    >
      <button
        type="button"
        onClick={onClose}
        className="absolute top-4 right-4 h-8 w-8 rounded-full flex items-center justify-center text-white transition-colors z-10"
        style={{ backgroundColor: 'var(--bg-tertiary)' }}
      >
        <X className="h-5 w-5" />
      </button>
      <img
        src={src}
        alt="Full size"
        className="max-w-[90vw] max-h-[90vh] object-contain rounded-lg"
        onClick={(e) => e.stopPropagation()}
      />
    </div>
  );
}

interface MessageBubbleProps {
  message: ChatMessage;
  isGroup: boolean;
}

function MessageBubble({ message, isGroup }: MessageBubbleProps) {
  const localPeerId = useConnectionStore((s) => s.localPeerId);
  const peers = usePoolStore((s) => s.peers);
  const setReplyingTo = useChatStore((s) => s.setReplyingTo);
  const addReaction = useChatStore((s) => s.addReaction);
  const selectedPrivatePeerId = useChatStore((s) => s.selectedPrivatePeerId);
  const updatePollVote = useChatStore((s) => s.updatePollVote);
  const [showReactions, setShowReactions] = useState(false);
  const [showLightbox, setShowLightbox] = useState(false);

  const imageDataUrl = useMemo(() => {
    if (message.contentType !== 'image' || !message.imageData) return null;
    const mimeType = detectImageMimeType(message.imageData);
    return base64ToDataUrl(message.imageData, mimeType);
  }, [message.contentType, message.imageData]);

  const isSelf = message.senderID === localPeerId;
  const peer = peers.find((p) => p.peerId === message.senderID);
  const avatarEmoji = message.senderAvatarEmoji ?? peer?.avatarEmoji ?? '😀';
  const colorIndex = message.senderAvatarColorIndex ?? peer?.avatarColorIndex ?? 0;
  const time = new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  const reactionEntries = Object.entries(message.reactions);

  function handleReaction(emoji: string) {
    if (!localPeerId) return;
    const currentReactors = message.reactions[emoji] ?? [];
    const isAdding = !currentReactors.includes(localPeerId);
    addReaction(message.id, emoji, localPeerId, isGroup, isGroup ? undefined : (selectedPrivatePeerId ?? undefined));
    setShowReactions(false);
    // Send reaction to peers
    import('../transport/websocket.ts').then(({ transport }) => {
      transport.sendReaction(message.id, emoji, localPeerId, isAdding, isGroup ? null : selectedPrivatePeerId ? [selectedPrivatePeerId] : null);
    });
  }

  function handlePollVote(option: string) {
    if (!localPeerId) return;
    updatePollVote(message.id, option, localPeerId, isGroup, isGroup ? undefined : (selectedPrivatePeerId ?? undefined));
    // Send vote to peers
    import('../transport/websocket.ts').then(({ transport }) => {
      transport.sendPollVote(message.id, option, localPeerId, isGroup ? null : selectedPrivatePeerId ? [selectedPrivatePeerId] : null);
    });
  }

  if (message.contentType === 'system') {
    return (
      <div className="flex justify-center py-1">
        <span className="text-[12px] px-3 py-1 rounded-full" style={{ backgroundColor: 'var(--system-msg-bg)', color: 'var(--text-secondary)' }}>
          {message.text}
        </span>
      </div>
    );
  }

  return (
    <div className={`flex gap-2 animate-slide-up group ${isSelf ? 'flex-row-reverse' : 'flex-row'}`}>
      {!isSelf && (
        <PeerAvatar emoji={avatarEmoji} colorIndex={colorIndex} size="sm" />
      )}

      <div className={`max-w-[75%] min-w-0 ${isSelf ? 'items-end' : 'items-start'} flex flex-col`}>
        {/* Sender name */}
        {!isSelf && (
          <span className="text-[11px] font-medium mb-0.5 px-1" style={{ color: 'var(--text-secondary)' }}>{message.senderName}</span>
        )}

        {/* Reply preview */}
        {message.replyTo && (
          <div
            className={`text-[12px] px-2 py-1 mb-0.5 rounded-lg max-w-full truncate ${isSelf ? 'self-end border-l-2 border-white/60' : 'self-start border-l-2 border-[#007AFF]'}`}
            style={{ backgroundColor: isSelf ? 'rgba(0, 122, 255, 0.3)' : 'var(--bubble-incoming)', color: 'var(--text-secondary)' }}
          >
            <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{message.replyTo.senderName}: </span>
            {message.replyTo.previewText}
          </div>
        )}

        {/* Message bubble */}
        <div
          className={`px-3 py-2 text-[15px] break-words relative ${
            message.contentType === 'emoji' && message.emoji && !message.text
              ? ''
              : 'rounded-[16px]'
          }`}
          style={
            message.contentType === 'emoji' && message.emoji && !message.text
              ? undefined
              : isSelf
                ? { backgroundColor: 'var(--bubble-outgoing)', color: 'var(--bubble-outgoing-text)' }
                : { backgroundColor: 'var(--bubble-incoming)', color: 'var(--bubble-incoming-text)' }
          }
        >
          {/* Voice content */}
          {message.contentType === 'voice' && message.voiceData && (
            <VoicePlayer voiceData={message.voiceData} voiceDuration={message.voiceDuration} isSelf={isSelf} />
          )}

          {/* Image content */}
          {message.contentType === 'image' && imageDataUrl && (
            <>
              <button
                type="button"
                onClick={() => setShowLightbox(true)}
                className="block -mx-1 -mt-0.5 mb-1"
              >
                <img
                  src={imageDataUrl}
                  alt="Shared image"
                  className="max-w-[200px] max-h-[200px] rounded-[14px] object-cover cursor-pointer hover:opacity-90 transition-opacity"
                  loading="lazy"
                />
              </button>
              {message.text && (
                <span>{message.text}</span>
              )}
              {showLightbox && (
                <ImageLightbox src={imageDataUrl} onClose={() => setShowLightbox(false)} />
              )}
            </>
          )}

          {/* Poll content */}
          {message.contentType === 'poll' && message.pollData && (
            <div className="space-y-2">
              <p className="font-medium text-[15px]">{message.pollData.question}</p>
              {message.pollData.options.map((option) => {
                const votes = message.pollData?.votes[option] ?? [];
                const totalVotes = Object.values(message.pollData?.votes ?? {}).reduce((sum, v) => sum + v.length, 0);
                const pct = totalVotes > 0 ? Math.round((votes.length / totalVotes) * 100) : 0;
                const hasVoted = localPeerId ? votes.includes(localPeerId) : false;

                return (
                  <button
                    key={option}
                    type="button"
                    onClick={() => handlePollVote(option)}
                    className={`w-full text-left px-3 py-1.5 rounded-lg text-[13px] relative overflow-hidden transition-colors ${
                      hasVoted ? 'border border-[rgba(0,122,255,0.5)]' : 'hover:opacity-80'
                    }`}
                    style={{ backgroundColor: hasVoted ? 'rgba(0, 122, 255, 0.2)' : 'rgba(255,255,255,0.1)' }}
                  >
                    <div
                      className="absolute inset-y-0 left-0 transition-all"
                      style={{ width: `${pct}%`, backgroundColor: 'rgba(0, 122, 255, 0.15)' }}
                    />
                    <span className="relative z-10">{option}</span>
                    <span className="relative z-10 float-right opacity-60">{votes.length} ({pct}%)</span>
                  </button>
                );
              })}
            </div>
          )}

          {/* Emoji content */}
          {message.contentType === 'emoji' && message.emoji && (
            <span className="text-[48px] leading-none">{message.emoji}</span>
          )}

          {/* Text content */}
          {(message.contentType === 'text' || (!message.pollData && !message.emoji)) && message.text && (
            <span>{message.text}</span>
          )}

        </div>

        {/* Timestamp + actions below bubble */}
        <div className={`flex items-center gap-1.5 px-1 mt-0.5 ${isSelf ? 'flex-row-reverse' : 'flex-row'}`}>
          {message.isEncrypted && <Lock className="h-2.5 w-2.5 text-[#30D158]" />}
          <span className="text-[11px]" style={{ color: 'var(--text-tertiary)' }}>{time}</span>
          <div className="flex gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
            <button
              type="button"
              onClick={() => setReplyingTo(message)}
              className="h-5 w-5 rounded-full flex items-center justify-center transition-colors"
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}
            >
              <Reply className="h-2.5 w-2.5" />
            </button>
            <button
              type="button"
              onClick={() => setShowReactions(!showReactions)}
              className="h-5 w-5 rounded-full flex items-center justify-center transition-colors"
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}
            >
              <SmilePlus className="h-2.5 w-2.5" />
            </button>
          </div>
        </div>

        {/* Reactions */}
        {reactionEntries.length > 0 && (
          <div className={`flex flex-wrap gap-1 mt-0.5 ${isSelf ? 'justify-end' : 'justify-start'}`}>
            {reactionEntries.map(([emoji, reactors]) => (
              <button
                key={emoji}
                type="button"
                onClick={() => handleReaction(emoji)}
                className="flex items-center gap-0.5 px-1.5 py-0.5 rounded-full text-xs transition-colors"
                style={{
                  backgroundColor: localPeerId && reactors.includes(localPeerId) ? 'rgba(0, 122, 255, 0.2)' : 'var(--bg-tertiary)',
                  border: localPeerId && reactors.includes(localPeerId) ? '1px solid rgba(0, 122, 255, 0.5)' : '1px solid transparent',
                }}
              >
                <span>{emoji}</span>
                <span style={{ color: 'var(--text-secondary)' }}>{reactors.length}</span>
              </button>
            ))}
          </div>
        )}

        {/* Reaction picker */}
        {showReactions && (
          <div className={`flex gap-1 mt-1 p-1.5 rounded-xl animate-fade-in ${isSelf ? 'self-end' : 'self-start'}`} style={{ backgroundColor: 'var(--bg-tertiary)' }}>
            {REACTION_EMOJIS.map((emoji) => (
              <button
                key={emoji}
                type="button"
                onClick={() => handleReaction(emoji)}
                className="h-7 w-7 rounded-lg flex items-center justify-center transition-colors text-sm"
                style={{ backgroundColor: 'transparent' }}
                onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--separator)')}
                onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
              >
                {emoji}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default MessageBubble;
