import { useState, useRef, useCallback, useEffect } from 'react';
import { Send, Smile, BarChart3, X, AtSign, Mic, Square, Image, Play, Pause, Trash2 } from 'lucide-react';
import { useChatStore } from '../stores/chat.ts';
import { usePoolStore } from '../stores/pool.ts';
import { useConnectionStore } from '../stores/connection.ts';
import EmojiPicker from './EmojiPicker.tsx';

const MAX_IMAGE_SIZE_BYTES = 1400000; // ~1.4MB base64, stays under 2MB relay limit with encryption overhead
const MAX_IMAGE_DIMENSION = 1920;
const MAX_VOICE_DURATION_S = 60;
const JPEG_QUALITY = 0.8;

function compressImage(file: File): Promise<{ base64: string; tooLarge: boolean }> {
  return new Promise((resolve, reject) => {
    const img = new window.Image();
    const reader = new FileReader();

    reader.onload = () => {
      img.onload = () => {
        const canvas = document.createElement('canvas');
        let { width, height } = img;

        if (width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION) {
          if (width > height) {
            height = Math.round((height / width) * MAX_IMAGE_DIMENSION);
            width = MAX_IMAGE_DIMENSION;
          } else {
            width = Math.round((width / height) * MAX_IMAGE_DIMENSION);
            height = MAX_IMAGE_DIMENSION;
          }
        }

        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext('2d');
        if (!ctx) { reject(new Error('Canvas context unavailable')); return; }
        ctx.drawImage(img, 0, 0, width, height);

        // Try progressively lower quality to fit under size limit
        let quality = JPEG_QUALITY;
        let dataUrl = canvas.toDataURL('image/jpeg', quality);
        let base64 = dataUrl.split(',')[1] ?? '';

        while (base64.length > MAX_IMAGE_SIZE_BYTES && quality > 0.1) {
          quality -= 0.1;
          dataUrl = canvas.toDataURL('image/jpeg', quality);
          base64 = dataUrl.split(',')[1] ?? '';
        }

        if (base64.length > MAX_IMAGE_SIZE_BYTES) {
          // Further reduce dimensions
          const scale = Math.sqrt(MAX_IMAGE_SIZE_BYTES / base64.length);
          canvas.width = Math.round(width * scale);
          canvas.height = Math.round(height * scale);
          ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
          dataUrl = canvas.toDataURL('image/jpeg', 0.5);
          base64 = dataUrl.split(',')[1] ?? '';
        }

        resolve({ base64, tooLarge: base64.length > MAX_IMAGE_SIZE_BYTES });
      };
      img.onerror = () => reject(new Error('Failed to load image'));
      img.src = reader.result as string;
    };
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsDataURL(file);
  });
}

function blobToBase64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onloadend = () => {
      const dataUrl = reader.result as string;
      const base64 = dataUrl.split(',')[1] ?? '';
      resolve(base64);
    };
    reader.onerror = () => reject(new Error('Failed to read blob'));
    reader.readAsDataURL(blob);
  });
}

interface ChatInputProps {
  onSendMessage: (text: string, replyTo?: { messageID: string; senderName: string; previewText: string }) => void;
  onSendPoll: (question: string, options: string[], allowVoteChange: boolean) => void;
  onSendVoice: (voiceData: string, voiceDuration: number) => void;
  onSendImage: (imageData: string, caption?: string) => void;
}

function ChatInput({ onSendMessage, onSendPoll, onSendVoice, onSendImage }: ChatInputProps) {
  const [text, setText] = useState('');
  const [showEmoji, setShowEmoji] = useState(false);
  const [showPoll, setShowPoll] = useState(false);
  const [pollQuestion, setPollQuestion] = useState('');
  const [pollOptions, setPollOptions] = useState(['', '']);
  const [pollAllowChange, setPollAllowChange] = useState(true);
  const [showMentions, setShowMentions] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const replyingTo = useChatStore((s) => s.replyingTo);
  const setReplyingTo = useChatStore((s) => s.setReplyingTo);
  const peers = usePoolStore((s) => s.peers);
  const localPeerId = useConnectionStore((s) => s.localPeerId);

  // Voice recording state
  const [isRecording, setIsRecording] = useState(false);
  const [recordingDuration, setRecordingDuration] = useState(0);
  const [voicePreview, setVoicePreview] = useState<{ blob: Blob; duration: number; url: string } | null>(null);
  const [isPreviewPlaying, setIsPreviewPlaying] = useState(false);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const recordingTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const recordingStartRef = useRef(0);
  const audioChunksRef = useRef<Blob[]>([]);
  const streamRef = useRef<MediaStream | null>(null);
  const previewAudioRef = useRef<HTMLAudioElement | null>(null);

  // Image state
  const [imagePreview, setImagePreview] = useState<{ base64: string; dataUrl: string } | null>(null);
  const [imageCaption, setImageCaption] = useState('');
  const [mediaError, setMediaError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Cleanup voice preview URL on unmount or change
  useEffect(() => {
    return () => {
      if (voicePreview) URL.revokeObjectURL(voicePreview.url);
    };
  }, [voicePreview]);

  function getPreferredAudioMimeType(): string {
    // Prefer mp4 (Safari supports it, and iOS can play it natively)
    if (MediaRecorder.isTypeSupported('audio/mp4')) return 'audio/mp4';
    if (MediaRecorder.isTypeSupported('audio/webm;codecs=opus')) return 'audio/webm;codecs=opus';
    if (MediaRecorder.isTypeSupported('audio/webm')) return 'audio/webm';
    if (MediaRecorder.isTypeSupported('audio/ogg;codecs=opus')) return 'audio/ogg;codecs=opus';
    return '';
  }

  const stopRecording = useCallback(() => {
    if (recordingTimerRef.current) {
      clearInterval(recordingTimerRef.current);
      recordingTimerRef.current = null;
    }
    const recorder = mediaRecorderRef.current;
    if (recorder && recorder.state !== 'inactive') {
      recorder.stop();
    }
  }, []);

  const startRecording = useCallback(async () => {
    setMediaError(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      streamRef.current = stream;
      const mimeType = getPreferredAudioMimeType();
      const options: MediaRecorderOptions = mimeType ? { mimeType } : {};
      const recorder = new MediaRecorder(stream, options);
      mediaRecorderRef.current = recorder;
      audioChunksRef.current = [];

      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) audioChunksRef.current.push(e.data);
      };

      const startTime = Date.now();
      recordingStartRef.current = startTime;

      recorder.onstop = () => {
        const chunks = audioChunksRef.current;
        if (chunks.length === 0) return;
        const actualMime = recorder.mimeType || mimeType || 'audio/webm';
        const blob = new Blob(chunks, { type: actualMime });
        const duration = (Date.now() - recordingStartRef.current) / 1000;
        const url = URL.createObjectURL(blob);
        setVoicePreview({ blob, duration, url });
        setIsRecording(false);
        setRecordingDuration(0);
        stream.getTracks().forEach((t) => t.stop());
        streamRef.current = null;
      };

      recorder.start(100);
      setIsRecording(true);

      recordingTimerRef.current = setInterval(() => {
        const elapsed = (Date.now() - recordingStartRef.current) / 1000;
        setRecordingDuration(elapsed);
        if (elapsed >= MAX_VOICE_DURATION_S) {
          stopRecording();
        }
      }, 200);
    } catch {
      setMediaError('Microphone access denied');
    }
  }, [stopRecording]);

  function discardVoicePreview() {
    if (voicePreview) {
      URL.revokeObjectURL(voicePreview.url);
      if (previewAudioRef.current) {
        previewAudioRef.current.pause();
        previewAudioRef.current = null;
      }
    }
    setVoicePreview(null);
    setIsPreviewPlaying(false);
  }

  function cancelRecording() {
    stopRecording();
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
    setIsRecording(false);
    setRecordingDuration(0);
    discardVoicePreview();
  }

  function togglePreviewPlay() {
    if (!voicePreview) return;
    if (isPreviewPlaying && previewAudioRef.current) {
      previewAudioRef.current.pause();
      setIsPreviewPlaying(false);
      return;
    }
    const audio = new Audio(voicePreview.url);
    previewAudioRef.current = audio;
    audio.onended = () => setIsPreviewPlaying(false);
    audio.play().then(() => setIsPreviewPlaying(true)).catch(() => setIsPreviewPlaying(false));
  }

  async function sendVoice() {
    if (!voicePreview) return;
    try {
      const base64 = await blobToBase64(voicePreview.blob);
      if (base64.length > MAX_IMAGE_SIZE_BYTES) {
        setMediaError('Voice message too large to send');
        return;
      }
      onSendVoice(base64, voicePreview.duration);
      discardVoicePreview();
    } catch {
      setMediaError('Failed to process voice message');
    }
  }

  function handleImagePick() {
    fileInputRef.current?.click();
  }

  async function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    setMediaError(null);
    const file = e.target.files?.[0];
    if (!file) return;
    // Reset input so same file can be selected again
    e.target.value = '';

    if (!file.type.startsWith('image/')) {
      setMediaError('Please select an image file');
      return;
    }

    try {
      const result = await compressImage(file);
      if (result.tooLarge) {
        setMediaError('Image is too large even after compression');
        return;
      }
      const dataUrl = `data:image/jpeg;base64,${result.base64}`;
      setImagePreview({ base64: result.base64, dataUrl });
      setImageCaption('');
    } catch {
      setMediaError('Failed to process image');
    }
  }

  function discardImagePreview() {
    setImagePreview(null);
    setImageCaption('');
  }

  function sendImage() {
    if (!imagePreview) return;
    onSendImage(imagePreview.base64, imageCaption.trim() || undefined);
    discardImagePreview();
  }

  function formatRecordingTime(seconds: number): string {
    const m = Math.floor(seconds / 60);
    const s = Math.floor(seconds % 60);
    return `${m}:${s.toString().padStart(2, '0')}`;
  }

  const handleSend = useCallback(() => {
    const trimmed = text.trim();
    if (trimmed.length === 0) return;

    onSendMessage(
      trimmed,
      replyingTo ? { messageID: replyingTo.id, senderName: replyingTo.senderName, previewText: replyingTo.text ?? '' } : undefined,
    );
    setText('');
    setReplyingTo(null);
    inputRef.current?.focus();
  }, [text, replyingTo, onSendMessage, setReplyingTo]);

  function handlePollSubmit() {
    const q = pollQuestion.trim();
    const opts = pollOptions.map((o) => o.trim()).filter((o) => o.length > 0);
    if (q.length === 0 || opts.length < 2) return;

    onSendPoll(q, opts, pollAllowChange);
    setShowPoll(false);
    setPollQuestion('');
    setPollOptions(['', '']);
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
    if (e.key === '@') {
      setShowMentions(true);
    }
  }

  function handleTextChange(e: React.ChangeEvent<HTMLInputElement>) {
    const val = e.target.value;
    setText(val);
    if (!val.includes('@')) {
      setShowMentions(false);
    }
  }

  function insertMention(name: string) {
    setText((prev) => {
      const atIdx = prev.lastIndexOf('@');
      if (atIdx >= 0) {
        return prev.slice(0, atIdx) + `@${name} `;
      }
      return `${prev}@${name} `;
    });
    setShowMentions(false);
    inputRef.current?.focus();
  }

  function handleEmojiSelect(emoji: string) {
    setText((prev) => prev + emoji);
    setShowEmoji(false);
    inputRef.current?.focus();
  }

  return (
    <div className="border-t border-[#38383A] bg-[#1C1C1E]">
      {/* Reply preview */}
      {replyingTo && (
        <div className="flex items-center gap-2 px-4 py-1.5 bg-[#2C2C2E] border-l-2 border-[#007AFF]">
          <div className="flex-1 min-w-0">
            <p className="text-[12px] text-[#007AFF]">Replying to {replyingTo.senderName}</p>
            <p className="text-[12px] truncate" style={{ color: 'rgba(235, 235, 245, 0.6)' }}>{replyingTo.text}</p>
          </div>
          <button type="button" onClick={() => setReplyingTo(null)} style={{ color: 'rgba(235, 235, 245, 0.6)' }}>
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Poll creator */}
      {showPoll && (
        <div className="p-3 bg-[#2C2C2E] border-b border-[#38383A] space-y-2 animate-slide-up">
          <div className="flex items-center justify-between">
            <span className="text-[13px] font-medium text-white">Create Poll</span>
            <button type="button" onClick={() => setShowPoll(false)} style={{ color: 'rgba(235, 235, 245, 0.6)' }}>
              <X className="h-4 w-4" />
            </button>
          </div>
          <input
            type="text"
            value={pollQuestion}
            onChange={(e) => setPollQuestion(e.target.value)}
            placeholder="Question"
            className="w-full px-2 py-1.5 bg-[#1C1C1E] border border-[#38383A] rounded-[10px] text-[15px] text-white"
          />
          {pollOptions.map((opt, idx) => (
            <div key={idx} className="flex gap-1">
              <input
                type="text"
                value={opt}
                onChange={(e) => {
                  const copy = [...pollOptions];
                  copy[idx] = e.target.value;
                  setPollOptions(copy);
                }}
                placeholder={`Option ${idx + 1}`}
                className="flex-1 px-2 py-1 bg-[#1C1C1E] border border-[#38383A] rounded-[10px] text-[15px] text-white"
              />
              {pollOptions.length > 2 && (
                <button type="button" onClick={() => setPollOptions(pollOptions.filter((_, i) => i !== idx))} className="text-[#FF453A] text-xs px-1">
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          ))}
          <div className="flex items-center justify-between">
            <button type="button" onClick={() => setPollOptions([...pollOptions, ''])} className="text-[13px] text-[#007AFF]">+ Add option</button>
            <label className="flex items-center gap-1.5 text-[12px]" style={{ color: 'rgba(235, 235, 245, 0.6)' }}>
              <input type="checkbox" checked={pollAllowChange} onChange={(e) => setPollAllowChange(e.target.checked)} className="rounded" />
              Allow vote change
            </label>
          </div>
          <button type="button" onClick={handlePollSubmit} className="w-full py-2 bg-[#007AFF] text-white text-[13px] font-semibold rounded-xl transition-colors">
            Send Poll
          </button>
        </div>
      )}

      {/* Media error */}
      {mediaError && (
        <div className="flex items-center gap-2 px-4 py-1.5 border-l-2 border-[#FF453A] animate-fade-in" style={{ backgroundColor: 'rgba(255, 69, 58, 0.1)' }}>
          <p className="flex-1 text-[12px] text-[#FF453A]">{mediaError}</p>
          <button type="button" onClick={() => setMediaError(null)} className="text-[#FF453A]">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {/* Voice preview */}
      {voicePreview && (
        <div className="flex items-center gap-2 px-4 py-2 bg-[#2C2C2E] border-b border-[#38383A] animate-slide-up">
          <button
            type="button"
            onClick={togglePreviewPlay}
            className="h-8 w-8 rounded-full bg-[#007AFF] flex items-center justify-center text-white transition-colors shrink-0"
          >
            {isPreviewPlaying ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5 ml-0.5" />}
          </button>
          <div className="flex-1 min-w-0">
            <div className="h-1.5 rounded-full bg-[#38383A] overflow-hidden">
              <div className="h-full w-full bg-[#007AFF] rounded-full" />
            </div>
            <span className="text-[10px] mt-0.5" style={{ color: 'rgba(235, 235, 245, 0.6)' }}>{formatRecordingTime(voicePreview.duration)}</span>
          </div>
          <button
            type="button"
            onClick={discardVoicePreview}
            className="text-[#FF453A] transition-colors shrink-0"
          >
            <Trash2 className="h-4 w-4" />
          </button>
          <button
            type="button"
            onClick={sendVoice}
            className="h-8 w-8 rounded-full bg-[#007AFF] flex items-center justify-center text-white transition-colors shrink-0"
          >
            <Send className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Image preview */}
      {imagePreview && (
        <div className="p-3 bg-[#2C2C2E] border-b border-[#38383A] space-y-2 animate-slide-up">
          <div className="flex items-start gap-2">
            <img
              src={imagePreview.dataUrl}
              alt="Preview"
              className="h-20 w-20 rounded-[14px] object-cover shrink-0"
            />
            <div className="flex-1 min-w-0 flex flex-col gap-1.5">
              <input
                type="text"
                value={imageCaption}
                onChange={(e) => setImageCaption(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); sendImage(); } }}
                placeholder="Add a caption (optional)"
                className="w-full px-2 py-1.5 bg-[#1C1C1E] border border-[#38383A] rounded-[10px] text-[15px] text-white placeholder-[rgba(235,235,245,0.3)] focus:border-[#007AFF] transition-colors"
              />
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={discardImagePreview}
                  className="text-[12px] text-[#FF453A] transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={sendImage}
                  className="px-3 py-1 bg-[#007AFF] text-white text-[12px] font-semibold rounded-lg transition-colors"
                >
                  Send Image
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept="image/*"
        onChange={handleFileChange}
        className="hidden"
      />

      {/* Input bar */}
      {isRecording ? (
        <div className="flex items-center gap-3 px-3 py-2 animate-fade-in">
          <div className="h-2.5 w-2.5 rounded-full bg-[#FF453A] animate-pulse shrink-0" />
          <span className="text-[15px] text-[#FF453A] font-medium tabular-nums">{formatRecordingTime(recordingDuration)}</span>
          <div className="flex-1 flex items-center justify-center">
            <span className="text-[12px]" style={{ color: 'rgba(235, 235, 245, 0.6)' }}>Recording...</span>
          </div>
          <button
            type="button"
            onClick={cancelRecording}
            className="transition-colors shrink-0" style={{ color: 'rgba(235, 235, 245, 0.6)' }}
          >
            <X className="h-5 w-5" />
          </button>
          <button
            type="button"
            onClick={stopRecording}
            className="h-10 w-10 rounded-full bg-[#FF453A] flex items-center justify-center text-white transition-colors shrink-0"
          >
            <Square className="h-3.5 w-3.5" />
          </button>
        </div>
      ) : (
        <div className="relative flex items-center gap-2 px-3 py-2">
          {/* Mentions dropdown */}
          {showMentions && (
            <div className="absolute bottom-full mb-1 left-3 bg-[#1C1C1E] rounded-xl p-1 w-48 max-h-32 overflow-y-auto z-20 animate-fade-in">
              {peers.filter((p) => p.peerId !== localPeerId).map((peer) => (
                <button
                  key={peer.peerId}
                  type="button"
                  onClick={() => insertMention(peer.displayName)}
                  className="w-full text-left px-2 py-1.5 text-[13px] text-white hover:bg-[#2C2C2E] rounded-lg flex items-center gap-1.5"
                >
                  <AtSign className="h-3 w-3 text-[#007AFF]" />
                  {peer.displayName}
                </button>
              ))}
            </div>
          )}

          {/* Emoji picker */}
          {showEmoji && (
            <EmojiPicker onSelect={handleEmojiSelect} onClose={() => setShowEmoji(false)} />
          )}

          <button
            type="button"
            onClick={() => { setShowEmoji(!showEmoji); setShowPoll(false); }}
            className="h-9 w-9 flex items-center justify-center transition-colors shrink-0" style={{ color: 'rgba(235, 235, 245, 0.6)' }}
          >
            <Smile className="h-5 w-5" />
          </button>

          <button
            type="button"
            onClick={() => { setShowPoll(!showPoll); setShowEmoji(false); }}
            className="h-9 w-9 flex items-center justify-center transition-colors shrink-0" style={{ color: 'rgba(235, 235, 245, 0.6)' }}
          >
            <BarChart3 className="h-5 w-5" />
          </button>

          <button
            type="button"
            onClick={handleImagePick}
            className="h-9 w-9 flex items-center justify-center transition-colors shrink-0"
            style={{ color: 'rgba(235, 235, 245, 0.6)' }}
            aria-label="Share image"
          >
            <Image className="h-5 w-5" />
          </button>

          <input
            ref={inputRef}
            type="text"
            value={text}
            onChange={handleTextChange}
            onKeyDown={handleKeyDown}
            placeholder="Type a message..."
            className="flex-1 px-4 py-2.5 bg-[#2C2C2E] rounded-[20px] text-[15px] text-white placeholder-[rgba(235,235,245,0.3)] focus:ring-0 transition-colors"
          />

          {text.trim().length > 0 ? (
            <button
              type="button"
              onClick={handleSend}
              className="h-10 w-10 rounded-full bg-[#007AFF] flex items-center justify-center text-white transition-colors shrink-0"
            >
              <Send className="h-4 w-4" />
            </button>
          ) : (
            <button
              type="button"
              onClick={startRecording}
              className="h-10 w-10 rounded-full bg-[#007AFF] flex items-center justify-center text-white transition-colors shrink-0"
              aria-label="Record voice message"
            >
              <Mic className="h-4 w-4" />
            </button>
          )}
        </div>
      )}
    </div>
  );
}

export default ChatInput;
