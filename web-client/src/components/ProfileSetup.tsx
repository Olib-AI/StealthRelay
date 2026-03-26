import { useState } from 'react';
import { AVATAR_EMOJIS, AVATAR_COLORS } from '../protocol/constants.ts';
import { usePoolStore } from '../stores/pool.ts';
import { Check, ChevronDown } from 'lucide-react';

interface ProfileSetupProps {
  compact?: boolean;
  onDone?: () => void;
}

function ProfileSetup({ compact = false, onDone }: ProfileSetupProps) {
  const userProfile = usePoolStore((s) => s.userProfile);
  const setUserProfile = usePoolStore((s) => s.setUserProfile);
  const [name, setName] = useState(userProfile.displayName);
  const [selectedEmoji, setSelectedEmoji] = useState(userProfile.avatarEmoji);
  const [selectedColor, setSelectedColor] = useState(userProfile.avatarColorIndex);
  const [showEmojiPicker, setShowEmojiPicker] = useState(false);

  function handleSave() {
    const trimmed = name.trim();
    if (trimmed.length === 0) return;
    setUserProfile({
      displayName: trimmed,
      avatarEmoji: selectedEmoji,
      avatarColorIndex: selectedColor,
    });
    onDone?.();
  }

  return (
    <div className="space-y-4">
      {/* Name input */}
      <div>
        <label className="block text-[12px] font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>Display Name</label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          maxLength={32}
          className="w-full px-3 py-2.5 rounded-[10px] text-[15px] focus:border-[#007AFF] transition-colors"
          style={{ backgroundColor: 'var(--bg-surface)', borderWidth: '1px', borderStyle: 'solid', borderColor: 'var(--separator)', color: 'var(--text-primary)' }}
          placeholder="Enter your name"
        />
      </div>

      {/* Avatar + color row */}
      <div className="flex items-center gap-3">
        {/* Emoji avatar with tap indicator */}
        <button
          type="button"
          onClick={() => setShowEmojiPicker(!showEmojiPicker)}
          className="relative h-12 w-12 rounded-full flex items-center justify-center text-xl shrink-0 transition-transform active:scale-95"
          style={{ backgroundColor: AVATAR_COLORS[selectedColor]! }}
        >
          {selectedEmoji}
          <span className="absolute -bottom-0.5 -right-0.5 h-5 w-5 rounded-full flex items-center justify-center" style={{ backgroundColor: 'var(--bg-tertiary)', border: '2px solid var(--bg-surface)' }}>
            <ChevronDown className="h-2.5 w-2.5" style={{ color: 'var(--text-secondary)' }} />
          </span>
        </button>

        {/* Color swatches - no label, vertically centered */}
        <div className="flex gap-2 flex-wrap items-center">
          {AVATAR_COLORS.map((color, idx) => (
            <button
              key={color}
              type="button"
              onClick={() => setSelectedColor(idx)}
              className="h-7 w-7 rounded-full flex items-center justify-center transition-transform active:scale-90"
              style={{ backgroundColor: color, boxShadow: idx === selectedColor ? `0 0 0 2px var(--bg-surface), 0 0 0 3.5px ${color}` : undefined }}
            >
              {idx === selectedColor && <Check className="h-3.5 w-3.5 text-white" />}
            </button>
          ))}
        </div>
      </div>

      {/* Emoji picker overlay */}
      {showEmojiPicker && (
        <div className="rounded-xl p-3 animate-fade-in" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
          <div className="grid grid-cols-8 gap-1">
            {AVATAR_EMOJIS.map((emoji) => (
              <button
                key={emoji}
                type="button"
                onClick={() => { setSelectedEmoji(emoji); setShowEmojiPicker(false); }}
                className="aspect-square rounded-lg flex items-center justify-center text-lg transition-all active:scale-90"
                style={emoji === selectedEmoji ? { backgroundColor: '#007AFF' } : undefined}
              >
                {emoji}
              </button>
            ))}
          </div>
        </div>
      )}

      {compact && (
        <button
          type="button"
          onClick={handleSave}
          className="w-full py-3 bg-[#007AFF] text-white text-[15px] font-semibold rounded-xl transition-colors"
        >
          Save Profile
        </button>
      )}

      {!compact && (
        <input
          type="hidden"
          ref={(el) => {
            if (el) {
              // Auto-save on unmount-like behavior: save whenever values change
              const trimmed = name.trim();
              if (trimmed.length > 0) {
                const current = usePoolStore.getState().userProfile;
                if (current.displayName !== trimmed || current.avatarEmoji !== selectedEmoji || current.avatarColorIndex !== selectedColor) {
                  setUserProfile({ displayName: trimmed, avatarEmoji: selectedEmoji, avatarColorIndex: selectedColor });
                }
              }
            }
          }}
        />
      )}
    </div>
  );
}

export default ProfileSetup;
