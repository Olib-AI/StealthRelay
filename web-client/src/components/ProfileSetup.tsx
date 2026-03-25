import { useState } from 'react';
import { AVATAR_EMOJIS, AVATAR_COLORS } from '../protocol/constants.ts';
import { usePoolStore } from '../stores/pool.ts';
import { Check } from 'lucide-react';

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
  const [showEmojiGrid, setShowEmojiGrid] = useState(!compact);

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
        <label className="block text-[12px] font-medium mb-1.5" style={{ color: 'rgba(235, 235, 245, 0.6)' }}>Display Name</label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          maxLength={32}
          className="w-full px-3 py-2.5 bg-[#1C1C1E] border border-[#38383A] rounded-[10px] text-white text-[15px] focus:border-[#007AFF] transition-colors"
          placeholder="Enter your name"
        />
      </div>

      {/* Preview + color */}
      <div className="flex items-center gap-3 sm:gap-4">
        <button
          type="button"
          onClick={() => setShowEmojiGrid(!showEmojiGrid)}
          className="h-12 w-12 sm:h-14 sm:w-14 rounded-full flex items-center justify-center text-xl sm:text-2xl shrink-0 transition-transform hover:scale-110"
          style={{ backgroundColor: AVATAR_COLORS[selectedColor]! }}
        >
          {selectedEmoji}
        </button>
        <div className="flex-1 min-w-0">
          <label className="block text-[12px] font-medium mb-1.5" style={{ color: 'rgba(235, 235, 245, 0.6)' }}>Color</label>
          <div className="flex gap-1.5 sm:gap-2 flex-wrap">
            {AVATAR_COLORS.map((color, idx) => (
              <button
                key={color}
                type="button"
                onClick={() => setSelectedColor(idx)}
                className="h-6 w-6 sm:h-7 sm:w-7 rounded-full flex items-center justify-center transition-transform hover:scale-110"
                style={{ backgroundColor: color }}
              >
                {idx === selectedColor && <Check className="h-3 w-3 sm:h-3.5 sm:w-3.5 text-white" />}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Emoji grid */}
      {showEmojiGrid && (
        <div>
          <label className="block text-[12px] font-medium mb-1.5" style={{ color: 'rgba(235, 235, 245, 0.6)' }}>Avatar Emoji</label>
          <div className="grid grid-cols-6 sm:grid-cols-8 gap-1 sm:gap-1.5">
            {AVATAR_EMOJIS.map((emoji) => (
              <button
                key={emoji}
                type="button"
                onClick={() => setSelectedEmoji(emoji)}
                className={`aspect-square rounded-lg flex items-center justify-center text-base sm:text-lg transition-all ${emoji === selectedEmoji ? 'bg-[#007AFF]' : 'bg-[#1C1C1E] hover:bg-[#2C2C2E]'}`}
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
