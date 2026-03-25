import { X } from 'lucide-react';

const EMOJI_CATEGORIES = {
  'Smileys': ['😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😂', '🙂', '🙃', '😉', '😊', '😇', '🥰', '😍', '🤩', '😘', '😗', '😚', '😋', '😛', '😜', '🤪', '😝', '🤑', '🤗', '🤭', '🤫', '🤔', '🤐', '🤨', '😐', '😑', '😶', '😏', '😒', '🙄', '😬', '🤥', '😌', '😔', '😪', '😮‍💨', '🤤', '😴', '😷', '🤒', '🤕', '🤢', '🤧', '🥵', '🥶', '🥴', '😵', '🤯', '🤠', '🥳', '😎', '🤓', '🧐', '😈', '👿', '👻', '💀', '☠️', '👽', '🤖', '🎃'],
  'Gestures': ['👍', '👎', '👊', '✊', '🤛', '🤜', '👏', '🙌', '👐', '🤲', '🤝', '🙏', '✌️', '🤞', '🤟', '🤘', '👌', '🤌', '🤏', '👈', '👉', '👆', '👇', '☝️', '✋', '🤚', '🖐️', '🖖', '👋', '🤙', '💪', '🦾', '🖕'],
  'Hearts': ['❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎', '💔', '❣️', '💕', '💞', '💓', '💗', '💖', '💘', '💝'],
  'Objects': ['🎮', '🎯', '🎲', '🎸', '🎨', '🚀', '⚡', '🔥', '🌟', '🌈', '🌙', '☀️', '🌸', '🍀', '💎', '🎭', '🏆', '🥇', '🎪', '🎬', '🎧', '🎤', '🎵', '🎶'],
} as const;

interface EmojiPickerProps {
  onSelect: (emoji: string) => void;
  onClose: () => void;
}

function EmojiPicker({ onSelect, onClose }: EmojiPickerProps) {
  return (
    <div className="absolute bottom-full mb-2 left-0 w-72 bg-[#1C1C1E] rounded-xl p-3 animate-slide-up z-20">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[12px] font-medium" style={{ color: 'rgba(235, 235, 245, 0.6)' }}>Emoji</span>
        <button type="button" onClick={onClose} style={{ color: 'rgba(235, 235, 245, 0.6)' }}>
          <X className="h-4 w-4" />
        </button>
      </div>
      <div className="max-h-48 overflow-y-auto space-y-2">
        {Object.entries(EMOJI_CATEGORIES).map(([category, emojis]) => (
          <div key={category}>
            <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'rgba(235, 235, 245, 0.3)' }}>{category}</p>
            <div className="grid grid-cols-8 gap-0.5">
              {emojis.map((emoji) => (
                <button
                  key={emoji}
                  type="button"
                  onClick={() => onSelect(emoji)}
                  className="h-8 w-8 rounded-lg flex items-center justify-center text-base hover:bg-[#2C2C2E] transition-colors"
                >
                  {emoji}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default EmojiPicker;
