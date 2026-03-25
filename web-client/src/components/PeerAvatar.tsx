import { AVATAR_COLORS } from '../protocol/constants.ts';

interface PeerAvatarProps {
  emoji: string;
  colorIndex: number;
  size?: 'sm' | 'md' | 'lg';
  isHost?: boolean;
}

function PeerAvatar({ emoji, colorIndex, size = 'md', isHost = false }: PeerAvatarProps) {
  const color = AVATAR_COLORS[colorIndex] ?? AVATAR_COLORS[0]!;
  const sizeClasses = {
    sm: 'h-8 w-8 text-sm',
    md: 'h-10 w-10 text-lg',
    lg: 'h-14 w-14 text-2xl',
  } as const;

  return (
    <div className="relative inline-flex">
      <div
        className={`${sizeClasses[size]} rounded-full flex items-center justify-center shrink-0`}
        style={{ backgroundColor: color }}
      >
        <span>{emoji}</span>
      </div>
      {isHost && (
        <span className="absolute -bottom-0.5 -right-0.5 h-3.5 w-3.5 rounded-full bg-[#FF9F0A] flex items-center justify-center text-[8px]">👑</span>
      )}
    </div>
  );
}

export default PeerAvatar;
