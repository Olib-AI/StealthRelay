import { usePoolStore } from '../stores/pool.ts';
import { useConnectionStore } from '../stores/connection.ts';
import PeerAvatar from './PeerAvatar.tsx';

function PeerList() {
  const peers = usePoolStore((s) => s.peers);
  const poolInfo = usePoolStore((s) => s.poolInfo);
  const localPeerId = useConnectionStore((s) => s.localPeerId);
  const userProfile = usePoolStore((s) => s.userProfile);

  const otherPeers = peers.filter((p) => p.peerId !== localPeerId);

  return (
    <div>
      {/* Self */}
      <div className="flex items-center gap-3 px-4 py-2.5 border-b border-[#38383A]">
        <PeerAvatar
          emoji={userProfile.avatarEmoji}
          colorIndex={userProfile.avatarColorIndex}
          size="sm"
          isHost={localPeerId === poolInfo?.hostPeerId}
        />
        <div className="min-w-0 flex-1">
          <p className="text-[15px] font-medium text-white truncate">
            {userProfile.displayName}
            <span className="text-[12px] ml-1.5" style={{ color: 'rgba(235, 235, 245, 0.3)' }}>(you)</span>
          </p>
        </div>
      </div>

      {/* Other peers */}
      {otherPeers.map((peer, index) => (
          <div key={peer.peerId} className={`flex items-center gap-3 px-4 py-2.5 transition-colors ${index < otherPeers.length - 1 ? 'border-b border-[#38383A]' : ''}`}>
            <PeerAvatar
              emoji={peer.avatarEmoji}
              colorIndex={peer.avatarColorIndex}
              size="sm"
              isHost={peer.peerId === poolInfo?.hostPeerId}
            />
            <div className="min-w-0 flex-1">
              <p className="text-[15px] font-medium text-white truncate">
                {peer.displayName}
                {peer.peerId === poolInfo?.hostPeerId && (
                  <span className="ml-1.5 text-[10px] font-bold text-white px-1.5 py-0.5 rounded-full bg-[#FF9F0A]">HOST</span>
                )}
              </p>
            </div>
          </div>
        ))}
    </div>
  );
}

export default PeerList;
