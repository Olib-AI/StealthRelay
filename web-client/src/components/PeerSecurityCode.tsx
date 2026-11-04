import { X } from 'lucide-react';
import { useChatStore } from '../stores/chat.ts';
import { usePoolStore } from '../stores/pool.ts';

function Row({ title, value, large }: { title: string; value: string; large?: boolean }) {
  return (
    <div className="space-y-1">
      <p className="text-[12px]" style={{ color: 'var(--text-secondary)' }}>{title}</p>
      <p className={`font-mono select-text break-all ${large ? 'text-[17px] font-semibold' : 'text-[13px]'}`} style={{ color: 'var(--text-primary)' }}>{value}</p>
    </div>
  );
}

/** PeerSecurityCodeView in the app. The codes come out the same on both sides unless someone swapped keys. */
function PeerSecurityCode({ peerId, onClose }: { peerId: string; onClose: () => void }) {
  const info = useChatStore((s) => s.peerSecurity[peerId]);
  const name = usePoolStore((s) => s.peers.find((peer) => peer.peerId === peerId)?.displayName) ?? 'this person';

  return (
    <div role="dialog" aria-label="Security code" className="absolute inset-0 z-[70] flex flex-col p-5 gap-4 overflow-y-auto" style={{ backgroundColor: 'var(--bg-page)' }}>
      <div className="flex items-center justify-between">
        <h2 className="text-[17px] font-semibold" style={{ color: 'var(--text-primary)' }}>Security code</h2>
        <button type="button" aria-label="Done" onClick={onClose} className="p-2 -m-2" style={{ color: 'var(--text-secondary)' }}>
          <X className="h-5 w-5" />
        </button>
      </div>
      {info ? (
        <>
          <p className="text-[14px]" style={{ color: 'var(--text-secondary)' }}>
            Compare this code with {name} in person or on a call. If it matches on both devices, nobody is intercepting your messages.
          </p>
          <Row title="Safety code" value={info.safetyCode} large />
          <Row title={`${name}'s key`} value={info.theirKey} />
          <Row title="Your key" value={info.yourKey} />
        </>
      ) : (
        <p className="text-[14px]" style={{ color: 'var(--text-secondary)' }}>No secure session with {name} yet.</p>
      )}
    </div>
  );
}

export default PeerSecurityCode;
