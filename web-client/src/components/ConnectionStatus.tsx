import { useConnectionStore } from '../stores/connection.ts';

function ConnectionStatus() {
  const status = useConnectionStore((s) => s.status);
  const error = useConnectionStore((s) => s.error);

  if (status === 'idle' || status === 'disconnected') return null;

  const config = {
    connecting: { dotColor: '#FF9F0A', text: 'Connecting...' },
    connected: { dotColor: '#30D158', text: 'Connected' },
    reconnecting: { dotColor: '#FF9F0A', text: 'Reconnecting...' },
    failed: { dotColor: '#FF453A', text: 'Disconnected' },
    waiting_approval: { dotColor: '#007AFF', text: 'Waiting for approval...' },
  } as const;

  const c = config[status];
  if (!c) return null;

  return (
    <div className="flex flex-col">
      <div className="flex items-center gap-2">
        <span className="h-2 w-2 rounded-full shrink-0" style={{ backgroundColor: c.dotColor }} />
        <span className="text-[13px] font-medium" style={{ color: 'var(--text-primary)' }}>{c.text}</span>
      </div>
      {error && (
        <p className="mt-1 text-[12px] text-[#FF453A] max-w-xs truncate">{error}</p>
      )}
    </div>
  );
}

export default ConnectionStatus;
