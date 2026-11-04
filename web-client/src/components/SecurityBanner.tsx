import { useEffect, useState } from 'react';
import { Lock, ShieldAlert, WifiOff } from 'lucide-react';
import { notProtectedText } from '../protocol/join-policy.ts';
import { useConnectionStore } from '../stores/connection.ts';

const STILL_WAITING_AFTER_MS = 20_000;

function peopleOnOlderVersion(count: number): string {
  return count === 1
    ? "1 person here uses an older version of StealthOS and can't read or send messages until they update."
    : `${count} people here use an older version of StealthOS and can't read or send messages until they update.`;
}

/** What the pool's protection is doing, whenever that is anything but fine. */
function SecurityBanner() {
  const security = useConnectionStore((s) => s.security);
  const hostOffline = useConnectionStore((s) => s.hostOffline);
  const reconnecting = useConnectionStore((s) => s.status === 'reconnecting');
  const securing = security?.kind === 'securing';
  const [stillWaiting, setStillWaiting] = useState(false);

  useEffect(() => {
    if (!securing) return;
    const timer = setTimeout(() => setStillWaiting(true), STILL_WAITING_AFTER_MS);
    return () => {
      clearTimeout(timer);
      setStillWaiting(false);
    };
  }, [securing]);

  let text: string | null = null;
  let warn = false;
  switch (security?.kind) {
    case 'securing':
      text = stillWaiting
        ? "Still waiting for the host to secure this pool. They may need to open StealthOS. Nothing you write is sent until it's secured."
        : "Securing this pool with the host. Nothing you write is sent until it's secured.";
      break;
    case 'hostNotProtected':
      warn = true;
      text = notProtectedText(security.legacyPeers.length);
      break;
    case 'downgradeRefused':
      warn = true;
      text = 'The host tried to turn off protection for this pool. That was refused, and your messages stay protected.';
      break;
    case 'protected':
      if (security.excludedPeers.length > 0) text = peopleOnOlderVersion(security.excludedPeers.length);
      break;
    default:
      break;
  }

  if (reconnecting) {
    return (
      <div role="status" className="shrink-0 flex items-start gap-2 px-4 py-2 text-[12px]" style={{ backgroundColor: 'var(--bg-surface)', color: 'var(--text-secondary)' }}>
        <WifiOff className="h-3.5 w-3.5 shrink-0 mt-0.5" />
        <span>Lost the connection to the relay. Trying again. What you write goes out when it's back, if that's within a few minutes.</span>
      </div>
    );
  }
  if (hostOffline && !warn) {
    return (
      <div role="status" className="shrink-0 flex items-start gap-2 px-4 py-2 text-[12px]" style={{ backgroundColor: 'var(--bg-surface)', color: 'var(--text-secondary)' }}>
        <WifiOff className="h-3.5 w-3.5 shrink-0 mt-0.5" />
        <span>The host is offline. Messages wait until they're back.</span>
      </div>
    );
  }
  if (!text) return null;

  const Icon = warn ? ShieldAlert : Lock;
  return (
    <div role="status" className="shrink-0 flex items-start gap-2 px-4 py-2 text-[12px]" style={{ backgroundColor: 'var(--bg-surface)', color: warn ? '#FF453A' : 'var(--text-secondary)' }}>
      <Icon className="h-3.5 w-3.5 shrink-0 mt-0.5" />
      <span>{text}</span>
    </div>
  );
}

export default SecurityBanner;
