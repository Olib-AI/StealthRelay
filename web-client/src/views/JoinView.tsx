import { useState, useCallback } from 'react';
import { Link2, QrCode, Loader2, AlertCircle, ArrowRight } from 'lucide-react';
import { useConnectionStore } from '../stores/connection.ts';
import { usePoolStore } from '../stores/pool.ts';
import { parseInvitationUrl, isInvitationExpired } from '../crypto/invitation.ts';
import { transport } from '../transport/websocket.ts';
import ProfileSetup from '../components/ProfileSetup.tsx';
import QRScanner from '../components/QRScanner.tsx';
import ThemeToggle from '../components/ThemeToggle.tsx';

function JoinView() {
  const [inviteUrl, setInviteUrl] = useState('');
  const [parseError, setParseError] = useState<string | null>(null);
  const [isValid, setIsValid] = useState(false);
  const [showScanner, setShowScanner] = useState(false);
  const status = useConnectionStore((s) => s.status);
  const error = useConnectionStore((s) => s.error);
  const powProgress = useConnectionStore((s) => s.powProgress);
  const userProfile = usePoolStore((s) => s.userProfile);

  const validateUrl = useCallback((url: string) => {
    setInviteUrl(url);
    setParseError(null);
    setIsValid(false);

    if (url.trim().length === 0) return;

    try {
      const parsed = parseInvitationUrl(url);
      if (isInvitationExpired(parsed)) {
        setParseError('This invitation has expired.');
        return;
      }
      setIsValid(true);
    } catch (err) {
      setParseError(err instanceof Error ? err.message : 'Invalid invitation URL');
    }
  }, []);

  function handleJoin() {
    if (!isValid || userProfile.displayName.trim().length === 0) return;
    transport.connect(inviteUrl);
  }

  function handleQRScan(result: string) {
    setShowScanner(false);
    validateUrl(result);
  }

  async function handlePaste() {
    try {
      const text = await navigator.clipboard.readText();
      validateUrl(text);
    } catch {
      // Clipboard access denied
    }
  }

  const isConnecting = status === 'connecting' || status === 'waiting_approval';

  return (
    <div className="flex-1 flex flex-col items-center min-h-0 overflow-y-auto px-4 py-6" style={{ backgroundColor: 'var(--bg-page)' }}>
      <div className="w-full max-w-md space-y-5">
        {/* Header */}
        <div className="text-center space-y-2">
          <img src="/logo.png" alt="StealthOS" className="h-20 w-20 mb-2 mx-auto" />
          <h1 className="text-[28px] font-bold" style={{ color: 'var(--text-primary)' }}>StealthRelay</h1>
          <p className="text-[15px]" style={{ color: 'var(--text-secondary)' }}>
            Join a pool to chat and play games with friends
          </p>
        </div>

        {/* Profile Setup */}
        <div className="rounded-xl p-4" style={{ backgroundColor: 'var(--bg-surface)' }}>
          <h2 className="text-[15px] font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Your Profile</h2>
          <ProfileSetup />
        </div>

        {/* Join Section */}
        <div className="rounded-xl p-4 space-y-3" style={{ backgroundColor: 'var(--bg-surface)' }}>
          <h2 className="text-[15px] font-semibold" style={{ color: 'var(--text-primary)' }}>Join a Pool</h2>

          {/* Invitation URL input */}
          <div className="space-y-2">
            <div className="relative">
              <div className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-tertiary)' }}>
                <Link2 className="h-4 w-4" />
              </div>
              <input
                type="text"
                value={inviteUrl}
                onChange={(e) => validateUrl(e.target.value)}
                placeholder="stealth://invite/..."
                className="w-full pl-9 pr-16 py-3 rounded-[10px] text-[15px] focus:border-[#007AFF] transition-colors"
                style={{ backgroundColor: 'var(--bg-surface)', borderWidth: '1px', borderStyle: 'solid', borderColor: 'var(--separator)', color: 'var(--text-primary)' }}
                disabled={isConnecting}
              />
              <button
                type="button"
                onClick={handlePaste}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-[#007AFF] font-medium px-2 py-1 rounded-md"
                style={{ backgroundColor: 'var(--bg-tertiary)' }}
                disabled={isConnecting}
              >
                Paste
              </button>
            </div>

            {parseError && (
              <div className="flex items-start gap-2 text-xs text-[#FF453A]">
                <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                <span>{parseError}</span>
              </div>
            )}

            {isValid && (
              <p className="text-xs text-[#30D158] flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-[#30D158]" />
                Valid invitation
              </p>
            )}
          </div>

          {/* QR Scanner button */}
          <button
            type="button"
            onClick={() => setShowScanner(true)}
            className="w-full flex items-center justify-center gap-2 py-3 rounded-xl text-[15px] transition-colors"
            style={{ backgroundColor: 'var(--bg-surface)', borderWidth: '1px', borderStyle: 'solid', borderColor: 'var(--separator)', color: 'var(--text-secondary)' }}
            disabled={isConnecting}
          >
            <QrCode className="h-4 w-4" />
            Scan QR Code
          </button>

          {/* Join button */}
          <button
            type="button"
            onClick={handleJoin}
            disabled={!isValid || isConnecting || userProfile.displayName.trim().length === 0}
            className="w-full flex items-center justify-center gap-2 py-4 bg-[#007AFF] hover:bg-[#0071E3] text-white text-[17px] font-semibold rounded-xl transition-colors disabled:cursor-not-allowed"
            style={(!isValid || isConnecting || userProfile.displayName.trim().length === 0) ? { backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' } : undefined}
          >
            {isConnecting ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                {status === 'waiting_approval' ? 'Waiting for host approval...' : 'Connecting...'}
              </>
            ) : (
              <>
                Join Pool
                <ArrowRight className="h-4 w-4" />
              </>
            )}
          </button>

          {/* PoW progress */}
          {powProgress !== null && (
            <div className="space-y-1">
              <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>Solving proof-of-work challenge...</p>
              <div className="h-1 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                <div className="h-full bg-[#007AFF] animate-pulse" style={{ width: '60%' }} />
              </div>
              <p className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{powProgress.toLocaleString()} hashes tried</p>
            </div>
          )}

          {/* Error display */}
          {error && status === 'failed' && (
            <div className="flex items-start gap-2 p-3 bg-[rgba(255,69,58,0.1)] rounded-xl">
              <AlertCircle className="h-4 w-4 text-[#FF453A] shrink-0 mt-0.5" />
              <p className="text-xs text-[#FF453A]">{error}</p>
            </div>
          )}
        </div>

        {/* Theme + Footer */}
        <div className="flex flex-col items-center gap-3" style={{ paddingBottom: 'env(safe-area-inset-bottom, 0px)' }}>
          <ThemeToggle />
          <p className="text-[11px]" style={{ color: 'var(--text-tertiary)' }}>
            End-to-end encrypted. No account required.
          </p>
        </div>
      </div>

      {/* QR Scanner modal */}
      {showScanner && (
        <QRScanner onScan={handleQRScan} onClose={() => setShowScanner(false)} />
      )}
    </div>
  );
}

export default JoinView;
