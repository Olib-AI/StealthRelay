import { useEffect, useRef, useState } from 'react';
import { Phone, PhoneOff, Mic, MicOff, Video, VideoOff, RotateCw } from 'lucide-react';
import { useCallStore } from '../stores/call.ts';
import { transport } from '../transport/websocket.ts';

function formatDuration(ms: number): string {
  const total = Math.floor(ms / 1000);
  const m = Math.floor(total / 60).toString().padStart(2, '0');
  const s = (total % 60).toString().padStart(2, '0');
  return `${m}:${s}`;
}

function RemoteVideo({ peerID }: { peerID: string }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  useEffect(() => {
    transport.attachRemoteVideoCanvas(peerID, canvasRef.current);
    return () => transport.attachRemoteVideoCanvas(peerID, null);
  }, [peerID]);
  return (
    <div className="relative rounded-xl overflow-hidden flex items-center justify-center" style={{ backgroundColor: '#1c1c1e' }}>
      {/* The canvas keeps its native pixel dimensions (set in playback's
         renderFrame from frame.displayWidth/Height) and CSS letterboxes it
         into the cell. `max-w/h-full` + auto width/height preserves aspect
         ratio without stretching when video is portrait inside a landscape
         container or vice versa. */}
      <canvas
        ref={canvasRef}
        className="block"
        style={{ maxWidth: '100%', maxHeight: '100%', width: 'auto', height: 'auto' }}
      />
      <div className="absolute bottom-2 left-2 px-2 py-1 rounded-md text-xs" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
        {peerID.slice(0, 8)}
      </div>
    </div>
  );
}

function LocalPreview({ active }: { active: boolean }) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  useEffect(() => {
    if (!active) return;
    const id = window.setInterval(() => {
      const stream = transport.getLocalVideoStream();
      if (stream && videoRef.current && videoRef.current.srcObject !== stream) {
        videoRef.current.srcObject = stream;
        videoRef.current.muted = true;
        videoRef.current.play().catch(() => undefined);
      }
    }, 250);
    return () => window.clearInterval(id);
  }, [active]);
  if (!active) return null;
  return (
    <video
      ref={videoRef}
      playsInline
      autoPlay
      muted
      className="absolute bottom-24 right-4 w-28 aspect-[3/4] rounded-lg shadow-lg object-cover border-2 border-white/20"
      style={{ backgroundColor: '#000' }}
    />
  );
}

export default function CallView() {
  const call = useCallStore((s) => s.call);
  const error = useCallStore((s) => s.errorMessage);
  const setError = useCallStore((s) => s.setError);
  const [now, setNow] = useState<number>(() => Date.now());

  useEffect(() => {
    if (!call || call.state !== 'active') return;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [call]);

  useEffect(() => {
    if (!error) return;
    const id = window.setTimeout(() => setError(null), 4000);
    return () => window.clearTimeout(id);
  }, [error, setError]);

  if (!call && !error) return null;

  if (!call && error) {
    return (
      <div className="fixed inset-x-0 top-3 z-50 flex justify-center pointer-events-none">
        <div className="rounded-xl px-4 py-2 text-sm text-white shadow-lg pointer-events-auto" style={{ backgroundColor: '#FF453A' }}>
          {error}
        </div>
      </div>
    );
  }

  if (!call) return null;

  const elapsed = call.startedAt ? Math.max(0, now - call.startedAt) : 0;
  const isVideoActive = call.state === 'active' && call.isVideoCall;
  const remotes = call.remotePeerIDs;

  return (
    <div
      className="fixed inset-0 z-40 flex flex-col items-center justify-between px-6 py-10"
      style={{ backgroundColor: 'rgba(0,0,0,0.95)', color: 'white' }}
    >
      {isVideoActive && remotes.length > 0 ? (
        <div
          className="absolute inset-0 grid gap-1 p-2"
          style={{
            gridTemplateColumns:
              remotes.length === 1 ? '1fr' : remotes.length <= 2 ? '1fr 1fr' : 'repeat(2, 1fr)',
            gridAutoRows: '1fr',
          }}
        >
          {remotes.map((peerID) => <RemoteVideo key={peerID} peerID={peerID} />)}
        </div>
      ) : null}

      <LocalPreview active={isVideoActive && call.videoEnabled} />

      <div className="text-center mt-12 space-y-2 z-10">
        <div className="text-sm uppercase tracking-widest opacity-70">
          {call.state === 'incoming' && (call.isVideoCall ? 'Incoming video call' : 'Incoming voice call')}
          {call.state === 'outgoing' && 'Calling…'}
          {call.state === 'active' && (call.isVideoCall ? 'Video call' : 'Voice call')}
          {call.state === 'ending' && 'Ending…'}
        </div>
        <div className="text-3xl font-semibold drop-shadow">{call.remoteDisplayName || 'Peer'}</div>
        {call.state === 'active' && (
          <div className="text-base opacity-80 font-mono">{formatDuration(elapsed)}</div>
        )}
        {call.remotePeerIDs.length > 1 && (
          <div className="text-xs opacity-60">{call.remotePeerIDs.length} participants</div>
        )}
      </div>

      <div className="flex items-center gap-6 z-10">
        {call.state === 'incoming' && (
          <>
            <button
              type="button"
              onClick={() => transport.rejectCall()}
              className="rounded-full p-5 shadow-lg"
              style={{ backgroundColor: '#FF453A' }}
              aria-label="Decline call"
            >
              <PhoneOff className="h-6 w-6" />
            </button>
            <button
              type="button"
              onClick={() => transport.acceptCall()}
              className="rounded-full p-5 shadow-lg"
              style={{ backgroundColor: '#30D158' }}
              aria-label="Accept call"
            >
              <Phone className="h-6 w-6" />
            </button>
          </>
        )}

        {(call.state === 'outgoing' || call.state === 'active' || call.state === 'ending') && (
          <>
            <button
              type="button"
              onClick={() => transport.toggleMute(!call.audioMuted)}
              className="rounded-full p-4"
              style={{ backgroundColor: call.audioMuted ? '#FF9F0A' : 'rgba(255,255,255,0.15)' }}
              aria-label={call.audioMuted ? 'Unmute microphone' : 'Mute microphone'}
              disabled={call.state !== 'active'}
            >
              {call.audioMuted ? <MicOff className="h-5 w-5" /> : <Mic className="h-5 w-5" />}
            </button>
            {call.isVideoCall && (
              <button
                type="button"
                onClick={() => transport.toggleCamera(!call.videoEnabled)}
                className="rounded-full p-4"
                style={{ backgroundColor: call.videoEnabled ? 'rgba(255,255,255,0.15)' : '#FF9F0A' }}
                aria-label={call.videoEnabled ? 'Stop camera' : 'Start camera'}
                disabled={call.state !== 'active'}
              >
                {call.videoEnabled ? <Video className="h-5 w-5" /> : <VideoOff className="h-5 w-5" />}
              </button>
            )}
            {call.isVideoCall && call.state === 'active' && call.videoEnabled && (
              <button
                type="button"
                onClick={() => transport.cycleLocalVideoRotation()}
                className="rounded-full p-4"
                style={{ backgroundColor: 'rgba(255,255,255,0.15)' }}
                aria-label="Rotate camera frame"
                title="Tap to rotate the outgoing video by 90° if peers see it sideways"
              >
                <RotateCw className="h-5 w-5" />
              </button>
            )}
            <button
              type="button"
              onClick={() => transport.hangup()}
              className="rounded-full p-5 shadow-lg"
              style={{ backgroundColor: '#FF453A' }}
              aria-label="Hang up"
            >
              <PhoneOff className="h-6 w-6" />
            </button>
          </>
        )}
      </div>

      {error && (
        <div className="rounded-xl px-4 py-2 text-sm text-white z-10" style={{ backgroundColor: '#FF453A' }}>
          {error}
        </div>
      )}
    </div>
  );
}
