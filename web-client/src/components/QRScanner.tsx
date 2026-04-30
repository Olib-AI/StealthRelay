import { useEffect, useRef, useState, useCallback } from 'react';
import { Html5Qrcode } from 'html5-qrcode';
import { X, Camera, FlashlightOff, Flashlight, RotateCcw } from 'lucide-react';

interface QRScannerProps {
  onScan: (result: string) => void;
  onClose: () => void;
}

type DetectorPath = 'native' | 'html5qrcode' | 'unsupported';

type BarcodeDetectorLike = {
  detect: (source: CanvasImageSource) => Promise<{ rawValue: string }[]>;
};

type BarcodeDetectorCtor = new (opts?: { formats?: string[] }) => BarcodeDetectorLike;

type TorchCapabilities = MediaTrackCapabilities & { torch?: boolean };
type TorchTrack = MediaStreamTrack & { getCapabilities?: () => TorchCapabilities };

function QRScanner({ onScan, onClose }: QRScannerProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const html5Ref = useRef<Html5Qrcode | null>(null);
  const hasScannedRef = useRef(false);
  const rafRef = useRef<number | null>(null);
  const intervalRef = useRef<number | null>(null);

  const [error, setError] = useState<string | null>(null);
  const [path, setPath] = useState<DetectorPath>('unsupported');
  const [torchSupported, setTorchSupported] = useState(false);
  const [torchOn, setTorchOn] = useState(false);
  const [facing, setFacing] = useState<'environment' | 'user'>('environment');

  const handleScan = useCallback((text: string) => {
    if (hasScannedRef.current) return;
    if (!text || !text.trim()) return;
    hasScannedRef.current = true;
    onScan(text.trim());
  }, [onScan]);

  const stopAll = useCallback(() => {
    if (rafRef.current !== null) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    if (intervalRef.current !== null) {
      window.clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    if (html5Ref.current) {
      const inst = html5Ref.current;
      html5Ref.current = null;
      inst.stop().then(() => inst.clear()).catch(() => undefined);
    }
    const stream = streamRef.current;
    if (stream) {
      for (const track of stream.getTracks()) track.stop();
      streamRef.current = null;
    }
    if (videoRef.current) {
      try { videoRef.current.pause(); } catch { /* already paused */ }
      videoRef.current.srcObject = null;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    hasScannedRef.current = false;

    async function startNative() {
      const Ctor = (window as unknown as { BarcodeDetector?: BarcodeDetectorCtor }).BarcodeDetector;
      if (!Ctor) return false;
      const detector = new Ctor({ formats: ['qr_code'] });
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: facing },
          width: { ideal: 1280 },
          height: { ideal: 720 },
        },
        audio: false,
      });
      if (cancelled) {
        for (const t of stream.getTracks()) t.stop();
        return true;
      }
      streamRef.current = stream;
      const track = stream.getVideoTracks()[0] as TorchTrack | undefined;
      const caps: TorchCapabilities | undefined = track?.getCapabilities?.();
      setTorchSupported(!!caps?.torch);

      const video = videoRef.current;
      if (!video) return true;
      video.srcObject = stream;
      video.muted = true;
      video.playsInline = true;
      video.setAttribute('webkit-playsinline', 'true');
      try { await video.play(); } catch { /* autoplay may need user gesture */ }

      const tick = async () => {
        if (cancelled || hasScannedRef.current) return;
        try {
          const results = await detector.detect(video);
          if (results.length > 0 && results[0]?.rawValue) {
            handleScan(results[0].rawValue);
            return;
          }
        } catch {
          // BarcodeDetector occasionally throws on dropped frames; just keep polling.
        }
        rafRef.current = requestAnimationFrame(() => { void tick(); });
      };
      rafRef.current = requestAnimationFrame(() => { void tick(); });
      setPath('native');
      return true;
    }

    async function startHtml5(): Promise<void> {
      const container = containerRef.current;
      if (!container) return;
      const scannerId = 'qr-scanner-html5';
      let scannerDiv = container.querySelector<HTMLDivElement>(`#${scannerId}`);
      if (!scannerDiv) {
        scannerDiv = document.createElement('div');
        scannerDiv.id = scannerId;
        scannerDiv.style.width = '100%';
        scannerDiv.style.height = '100%';
        container.appendChild(scannerDiv);
      }
      const scanner = new Html5Qrcode(scannerId, {
        verbose: false,
        useBarCodeDetectorIfSupported: true,
        formatsToSupport: undefined,
      } as unknown as ConstructorParameters<typeof Html5Qrcode>[1]);
      html5Ref.current = scanner;
      try {
        await scanner.start(
          { facingMode: facing },
          {
            fps: 30,
            // Intentionally NO qrbox — scan the entire frame so the user
            // doesn't have to align the code. html5-qrcode otherwise crops
            // to a tiny window and misses easy reads.
            disableFlip: false,
            videoConstraints: {
              facingMode: { ideal: facing },
              width: { ideal: 1280 },
              height: { ideal: 720 },
              // @ts-expect-error iOS Safari accepts focusMode in constraints
              focusMode: 'continuous',
            },
          },
          (text) => handleScan(text),
          () => undefined,
        );
        const tracks = (scanner.getRunningTrackCameraCapabilities()?.torchFeature?.()
          ? true
          : false);
        setTorchSupported(tracks);
        setPath('html5qrcode');
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes('NotAllowedError') || msg.includes('denied')) {
          setError('Camera access denied. Allow camera access and reopen the scanner.');
        } else if (msg.includes('NotFoundError') || msg.includes('no camera')) {
          setError('No camera found on this device.');
        } else {
          setError(`Camera unavailable: ${msg}`);
        }
      }
    }

    (async () => {
      try {
        const ok = await startNative();
        if (cancelled) return;
        if (!ok) await startHtml5();
      } catch (err) {
        if (cancelled) return;
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes('NotAllowedError') || msg.includes('denied')) {
          setError('Camera access denied. Allow camera access and reopen the scanner.');
        } else {
          // Native path threw — try the library fallback.
          await startHtml5();
        }
      }
    })();

    return () => {
      cancelled = true;
      stopAll();
    };
  }, [facing, handleScan, stopAll]);

  const toggleTorch = useCallback(async () => {
    const stream = streamRef.current;
    if (!stream) return;
    const track = stream.getVideoTracks()[0] as TorchTrack | undefined;
    if (!track) return;
    try {
      const next = !torchOn;
      await track.applyConstraints({
        // @ts-expect-error torch is a non-standard but widely-supported constraint
        advanced: [{ torch: next }],
      });
      setTorchOn(next);
    } catch {
      // Torch unavailable on this device.
    }
  }, [torchOn]);

  const flipCamera = useCallback(() => {
    setFacing((f) => (f === 'environment' ? 'user' : 'environment'));
  }, []);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0, 0, 0, 0.5)' }}>
      <div className="rounded-[20px] w-full max-w-sm p-4 space-y-3" style={{ backgroundColor: 'var(--bg-surface)' }}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
            <Camera className="h-5 w-5" />
            <h3 className="text-[15px] font-semibold">Scan Invitation QR</h3>
          </div>
          <div className="flex items-center gap-1">
            {torchSupported && (
              <button
                type="button"
                onClick={() => void toggleTorch()}
                title={torchOn ? 'Turn off flashlight' : 'Turn on flashlight'}
                className="p-2 rounded-full"
                style={{ color: torchOn ? '#FFD60A' : 'var(--text-secondary)' }}
              >
                {torchOn ? <Flashlight className="h-5 w-5" /> : <FlashlightOff className="h-5 w-5" />}
              </button>
            )}
            <button
              type="button"
              onClick={flipCamera}
              title="Flip camera"
              className="p-2 rounded-full"
              style={{ color: 'var(--text-secondary)' }}
            >
              <RotateCcw className="h-5 w-5" />
            </button>
            <button type="button" onClick={onClose} className="p-2 rounded-full transition-colors" style={{ color: 'var(--text-secondary)' }}>
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        <div ref={containerRef} className="relative rounded-xl overflow-hidden bg-black w-full" style={{ minHeight: 280, aspectRatio: '4/3' }}>
          {path === 'native' && (
            <video
              ref={videoRef}
              className="absolute inset-0 w-full h-full object-cover"
              playsInline
              muted
              autoPlay
            />
          )}
          {/* Soft scan-area hint, but we still scan the entire frame */}
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
            <div
              className="rounded-2xl"
              style={{
                width: '70%',
                aspectRatio: '1 / 1',
                boxShadow: '0 0 0 9999px rgba(0,0,0,0.35)',
                border: '2px dashed rgba(255,255,255,0.6)',
              }}
            />
          </div>
        </div>

        {error && (
          <p className="text-[12px] text-[#FF453A] text-center">{error}</p>
        )}

        <p className="text-[12px] text-center" style={{ color: 'var(--text-tertiary)' }}>
          Point at the QR. Whole frame is scanned — alignment isn't required.
        </p>
      </div>
    </div>
  );
}

export default QRScanner;
