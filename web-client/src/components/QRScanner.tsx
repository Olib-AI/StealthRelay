import { useEffect, useRef, useState } from 'react';
import { Html5Qrcode } from 'html5-qrcode';
import { X, Camera } from 'lucide-react';

interface QRScannerProps {
  onScan: (result: string) => void;
  onClose: () => void;
}

function QRScanner({ onScan, onClose }: QRScannerProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);
  const hasScanned = useRef(false);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const scannerId = 'qr-scanner-element';
    // Clean any previous scanner div
    const existing = container.querySelector(`#${scannerId}`);
    if (existing) existing.remove();

    const scannerDiv = document.createElement('div');
    scannerDiv.id = scannerId;
    container.appendChild(scannerDiv);

    const scanner = new Html5Qrcode(scannerId);
    let running = false;

    // Use a responsive qrbox that fits the container
    const containerWidth = container.clientWidth;
    const qrboxSize = Math.min(Math.floor(containerWidth * 0.8), 250);

    scanner
      .start(
        { facingMode: 'environment' },
        {
          fps: 15,
          qrbox: { width: qrboxSize, height: qrboxSize },
          aspectRatio: 1.0,
        },
        (text) => {
          if (hasScanned.current) return;
          // Accept any scanned text — the invitation parser will validate it
          // The QR might contain stealth://invite/..., stealth://claim/..., or a URL
          if (text && text.trim().length > 0) {
            hasScanned.current = true;
            running = false;
            scanner.stop().catch(() => {});
            onScan(text.trim());
          }
        },
        () => {},
      )
      .then(() => {
        running = true;
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes('NotAllowedError') || msg.includes('denied')) {
          setError('Camera access denied. Please allow camera access and try again.');
        } else if (msg.includes('NotFoundError') || msg.includes('no camera')) {
          setError('No camera found on this device.');
        } else {
          setError(`Camera unavailable: ${msg}`);
        }
      });

    return () => {
      if (running) {
        running = false;
        scanner.stop().then(() => scanner.clear()).catch(() => {});
      }
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0, 0, 0, 0.5)' }}>
      <div className="rounded-[20px] w-full max-w-sm p-4 space-y-3" style={{ backgroundColor: 'var(--bg-surface)' }}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
            <Camera className="h-5 w-5" />
            <h3 className="text-[15px] font-semibold">Scan Invitation QR</h3>
          </div>
          <button type="button" onClick={onClose} className="transition-colors" style={{ color: 'var(--text-secondary)' }}>
            <X className="h-5 w-5" />
          </button>
        </div>

        <div ref={containerRef} className="rounded-xl overflow-hidden bg-black w-full" style={{ minHeight: 280 }} />

        {error && (
          <p className="text-[12px] text-[#FF453A] text-center">{error}</p>
        )}

        <p className="text-[12px] text-center" style={{ color: 'var(--text-tertiary)' }}>
          Point your camera at a StealthRelay invitation QR code
        </p>
      </div>
    </div>
  );
}

export default QRScanner;
