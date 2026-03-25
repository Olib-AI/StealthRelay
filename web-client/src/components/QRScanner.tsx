import { useEffect, useRef, useState } from 'react';
import { Html5Qrcode } from 'html5-qrcode';
import { X, Camera } from 'lucide-react';

interface QRScannerProps {
  onScan: (result: string) => void;
  onClose: () => void;
}

function QRScanner({ onScan, onClose }: QRScannerProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const scannerRef = useRef<Html5Qrcode | null>(null);
  const [error, setError] = useState<string | null>(null);
  const hasScanned = useRef(false);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const scannerId = 'qr-scanner-element';
    let scannerDiv = container.querySelector(`#${scannerId}`);
    if (!scannerDiv) {
      scannerDiv = document.createElement('div');
      scannerDiv.id = scannerId;
      container.appendChild(scannerDiv);
    }

    const scanner = new Html5Qrcode(scannerId);
    scannerRef.current = scanner;

    scanner
      .start(
        { facingMode: 'environment' },
        { fps: 10, qrbox: { width: 250, height: 250 } },
        (text) => {
          if (!hasScanned.current && text.includes('stealth://invite/')) {
            hasScanned.current = true;
            scanner.stop().catch(() => {});
            onScan(text);
          }
        },
        () => {},
      )
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        setError(`Camera access denied or unavailable: ${msg}`);
      });

    return () => {
      scanner.stop().catch(() => {});
      scanner.clear();
    };
  }, [onScan]);

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

        <div ref={containerRef} className="rounded-xl overflow-hidden bg-black aspect-square" />

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
