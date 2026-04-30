// Local camera capture → H.264 AVCC encoded chunks.
// Output bytes match iOS `VideoCallService` so an iOS callee can decode them
// with VTDecompressionSession unchanged.

import { VIDEO } from './types.ts';
import { parseAvcCDescription, prependParameterSets, extractParameterSets, setRefIdcHigh } from './avcc.ts';

const HIGH_REF_IDC_TYPES: ReadonlySet<number> = new Set([5, 7, 8]); // IDR, SPS, PPS

export type EncodedFrame = {
  bytes: Uint8Array;
  isKeyFrame: boolean;
  /** Frame counter — fed straight into the wire `MediaFrameHeader.sequence`. */
  sequence: number;
};

export type StartVideoCaptureOptions = {
  onFrame: (frame: EncodedFrame) => void;
  onError?: (error: Error) => void;
  /** Local element to attach the raw camera stream for self-preview. */
  previewVideoEl?: HTMLVideoElement | null;
};

export type VideoCapture = {
  stop(): Promise<void>;
  setEnabled(enabled: boolean): void;
  isEnabled(): boolean;
  forceKeyframe(): void;
  /** Rotate the outgoing canvas by 0°, 90°, 180°, or 270° clockwise. */
  setRotation(degrees: 0 | 90 | 180 | 270): void;
  getRotation(): 0 | 90 | 180 | 270;
  stream: MediaStream;
};

export async function startVideoCapture(opts: StartVideoCaptureOptions): Promise<VideoCapture> {
  const stream = await navigator.mediaDevices.getUserMedia({
    video: {
      width: { ideal: VIDEO.width },
      height: { ideal: VIDEO.height },
      frameRate: { ideal: VIDEO.fps, max: VIDEO.fps },
      facingMode: 'user',
    },
    audio: false,
  });

  if (opts.previewVideoEl) {
    opts.previewVideoEl.srcObject = stream;
    opts.previewVideoEl.muted = true;
    void opts.previewVideoEl.play().catch(() => { /* will be retried */ });
  }

  const videoTrack = stream.getVideoTracks()[0];
  if (!videoTrack) throw new Error('No video track from getUserMedia');

  if (typeof window.VideoEncoder === 'undefined') {
    for (const t of stream.getTracks()) t.stop();
    throw new Error('Browser does not support WebCodecs VideoEncoder (use Chrome/Edge or Safari 17+)');
  }
  const hasTrackProcessor = typeof (window as unknown as { MediaStreamTrackProcessor?: unknown }).MediaStreamTrackProcessor !== 'undefined';

  let sequence = 0;
  let sps: Uint8Array | undefined;
  let pps: Uint8Array | undefined;
  let enabled = true;
  let stopped = false;
  let pendingKeyframe = false;
  let framesSinceKeyframe = 0;

  const encoder = new VideoEncoder({
    output: (chunk: EncodedVideoChunk, metadata?: EncodedVideoChunkMetadata) => {
      if (metadata?.decoderConfig?.description) {
        const descSrc = metadata.decoderConfig.description;
        const desc =
          descSrc instanceof Uint8Array
            ? descSrc
            : ArrayBuffer.isView(descSrc)
              ? new Uint8Array(descSrc.buffer, descSrc.byteOffset, descSrc.byteLength)
              : new Uint8Array(descSrc);
        try {
          const ps = parseAvcCDescription(desc);
          sps = ps.sps;
          pps = ps.pps;
          // WebCodecs emits Baseline SPS with all constraint flags zero.
          // Apple VideoToolbox rejects/ignores Baseline streams that don't
          // declare themselves as Constrained Baseline. Set
          // constraint_set0+1+2 (byte 2 = 0xE0). Purely advisory, does not
          // change the bitstream.
          if (sps.length >= 3) sps[2] = (sps[2] ?? 0) | 0xe0;
          // Force `nal_ref_idc = 11` on SPS and PPS NAL header bytes.
          // WebCodecs emits with ref_idc=01; Apple VideoToolbox treats
          // parameter sets with low ref_idc as discardable on some paths.
          if (sps.length >= 1) sps[0] = (sps[0]! & 0x9f) | 0x60;
          if (pps.length >= 1) pps[0] = (pps[0]! & 0x9f) | 0x60;
        } catch {
          // Wait for a valid avcC.
        }
      }
      const buf = new ArrayBuffer(chunk.byteLength);
      chunk.copyTo(buf);
      let bytes: Uint8Array = new Uint8Array(buf);
      const isKey = chunk.type === 'key';
      if (isKey && sps && pps) {
        const inline = extractParameterSets(bytes);
        if (!inline.sps || !inline.pps) {
          bytes = prependParameterSets(bytes, sps, pps) as Uint8Array;
        }
        // Force ref_idc=11 on parameter sets and IDR slice — Apple's decoder
        // treats parameter sets / reference frames with low ref_idc as
        // discardable, which silently breaks the whole stream.
        setRefIdcHigh(bytes, HIGH_REF_IDC_TYPES);
      }
      sequence++;
      opts.onFrame({ bytes, isKeyFrame: isKey, sequence });
    },
    error: (err) => {
      opts.onError?.(err instanceof Error ? err : new Error(String(err)));
    },
  });

  // Encoder dimensions are reconfigured dynamically when rotation changes so
  // the SPS in the H.264 stream matches the actual pixel dimensions of the
  // canvas we're feeding it. Without this, rotation-induced
  // landscape↔portrait swaps cause the receiver to stretch the picture.
  let configuredW = -1;
  let configuredH = -1;
  function configureEncoder(w: number, h: number): void {
    if (configuredW === w && configuredH === h) return;
    encoder.configure({
      codec: 'avc1.42E01E',
      width: w,
      height: h,
      bitrate: VIDEO.bitrate,
      framerate: VIDEO.fps,
      hardwareAcceleration: 'prefer-hardware',
      avc: { format: 'avc' },
      latencyMode: 'realtime',
    });
    configuredW = w;
    configuredH = h;
    pendingKeyframe = true;
    sps = undefined;
    pps = undefined;
  }

  const minIntervalUs = Math.floor(1_000_000 / VIDEO.fps);
  let lastEncodeUs = -1;

  // Default rotation guess: portrait source → -90° (=270° CW) brings the
  // typical front-camera feed upright. User can override.
  const initialRotation: 0 | 90 | 180 | 270 = 270;
  let rotation: 0 | 90 | 180 | 270 = initialRotation;

  const consumeFrame = (frame: VideoFrame): void => {
    const ts = frame.timestamp;
    const tooSoon = lastEncodeUs >= 0 && ts - lastEncodeUs < minIntervalUs;
    if (!enabled || tooSoon) {
      frame.close();
      return;
    }
    lastEncodeUs = ts;

    framesSinceKeyframe++;
    const requestKey =
      pendingKeyframe ||
      framesSinceKeyframe >= VIDEO.keyframeInterval ||
      sequence === 0;
    if (requestKey) {
      framesSinceKeyframe = 0;
      pendingKeyframe = false;
    }

    try {
      configureEncoder(frame.codedWidth, frame.codedHeight);
      encoder.encode(frame, { keyFrame: requestKey });
    } catch (e) {
      opts.onError?.(e instanceof Error ? e : new Error(String(e)));
    }
    frame.close();
  };

  // Source of VideoFrame objects: prefer MediaStreamTrackProcessor (Chrome /
  // Edge), fall back to a hidden <video> + requestVideoFrameCallback (Safari).
  type FrameSource = { stop(): void };
  const startTrackProcessorPump = (): FrameSource => {
    type MSPCtor = new (opts: { track: MediaStreamTrack }) => { readable: ReadableStream<VideoFrame> };
    const Ctor = (window as unknown as { MediaStreamTrackProcessor: MSPCtor }).MediaStreamTrackProcessor;
    const processor = new Ctor({ track: videoTrack });
    const reader = processor.readable.getReader();
    void (async () => {
      while (!stopped) {
        const { done, value: frame } = await reader.read();
        if (done) break;
        if (!frame) continue;
        consumeFrame(frame);
      }
    })().catch((e) => opts.onError?.(e instanceof Error ? e : new Error(String(e))));
    return {
      stop() {
        try { reader.cancel().catch(() => undefined); } catch { /* already cancelled */ }
      },
    };
  };

  const startVideoElementPump = (): FrameSource => {
    // The hidden <video> must be attached to the DOM on Safari iOS — a
    // detached element silently stalls when its srcObject is a MediaStream.
    const el = document.createElement('video');
    el.muted = true;
    el.playsInline = true;
    el.autoplay = true;
    el.setAttribute('webkit-playsinline', 'true');
    el.style.position = 'fixed';
    el.style.width = '1px';
    el.style.height = '1px';
    el.style.opacity = '0';
    el.style.pointerEvents = 'none';
    el.style.left = '-9999px';
    document.body.appendChild(el);
    el.srcObject = stream;

    // Snapshot each tick into a canvas so VideoFrame holds independent
    // pixel data. Constructing VideoFrame directly from the <video> on
    // Safari iOS reuses the same GPU surface and the encoder sees frame 1
    // repeatedly.
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');

    let intervalHandle: number | null = null;
    let firstTs: number | null = null;

    const tick = () => {
      if (stopped) return;
      if (!ctx) return;
      if (el.readyState < 2 || el.videoWidth === 0) return;
      // Rotation is user-controllable (CallView exposes a button). 0° and
      // 180° keep source dimensions; 90° and 270° transpose them.
      const sw = el.videoWidth;
      const sh = el.videoHeight;
      const swap = rotation === 90 || rotation === 270;
      const targetW = swap ? sh : sw;
      const targetH = swap ? sw : sh;
      if (canvas.width !== targetW || canvas.height !== targetH) {
        canvas.width = targetW;
        canvas.height = targetH;
      }
      ctx.save();
      if (rotation !== 0) {
        ctx.translate(canvas.width / 2, canvas.height / 2);
        ctx.rotate((rotation * Math.PI) / 180);
        ctx.drawImage(el, -sw / 2, -sh / 2);
      } else {
        ctx.drawImage(el, 0, 0);
      }
      ctx.restore();
      try {
        if (firstTs === null) firstTs = performance.now();
        const ts = Math.round((performance.now() - firstTs) * 1000);
        const frame = new VideoFrame(canvas, { timestamp: ts });
        consumeFrame(frame);
      } catch (e) {
        opts.onError?.(e instanceof Error ? e : new Error(String(e)));
      }
    };

    void el.play().then(() => {
      intervalHandle = window.setInterval(tick, Math.max(16, Math.floor(1000 / VIDEO.fps)));
    }).catch((e) => opts.onError?.(e instanceof Error ? e : new Error(String(e))));

    return {
      stop() {
        if (intervalHandle !== null) window.clearInterval(intervalHandle);
        try { el.pause(); } catch { /* already paused */ }
        el.srcObject = null;
        try { el.remove(); } catch { /* already detached */ }
      },
    };
  };

  const frameSource: FrameSource = hasTrackProcessor
    ? startTrackProcessorPump()
    : startVideoElementPump();

  return {
    async stop() {
      stopped = true;
      frameSource.stop();
      try {
        if (encoder.state !== 'closed') {
          await encoder.flush().catch(() => undefined);
          encoder.close();
        }
      } catch { /* already closed */ }
      for (const t of stream.getTracks()) t.stop();
      if (opts.previewVideoEl) opts.previewVideoEl.srcObject = null;
    },
    setEnabled(v: boolean) {
      enabled = v;
      if (v) pendingKeyframe = true; // First frame after re-enable is a keyframe.
    },
    isEnabled() { return enabled; },
    forceKeyframe() { pendingKeyframe = true; },
    setRotation(deg) {
      rotation = deg;
      pendingKeyframe = true; // Force a keyframe so receivers re-anchor.
    },
    getRotation() { return rotation; },
    stream,
  };
}
