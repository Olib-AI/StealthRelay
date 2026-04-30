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
  stream: MediaStream;
};

declare class MediaStreamTrackProcessor<T> {
  constructor(opts: { track: MediaStreamTrack });
  readonly readable: ReadableStream<T>;
}

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

  if (typeof window.VideoEncoder === 'undefined' || typeof (window as unknown as { MediaStreamTrackProcessor?: unknown }).MediaStreamTrackProcessor === 'undefined') {
    for (const t of stream.getTracks()) t.stop();
    throw new Error('Browser does not support WebCodecs VideoEncoder + MediaStreamTrackProcessor (use Chrome/Edge or Safari 17+)');
  }

  let sequence = 0;
  let sps: Uint8Array | undefined;
  let pps: Uint8Array | undefined;
  let enabled = true;
  let stopped = false;
  let pendingKeyframe = false;
  let framesSinceKeyframe = 0;
  let keyCount = 0;
  let deltaCount = 0;
  const hexDump = (b: Uint8Array, n = 32): string =>
    Array.from(b.slice(0, n))
      .map((x) => x.toString(16).padStart(2, '0'))
      .join(' ');

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
          // Apple VideoToolbox is documented to reject Baseline streams that
          // do not declare themselves as Constrained Baseline. Set
          // constraint_set0_flag + constraint_set1_flag + constraint_set2_flag
          // (byte 2 = 0xE0) — purely advisory, does not change the bitstream.
          if (sps.length >= 3) {
            sps[2] = (sps[2] ?? 0) | 0xe0;
          }
          // Force `nal_ref_idc = 11` (highest priority) on SPS and PPS NAL
          // header bytes. WebCodecs emits them with ref_idc=01; Apple
          // VideoToolbox is lenient on slice NALs but pickier on parameter
          // sets, occasionally treating ref_idc<11 as discardable. iOS's own
          // encoder always uses 11.
          if (sps.length >= 1) sps[0] = (sps[0]! & 0x9f) | 0x60;
          if (pps.length >= 1) pps[0] = (pps[0]! & 0x9f) | 0x60;
          // SPS bytes: [0]=NAL hdr, [1]=profile_idc, [2]=constraint flags, [3]=level_idc.
          const profile = sps[1];
          const constraints = sps[2];
          const level = sps[3];
          const profileName =
            profile === 0x42 ? 'Baseline' :
            profile === 0x4d ? 'Main' :
            profile === 0x64 ? 'High' :
            `0x${profile?.toString(16) ?? '??'}`;
          console.log('[VIDEO/SEND] cached SPS/PPS', {
            sps: sps.length,
            pps: pps.length,
            profile: profileName,
            profile_idc: profile,
            constraints: `0x${constraints?.toString(16) ?? '??'}`,
            level_idc: level,
            spsHex: hexDump(sps),
            ppsHex: hexDump(pps),
          });
        } catch (e) {
          console.warn('[VIDEO/SEND] avcC parse failed', e);
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
      if (isKey) {
        keyCount++;
        // Pull out just the NAL header bytes that matter — console.log
        // truncates the middle of long hex dumps.
        const nalHeaders: { type: number; ref_idc: number; byte: string }[] = [];
        let off = 0;
        while (off + 4 <= bytes.length && nalHeaders.length < 6) {
          const len =
            (bytes[off]! << 24) | (bytes[off + 1]! << 16) | (bytes[off + 2]! << 8) | bytes[off + 3]!;
          if (len <= 0 || off + 4 + len > bytes.length) break;
          const h = bytes[off + 4]!;
          nalHeaders.push({
            type: h & 0x1f,
            ref_idc: (h >> 5) & 0x03,
            byte: `0x${h.toString(16).padStart(2, '0')}`,
          });
          off += 4 + len;
        }
        const nalSummary = nalHeaders
          .map((n) => `t${n.type}/r${n.ref_idc}=${n.byte}`)
          .join(' | ');
        console.log(`[VIDEO/SEND] keyframe seq=${sequence} size=${bytes.length} nals: ${nalSummary}`);
      } else {
        deltaCount++;
        if (deltaCount % 30 === 1) {
          console.log('[VIDEO/SEND] delta progress', { seq: sequence, keys: keyCount, deltas: deltaCount, finalSize: bytes.length });
        }
      }
      opts.onFrame({ bytes, isKeyFrame: isKey, sequence });
    },
    error: (err) => {
      console.warn('[VIDEO/SEND] encoder error', err);
      opts.onError?.(err instanceof Error ? err : new Error(String(err)));
    },
  });
  console.log('[VIDEO/SEND] encoder configured', { width: VIDEO.width, height: VIDEO.height, fps: VIDEO.fps });

  const trackSettings = videoTrack.getSettings();
  const cfgWidth = trackSettings.width ?? VIDEO.width;
  const cfgHeight = trackSettings.height ?? VIDEO.height;
  encoder.configure({
    codec: 'avc1.42E01E', // H.264 Baseline, level mostly cosmetic — encoder may upgrade
    width: cfgWidth,
    height: cfgHeight,
    bitrate: VIDEO.bitrate,
    framerate: VIDEO.fps,
    hardwareAcceleration: 'prefer-hardware',
    avc: { format: 'avc' },
    latencyMode: 'realtime',
  });

  const processor = new MediaStreamTrackProcessor<VideoFrame>({ track: videoTrack });
  const reader = processor.readable.getReader();

  let lastEncodeUs = -1;
  const minIntervalUs = Math.floor(1_000_000 / VIDEO.fps);

  const pump = async (): Promise<void> => {
    while (!stopped) {
      const { done, value: frame } = await reader.read();
      if (done) break;
      if (!frame) continue;

      // Drop frames if disabled or pacing exceeded — saves CPU and matches
      // iOS's effective 15 fps rate.
      const ts = frame.timestamp;
      const tooSoon = lastEncodeUs >= 0 && ts - lastEncodeUs < minIntervalUs;
      if (!enabled || tooSoon) {
        frame.close();
        continue;
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
        encoder.encode(frame, { keyFrame: requestKey });
      } catch (e) {
        opts.onError?.(e instanceof Error ? e : new Error(String(e)));
      }
      frame.close();
    }
  };
  void pump().catch((e) => opts.onError?.(e instanceof Error ? e : new Error(String(e))));

  return {
    async stop() {
      stopped = true;
      try { reader.cancel().catch(() => undefined); } catch { /* already cancelled */ }
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
    stream,
  };
}
