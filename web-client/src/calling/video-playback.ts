// Per-peer H.264 decoder + canvas renderer.

import { buildAvcCDescription, extractParameterSets } from './avcc.ts';

export class VideoPlayback {
  private decoder: VideoDecoder | null = null;
  private canvas: HTMLCanvasElement | null = null;
  private ctx: CanvasRenderingContext2D | null = null;
  private configured = false;
  private sps: Uint8Array | null = null;
  private pps: Uint8Array | null = null;
  private droppedKeyframeWait = true;
  private nextChunkTs = 0;
  private onConfigError?: (error: Error) => void;

  attachCanvas(canvas: HTMLCanvasElement): void {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
  }

  detachCanvas(): void {
    this.canvas = null;
    this.ctx = null;
  }

  start(onConfigError?: (error: Error) => void): void {
    if (this.decoder) return;
    this.onConfigError = onConfigError;
    if (typeof window.VideoDecoder === 'undefined') {
      onConfigError?.(new Error('Browser does not support WebCodecs VideoDecoder'));
      return;
    }
    this.decoder = new VideoDecoder({
      output: (frame) => this.renderFrame(frame),
      error: (err) => {
        // Reset on hard error; next keyframe reconfigures.
        this.configured = false;
        this.droppedKeyframeWait = true;
        onConfigError?.(err instanceof Error ? err : new Error(String(err)));
      },
    });
  }

  async stop(): Promise<void> {
    this.configured = false;
    this.droppedKeyframeWait = true;
    if (this.decoder) {
      try {
        if (this.decoder.state !== 'closed') {
          await this.decoder.flush().catch(() => undefined);
          this.decoder.close();
        }
      } catch { /* already closed */ }
      this.decoder = null;
    }
  }

  feed(args: { bytes: Uint8Array; isKeyFrame: boolean }): void {
    const decoder = this.decoder;
    if (!decoder) return;

    let payload = args.bytes;
    if (args.isKeyFrame) {
      const { sps, pps, body } = extractParameterSets(args.bytes);
      if (sps) this.sps = sps;
      if (pps) this.pps = pps;
      payload = body;
      if (!this.configured && this.sps && this.pps) {
        try {
          const description = buildAvcCDescription(this.sps, this.pps);
          decoder.configure({
            codec: 'avc1.42E01E',
            description: description.buffer.slice(
              description.byteOffset,
              description.byteOffset + description.byteLength,
            ),
            optimizeForLatency: true,
            hardwareAcceleration: 'prefer-hardware',
          });
          this.configured = true;
          this.droppedKeyframeWait = false;
        } catch (e) {
          this.onConfigError?.(e instanceof Error ? e : new Error(String(e)));
          return;
        }
      }
    }

    if (!this.configured) {
      // Until we've seen a keyframe with SPS+PPS we can't initialise the
      // decoder — drop everything else.
      return;
    }
    if (this.droppedKeyframeWait && !args.isKeyFrame) return;

    try {
      const buf = new ArrayBuffer(payload.byteLength);
      new Uint8Array(buf).set(payload);
      const chunk = new EncodedVideoChunk({
        type: args.isKeyFrame ? 'key' : 'delta',
        timestamp: this.nextChunkTs,
        data: buf,
      });
      this.nextChunkTs += Math.floor(1_000_000 / 15); // matches sender pacing
      decoder.decode(chunk);
    } catch (e) {
      // Bad chunk — wait for next keyframe to recover.
      this.configured = false;
      this.droppedKeyframeWait = true;
      this.onConfigError?.(e instanceof Error ? e : new Error(String(e)));
    }
  }

  private renderFrame(frame: VideoFrame): void {
    const canvas = this.canvas;
    const ctx = this.ctx;
    if (!canvas || !ctx) {
      frame.close();
      return;
    }
    if (canvas.width !== frame.displayWidth || canvas.height !== frame.displayHeight) {
      canvas.width = frame.displayWidth;
      canvas.height = frame.displayHeight;
    }
    ctx.drawImage(frame, 0, 0, canvas.width, canvas.height);
    frame.close();
  }
}
