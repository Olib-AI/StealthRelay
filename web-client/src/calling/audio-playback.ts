// Decoded-audio jitter buffer + scheduler.
// Holds incoming Float32 frames keyed by sequence, waits for an adaptive
// minimum depth (default 3 frames = 60 ms), then schedules them onto an
// AudioContext at consecutive playback times. Mirrors the policy of
// LocalPackages/PoolChat/Sources/Calling/Services/AudioCallService.swift.

import { AUDIO } from './types.ts';

const FRAME_DURATION_S = AUDIO.frameMs / 1000;
const TARGET_DEPTH_DEFAULT = 3;
const MAX_DEPTH = 10;

type Pending = {
  sequence: number;
  samples: Float32Array;
};

export class AudioPlayback {
  private ctx: AudioContext | null = null;
  private destination: GainNode | null = null;
  private buffer: Pending[] = [];
  private nextScheduledAt = 0;
  private lastPlayedSequence: number | null = null;
  private targetDepth = TARGET_DEPTH_DEFAULT;
  private dropouts = 0;
  private timer: number | null = null;
  private readonly tickMs = AUDIO.frameMs;

  async start(): Promise<void> {
    if (this.ctx) return;
    this.ctx = new AudioContext({ sampleRate: AUDIO.sampleRate });
    if (this.ctx.state === 'suspended') {
      await this.ctx.resume();
    }
    this.destination = this.ctx.createGain();
    this.destination.gain.value = 1;
    this.destination.connect(this.ctx.destination);
    this.nextScheduledAt = this.ctx.currentTime + 0.05;
    this.timer = window.setInterval(() => this.drain(), this.tickMs);
  }

  async stop(): Promise<void> {
    if (this.timer !== null) {
      window.clearInterval(this.timer);
      this.timer = null;
    }
    this.buffer = [];
    this.lastPlayedSequence = null;
    this.dropouts = 0;
    this.targetDepth = TARGET_DEPTH_DEFAULT;
    if (this.destination) {
      try { this.destination.disconnect(); } catch { /* already disconnected */ }
      this.destination = null;
    }
    if (this.ctx) {
      try { await this.ctx.close(); } catch { /* already closed */ }
      this.ctx = null;
    }
  }

  push(sequence: number, samples: Float32Array): void {
    if (this.lastPlayedSequence !== null && sequence <= this.lastPlayedSequence) {
      // Late-arriving — drop.
      return;
    }
    // Insert sorted by sequence.
    const idx = this.buffer.findIndex((p) => p.sequence > sequence);
    const entry: Pending = { sequence, samples };
    if (idx === -1) this.buffer.push(entry);
    else this.buffer.splice(idx, 0, entry);

    while (this.buffer.length > MAX_DEPTH) {
      // Drop oldest if buffer overflows (possible on bursty packet arrivals).
      this.buffer.shift();
    }
  }

  private drain(): void {
    if (!this.ctx || !this.destination) return;
    if (this.buffer.length < this.targetDepth) return;

    // Slip schedule forward if we've fallen behind real time.
    if (this.nextScheduledAt < this.ctx.currentTime) {
      this.nextScheduledAt = this.ctx.currentTime + 0.01;
    }

    const next = this.buffer.shift();
    if (!next) return;

    if (this.lastPlayedSequence !== null && next.sequence !== this.lastPlayedSequence + 1) {
      // Gap detected — count for adaptive depth.
      this.dropouts++;
      if (this.dropouts > 3 && this.targetDepth < MAX_DEPTH - 1) {
        this.targetDepth++;
        this.dropouts = 0;
      }
    }
    this.lastPlayedSequence = next.sequence;

    const audioBuffer = this.ctx.createBuffer(1, next.samples.length, AUDIO.sampleRate);
    // Reify into a fresh ArrayBuffer-backed Float32Array to satisfy the
    // strict ArrayBuffer (vs SharedArrayBuffer) typing in copyToChannel.
    const reified = new Float32Array(next.samples.length);
    reified.set(next.samples);
    audioBuffer.copyToChannel(reified, 0);
    const src = this.ctx.createBufferSource();
    src.buffer = audioBuffer;
    src.connect(this.destination);
    src.start(this.nextScheduledAt);
    this.nextScheduledAt += FRAME_DURATION_S;
  }

  setVolume(v: number): void {
    if (this.destination) this.destination.gain.value = v;
  }
}
