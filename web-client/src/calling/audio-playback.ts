// Decoded-audio jitter buffer + scheduler.
// Holds incoming Float32 frames keyed by sequence, waits for an adaptive
// minimum depth (default 3 frames = 60 ms), then schedules them onto an
// AudioContext at consecutive playback times. Mirrors the policy of
// LocalPackages/PoolChat/Sources/Calling/Services/AudioCallService.swift.

import { AUDIO } from './types.ts';

const TARGET_DEPTH_DEFAULT = 3;
const MAX_DEPTH = 10;

type Pending = {
  sequence: number;
  samples: Float32Array;
};

export class AudioPlayback {
  private ctx: AudioContext | null = null;
  private destination: GainNode | null = null;
  private streamDest: MediaStreamAudioDestinationNode | null = null;
  private audioEl: HTMLAudioElement | null = null;
  private keepAliveOsc: OscillatorNode | null = null;
  private keepAliveGain: GainNode | null = null;
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

    // Single output path: MediaStreamAudioDestinationNode → hidden
    // <audio playsinline> element. Connecting `ctx.destination` in
    // parallel doubles loudness AND defeats browser-level echo
    // cancellation — `getUserMedia({ echoCancellation: true })` can only
    // cancel audio it sees through media elements, not raw
    // AudioContext.destination output. Routing through <audio> alone:
    //   - bypasses the iOS ringer/silent switch (audio elements ignore it)
    //   - lets the browser's AEC match outgoing audio against the mic
    //     stream and subtract it, killing the round-trip echo where iOS's
    //     mic picks up the web client's speaker output.
    this.streamDest = this.ctx.createMediaStreamDestination();
    this.destination.connect(this.streamDest);
    const el = document.createElement('audio');
    el.autoplay = true;
    el.setAttribute('playsinline', 'true');
    el.setAttribute('webkit-playsinline', 'true');
    el.muted = false;
    el.volume = 1;
    el.style.position = 'fixed';
    el.style.left = '-9999px';
    el.style.width = '1px';
    el.style.height = '1px';
    el.style.opacity = '0';
    el.style.pointerEvents = 'none';
    document.body.appendChild(el);
    el.srcObject = this.streamDest.stream;
    this.audioEl = el;
    try { await el.play(); } catch { /* will retry on next user gesture */ }

    // Silent-buffer primer fully unlocks the audio graph on iOS Safari.
    const primer = this.ctx.createBuffer(1, 1, AUDIO.sampleRate);
    const primerSrc = this.ctx.createBufferSource();
    primerSrc.buffer = primer;
    primerSrc.connect(this.destination);
    primerSrc.start(0);

    // Keep-alive: a constant-running silent oscillator stops Safari iOS
    // from auto-suspending the AudioContext when there's a brief gap with
    // no active sources. Gain is 0 so it's inaudible, but the audio graph
    // stays "live" and `ctx.state` remains 'running'.
    const keepAliveOsc = this.ctx.createOscillator();
    const keepAliveGain = this.ctx.createGain();
    keepAliveGain.gain.value = 0;
    keepAliveOsc.connect(keepAliveGain);
    keepAliveGain.connect(this.destination);
    keepAliveOsc.start(0);
    this.keepAliveOsc = keepAliveOsc;
    this.keepAliveGain = keepAliveGain;

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
    if (this.keepAliveOsc) {
      try { this.keepAliveOsc.stop(); } catch { /* already stopped */ }
      try { this.keepAliveOsc.disconnect(); } catch { /* already disconnected */ }
      this.keepAliveOsc = null;
    }
    if (this.keepAliveGain) {
      try { this.keepAliveGain.disconnect(); } catch { /* already disconnected */ }
      this.keepAliveGain = null;
    }
    if (this.audioEl) {
      try { this.audioEl.pause(); } catch { /* already paused */ }
      this.audioEl.srcObject = null;
      try { this.audioEl.remove(); } catch { /* already detached */ }
      this.audioEl = null;
    }
    if (this.streamDest) {
      try { this.streamDest.disconnect(); } catch { /* already disconnected */ }
      this.streamDest = null;
    }
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
    // Drain immediately so we don't depend on the 20 ms interval timer
    // catching up — iOS variable buffer sizes (1360-sample/85 ms chunks)
    // would otherwise drift further behind real time on every tick.
    this.drain();
  }

  private drain(): void {
    if (!this.ctx || !this.destination) return;
    // Safari iOS sometimes slips the context back to 'suspended' after a
    // background tab tick or a memory event. Resume opportunistically.
    if (this.ctx.state === 'suspended') {
      void this.ctx.resume().catch(() => undefined);
    }
    if (this.audioEl && this.audioEl.paused) {
      void this.audioEl.play().catch(() => undefined);
    }
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
    // Schedule duration from the actual sample count, not a fixed 20 ms —
    // iOS taps deliver variable buffer sizes (e.g. 1360 samples ≈ 85 ms)
    // rather than always 320 samples.
    this.nextScheduledAt += next.samples.length / AUDIO.sampleRate;
  }

  setVolume(v: number): void {
    if (this.destination) this.destination.gain.value = v;
  }
}
