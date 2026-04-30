// Microphone capture → 20 ms / 16 kHz / mono / Float32 frames.
// Each frame's bytes are exactly what iOS `AudioCallService` puts on the
// wire (raw Float32 little-endian, 1280 bytes per frame).

import { AUDIO } from './types.ts';

import workletURL from './audio-worklet-processor.ts?worker&url';

export type CaptureFrame = Float32Array;

export type StartCaptureOptions = {
  onFrame: (frame: CaptureFrame) => void;
  onError?: (error: Error) => void;
};

export type AudioCapture = {
  stop(): Promise<void>;
  setMuted(muted: boolean): void;
  isMuted(): boolean;
};

export async function startAudioCapture(opts: StartCaptureOptions): Promise<AudioCapture> {
  const stream = await navigator.mediaDevices.getUserMedia({
    audio: {
      channelCount: AUDIO.channels,
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true,
      sampleRate: AUDIO.sampleRate,
    },
    video: false,
  });

  // AudioContext at 16 kHz forces the source node to resample for us.
  const ctx = new AudioContext({ sampleRate: AUDIO.sampleRate });
  if (ctx.state === 'suspended') {
    await ctx.resume();
  }
  await ctx.audioWorklet.addModule(workletURL);

  const source = ctx.createMediaStreamSource(stream);
  const node = new AudioWorkletNode(ctx, 'frame-batcher', {
    numberOfInputs: 1,
    numberOfOutputs: 0,
    channelCount: 1,
    channelCountMode: 'explicit',
    channelInterpretation: 'speakers',
  });

  let muted = false;
  const silence = new Float32Array(AUDIO.samplesPerFrame);

  node.port.onmessage = (ev: MessageEvent<{ type: 'frame'; samples: Float32Array }>) => {
    if (ev.data?.type !== 'frame') return;
    if (muted) {
      opts.onFrame(silence);
    } else {
      opts.onFrame(ev.data.samples);
    }
  };

  source.connect(node);

  return {
    async stop() {
      try {
        node.port.onmessage = null;
        node.disconnect();
        source.disconnect();
        for (const track of stream.getTracks()) track.stop();
        await ctx.close();
      } catch (e) {
        opts.onError?.(e instanceof Error ? e : new Error(String(e)));
      }
    },
    setMuted(v: boolean) {
      muted = v;
    },
    isMuted() {
      return muted;
    },
  };
}
