// Audio worklet that batches 128-sample input chunks into 320-sample frames
// (20 ms at 16 kHz, mono Float32). Posts each frame as a transferable
// ArrayBuffer to the main thread.
//
// This file is loaded as a module via `audioContext.audioWorklet.addModule`
// — see `audio-capture.ts` for the build pipeline.

/// <reference lib="webworker" />

type WorkletMessage = { type: 'frame'; samples: Float32Array };

declare const sampleRate: number;
declare class AudioWorkletProcessor {
  readonly port: MessagePort;
}
declare function registerProcessor(
  name: string,
  ctor: new () => AudioWorkletProcessor & {
    process(
      inputs: Float32Array[][],
      outputs: Float32Array[][],
      parameters: Record<string, Float32Array>,
    ): boolean;
  },
): void;

const FRAME_SIZE = 320;

class FrameBatcher extends AudioWorkletProcessor {
  private buffer = new Float32Array(FRAME_SIZE);
  private filled = 0;

  process(inputs: Float32Array[][]): boolean {
    const input = inputs[0];
    if (!input || !input[0]) return true;
    const channel = input[0];
    let off = 0;
    while (off < channel.length) {
      const take = Math.min(FRAME_SIZE - this.filled, channel.length - off);
      this.buffer.set(channel.subarray(off, off + take), this.filled);
      this.filled += take;
      off += take;
      if (this.filled === FRAME_SIZE) {
        const out = new Float32Array(FRAME_SIZE);
        out.set(this.buffer);
        const msg: WorkletMessage = { type: 'frame', samples: out };
        this.port.postMessage(msg, [out.buffer]);
        this.filled = 0;
      }
    }
    void sampleRate;
    return true;
  }
}

registerProcessor('frame-batcher', FrameBatcher);
