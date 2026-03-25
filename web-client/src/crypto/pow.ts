export interface PowResult {
  challenge: string;
  solution: string;
}

export function solvePowAsync(
  challenge: string,
  difficulty: number,
  onProgress?: (nonce: number) => void,
): Promise<PowResult> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(
      new URL('./pow.worker.ts', import.meta.url),
      { type: 'module' },
    );

    worker.onmessage = (e: MessageEvent<{ type: string; solution?: string; nonce?: number }>) => {
      if (e.data.type === 'solution' && e.data.solution) {
        worker.terminate();
        resolve({ challenge, solution: e.data.solution });
      } else if (e.data.type === 'progress' && onProgress && e.data.nonce !== undefined) {
        onProgress(e.data.nonce);
      }
    };

    worker.onerror = (err) => {
      worker.terminate();
      reject(new Error(`PoW worker error: ${err.message}`));
    };

    worker.postMessage({ challenge, difficulty });
  });
}
