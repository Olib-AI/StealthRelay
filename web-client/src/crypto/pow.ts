export interface PowResult {
  challenge: string;
  solution: string;
}

export function solvePowAsync(
  challenge: string,
  difficulty: number,
  onProgress?: (nonce: number) => void,
  timeBudgetMs?: number,
): Promise<PowResult> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(
      new URL('./pow.worker.ts', import.meta.url),
      { type: 'module' },
    );

    const timer = timeBudgetMs === undefined ? null : setTimeout(() => {
      worker.terminate();
      reject(new Error('Solving the relay server\'s challenge took too long.'));
    }, timeBudgetMs);
    const finished = () => { if (timer !== null) clearTimeout(timer); };

    worker.onmessage = (e: MessageEvent<{ type: string; solution?: string; nonce?: number }>) => {
      if (e.data.type === 'solution' && e.data.solution) {
        finished();
        worker.terminate();
        resolve({ challenge, solution: e.data.solution });
      } else if (e.data.type === 'progress' && onProgress && e.data.nonce !== undefined) {
        onProgress(e.data.nonce);
      }
    };

    worker.onerror = (err) => {
      finished();
      worker.terminate();
      reject(new Error(`PoW worker error: ${err.message}`));
    };

    worker.postMessage({ challenge, difficulty });
  });
}
