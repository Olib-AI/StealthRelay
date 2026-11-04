export interface PowResult {
  challenge: string;
  solution: string;
}

export interface PowTask {
  result: Promise<PowResult>;
  /** Stops the worker. `result` rejects, so nothing is left running or waiting. */
  cancel: () => void;
}

export function solvePowAsync(
  challenge: string,
  difficulty: number,
  onProgress?: (nonce: number) => void,
  timeBudgetMs?: number,
): PowTask {
  let cancel: () => void = () => {};
  const result = new Promise<PowResult>((resolve, reject) => {
    const worker = new Worker(
      new URL('./pow.worker.ts', import.meta.url),
      { type: 'module' },
    );
    let timer: ReturnType<typeof setTimeout> | null = null;
    const stop = () => {
      if (timer !== null) clearTimeout(timer);
      worker.terminate();
    };
    cancel = () => {
      stop();
      reject(new Error('Cancelled.'));
    };
    if (timeBudgetMs !== undefined) {
      timer = setTimeout(() => {
        stop();
        reject(new Error('Solving the relay server\'s challenge took too long.'));
      }, timeBudgetMs);
    }

    worker.onmessage = (e: MessageEvent<{ type: string; solution?: string; nonce?: number }>) => {
      if (e.data.type === 'solution' && e.data.solution) {
        stop();
        resolve({ challenge, solution: e.data.solution });
      } else if (e.data.type === 'progress' && onProgress && e.data.nonce !== undefined) {
        onProgress(e.data.nonce);
      }
    };

    worker.onerror = (err) => {
      stop();
      reject(new Error(`PoW worker error: ${err.message}`));
    };

    worker.postMessage({ challenge, difficulty });
  });
  return { result, cancel };
}
