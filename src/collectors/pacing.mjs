// Keeps a client under a requests-per-minute budget and retries HTTP 429
// ("too many requests") a bounded number of times.
export const RETRY_429_MS = Object.freeze([15_000, 30_000, 45_000]);
const realSleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function createPacer({ requestsPerMinute = 120, sleep = realSleep, now = Date.now } = {}) {
  const gapMs = requestsPerMinute > 0 ? 60_000 / requestsPerMinute : 0;
  let lastAt = -Infinity;
  return async function paced(fn) {
    for (let attempt = 0; ; attempt++) {
      if (gapMs) {
        const wait = lastAt + gapMs - now();
        if (wait > 0) await sleep(wait);
        lastAt = now();
      }
      try {
        return await fn();
      } catch (error) {
        if (error.status !== 429 || attempt >= RETRY_429_MS.length) throw error;
        await sleep(RETRY_429_MS[attempt]);
      }
    }
  };
}
