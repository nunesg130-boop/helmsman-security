// Each task runs immediately, then again `everyMs` after it finishes, so a
// slow run never overlaps itself. stop() waits for in-flight runs.
export function startScheduler({ tasks, onError = (name, e) => console.error(`[scheduler] ${name}: ${e.message}`), setTimer = setTimeout, clearTimer = clearTimeout }) {
  let stopped = false;
  const timers = new Map();
  const inflight = new Set();

  function schedule(task, delay) {
    if (stopped) return;
    timers.set(task.name, setTimer(() => tick(task), delay));
  }

  function tick(task) {
    if (stopped) return;
    const p = (async () => {
      try { await task.run(); } catch (e) { onError(task.name, e); }
    })();
    inflight.add(p);
    p.finally(() => { inflight.delete(p); schedule(task, task.everyMs); });
  }

  for (const t of tasks) tick(t);

  return {
    async stop() {
      stopped = true;
      for (const t of timers.values()) clearTimer(t);
      await Promise.allSettled([...inflight]);
    }
  };
}
