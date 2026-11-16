import test from "node:test";
import assert from "node:assert/strict";
import { startScheduler } from "../src/scheduler.mjs";

test("runs immediately and never overlaps a slow task", async () => {
  let running = 0;
  let maxRunning = 0;
  let runs = 0;
  const sched = startScheduler({
    tasks: [{ name: "slow", everyMs: 5, run: async () => { running += 1; maxRunning = Math.max(maxRunning, running); runs += 1; await new Promise((r) => setTimeout(r, 30)); running -= 1; } }]
  });
  await new Promise((r) => setTimeout(r, 120));
  await sched.stop();
  assert.ok(runs >= 2, `ran ${runs} times`);
  assert.equal(maxRunning, 1);
});

test("a throwing task is reported and keeps its schedule", async () => {
  const errors = [];
  let runs = 0;
  const sched = startScheduler({ tasks: [{ name: "bad", everyMs: 5, run: async () => { runs += 1; throw new Error("x"); } }], onError: (name, e) => errors.push([name, e.message]) });
  await new Promise((r) => setTimeout(r, 40));
  await sched.stop();
  assert.ok(runs >= 2);
  assert.deepEqual(errors[0], ["bad", "x"]);
});

test("stop waits for the in-flight run", async () => {
  let finished = false;
  const sched = startScheduler({ tasks: [{ name: "t", everyMs: 1000, run: async () => { await new Promise((r) => setTimeout(r, 30)); finished = true; } }] });
  await new Promise((r) => setTimeout(r, 5));
  await sched.stop();
  assert.equal(finished, true);
});

test("a run that reports failure is retried after retryMs, not a full interval", async () => {
  const delays = [];
  let runs = 0;
  const sched = startScheduler({
    tasks: [{ name: "vulns", everyMs: 3600_000, retryMs: 300_000, run: async () => { runs += 1; return { status: runs === 1 ? "failed" : "ok" }; } }],
    setTimer: (fn, ms) => { delays.push(ms); return 0; }, clearTimer: () => {}
  });
  await new Promise((r) => setTimeout(r, 10));
  await sched.stop();
  assert.deepEqual(delays, [300_000]);
});

test("a throwing run also uses retryMs; a task without retryMs keeps its interval", async () => {
  const delays = [];
  const sched = startScheduler({
    tasks: [
      { name: "a", everyMs: 1000, retryMs: 50, run: async () => { throw new Error("x"); } },
      { name: "b", everyMs: 1000, run: async () => ({ status: "failed" }) }
    ],
    onError: () => {}, setTimer: (fn, ms) => { delays.push(ms); return 0; }, clearTimer: () => {}
  });
  await new Promise((r) => setTimeout(r, 10));
  await sched.stop();
  assert.deepEqual(delays.sort((x, y) => x - y), [50, 1000]);
});
