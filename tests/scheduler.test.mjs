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
