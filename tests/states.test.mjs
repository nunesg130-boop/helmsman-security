import test from "node:test";
import assert from "node:assert/strict";
import { STATES, result } from "../src/states.mjs";

test("STATES are exactly the five states", () => {
  assert.deepEqual([...STATES], ["ok", "issue", "unknown", "not_applicable", "excluded"]);
  assert.ok(Object.isFrozen(STATES));
});
test("result rejects states outside STATES", () => assert.throws(() => result("green", "x"), TypeError));
test("result requires a reason", () => assert.throws(() => result("ok", ""), TypeError));
test("result carries evidence and extra fields", () => {
  const r = result("unknown", "away", [], { roaming: true });
  assert.deepEqual(r, { state: "unknown", reason: "away", evidence: [], roaming: true });
});
