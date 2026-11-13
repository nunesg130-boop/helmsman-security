import test from "node:test";
import assert from "node:assert/strict";
import { compareVersions } from "../src/version.mjs";

test("compareVersions orders numeric segments", () => {
  assert.equal(compareVersions("6.8.12-4-pve", "6.8.12-10-pve"), -1);
  assert.equal(compareVersions("6.11.4-301.fc41", "6.11.4-301.fc41"), 0);
  assert.equal(compareVersions("1:2.3", "2.4"), 1);
  assert.equal(compareVersions("10.0", "9.9"), 1);
});
