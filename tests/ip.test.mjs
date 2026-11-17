import test from "node:test";
import assert from "node:assert/strict";
import { parseV4, inRange, inRanges, isPrivate, isPrivateRange, PUBLIC_VISITOR } from "../src/exposure/ip.mjs";

test("addresses and ranges parse; bad ones are rejected", () => {
  assert.equal(parseV4("192.168.0.1"), 0xc0a80001);
  for (const bad of ["192.168.0.256", "1.2.3", "::1", "", null]) assert.equal(parseV4(bad), null);
});
test("range membership", () => {
  assert.ok(inRange("192.168.0.116", "192.168.0.0/24"));
  assert.ok(inRange("192.168.0.116", "192.168.0.116"));
  assert.ok(!inRange("192.168.1.116", "192.168.0.0/24"));
  assert.ok(inRange("8.8.8.8", "0.0.0.0/0"));
  assert.ok(!inRange("192.168.0.1", "fd00::/8"));
  assert.ok(inRanges("10.1.2.3", ["192.168.0.0/16", "10.0.0.0/8"]));
});
test("private space", () => {
  assert.deepEqual(["192.168.0.108", "10.0.0.1", "172.16.5.5", "172.32.0.1", "8.8.8.8", PUBLIC_VISITOR].map(isPrivate), [true, true, true, false, false, false]);
  assert.deepEqual(["192.168.0.0/24", "192.168.0.108/32", "0.0.0.0/0", "192.0.0.0/8", "10.0.0.0/7", "junk"].map(isPrivateRange), [true, true, false, false, false, false]);
});
