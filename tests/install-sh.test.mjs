import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// The installer runs as root over a folder the scanner user can write in.
// It must never follow a link the scanner could have planted there.
const script = readFileSync(new URL("../deploy/grype/install.sh", import.meta.url), "utf8");

test("the state folder is owned by root, so the scanner can't swap its subfolders", () => {
  assert.match(script, /install -d -m 0755 -o root -g "\$ENGINE_GROUP" "\$STATE"/u);
});
test("the request folder is root-owned and only the engine's group can write it", () => {
  assert.match(script, /install -d -m 2775 -o root -g "\$ENGINE_GROUP" "\$STATE\/spool"/u);
});
test("every folder is checked for a symbolic link before it is created or changed", () => {
  assert.match(script, /refuse_link\(\)/u);
  for (const d of ["\"$STATE\"", "\"$STATE/spool\"", "\"$STATE/out\"", "\"$STATE/db\"", "\"$STATE/tmp\"", "\"$STATE/home\""]) {
    assert.ok(script.includes(`refuse_link ${d}`), d);
  }
  const firstInstall = script.indexOf('install -d -m 0755 -o root -g "$ENGINE_GROUP" "$STATE"');
  assert.ok(script.indexOf("refuse_link \"$STATE\"") < firstInstall, "checked before use");
});
test("the scanner gets its own home folder", () => assert.match(script, /"\$STATE\/home"/u));
