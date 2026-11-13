import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "../src/db.mjs";
import { EvidenceStore } from "../src/evidence.mjs";

test("power loss mid-run leaves no evidence and an interrupted run", async () => {
  const file = join(mkdtempSync(join(tmpdir(), "hs-pl-")), "e.db");
  openDb(file).close();
  const child = spawn(process.execPath, ["--no-warnings", "tests/helpers/slow-run.mjs", file], { stdio: ["ignore", "pipe", "inherit"] });
  await new Promise((resolve, reject) => {
    child.stdout.on("data", (d) => { if (String(d).includes("ready")) resolve(); });
    child.on("exit", () => reject(new Error("child exited early")));
  });
  child.kill("SIGKILL");
  await new Promise((r) => child.once("exit", r));
  const store = new EvidenceStore(openDb(file), "default");
  assert.equal(store.failOpenRuns(Date.now()), 1);
  assert.equal(store.get("pve:node:norco", "pve.time"), null);
});
