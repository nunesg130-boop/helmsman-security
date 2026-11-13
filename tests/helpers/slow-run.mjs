// Test helper: begins a collector run, writes evidence inside an open
// transaction, then hangs so the parent can SIGKILL it mid-run.
import { openDb } from "../../src/db.mjs";
import { EvidenceStore } from "../../src/evidence.mjs";

const db = openDb(process.argv[2]);
const store = new EvidenceStore(db, "default");
const run = store.beginRun("proxmox", Date.now());
db.exec("BEGIN IMMEDIATE");
store.put(run, { assetKey: "pve:node:norco", kind: "pve.time", source: "proxmox", value: { offsetSeconds: 0 }, collectedAt: Date.now(), staleAfterMs: 60000 });
process.stdout.write("ready\n");
setInterval(() => {}, 1000);
