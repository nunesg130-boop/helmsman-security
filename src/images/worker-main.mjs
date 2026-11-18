// Entry point for the hs-grype service (run by systemd as user hs-grype).
// Reads only the root-owned install record and its own state directory.
import { readFileSync } from "node:fs";
import { createWorker } from "./worker.mjs";

const LIB = process.env.HS_GRYPE_LIB ?? "/usr/local/lib/hs-grype";
const STATE = process.env.HS_GRYPE_STATE ?? "/var/lib/hs-grype";
const INTERVAL_MS = 60_000;
const log = (m) => console.log(`[hs-grype] ${m}`);

const installed = JSON.parse(readFileSync(`${LIB}/installed.json`, "utf8"));
const worker = createWorker({ binDir: `${LIB}/bin`, stateDir: STATE, installed, log });
await worker.start();
log(`started: grype ${installed.grype.version}, syft ${installed.syft.version}`);

let stopping = false;
let busy = Promise.resolve();
const loop = async () => {
  while (!stopping) {
    busy = worker.tick().catch((e) => log(`tick failed: ${e.message}`));
    await busy;
    await new Promise((r) => setTimeout(r, INTERVAL_MS).unref());
  }
};
const stop = async () => { stopping = true; await busy; await worker.stop(); process.exit(0); };
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
loop();
