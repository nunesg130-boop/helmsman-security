// Syntax-check every .mjs file with `node --check`. No dependencies.
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const roots = ["src", "scripts", "tests"];
const files = [];
function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (p.endsWith(".mjs")) files.push(p);
  }
}
for (const r of roots) walk(r);
let failed = 0;
for (const f of files) {
  const r = spawnSync(process.execPath, ["--check", f], { encoding: "utf8" });
  if (r.status !== 0) { failed += 1; process.stderr.write(r.stderr); }
}
console.log(`lint: ${files.length - failed}/${files.length} files ok`);
process.exit(failed ? 1 : 0);
