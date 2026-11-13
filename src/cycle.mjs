import { runCollector } from "./collect.mjs";
import { linkAssets } from "./identity.mjs";
import { evaluateAll } from "./ledger.mjs";
import { threshold } from "./checks/thresholds.mjs";
import { INVENTORY_KEY } from "./checks/runner.mjs";

function staleAfterMs(config) {
  return threshold(config, "collectMinutes") * threshold(config, "staleFactor") * 60_000;
}

// One collection cycle: run each configured collector, keep each one's last
// successful inventory (so a failing collector doesn't make machines vanish;
// their evidence ages to unknown instead), link assets, evaluate every check
// and write the ledger.
export async function collectionCycle({ db, tenantId, store, holds, ledger, config, sources, now = Date.now, secrets = [] }) {
  const stale = staleAfterMs(config);
  const statuses = {};
  for (const [name, fn] of Object.entries(sources)) {
    const r = await runCollector(store, name, async () => {
      const out = await fn();
      const evidence = [...(out.evidence ?? [])];
      if (out.inventory) evidence.push({ assetKey: INVENTORY_KEY, kind: `inventory.${name}`, source: name, value: out.inventory });
      return { evidence: evidence.map((e) => ({ source: name, ...e })), warnings: out.warnings };
    }, { now, staleAfterMs: stale, secrets });
    statuses[name] = r.status;
  }

  const inv = (name) => store.get(INVENTORY_KEY, `inventory.${name}`)?.value ?? {};
  const manualLinks = db.prepare("SELECT asset_key, source, source_id FROM manual_links WHERE tenant_id = ?").all(tenantId)
    .map((r) => ({ assetKey: r.asset_key, source: r.source, sourceId: r.source_id }));
  const { assets } = linkAssets({
    nodes: inv("proxmox").nodes ?? [],
    guests: inv("proxmox").guests ?? [],
    agents: inv("wazuh").agents ?? [],
    dockerHosts: (config.docker ?? []).map((d) => ({ name: d.name, assetKey: d.assetKey })),
    manualLinks,
    classes: { roaming: config.assets?.roaming ?? [], appliances: config.assets?.appliances ?? [] }
  });
  for (const n of config.network ?? []) assets.push({ assetKey: `net:${n.name}`, name: n.name, class: "network", sources: { network: { ip: n.ip ?? null } } });

  const t = now();
  const upsert = db.prepare(
    `INSERT INTO assets (tenant_id, asset_key, class, name, sources_json, ambiguous_reason, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (tenant_id, asset_key) DO UPDATE SET class = excluded.class, name = excluded.name, sources_json = excluded.sources_json,
       ambiguous_reason = excluded.ambiguous_reason, last_seen_at = excluded.last_seen_at`
  );
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const a of assets) upsert.run(tenantId, a.assetKey, a.class, a.name, JSON.stringify(a.sources ?? {}), a.ambiguous ? a.ambiguousReason : null, t);
    db.exec("COMMIT");
  } catch (e) { db.exec("ROLLBACK"); throw e; }

  // Evaluate everything seen in the last 7 days: a machine that dropped out of
  // inventory stays visible (as unknown) until it's been gone a week.
  const known = db.prepare("SELECT asset_key, class, name, sources_json, ambiguous_reason FROM assets WHERE tenant_id = ?").all(tenantId).map((r) => ({
    assetKey: r.asset_key, class: r.class, name: r.name, sources: JSON.parse(r.sources_json),
    ...(r.ambiguous_reason ? { ambiguous: true, ambiguousReason: r.ambiguous_reason } : {})
  }));
  const rows = evaluateAll({ store, holds, assets: known, config, now: t });
  ledger.write(rows, t);
  return { collectors: statuses, assets: known.length, rows: rows.length };
}

export async function eolCycle({ store, config, now = Date.now, fetchEol }) {
  return runCollector(store, "eol", fetchEol, { now, staleAfterMs: threshold(config, "eolMaxAgeDays") * 86400_000 });
}
