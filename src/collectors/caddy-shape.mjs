// Reads the route "shape" file that the Caddy host exports for the engine
// (deploy/caddy/). The engine never talks to Caddy's admin API and never
// sees its secrets. A stale, empty or unexpected file fails the run, so
// exposure becomes unknown instead of resting on old routes.
export const SHAPE_VERSION = 2;
const FUTURE_TOLERANCE_MS = 5 * 60_000;
const parseError = (message) => Object.assign(new Error(message), { code: "parse" });

export function validateShape(doc, { now, maxAgeMs }) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw parseError("Caddy shape is not an object");
  if (doc.version !== SHAPE_VERSION) throw parseError(`Caddy shape version ${doc.version ?? "missing"} (expected ${SHAPE_VERSION}); update the exporter on the Caddy host`);
  if (!Array.isArray(doc.servers)) throw parseError("Caddy shape has no servers list");
  const generatedAt = Number(doc.generatedAt) * 1000;
  if (!Number.isFinite(generatedAt)) throw parseError("Caddy shape has no generatedAt time");
  if (generatedAt > now + FUTURE_TOLERANCE_MS) throw parseError("Caddy shape is dated in the future (clock difference?)");
  if (now - generatedAt > maxAgeMs) throw parseError(`Caddy shape is ${Math.round((now - generatedAt) / 60_000)} min old (the exporter on the Caddy host has stopped?)`);
  if (!doc.servers.some((s) => Array.isArray(s?.routes) && s.routes.length > 0)) throw parseError("Caddy shape lists no routes");
  return { generatedAt, servers: doc.servers };
}

export async function collectCaddyShape({ http, cfg, now = Date.now }) {
  const doc = await http.fetchJson(cfg.url, { timeoutMs: 8000, maxBytes: 5_000_000 });
  const shape = validateShape(doc, { now: now(), maxAgeMs: cfg.maxAgeMinutes * 60_000 });
  return { evidence: [{ assetKey: cfg.assetKey, kind: "caddy.shape", value: { version: SHAPE_VERSION, ...shape }, collectedAt: shape.generatedAt }] };
}
