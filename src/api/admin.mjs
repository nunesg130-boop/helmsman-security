import http from "node:http";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";

// Admin listener: holds, exclusions, manual links, credentials. Reached only
// through Caddy + Authentik. Connections from any IP other than the Caddy
// host are dropped before parsing; every request must carry the Authentik
// owner header; changes must be same-origin JSON.
const PAGE = readFileSync(new URL("./admin-page.html", import.meta.url), "utf8");
const MAX_BODY = 64 * 1024;
const SETTABLE = new Set(["proxmox.tokenSecret", "wazuh.password"]);

const stripV4Mapped = (ip) => String(ip ?? "").replace(/^::ffff:/u, "");

function send(res, status, body) {
  if (status === 204) { res.writeHead(204, { "cache-control": "no-store" }); return res.end(); }
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" });
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => { size += c.length; if (size > MAX_BODY) { reject(Object.assign(new Error("body too large"), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on("end", () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); }
      catch { reject(Object.assign(new Error("invalid JSON"), { status: 400 })); }
    });
  });
}

export function createAdminServer({ db, tenantId, holds, credentials, config, now = Date.now }) {
  const allowIp = config.listen.adminAllowIp;
  const owner = config.owner.authentikUser;
  const origin = config.owner.adminOrigin;

  async function handle(req, res) {
    if (req.headers["x-authentik-username"] !== owner) return send(res, 403, { error: "forbidden" });
    const url = new URL(req.url, "http://admin.local");
    const p = url.pathname;
    const mutating = req.method !== "GET";
    if (mutating) {
      if (!String(req.headers["content-type"] ?? "").startsWith("application/json") && req.method !== "DELETE") return send(res, 403, { error: "JSON required" });
      if (!origin || req.headers.origin !== origin) return send(res, 403, { error: "cross-origin request refused" });
    }

    if (req.method === "GET" && p === "/") {
      const nonce = randomBytes(16).toString("base64");
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer"
      });
      return res.end(PAGE.replaceAll("__NONCE__", nonce));
    }

    if (p === "/admin/holds" && req.method === "GET") return send(res, 200, { items: holds.list(now()) });
    if (p === "/admin/holds" && req.method === "POST") {
      const b = await readJson(req);
      try {
        const id = holds.add({ kind: b.kind, assetKey: b.assetKey, checkId: b.checkId ?? null, product: b.product ?? null, version: b.version ?? null, reason: b.reason, expiresAt: b.expiresAt ?? null }, now());
        return send(res, 201, { id });
      } catch (e) { return send(res, 400, { error: e.message }); }
    }
    const holdId = /^\/admin\/holds\/(\d+)$/u.exec(p);
    if (holdId && req.method === "DELETE") return send(res, holds.remove(Number(holdId[1])) ? 204 : 404, { error: "not found" });

    if (p === "/admin/credentials" && req.method === "GET") return send(res, 200, { items: credentials.list() });
    const cred = /^\/admin\/credentials\/([\w.]+)$/u.exec(p);
    if (cred && req.method === "PUT") {
      if (!SETTABLE.has(cred[1])) return send(res, 400, { error: "this credential can't be set here" });
      const b = await readJson(req);
      if (typeof b.value !== "string" || !b.value) return send(res, 400, { error: "value required" });
      credentials.set(cred[1], b.value, now());
      return send(res, 204);
    }

    if (p === "/admin/api-token/rotate" && req.method === "POST") {
      await readJson(req);
      const token = randomBytes(32).toString("base64url");
      credentials.set("api.readToken", token, now());
      return send(res, 200, { token });
    }

    if (p === "/admin/links" && req.method === "GET") {
      const items = db.prepare("SELECT asset_key, source, source_id FROM manual_links WHERE tenant_id = ? ORDER BY asset_key").all(tenantId)
        .map((r) => ({ assetKey: r.asset_key, source: r.source, sourceId: r.source_id }));
      return send(res, 200, { items });
    }
    if (p === "/admin/links" && req.method === "POST") {
      const b = await readJson(req);
      if (typeof b.assetKey !== "string" || !b.assetKey || b.source !== "wazuh" || typeof b.sourceId !== "string" || !b.sourceId) return send(res, 400, { error: "assetKey, source 'wazuh' and sourceId required" });
      db.prepare("INSERT INTO manual_links (tenant_id, asset_key, source, source_id) VALUES (?, ?, ?, ?) ON CONFLICT (tenant_id, source, source_id) DO UPDATE SET asset_key = excluded.asset_key")
        .run(tenantId, b.assetKey, b.source, b.sourceId);
      return send(res, 201, { ok: true });
    }
    if (p === "/admin/links" && req.method === "DELETE") {
      const n = db.prepare("DELETE FROM manual_links WHERE tenant_id = ? AND source = ? AND source_id = ?").run(tenantId, url.searchParams.get("source") ?? "", url.searchParams.get("sourceId") ?? "").changes;
      return send(res, n ? 204 : 404, { error: "not found" });
    }
    return send(res, 404, { error: "not found" });
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => send(res, e.status ?? 500, { error: e.status ? e.message : "internal error" }));
  });
  server.on("connection", (socket) => {
    if (stripV4Mapped(socket.remoteAddress) !== allowIp) socket.destroy();
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;

  return new Promise((resolve) => {
    server.listen(config.listen.adminPort, config.listen.adminHost, () => resolve({
      port: server.address().port,
      close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); })
    }));
  });
}
