import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { randomBytes } from "node:crypto";
import { openDb } from "../src/db.mjs";
import { HoldStore } from "../src/holds.mjs";
import { CredentialStore, createSecretBox } from "../src/secrets.mjs";
import { createAdminServer } from "../src/api/admin.mjs";

const ORIGIN = "https://security.lan";
async function setup(allowIp = "127.0.0.1") {
  const db = openDb(":memory:");
  const holds = new HoldStore(db, "default");
  const credentials = new CredentialStore(db, "default", createSecretBox(randomBytes(32)));
  const config = { listen: { adminHost: "127.0.0.1", adminPort: 0, adminAllowIp: allowIp }, owner: { authentikUser: "owner", adminOrigin: ORIGIN } };
  const srv = await createAdminServer({ db, tenantId: "default", holds, credentials, config });
  return { srv, db, holds, credentials };
}

function req(port, path, { method = "GET", user = "owner", origin = ORIGIN, body, type = "application/json" } = {}) {
  return new Promise((resolve) => {
    const headers = {};
    if (user) headers["x-authentik-username"] = user;
    if (origin) headers.origin = origin;
    if (body !== undefined) headers["content-type"] = type;
    const r = http.request({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      let b = "";
      res.on("data", (d) => { b += d; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, text: b, body: (() => { try { return JSON.parse(b); } catch { return null; } })() }));
    });
    r.on("error", (e) => resolve({ status: 0, error: e.code }));
    if (body !== undefined) r.write(typeof body === "string" ? body : JSON.stringify(body));
    r.end();
  });
}

test("connection from another IP is dropped", async () => {
  const { srv } = await setup("10.9.9.9");
  try {
    const r = await req(srv.port, "/admin/holds");
    assert.equal(r.status, 0);
  } finally { await srv.close(); }
});

test("admin listener", async (t) => {
  const { srv, credentials } = await setup();
  t.after(() => srv.close());

  await t.test("missing Authentik header 403", async () => assert.equal((await req(srv.port, "/admin/holds", { user: null })).status, 403));
  await t.test("wrong user 403", async () => assert.equal((await req(srv.port, "/admin/holds", { user: "intruder" })).status, 403));
  await t.test("page served with a CSP", async () => {
    const r = await req(srv.port, "/");
    assert.equal(r.status, 200);
    assert.match(r.headers["content-security-policy"], /default-src 'none'/u);
    assert.match(r.text, /Helmsman Security/u);
  });
  await t.test("cross-origin POST 403", async () => {
    assert.equal((await req(srv.port, "/admin/holds", { method: "POST", origin: "https://evil.example", body: { kind: "exclusion", assetKey: "a", checkId: "c", reason: "r" } })).status, 403);
  });
  await t.test("non-JSON POST 403", async () => {
    assert.equal((await req(srv.port, "/admin/holds", { method: "POST", type: "text/plain", body: "{}" })).status, 403);
  });
  await t.test("holds add, list, delete", async () => {
    const add = await req(srv.port, "/admin/holds", { method: "POST", body: { kind: "exclusion", assetKey: "pve:guest:152", checkId: "backup_jobs", reason: "not needed" } });
    assert.equal(add.status, 201);
    assert.equal((await req(srv.port, "/admin/holds")).body.items.length, 1);
    assert.equal((await req(srv.port, `/admin/holds/${add.body.id}`, { method: "DELETE" })).status, 204);
    assert.equal((await req(srv.port, "/admin/holds")).body.items.length, 0);
  });
  await t.test("hold without reason is 400", async () => {
    assert.equal((await req(srv.port, "/admin/holds", { method: "POST", body: { kind: "exclusion", assetKey: "a", checkId: "c" } })).status, 400);
  });
  await t.test("credential value is write-only", async () => {
    assert.equal((await req(srv.port, "/admin/credentials/wazuh.password", { method: "PUT", body: { value: "pw-xyz" } })).status, 204);
    const list = await req(srv.port, "/admin/credentials");
    assert.deepEqual(list.body.items.map((c) => c.name), ["wazuh.password"]);
    assert.ok(!list.text.includes("pw-xyz"));
    assert.equal(credentials.get("wazuh.password"), "pw-xyz");
    assert.equal((await req(srv.port, "/admin/credentials/wazuh.password")).status, 404);
  });
  await t.test("the API token can't be set directly", async () => {
    assert.equal((await req(srv.port, "/admin/credentials/api.readToken", { method: "PUT", body: { value: "mine" } })).status, 400);
  });
  await t.test("token rotate returns the token once and replaces the old one", async () => {
    credentials.set("api.readToken", "old-token", 1);
    const r = await req(srv.port, "/admin/api-token/rotate", { method: "POST", body: {} });
    assert.equal(r.status, 200);
    assert.ok(r.body.token.length >= 40);
    assert.equal(credentials.get("api.readToken"), r.body.token);
    assert.ok(!(await req(srv.port, "/admin/credentials")).text.includes(r.body.token));
  });
  await t.test("manual links add, list, delete", async () => {
    assert.equal((await req(srv.port, "/admin/links", { method: "POST", body: { assetKey: "pve:guest:109", source: "wazuh", sourceId: "007" } })).status, 201);
    assert.deepEqual((await req(srv.port, "/admin/links")).body.items, [{ assetKey: "pve:guest:109", source: "wazuh", sourceId: "007" }]);
    assert.equal((await req(srv.port, "/admin/links?source=wazuh&sourceId=007", { method: "DELETE" })).status, 204);
    assert.equal((await req(srv.port, "/admin/links")).body.items.length, 0);
  });
});
