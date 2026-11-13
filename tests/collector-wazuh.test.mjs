import test from "node:test";
import assert from "node:assert/strict";
import { createWazuh414 } from "../src/collectors/wazuh414.mjs";
import { collectWazuh } from "../src/collectors/wazuh.mjs";
import { createHttp } from "../src/http.mjs";
import { startFixtureServer } from "./helpers/fixture-server.mjs";
import { wazuhRoutes, page } from "./fixtures/wazuh-fixture.mjs";

const NOW = Date.parse("2026-11-12T12:00:00Z");
async function withAdapter(routes, fn) {
  const srv = await startFixtureServer(routes);
  try {
    const adapter = createWazuh414({ http: createHttp({ allowHosts: ["127.0.0.1"] }), baseUrl: srv.url, user: "helmsec", password: "pw-secret", certSha256: srv.certSha256 });
    return await fn(adapter, srv);
  } finally { await srv.close(); }
}
const ev = (out, key, kind) => out.evidence.find((e) => e.assetKey === key && e.kind === kind);

test("logs in with basic auth and sends the bearer token", async () => {
  await withAdapter(wazuhRoutes(), async (a, srv) => {
    await a.listAgents();
    const login = srv.requests[0];
    assert.equal(login.method, "POST");
    assert.equal(login.headers.authorization, `Basic ${Buffer.from("helmsec:pw-secret").toString("base64")}`);
    assert.equal(srv.requests[1].headers.authorization, "Bearer jwt-1");
  });
});

test("re-authenticates once on 401", async () => {
  let calls = 0;
  const routes = wazuhRoutes({ "/agents": () => (++calls === 1 ? [401, {}] : [200, page([{ id: "001", name: "norco", status: "active" }])]) });
  await withAdapter(routes, async (a, srv) => {
    const agents = await a.listAgents();
    assert.equal(agents.length, 1);
    assert.equal(srv.requests.filter((r) => r.method === "POST").length, 2);
  });
});

test("a second 401 fails with auth", async () => {
  await withAdapter(wazuhRoutes({ "/agents": () => [401, {}] }), async (a) => {
    await assert.rejects(a.listAgents(), (e) => e.code === "auth");
  });
});

test("pages agents until total", async () => {
  const routes = wazuhRoutes({
    "GET /agents?limit=500&offset=0": page([{ id: "001", name: "a", status: "active" }], 2),
    "GET /agents?limit=500&offset=500": page([{ id: "002", name: "b", status: "active" }], 2)
  });
  await withAdapter(routes, async (a) => assert.deepEqual((await a.listAgents()).map((x) => x.id), ["001", "002"]));
});

test("normalizes agents; the manager's 9999 keepalive becomes null", async () => {
  await withAdapter(wazuhRoutes(), async (a) => {
    const agents = await a.listAgents();
    assert.deepEqual(agents.find((x) => x.id === "000"), { id: "000", name: "wazuh", ip: "127.0.0.1", status: "active", lastKeepAlive: null });
    assert.equal(agents.find((x) => x.id === "001").lastKeepAlive, Date.parse("2026-11-12T11:55:00+00:00"));
  });
});

test("os, packages, ports and netiface are normalized", async () => {
  await withAdapter(wazuhRoutes(), async (a) => {
    assert.deepEqual(await a.os("001"), { platform: "debian", name: "Debian GNU/Linux", version: "12 (bookworm)", major: "12", minor: "8", kernelRelease: "6.8.12-4-pve" });
    assert.equal((await a.packages("001")).scanned, true);
    assert.deepEqual((await a.ports("001"))[0], { protocol: "tcp", localIp: "0.0.0.0", localPort: 8006, process: "pveproxy", pid: 1234 });
    assert.deepEqual(await a.netiface("001"), { macs: ["aa:bb:cc:dd:ee:01"] });
  });
});

test("empty package list is scanned:false", async () => {
  await withAdapter(wazuhRoutes(), async (a) => assert.deepEqual(await a.packages("000"), { items: [], scanned: false }));
});

test("collectWazuh writes agent evidence and inventory, skipping never_connected inventory", async () => {
  await withAdapter(wazuhRoutes(), async (a) => {
    const out = await collectWazuh({ adapter: a, now: () => NOW });
    assert.equal(ev(out, "wazuh:agent:001", "wazuh.agent").value.status, "active");
    assert.ok(ev(out, "wazuh:agent:001", "wazuh.packages"));
    assert.ok(ev(out, "wazuh:agent:011", "wazuh.agent"));
    assert.equal(ev(out, "wazuh:agent:011", "wazuh.packages"), undefined);
    assert.deepEqual(out.inventory.agents.find((x) => x.id === "001").macs, ["aa:bb:cc:dd:ee:01"]);
  });
});

test("inventory from a disconnected agent is dated at its last keepalive, not now", async () => {
  await withAdapter(wazuhRoutes(), async (a) => {
    const out = await collectWazuh({ adapter: a, now: () => NOW });
    assert.equal(ev(out, "wazuh:agent:010", "wazuh.agent").collectedAt, NOW);
    assert.equal(ev(out, "wazuh:agent:010", "wazuh.packages").collectedAt, Date.parse("2026-11-10T08:00:00+00:00"));
    assert.equal(ev(out, "wazuh:agent:001", "wazuh.packages").collectedAt, NOW);
  });
});

test("per-agent syscollector failure is a warning", async () => {
  await withAdapter(wazuhRoutes({ "/syscollector/001/packages": () => [500, {}] }), async (a) => {
    const out = await collectWazuh({ adapter: a, now: () => NOW });
    assert.ok(out.warnings.some((w) => /agent 001/u.test(w)));
    assert.ok(ev(out, "wazuh:agent:001", "wazuh.agent"));
    assert.equal(ev(out, "wazuh:agent:001", "wazuh.packages"), undefined);
  });
});
