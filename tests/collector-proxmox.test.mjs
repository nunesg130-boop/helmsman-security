import test from "node:test";
import assert from "node:assert/strict";
import { collectProxmox, parseNet } from "../src/collectors/proxmox.mjs";
import { createHttp } from "../src/http.mjs";
import { startFixtureServer } from "./helpers/fixture-server.mjs";
import { proxmoxRoutes, T } from "./fixtures/proxmox-fixture.mjs";

const NOW = T * 1000;
async function collect(routes) {
  const srv = await startFixtureServer(routes);
  try {
    const out = await collectProxmox({
      http: createHttp({ allowHosts: ["127.0.0.1"] }),
      cfg: { baseUrl: srv.url, tokenId: "root@pam!helmsec", certSha256: srv.certSha256, backupStorage: "backups" },
      secret: "11111111-aaaa",
      now: () => NOW
    });
    return { out, srv };
  } finally { await srv.close(); }
}
const ev = (out, key, kind) => out.evidence.find((e) => e.assetKey === key && e.kind === kind)?.value;

test("parses MACs and static IPs from qemu and lxc net lines", () => {
  assert.deepEqual(parseNet({ net0: "virtio=BC:24:11:AA:00:01,bridge=vmbr0" }), { macs: ["BC:24:11:AA:00:01"], ips: [] });
  assert.deepEqual(parseNet({ net0: "name=eth0,hwaddr=BC:24:11:AA:00:02,ip=192.168.0.114/24", net1: "name=eth1,hwaddr=BC:24:11:AA:00:09,ip=dhcp" }), { macs: ["BC:24:11:AA:00:02", "BC:24:11:AA:00:09"], ips: ["192.168.0.114"] });
});

test("sends the API token header and only GETs", async () => {
  const { out, srv } = await collect(proxmoxRoutes());
  assert.ok(srv.requests.every((r) => r.method === "GET"));
  assert.equal(srv.requests[0].headers.authorization, "PVEAPIToken=root@pam!helmsec=11111111-aaaa");
  assert.deepEqual(out.inventory.nodes, [{ name: "norco", ip: "192.168.0.10" }, { name: "main", ip: "192.168.0.4" }]);
  assert.deepEqual(out.inventory.guests.find((g) => g.vmid === 114), { vmid: 114, type: "lxc", name: "ollama", node: "norco", macs: ["BC:24:11:AA:00:02"], ips: ["192.168.0.114"] });
});

test("backup coverage honours exclude", async () => {
  const { out } = await collect(proxmoxRoutes());
  assert.equal(ev(out, "pve:guest:114", "pve.backups").coveredByJob, false);
  assert.equal(ev(out, "pve:guest:109", "pve.backups").coveredByJob, true);
});

test("newest backup per vmid across nodes, and last task by vmid", async () => {
  const { out } = await collect(proxmoxRoutes());
  const b = ev(out, "pve:guest:109", "pve.backups");
  assert.equal(b.newestBackupAt, (T - 3600) * 1000);
  assert.deepEqual(b.lastTask, { status: "OK", endtime: (T - 3600) * 1000 });
  assert.equal(ev(out, "pve:guest:100", "pve.backups").lastTask.status, "job errors");
  assert.equal(ev(out, "pve:guest:114", "pve.backups").newestBackupAt, null);
});

test("offsetSeconds uses the request midpoint", async () => {
  const { out } = await collect(proxmoxRoutes());
  assert.equal(ev(out, "pve:node:norco", "pve.time").offsetSeconds, 0);
  assert.equal(ev(out, "pve:node:main", "pve.time").offsetSeconds, 7);
});

test("disks and storage land on node assets", async () => {
  const { out } = await collect(proxmoxRoutes());
  assert.equal(ev(out, "pve:node:norco", "pve.disks")[0].wearout, 97);
  assert.equal(ev(out, "pve:node:main", "pve.storage")[0].storage, "backups");
});

test("one node down yields a warning, not a failure", async () => {
  const { out } = await collect(proxmoxRoutes({ "/api2/json/nodes/main/time": () => [595, "no route"], "/api2/json/nodes/main/disks/list": () => [500, "x"] }));
  assert.ok(out.warnings.some((w) => /main/u.test(w)));
  assert.equal(ev(out, "pve:node:main", "pve.time"), undefined);
  assert.ok(ev(out, "pve:node:norco", "pve.time"));
});

test("offline node in cluster status is skipped with a warning", async () => {
  const routes = proxmoxRoutes();
  routes["/api2/json/cluster/status"].data[2].online = 0;
  const { out } = await collect(routes);
  assert.ok(out.warnings.some((w) => /main is offline/u.test(w)));
  assert.equal(ev(out, "pve:node:main", "pve.disks"), undefined);
});

test("401 fails the run with auth", async () => {
  await assert.rejects(collect(proxmoxRoutes({ "/api2/json/cluster/status": () => [401, {}] })), (e) => e.code === "auth");
});
