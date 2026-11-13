import test from "node:test";
import assert from "node:assert/strict";
import { createHttp, CollectorError, redact } from "../src/http.mjs";
import { startFixtureServer } from "./helpers/fixture-server.mjs";

test("pinned cert accepted", async () => {
  const srv = await startFixtureServer({ "/x": { ok: 1 } });
  try {
    const http = createHttp({ allowHosts: ["127.0.0.1"] });
    assert.deepEqual(await http.fetchJson(`${srv.url}/x`, { certSha256: srv.certSha256 }), { ok: 1 });
  } finally { await srv.close(); }
});

test("wrong pin rejected with tls before any request is sent", async () => {
  const srv = await startFixtureServer({ "/x": { ok: 1 } });
  try {
    const http = createHttp({ allowHosts: ["127.0.0.1"] });
    await assert.rejects(http.fetchJson(`${srv.url}/x`, { certSha256: "00".repeat(32), headers: { authorization: "Bearer s3cret" } }), (e) => e instanceof CollectorError && e.code === "tls");
    assert.equal(srv.requests.length, 0);
  } finally { await srv.close(); }
});

test("self-signed cert without a pin is rejected", async () => {
  const srv = await startFixtureServer({ "/x": { ok: 1 } });
  try {
    await assert.rejects(createHttp({ allowHosts: ["127.0.0.1"] }).fetchJson(`${srv.url}/x`), (e) => e.code === "tls");
  } finally { await srv.close(); }
});

test("host outside allowlist rejected before connecting", async () => {
  await assert.rejects(createHttp({ allowHosts: ["127.0.0.1"] }).fetchJson("https://example.com/"), (e) => e.code === "egress_denied");
});

test("plain http refused unless the host is an allowed http host", async () => {
  const srv = await startFixtureServer({ "/v": { v: 1 } }, { tls: false });
  try {
    await assert.rejects(createHttp({ allowHosts: ["127.0.0.1"] }).fetchJson(`${srv.url}/v`), (e) => e.code === "egress_denied");
    assert.deepEqual(await createHttp({ allowHosts: [], allowHttpHosts: ["127.0.0.1"] }).fetchJson(`${srv.url}/v`), { v: 1 });
  } finally { await srv.close(); }
});

test("timeout", async () => {
  const srv = await startFixtureServer({ "/slow": () => new Promise((r) => setTimeout(() => r([200, {}]), 500)) });
  try {
    await assert.rejects(createHttp({ allowHosts: ["127.0.0.1"] }).fetchJson(`${srv.url}/slow`, { certSha256: srv.certSha256, timeoutMs: 100 }), (e) => e.code === "timeout");
  } finally { await srv.close(); }
});

test("oversize body is too_large", async () => {
  const srv = await startFixtureServer({ "/big": { blob: "x".repeat(5000) } });
  try {
    await assert.rejects(createHttp({ allowHosts: ["127.0.0.1"] }).fetchJson(`${srv.url}/big`, { certSha256: srv.certSha256, maxBytes: 1000 }), (e) => e.code === "too_large");
  } finally { await srv.close(); }
});

test("401 is auth and the body is never echoed", async () => {
  const srv = await startFixtureServer({ "/a": () => [401, { message: "token secret-abc invalid" }] });
  try {
    await assert.rejects(createHttp({ allowHosts: ["127.0.0.1"] }).fetchJson(`${srv.url}/a`, { certSha256: srv.certSha256 }), (e) => e.code === "auth" && !e.message.includes("secret-abc"));
  } finally { await srv.close(); }
});

test("500 is http with status only", async () => {
  const srv = await startFixtureServer({ "/e": () => [500, "boom"] });
  try {
    await assert.rejects(createHttp({ allowHosts: ["127.0.0.1"] }).fetchJson(`${srv.url}/e`, { certSha256: srv.certSha256 }), (e) => e.code === "http" && e.message === "HTTP 500");
  } finally { await srv.close(); }
});

test("invalid JSON is parse", async () => {
  const srv = await startFixtureServer({ "/p": "not json" });
  try {
    await assert.rejects(createHttp({ allowHosts: ["127.0.0.1"] }).fetchJson(`${srv.url}/p`, { certSha256: srv.certSha256 }), (e) => e.code === "parse");
  } finally { await srv.close(); }
});

test("PUT refused, POST only to the Wazuh login path", async () => {
  const http = createHttp({ allowHosts: ["127.0.0.1"] });
  await assert.rejects(http.fetchJson("https://127.0.0.1:1/x", { method: "PUT" }), (e) => e.code === "egress_denied");
  await assert.rejects(http.fetchJson("https://127.0.0.1:1/x", { method: "POST" }), (e) => e.code === "egress_denied");
  const srv = await startFixtureServer({ "POST /security/user/authenticate": { data: { token: "t" } } });
  try {
    assert.deepEqual(await http.fetchJson(`${srv.url}/security/user/authenticate`, { method: "POST", certSha256: srv.certSha256 }), { data: { token: "t" } });
  } finally { await srv.close(); }
});

test("redact strips PVEAPIToken, bearer, url credentials and given secrets", () => {
  const text = "GET failed Authorization: PVEAPIToken=root@pam!hs=11111111-2222 Bearer eyJabc.def password=hunter2 https://user:pw@host/ mysecretvalue";
  const out = redact(text, ["mysecretvalue"]);
  for (const s of ["11111111-2222", "eyJabc", "hunter2", "user:pw", "mysecretvalue"]) assert.ok(!out.includes(s), `${s} leaked: ${out}`);
});
