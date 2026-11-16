import https from "node:https";
import http from "node:http";
import tls from "node:tls";
import { redact } from "./redact.mjs";

export { redact };

export class CollectorError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CollectorError";
    this.code = code;
  }
}

const LOGIN_PATH = "/security/user/authenticate";
const normFp = (fp) => String(fp ?? "").replace(/:/gu, "").toLowerCase();

// An agent whose connections are verified against a pinned SHA-256
// fingerprint BEFORE the socket is handed to the request, so no header
// (and no credential) is ever written to an unverified peer.
function pinnedAgent(pin, timeoutMs) {
  const agent = new https.Agent({ keepAlive: false });
  agent.createConnection = (options, oncreate) => {
    const socket = tls.connect({ ...options, rejectUnauthorized: false });
    let done = false;
    const finish = (err, s) => { if (!done) { done = true; oncreate(err, s); } };
    // The request's own timeout only starts once it has the socket, so the
    // TCP connect + TLS handshake needs its own limit.
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      finish(new CollectorError("timeout", `no TLS handshake within ${timeoutMs} ms`));
    });
    socket.once("secureConnect", () => {
      socket.setTimeout(0);
      const fp = normFp(socket.getPeerCertificate()?.fingerprint256);
      if (fp !== pin) {
        socket.destroy();
        finish(new CollectorError("tls", "server certificate does not match the pinned fingerprint"));
      } else finish(null, socket);
    });
    socket.once("error", (e) => finish(e));
    return undefined;
  };
  return agent;
}

export function createHttp({ allowHosts = [], allowHttpHosts = [] } = {}) {
  const httpsHosts = new Set(allowHosts.map((h) => h.toLowerCase()));
  const plainHosts = new Set(allowHttpHosts.map((h) => h.toLowerCase()));

  // Raw bytes, with the same egress, pinning, status and size rules.
  // A GET may be redirected within the same host (e.g. "latest" -> a dated
  // file), at most three times. Redirects to another host are refused.
  function fetchBuffer(url, options = {}) {
    const { method = "GET", headers = {}, body, timeoutMs = 10_000, deadlineMs = timeoutMs * 3, maxBytes = 50_000_000, certSha256, redirects = 0 } = options;
    return new Promise((resolve, reject) => {
      let u;
      try { u = new URL(url); } catch { return reject(new CollectorError("egress_denied", "invalid URL")); }
      const host = u.hostname.toLowerCase().replace(/^\[|\]$/gu, "");
      if (u.protocol === "https:" ? !httpsHosts.has(host) : !(u.protocol === "http:" && plainHosts.has(host))) {
        return reject(new CollectorError("egress_denied", `${u.protocol}//${host} is not an allowed destination`));
      }
      if (method !== "GET" && !(method === "POST" && u.pathname === LOGIN_PATH)) {
        return reject(new CollectorError("egress_denied", `${method} ${u.pathname} is not allowed (read-only engine)`));
      }
      const lib = u.protocol === "https:" ? https : http;
      // A GET may carry a JSON body (search queries); it still changes nothing.
      // Node sends no body on a GET unless its length is declared.
      const payload = body === undefined ? null : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
      const opts = { method, headers: { accept: "application/json", ...(payload ? { "content-type": "application/json", "content-length": payload.length } : {}), ...headers } };
      if (u.protocol === "https:") {
        if (certSha256) opts.agent = pinnedAgent(normFp(certSha256), timeoutMs);
        else opts.rejectUnauthorized = true;
      }
      let settled = false;
      let deadline = null;
      const fail = (e) => { if (!settled) { settled = true; clearTimeout(deadline); reject(e); } };
      const req = lib.request(u, opts, (res) => {
        const status = res.statusCode ?? 0;
        if (status === 401 || status === 403) { res.resume(); return fail(new CollectorError("auth", `HTTP ${status}`)); }
        if ([301, 302, 303, 307, 308].includes(status)) {
          res.resume();
          let next = null;
          try { next = new URL(res.headers.location ?? "", u); } catch { /* handled below */ }
          if (!next || method !== "GET" || payload || next.host !== u.host || next.protocol !== u.protocol) {
            return fail(Object.assign(new CollectorError("http", `HTTP ${status} redirect not followed`), { status }));
          }
          if (redirects >= 3) return fail(Object.assign(new CollectorError("http", "too many redirects"), { status }));
          settled = true;
          clearTimeout(deadline);
          return resolve(fetchBuffer(next.href, { ...options, redirects: redirects + 1 }));
        }
        if (status < 200 || status >= 300) { res.resume(); return fail(Object.assign(new CollectorError("http", `HTTP ${status}`), { status })); }
        const chunks = [];
        let size = 0;
        res.on("data", (c) => {
          size += c.length;
          if (size > maxBytes) { req.destroy(); return fail(new CollectorError("too_large", `response larger than ${maxBytes} bytes`)); }
          chunks.push(c);
        });
        res.on("end", () => {
          if (settled) return;
          settled = true;
          clearTimeout(deadline);
          resolve(Buffer.concat(chunks));
        });
        res.on("error", (e) => fail(new CollectorError("network", e.message)));
      });
      req.setTimeout(timeoutMs, () => { req.destroy(); fail(new CollectorError("timeout", `no answer within ${timeoutMs} ms`)); });
      // Overall limit, so a server trickling bytes can't hold a run forever.
      deadline = setTimeout(() => { req.destroy(); fail(new CollectorError("timeout", `request took longer than ${deadlineMs} ms`)); }, deadlineMs);
      req.on("error", (e) => {
        if (e instanceof CollectorError) return fail(e);
        const code = /certificate|self[- ]signed|SSL|TLS/iu.test(`${e.code} ${e.message}`) ? "tls" : "network";
        fail(new CollectorError(code, redact(`${e.code ?? ""} ${e.message}`.trim())));
      });
      if (payload) req.write(payload);
      req.end();
    });
  }

  async function fetchJson(url, options = {}) {
    const buf = await fetchBuffer(url, { maxBytes: 5_000_000, ...options });
    try { return JSON.parse(buf.toString("utf8")); }
    catch { throw new CollectorError("parse", "response was not valid JSON"); }
  }

  return { fetchJson, fetchBuffer };
}
