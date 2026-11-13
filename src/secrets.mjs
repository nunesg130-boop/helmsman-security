import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { readFileSync, statSync } from "node:fs";

// AES-256-GCM, stored as v1.<iv>.<tag>.<ciphertext> (base64url). The master
// key lives in a file outside the database.
export function createSecretBox(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new TypeError("master key must be 32 bytes");
  return {
    seal(plain) {
      const iv = randomBytes(12);
      const c = createCipheriv("aes-256-gcm", key, iv);
      const ct = Buffer.concat([c.update(String(plain), "utf8"), c.final()]);
      return ["v1", iv.toString("base64url"), c.getAuthTag().toString("base64url"), ct.toString("base64url")].join(".");
    },
    open(sealed) {
      const [v, iv, tag, ct] = String(sealed).split(".");
      if (v !== "v1" || !iv || !tag || ct === undefined) throw new Error("not a sealed value");
      const d = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
      d.setAuthTag(Buffer.from(tag, "base64url"));
      return Buffer.concat([d.update(Buffer.from(ct, "base64url")), d.final()]).toString("utf8");
    }
  };
}

export const CREDENTIAL_NAMES = Object.freeze(["proxmox.tokenSecret", "wazuh.password", "api.readToken"]);

export class CredentialStore {
  constructor(db, tenantId, box) {
    if (!tenantId) throw new TypeError("tenantId is required");
    this.db = db;
    this.tenantId = tenantId;
    this.box = box;
  }

  #check(name) {
    if (!CREDENTIAL_NAMES.includes(name)) throw new TypeError(`unknown credential ${name}`);
  }

  set(name, plain, now) {
    this.#check(name);
    if (typeof plain !== "string" || !plain) throw new TypeError("credential value must be a non-empty string");
    this.db.prepare(
      `INSERT INTO credentials (tenant_id, name, sealed, updated_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (tenant_id, name) DO UPDATE SET sealed = excluded.sealed, updated_at = excluded.updated_at`
    ).run(this.tenantId, name, this.box.seal(plain), now);
  }

  get(name) {
    this.#check(name);
    const r = this.db.prepare("SELECT sealed FROM credentials WHERE tenant_id = ? AND name = ?").get(this.tenantId, name);
    return r ? this.box.open(r.sealed) : null;
  }

  has(name) {
    this.#check(name);
    return Boolean(this.db.prepare("SELECT 1 AS x FROM credentials WHERE tenant_id = ? AND name = ?").get(this.tenantId, name));
  }

  list() {
    return this.db.prepare("SELECT name, updated_at FROM credentials WHERE tenant_id = ? ORDER BY name").all(this.tenantId).map((r) => ({ name: r.name, updatedAt: r.updated_at }));
  }
}

// The key file holds 64 hex characters (e.g. `openssl rand -hex 32`).
export function loadMasterKey(path) {
  const st = statSync(path);
  if (st.mode & 0o077) throw new Error(`master key ${path} is readable by group or others; chmod 600 it`);
  const text = readFileSync(path, "utf8").trim();
  if (!/^[0-9a-fA-F]{64}$/u.test(text)) throw new Error("master key must be 64 hex characters");
  return Buffer.from(text, "hex");
}
