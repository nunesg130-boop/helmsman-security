// Small IPv4 helpers for exposure reasoning. IPv6 ranges are recognised but
// never match an IPv4 address.
export function parseV4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u.exec(String(ip ?? "").trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

// "a.b.c.d" or "a.b.c.d/n" -> { base, mask, bits } | null
export function parseRange(range) {
  const [addr, bitsText] = String(range ?? "").trim().split("/");
  const base = parseV4(addr);
  if (base == null) return null;
  const bits = bitsText === undefined ? 32 : Number(bitsText);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (base & mask) >>> 0, mask, bits };
}

export function inRange(ip, range) {
  const a = parseV4(ip);
  const r = parseRange(range);
  return a != null && r != null && ((a & r.mask) >>> 0) === r.base;
}

export const inRanges = (ip, ranges) => (ranges ?? []).some((r) => inRange(ip, r));

const PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"];
export const isPrivate = (ip) => inRanges(ip, PRIVATE);

// True when the range lies entirely inside private address space.
export function isPrivateRange(range) {
  const r = parseRange(range);
  if (!r) return false;
  return PRIVATE.some((p) => { const q = parseRange(p); return r.bits >= q.bits && ((r.base & q.mask) >>> 0) === q.base; });
}

// A stand-in for "some visitor on the internet" when evaluating restrictions.
export const PUBLIC_VISITOR = "203.0.113.7";
