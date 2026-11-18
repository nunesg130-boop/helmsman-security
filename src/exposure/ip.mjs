// Small address helpers for exposure reasoning. Addresses are IPv4; IPv6
// ranges are recognised (and classed private or public) but never contain an
// IPv4 address.
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

// "a:b::c/n" -> { first: 16-bit first group, bits, loopback } | null
function parseV6Range(range) {
  const [addr, bitsText] = String(range ?? "").trim().toLowerCase().split("/");
  if (!addr.includes(":") || !/^[0-9a-f:]+$/u.test(addr) || addr.split("::").length > 2) return null;
  const groups = addr.split(":");
  if (groups.some((g) => g.length > 4) || groups.length > 8) return null;
  const bits = bitsText === undefined ? 128 : Number(bitsText);
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return null;
  const first = addr.startsWith("::") ? 0 : Number.parseInt(groups[0], 16);
  const loopback = /^(0{0,4}:){0,7}:?0{0,3}1$/u.test(addr.replace(/^::/u, "0:")) || addr === "::1";
  return { first, bits, loopback };
}

export const isValidRange = (range) => parseRange(range) != null || parseV6Range(range) != null;

const PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"];
export const isPrivate = (ip) => inRanges(ip, PRIVATE);

// True when the range lies entirely inside private address space.
export function isPrivateRange(range) {
  const v6 = parseV6Range(range);
  if (v6) return (v6.bits >= 7 && (v6.first & 0xfe00) === 0xfc00) || (v6.bits >= 10 && (v6.first & 0xffc0) === 0xfe80) || (v6.loopback && v6.bits === 128);
  const r = parseRange(range);
  if (!r) return false;
  return PRIVATE.some((p) => { const q = parseRange(p); return r.bits >= q.bits && ((r.base & q.mask) >>> 0) === q.base; });
}

// "Any visitor on the internet": a restriction is evaluated against every
// public address at once, never against one sample address.
export const PUBLIC_VISITOR = "public";
