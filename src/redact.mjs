// Strip anything that looks like a credential from text before it is stored
// or shown. Callers also pass the actual secret values they hold.
const PATTERNS = [
  /PVEAPIToken=\S+/giu,
  /\bBearer\s+[^\s,;]+/giu,
  /\bBasic\s+[A-Za-z0-9+/=]{8,}/gu,
  /Authorization:\s*[^\r\n]+/giu,
  /\b(password|passwd|secret|token|apikey|api_key)=([^\s&]+)/giu,
  /\/\/[^/\s:@]+:[^/\s@]+@/gu
];

export function redact(text, secrets = []) {
  let out = String(text ?? "");
  for (const s of secrets) {
    if (typeof s === "string" && s.length >= 4) out = out.split(s).join("[redacted]");
  }
  for (const p of PATTERNS) {
    out = out.replace(p, (m, key) => (typeof key === "string" && /=/u.test(m) && !m.startsWith("PVEAPIToken") ? `${key}=[redacted]` : "[redacted]"));
  }
  return out.length > 500 ? `${out.slice(0, 500)}…` : out;
}
