// Compare package/kernel version strings: an optional "epoch:" prefix wins,
// then runs of digits compare numerically and other runs compare as text.
function split(v) {
  const s = String(v ?? "");
  const i = s.indexOf(":");
  const hasEpoch = i > 0 && /^\d+$/u.test(s.slice(0, i));
  return { epoch: hasEpoch ? Number(s.slice(0, i)) : 0, rest: hasEpoch ? s.slice(i + 1) : s };
}

function tokens(s) {
  return s.match(/\d+|[^\d]+/gu) ?? [];
}

export function compareVersions(a, b) {
  const A = split(a);
  const B = split(b);
  if (A.epoch !== B.epoch) return A.epoch > B.epoch ? 1 : -1;
  const ta = tokens(A.rest);
  const tb = tokens(B.rest);
  const n = Math.max(ta.length, tb.length);
  for (let i = 0; i < n; i += 1) {
    const x = ta[i];
    const y = tb[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xNum = /^\d+$/u.test(x);
    const yNum = /^\d+$/u.test(y);
    if (xNum && yNum) {
      const d = BigInt(x) - BigInt(y);
      if (d !== 0n) return d > 0n ? 1 : -1;
    } else if (x !== y) {
      if (xNum !== yNum) return xNum ? 1 : -1;
      return x > y ? 1 : -1;
    }
  }
  return 0;
}
