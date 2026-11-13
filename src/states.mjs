// The only result states the engine knows. "ok" can only come from fresh
// evidence (enforced by checks/runner.mjs); anything we can't confirm is
// "unknown", never "ok".
export const STATES = Object.freeze(["ok", "issue", "unknown", "not_applicable", "excluded"]);

const STATE_SET = new Set(STATES);

export function result(state, reason, evidence = [], extra = {}) {
  if (!STATE_SET.has(state)) throw new TypeError(`Unknown result state: ${state}`);
  if (typeof reason !== "string" || reason.trim() === "") throw new TypeError("A result needs a reason.");
  if (!Array.isArray(evidence)) throw new TypeError("evidence must be an array.");
  return { ...extra, state, reason, evidence };
}
