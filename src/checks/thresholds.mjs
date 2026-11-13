export const DEFAULT_THRESHOLDS = Object.freeze({
  collectMinutes: 15,
  staleFactor: 3,
  eolRefreshHours: 24,
  eolMaxAgeDays: 7,
  backupMaxAgeDays: 2,
  clockDriftSeconds: 5,
  storageFillPct: 85,
  ssdLifeRemainingPct: 10
});

export function threshold(config, key) {
  const v = config?.thresholds?.[key];
  return Number.isFinite(v) ? v : DEFAULT_THRESHOLDS[key];
}
