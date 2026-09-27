/**
 * Shared normalisation helpers used by every live provider adapter.
 *
 * Centralising these guarantees that two providers describing the same
 * indicator produce *comparable* numbers, which is a precondition for the
 * risk-scoring engine to reason about corroboration.
 */
import type { DetectionStats, Verdict } from '../core/types.js';

export const uniq = (values: Array<string | null | undefined>): string[] => {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of values) {
    if (typeof v !== 'string') continue;
    const trimmed = v.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(trimmed);
  }
  return out;
};

export const clamp = (n: number, min: number, max: number): number => Math.min(max, Math.max(min, n));

export const safeInt = (value: unknown): number | null => {
  const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(n) ? n : null;
};

export const safeStr = (value: unknown): string | null => {
  if (typeof value === 'string') {
    const t = value.trim();
    return t ? t : null;
  }
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return null;
};

/** Build the detection statistics block from raw engine counters. */
export function buildDetectionStats(input: {
  malicious: number;
  suspicious: number;
  harmless: number;
  unsupported?: number;
  undetected?: number;
  lastAnalysisAt?: string | null;
}): DetectionStats {
  const malicious = Math.max(0, input.malicious);
  const suspicious = Math.max(0, input.suspicious);
  const harmless = Math.max(0, input.harmless);
  const unsupported = Math.max(0, input.unsupported ?? 0);
  const undetected = Math.max(0, input.undetected ?? 0);
  const total = malicious + suspicious + harmless;
  return {
    malicious,
    suspicious,
    harmless,
    unsupported,
    undetected,
    total,
    ratio: total > 0 ? Number((malicious / total).toFixed(4)) : null,
    lastAnalysisAt: input.lastAnalysisAt ?? null,
  };
}

/**
 * Translate engine counters into a coarse verdict.
 *
 * Thresholds are deliberately conservative: two or more independent engines
 * must flag the indicator before we call it "malicious", because a single
 * signature engine firing is usually a false positive.
 */
export function verdictFromStats(stats: DetectionStats | null): Verdict {
  if (!stats || stats.total === 0) return 'unknown';
  if (stats.malicious >= 2 || (stats.malicious >= 1 && stats.ratio !== null && stats.ratio >= 0.05)) {
    return 'malicious';
  }
  if (stats.malicious === 1) return 'suspicious';
  if (stats.suspicious >= 1) return 'suspicious';
  if (stats.harmless > 0 || (stats.undetected ?? 0) > 0) return 'clean';
  return 'unknown';
}

/**
 * Deterministic 0-100 "provider reputation score" (higher = worse).
 *
 *   score = min(100, 5 x malicious + 2 x suspicious + 1 x (VT community reputation, floored at 0))
 *
 * Rationale: the malicious count dominates because it represents independent
 * engine consensus; the community reputation term is bounded so a heavily
 * down-voted object cannot dominate. No randomness, no hidden scaling.
 */
export function reputationScoreFromStats(
  stats: DetectionStats | null,
  communityReputation: number | null = null,
): number | null {
  if (!stats || stats.total === 0) return communityReputation === null ? null : clamp(communityReputation, 0, 100);
  const base = stats.malicious * 5 + stats.suspicious * 2;
  const community = communityReputation === null ? 0 : clamp(communityReputation, 0, 100);
  return clamp(Math.round(base + community), 0, 100);
}

/** Unix seconds (VT/AbuseIPDB style) or ISO string -> ISO string. */
export function toIso(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number' && Number.isFinite(value)) {
    const ms = value > 1e12 ? value : value * 1000;
    const d = new Date(ms);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const d = new Date(trimmed.includes('T') ? trimmed : trimmed.replace(' ', 'T') + 'Z');
    if (!Number.isNaN(d.getTime())) return d.toISOString();
    return null;
  }
  return null;
}
