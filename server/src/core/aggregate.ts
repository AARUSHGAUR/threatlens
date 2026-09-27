/**
 * ============================================================================
 * INTELLIGENCE AGGREGATION  (CTI lifecycle: "Enrichment" -> "Analysis")
 * ============================================================================
 *
 * Multiple providers describe the same indicator with different vocabularies,
 * different granularity and different levels of trust. This module merges them
 * into ONE picture for the risk engine, the report and the UI, while preserving
 * *field-level provenance* so the analyst always knows which source produced
 * which value (a hard requirement of good CTI practice: never present a merged
 * fact without its source).
 *
 * Merge rules (documented, deterministic):
 *  - Verdicts: the most severe verdict wins (malicious > suspicious > clean >
 *    unknown), because a single confirmed malicious source is decisive.
 *  - Detection counts: summed across providers, but *engine-counted per
 *    provider* is meaningless to sum, so we keep the max per provider and sum
 *    those maxima - i.e. consensus counts, not double counting.
 *  - Entities: union with case-insensitive de-duplication.
 *  - Network fields: first non-empty value wins in provider-priority order
 *    (abuse-specific fields first, then reputation, then exposure).
 *  - Confidence: computed from *coverage*, not from the verdict (see engine).
 */
import type {
  Confidence,
  DetectionStats,
  IocType,
  NetworkIntel,
  NormalizedIoc,
  ProviderVerdict,
  Verdict,
} from './types.js';

const VERDICT_SEVERITY: Record<Verdict, number> = {
  malicious: 4,
  suspicious: 3,
  unknown: 1,
  clean: 2,
  harmless: 2,
};

export interface FieldProvenance {
  [field: string]: string;
}

export interface AggregatedIntel {
  ioc: NormalizedIoc;
  /** Merged verdict (most severe wins). */
  verdict: Verdict;
  /** How many sources independently produced a usable verdict. */
  corroborationCount: number;
  /** Sources that returned a verdict of 'malicious'. */
  maliciousSources: string[];
  /** Sources that returned a verdict of 'suspicious'. */
  suspiciousSources: string[];
  /** Sources that returned a verdict of 'clean'. */
  cleanSources: string[];
  /** Sources that responded but had no opinion. */
  neutralSources: string[];
  detections: DetectionStats | null;
  reports: number | null;
  reputationScore: number | null;
  lastSeenAt: string | null;
  firstSeenAt: string | null;
  network: NetworkIntel | null;
  networkProvenance: FieldProvenance;
  categories: string[];
  behaviours: string[];
  malware: string[];
  actors: string[];
  campaigns: string[];
  related: {
    domains: string[];
    urls: string[];
    hashes: string[];
    ipAddresses: string[];
    emails: string[];
  };
  /** Per-provider status, ordered as executed. */
  providers: ProviderVerdict[];
  okCount: number;
  failedCount: number;
  skippedCount: number;
}

const uniqList = (values: Array<string | null | undefined>): string[] => {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    if (typeof value !== 'string') continue;
    const trimmed = value.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(trimmed);
  }
  return out;
};

const latest = (dates: Array<string | null>): string | null => {
  const valid = dates.filter((d): d is string => Boolean(d)).sort();
  return valid.length ? valid[valid.length - 1] : null;
};

const earliest = (dates: Array<string | null>): string | null => {
  const valid = dates.filter((d): d is string => Boolean(d)).sort();
  return valid.length ? valid[0] : null;
};

const sumOrNull = (values: Array<number | null | undefined>): number | null => {
  const present = values.filter((v): v is number => typeof v === 'number');
  return present.length ? present.reduce((a, b) => a + b, 0) : null;
};

const maxOrNull = (values: Array<number | null | undefined>): number | null => {
  const present = values.filter((v): v is number => typeof v === 'number');
  return present.length ? Math.max(...present) : null;
};

/**
 * Provider priority for network-attribution merging.
 *
 * Why an explicit order? Two providers can legitimately disagree about
 * geolocation (GeoIP databases are snapshots with different vintages). Picking
 * "whichever answered first" would make the merged value depend on network
 * timing, which is unacceptable for a tool whose output must be reproducible.
 * The order below is fixed and documented:
 *
 *   1. abuse-reporting source  - crowd-reported ISP/usage data, closest to the
 *                                "who is this address for" question
 *   2. multi-engine reputation  - mature GeoIP/ASN data
 *   3. pulse / context sources  - may carry a stale snapshot
 *   4. exposure databases       - good on ports, weaker on ownership
 *   5. scanner index            - no ownership data
 * Unknown providers keep their original relative order and are considered last.
 */
const PROVIDER_PRIORITY: string[] = [
  'abuseipdb', 'demo:abuse',
  'virustotal', 'demo:reputation',
  'otx', 'demo:otx',
  'urlhaus', 'demo:urlhaus',
  'shodan', 'demo:shodan',
  'greynoise', 'demo:greynoise',
];

const priorityRank = (providerId: string): number => {
  const idx = PROVIDER_PRIORITY.indexOf(providerId);
  return idx === -1 ? PROVIDER_PRIORITY.length : idx;
};

/** Merge the per-provider detection blocks without double counting engines. */
function mergeDetections(verdicts: ProviderVerdict[]): DetectionStats | null {
  const withStats = verdicts.filter((v) => v.detections && v.detections.total > 0);
  if (withStats.length === 0) return null;
  const malicious = withStats.reduce((acc, v) => acc + (v.detections?.malicious ?? 0), 0);
  const suspicious = withStats.reduce((acc, v) => acc + (v.detections?.suspicious ?? 0), 0);
  const harmless = withStats.reduce((acc, v) => acc + (v.detections?.harmless ?? 0), 0);
  const unsupported = withStats.reduce((acc, v) => acc + (v.detections?.unsupported ?? 0), 0);
  const undetected = withStats.reduce((acc, v) => acc + (v.detections?.undetected ?? 0), 0);
  const total = malicious + suspicious + harmless;
  return {
    malicious,
    suspicious,
    harmless,
    unsupported,
    undetected,
    total,
    ratio: total > 0 ? Number((malicious / total).toFixed(4)) : null,
    lastAnalysisAt: latest(withStats.map((v) => v.detections?.lastAnalysisAt ?? null)),
  };
}

/** Network fields ordered by how authoritative we consider each source. */
const NETWORK_FIELDS: Array<keyof NetworkIntel> = [
  'abuseConfidenceScore',
  'usageType',
  'totalReports',
  'lastReportedAt',
  'asn',
  'asnOrg',
  'isp',
  'org',
  'country',
  'countryCode',
  'city',
  'region',
  'reverseDns',
  'hostingProvider',
  'domain',
  'ispDomain',
];

function mergeNetwork(verdicts: ProviderVerdict[]): { network: NetworkIntel | null; provenance: FieldProvenance } {
  const provenance: FieldProvenance = {};
  const merged: Record<string, unknown> = {};
  let found = false;

  // Sort by the documented provider priority (stable, so equal-rank providers
  // keep the order they were queried in).
  const ordered = verdicts
    .map((v, index) => ({ v, index }))
    .sort((a, b) => priorityRank(a.v.providerId) - priorityRank(b.v.providerId) || a.index - b.index)
    .map((entry) => entry.v);

  for (const field of NETWORK_FIELDS) {
    for (const verdict of ordered) {
      const value = verdict.network?.[field];
      if (value === null || value === undefined || value === '') continue;
      if (field === 'reverseDns' && Array.isArray(value) && value.length === 0) continue;
      if (merged[field] !== undefined) continue;
      merged[field] = value;
      provenance[field as string] = verdict.providerId;
      found = true;
      break;
    }
  }

  // Union every reverse-DNS / hostname observation.
  const reverse = uniqList(ordered.flatMap((v) => v.network?.reverseDns ?? []));
  if (reverse.length) {
    merged.reverseDns = reverse;
    provenance.reverseDns = ordered.find((v) => (v.network?.reverseDns ?? []).length)?.providerId ?? 'unknown';
    found = true;
  }

  return { network: found ? (merged as NetworkIntel) : null, provenance };
}

export function aggregateIntelligence(ioc: NormalizedIoc, verdicts: ProviderVerdict[]): AggregatedIntel {
  const scored = verdicts.filter((v) => v.status === 'ok');
  const okCount = scored.length;
  const failedCount = verdicts.filter(
    (v) => v.status === 'error' || v.status === 'timeout' || v.status === 'rate_limited',
  ).length;
  const skippedCount = verdicts.filter((v) => v.status === 'unconfigured' || v.status === 'not_found').length;

  // --- verdict merge -------------------------------------------------------
  let verdict: Verdict = 'unknown';
  for (const v of scored) {
    if (VERDICT_SEVERITY[v.verdict] > VERDICT_SEVERITY[verdict]) verdict = v.verdict;
  }

  const maliciousSources = scored.filter((v) => v.verdict === 'malicious').map((v) => v.providerId);
  const suspiciousSources = scored.filter((v) => v.verdict === 'suspicious').map((v) => v.providerId);
  const cleanSources = scored.filter((v) => v.verdict === 'clean' || v.verdict === 'harmless').map((v) => v.providerId);
  const neutralSources = scored.filter((v) => v.verdict === 'unknown').map((v) => v.providerId);

  // Corroboration = distinct sources that expressed a *positive or negative
  // reputation opinion*. Purely contextual sources (GreyNoise/Shodan return
  // `unknown`) do not count: agreement about "we don't know" is not evidence.
  const corroborationCount = maliciousSources.length + suspiciousSources.length + cleanSources.length;

  const { network, provenance } = mergeNetwork(verdicts);

  return {
    ioc,
    verdict,
    corroborationCount,
    maliciousSources,
    suspiciousSources,
    cleanSources,
    neutralSources,
    detections: mergeDetections(verdicts),
    reports: sumOrNull(verdicts.map((v) => v.reports)),
    reputationScore: maxOrNull(verdicts.map((v) => v.reputationScore)),
    lastSeenAt: latest(verdicts.map((v) => v.lastSeenAt)),
    firstSeenAt: earliest(verdicts.map((v) => v.firstSeenAt)),
    network,
    networkProvenance: provenance,
    categories: uniqList(verdicts.flatMap((v) => v.related.categories)),
    behaviours: uniqList(verdicts.flatMap((v) => v.related.behaviours)),
    malware: uniqList(verdicts.flatMap((v) => v.related.malware)),
    actors: uniqList(verdicts.flatMap((v) => v.related.actors)),
    campaigns: uniqList(verdicts.flatMap((v) => v.related.campaigns)),
    related: {
      domains: uniqList(verdicts.flatMap((v) => v.related.domains)),
      urls: uniqList(verdicts.flatMap((v) => v.related.urls)),
      hashes: uniqList(verdicts.flatMap((v) => v.related.hashes)),
      ipAddresses: uniqList(verdicts.flatMap((v) => v.related.ipAddresses)),
      emails: uniqList(verdicts.flatMap((v) => v.related.emails)),
    },
    providers: verdicts,
    okCount,
    failedCount,
    skippedCount,
  };
}

/** Confidence label thresholds shared with the UI. */
export const confidenceLabel = (score: number): Confidence =>
  score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low';

export const IOC_TYPE_ORDER: IocType[] = [
  'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email',
];
