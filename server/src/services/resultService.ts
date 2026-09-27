/**
 * ============================================================================
 * INVESTIGATION RESULT ASSEMBLY
 * ============================================================================
 *
 * Rebuilds the complete analyst-facing view of a stored investigation.
 *
 * KEY DESIGN DECISION: enrichment evidence is read from the database, never
 * re-fetched. The risk score, ATT&CK mapping, recommendations and correlation
 * graph are then *re-derived* from that stored evidence by the same
 * deterministic engines used during the investigation. Consequences:
 *   - reopening a 3-month-old investigation shows the intelligence as it was,
 *   - the risk breakdown always matches the evidence shown next to it,
 *   - no provider quota is consumed by simply looking at history.
 */
import { aggregateIntelligence, confidenceLabel, type AggregatedIntel } from '../core/aggregate.js';
import { computeSignals } from './investigationService.js';
import { scoreRisk, riskLevelFor } from '../core/risk/engine.js';
import { buildCorrelationGraph } from '../core/correlation/correlator.js';
import { buildDefensiveActions } from '../core/recommendations/engine.js';
import { IOC_TYPE_LABEL, describeIoc, shannonEntropy, validateIoc } from '../core/ioc/validate.js';
import { demoProfileFor } from '../providers/demo/index.js';
import type {
  Confidence,
  CorrelationGraph,
  DefensiveAction,
  NetworkIntel,
  NormalizedIoc,
  RiskFactor,
  RiskLevel,
  TechniqueMapping,
  Verdict,
} from '../core/types.js';
import {
  iocById,
  normalizedFromRow,
  rebuildVerdicts,
  riskFactorsFor,
  findInvestigation,
  timelineFor,
  type InvestigationRow,
} from '../repositories/investigations.js';
import {
  actorsForInvestigation,
  campaignsForInvestigation,
  malwareForInvestigation,
  relatedIocsForInvestigation,
  techniquesForInvestigation,
  parseJsonArray,
} from '../repositories/knowledge.js';
import { learnedRelationshipsFor, relationshipsForIoc, type IocRow } from '../repositories/indicators.js';
import { findUserById } from '../repositories/users.js';

export interface ProviderSummary {
  id: string;
  name: string;
  origin: 'live' | 'demo';
  status: string;
  verdict: Verdict;
  reputationScore: number | null;
  reports: number | null;
  detections: {
    malicious: number;
    suspicious: number;
    harmless: number;
    unsupported: number;
    undetected: number;
    total: number;
    ratio: number | null;
  } | null;
  lastAnalysisAt: string | null;
  firstSeenAt: string | null;
  durationMs: number;
  error: { code: string; message: string; retryable: boolean } | null;
  network: NetworkIntel | null;
  related: {
    domains: string[];
    urls: string[];
    hashes: string[];
    ipAddresses: string[];
    emails: string[];
    categories: string[];
    malware: string[];
    actors: string[];
    campaigns: string[];
    behaviours: string[];
  };
  rawExcerpt: string | null;
  url: string | null;
}

export interface InvestigationDetail {
  id: number;
  reference: string;
  status: InvestigationRow['status'];
  mode: 'live' | 'demo';
  createdAt: string;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  requestedBy: { id: number; name: string } | null;
  ioc: {
    id: number;
    value: string;
    raw: string;
    type: NormalizedIoc['type'];
    typeLabel: string;
    description: string;
    parsed: NormalizedIoc['parsed'];
    isDocumentation: boolean;
    isPrivate: boolean;
    timesSeen: number;
    firstSeenAt: string;
    lastSeenAt: string;
    notes: string | null;
  };
  assessment: {
    score: number;
    rawScore: number;
    clamped: boolean;
    level: RiskLevel;
    /**
     * True when no source returned usable intelligence. In that case the stored
     * score of 0 must NOT be read as "clean" - there is simply no evidence, and
     * the UI/report say so explicitly.
     */
    insufficientIntelligence: boolean;
    confidenceScore: number;
    confidenceLabel: Confidence;
    verdict: Verdict;
    factors: RiskFactor[];
    methodology: string;
  };
  reputation: {
    verdict: Verdict;
    detections: AggregatedIntel['detections'];
    reports: number | null;
    reputationScore: number | null;
    lastSeenAt: string | null;
    firstSeenAt: string | null;
    maliciousSources: string[];
    suspiciousSources: string[];
    cleanSources: string[];
    neutralSources: string[];
    corroborationCount: number;
  };
  network: {
    fields: Array<{ label: string; value: string | null; source: string | null }>;
    raw: NetworkIntel | null;
  };
  threatIntel: {
    malware: Array<{ name: string; type: string | null; platform: string[]; capabilities: string[]; origin: string; confidence: Confidence; basis: string; description: string | null; techniqueIds: string[] }>;
    actors: Array<{ name: string; externalId: string; origin: string; sophistication: string | null; motivation: string[]; description: string | null; firstSeenYear: number | null; aliases: string[]; confidence: Confidence; basis: string }>;
    campaigns: Array<{ name: string; externalId: string; origin: string; description: string | null; firstSeen: string | null; confidence: Confidence }>;
    categories: string[];
    behaviours: string[];
    relatedDomains: string[];
    relatedUrls: string[];
    relatedHashes: string[];
    relatedIps: string[];
    relatedEmails: string[];
  };
  techniques: TechniqueMapping[];
  providers: ProviderSummary[];
  graph: CorrelationGraph;
  recommendations: DefensiveAction[];
  timeline: Array<{ seq: number; at: string; kind: string; title: string; description: string; source: string | null; meta: Record<string, unknown> | null }>;
  relatedIocs: Array<{ iocId: number; value: string; type: NormalizedIoc['type']; typeLabel: string; relation: string; confidence: Confidence; source: string; isDocumentation: boolean }>;
  analyst: { notes: string | null; assessment: string | null; rating: string | null };
  demo: null | { title: string; summary: string; analystNote: string };
  warnings: Array<{ code: string; message: string }>;
  counts: { providers: number; ok: number; failed: number; techniques: number; related: number; timeline: number };
}

const NETWORK_FIELDS: Array<{ key: keyof NetworkIntel; label: string }> = [
  { key: 'country', label: 'Country' },
  { key: 'city', label: 'City' },
  { key: 'region', label: 'Region' },
  { key: 'asn', label: 'ASN' },
  { key: 'asnOrg', label: 'AS organisation' },
  { key: 'isp', label: 'ISP' },
  { key: 'org', label: 'Organisation' },
  { key: 'reverseDns', label: 'Reverse DNS / hostnames' },
  { key: 'hostingProvider', label: 'Hosting provider' },
  { key: 'usageType', label: 'Usage type' },
  { key: 'domain', label: 'Associated domain' },
  { key: 'ispDomain', label: 'ISP domain' },
  { key: 'abuseConfidenceScore', label: 'Abuse confidence score' },
  { key: 'totalReports', label: 'Total abuse reports' },
  { key: 'lastReportedAt', label: 'Last reported' },
];

const fmt = (value: unknown): string | null => {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.length ? value.join(', ') : null;
  if (typeof value === 'number') return String(value);
  const s = String(value).trim();
  return s && s !== '-' ? s : null;
};

export function buildInvestigationDetail(investigationId: number): InvestigationDetail | null {
  const row = findInvestigation(investigationId);
  if (!row) return null;
  const iocRow = iocById(row.ioc_id) as IocRow | undefined;
  if (!iocRow) return null;

  const ioc = normalizedFromRow(iocRow);
  // Re-validate so `parsed` (URL parts, registrable domain, ...) is complete.
  const revalidation = validateIoc(iocRow.value);
  const warnings = revalidation.ok ? revalidation.warnings.map((w) => ({ code: w.code, message: w.message })) : [];
  const fullIoc: NormalizedIoc = revalidation.ok ? revalidation.ioc : ioc;

  const verdicts = rebuildVerdicts(investigationId);
  const intel = aggregateIntelligence(fullIoc, verdicts);
  const signals = computeSignals(fullIoc, intel, revalidation.ok ? revalidation.warnings : []);

  // --- risk: prefer the stored score, recompute for the explanation ---------
  const storedFactors = riskFactorsFor(investigationId);
  const recomputed = scoreRisk({ ioc: fullIoc, intel, signals, mode: row.mode });
  const factors: RiskFactor[] = storedFactors.length
    ? storedFactors.map((f) => ({
        id: f.factor_id,
        label: f.label,
        points: f.points,
        evidence: f.evidence,
        sources: f.sources,
        category: f.category as RiskFactor['category'],
      }))
    : [...recomputed.factors, ...recomputed.offsets];

  const score = row.risk_score ?? recomputed.score;
  const level = row.risk_level ?? riskLevelFor(score);
  const confidenceScore = row.confidence_score ?? recomputed.confidenceScore;

  // --- ATT&CK -------------------------------------------------------------
  const techniqueRows = techniquesForInvestigation(investigationId);
  const techniques: TechniqueMapping[] = techniqueRows.map((t) => ({
    techniqueId: t.external_id,
    name: t.name,
    tactic: t.tactic,
    tacticPhase: t.relationship,
    description: t.description ?? '',
    relationship: t.rationale,
    confidence: t.confidence,
    reference: t.reference_url,
    mappingBasis: t.mapping_basis as TechniqueMapping['mappingBasis'],
  }));

  // --- correlation graph --------------------------------------------------
  const learned = learnedRelationshipsFor(iocRow.id).filter((e) => e.sourceIocId === iocRow.id);
  const graph = buildCorrelationGraph({
    ioc: fullIoc,
    intel,
    riskLevel: level,
    techniques,
    learnedEdges: learned,
  });

  // --- defensive recommendations -----------------------------------------
  const recommendations = buildDefensiveActions({
    iocType: fullIoc.type,
    value: fullIoc.value,
    riskLevel: level,
    intel,
    relatedDomains: intel.related.domains,
    relatedIps: intel.related.ipAddresses,
    relatedHashes: intel.related.hashes,
    relatedUrls: intel.related.urls,
    actors: intel.actors,
    malware: intel.malware,
    isDocumentation: Boolean(iocRow.is_documentation),
  });

  // --- entities -----------------------------------------------------------
  const malwareRows = malwareForInvestigation(investigationId);
  const actorRows = actorsForInvestigation(investigationId);
  const campaignRows = campaignsForInvestigation(investigationId);
  const relatedRows = relatedIocsForInvestigation(investigationId);

  const providerSummaries: ProviderSummary[] = verdicts.map((v) => ({
    id: v.providerId,
    name: v.providerName,
    origin: v.origin,
    status: v.status,
    verdict: v.verdict,
    reputationScore: v.reputationScore,
    reports: v.reports,
    detections: v.detections
      ? {
          malicious: v.detections.malicious,
          suspicious: v.detections.suspicious,
          harmless: v.detections.harmless,
          unsupported: v.detections.unsupported,
          undetected: v.detections.undetected ?? 0,
          total: v.detections.total,
          ratio: v.detections.ratio,
        }
      : null,
    lastAnalysisAt: v.lastSeenAt,
    firstSeenAt: v.firstSeenAt,
    durationMs: v.durationMs,
    error: v.error ? { code: v.error.code, message: v.error.message, retryable: v.error.retryable } : null,
    network: v.network,
    related: v.related,
    rawExcerpt: v.rawExcerpt,
    url: v.url ?? null,
  }));

  const timeline = timelineFor(investigationId).map((t) => ({
    seq: t.seq,
    at: t.at,
    kind: t.kind,
    title: t.title,
    description: t.description,
    source: t.source,
    meta: t.meta_json ? (JSON.parse(t.meta_json) as Record<string, unknown>) : null,
  }));

  const demoProfile = row.mode === 'demo' ? demoProfileFor(fullIoc) : null;

  const networkFields = NETWORK_FIELDS.map((f) => ({
    label: f.label,
    value: fmt(intel.network?.[f.key] as unknown),
    source: intel.networkProvenance[f.key as string] ?? null,
  })).filter((f) => f.value !== null);

  const user = row.requested_by ? findUserById(row.requested_by) : null;

  return {
    id: row.id,
    reference: row.reference,
    status: row.status,
    mode: row.mode,
    createdAt: row.created_at,
    startedAt: row.started_at,
    completedAt: row.completed_at,
    durationMs: row.duration_ms,
    requestedBy: user ? { id: user.id, name: user.display_name } : null,
    ioc: {
      id: iocRow.id,
      value: iocRow.value,
      raw: iocRow.value,
      type: fullIoc.type,
      typeLabel: IOC_TYPE_LABEL[fullIoc.type],
      description: describeIoc(fullIoc),
      parsed: fullIoc.parsed,
      isDocumentation: Boolean(iocRow.is_documentation),
      isPrivate: Boolean(iocRow.is_private),
      timesSeen: iocRow.times_seen,
      firstSeenAt: iocRow.first_seen_at,
      lastSeenAt: iocRow.last_seen_at,
      notes: iocRow.notes,
    },
    assessment: {
      score,
      rawScore: recomputed.rawScore,
      clamped: recomputed.rawScore > 100 || recomputed.rawScore < 0,
      insufficientIntelligence: verdicts.every((v) => v.status !== 'ok'),
      level,
      confidenceScore,
      confidenceLabel: confidenceLabel(confidenceScore),
      verdict: intel.verdict,
      factors,
      methodology: recomputed.methodology,
    },
    reputation: {
      verdict: intel.verdict,
      detections: intel.detections,
      reports: intel.reports,
      reputationScore: intel.reputationScore,
      lastSeenAt: intel.lastSeenAt,
      firstSeenAt: intel.firstSeenAt,
      maliciousSources: intel.maliciousSources,
      suspiciousSources: intel.suspiciousSources,
      cleanSources: intel.cleanSources,
      neutralSources: intel.neutralSources,
      corroborationCount: intel.corroborationCount,
    },
    network: { fields: networkFields, raw: intel.network },
    threatIntel: {
      malware: malwareRows.map((m) => ({
        name: m.name,
        type: m.malware_type,
        platform: parseJsonArray(m.platform_json),
        capabilities: parseJsonArray(m.capabilities_json),
        origin: m.origin,
        confidence: m.confidence,
        basis: m.basis,
        description: m.description,
        techniqueIds: [],
      })),
      actors: actorRows.map((a) => ({
        name: a.name,
        externalId: a.external_id,
        origin: a.origin,
        sophistication: a.sophistication,
        motivation: parseJsonArray(a.motivation_json),
        description: a.description,
        firstSeenYear: a.first_seen_year,
        aliases: parseJsonArray(a.aliases_json),
        confidence: a.confidence,
        basis: a.basis,
      })),
      campaigns: campaignRows.map((c) => ({
        name: c.name,
        externalId: c.external_id,
        origin: c.origin,
        description: c.description,
        firstSeen: c.first_seen,
        confidence: c.confidence,
      })),
      categories: intel.categories,
      behaviours: intel.behaviours,
      relatedDomains: intel.related.domains,
      relatedUrls: intel.related.urls,
      relatedHashes: intel.related.hashes,
      relatedIps: intel.related.ipAddresses,
      relatedEmails: intel.related.emails,
    },
    techniques,
    providers: providerSummaries,
    graph,
    recommendations,
    timeline,
    relatedIocs: relatedRows.map((r) => ({
      iocId: r.ioc_id,
      value: r.value,
      type: r.type,
      typeLabel: IOC_TYPE_LABEL[r.type],
      relation: r.relation,
      confidence: r.confidence,
      source: r.source,
      isDocumentation: Boolean(r.is_documentation),
    })),
    analyst: {
      notes: row.analyst_notes,
      assessment: row.analyst_assessment,
      rating: row.analyst_rating,
    },
    demo: demoProfile
      ? { title: demoProfile.title, summary: demoProfile.summary, analystNote: demoProfile.analystNote }
      : null,
    warnings,
    counts: {
      providers: verdicts.length,
      ok: verdicts.filter((v) => v.status === 'ok').length,
      failed: verdicts.filter((v) => v.status === 'error' || v.status === 'timeout' || v.status === 'rate_limited').length,
      techniques: techniques.length,
      related: relatedRows.length,
      timeline: timeline.length,
    },
  };
}

export { shannonEntropy, relationshipsForIoc };
