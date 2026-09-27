/**
 * Investigation repository: investigations, enrichment snapshots, risk
 * explanation rows and the investigation timeline.
 *
 * The most interesting function here is `rebuildVerdicts()`: it reconstructs the
 * full list of ProviderVerdicts from the stored `enrichment_results` rows. That
 * is what lets an investigation opened three months later be re-rendered
 * (graph, ATT&CK mapping, recommendations) using *the intelligence as it was at
 * the time*, instead of calling the providers again and silently mixing in
 * today's data. The stored snapshot is the intelligence; the derived views are
 * pure functions of it.
 */
import { fromJson, getDb, nowIso, q } from '../db/index.js';
import type {
  DetectionStats,
  IocType,
  InvestigationStatus,
  NetworkIntel,
  NormalizedIoc,
  ProviderVerdict,
  RelatedIntel,
  RiskLevel,
  Verdict,
} from '../core/types.js';
import { IOC_TYPE_LABEL, describeIoc } from '../core/ioc/validate.js';

export interface InvestigationRow {
  id: number;
  reference: string;
  ioc_id: number;
  requested_by: number | null;
  status: InvestigationStatus;
  mode: 'live' | 'demo';
  risk_score: number | null;
  risk_level: RiskLevel | null;
  confidence_score: number | null;
  verdict: Verdict | null;
  providers_ok: number;
  providers_failed: number;
  providers_skipped: number;
  duration_ms: number | null;
  error_code: string | null;
  error_message: string | null;
  analyst_notes: string | null;
  analyst_assessment: string | null;
  analyst_rating: string | null;
  started_at: string;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface EnrichmentRow {
  id: number;
  investigation_id: number;
  ioc_id: number;
  provider_id: string;
  provider_name: string;
  origin: 'live' | 'demo';
  status: ProviderVerdict['status'];
  verdict: Verdict;
  reputation_score: number | null;
  report_count: number | null;
  malicious_count: number | null;
  suspicious_count: number | null;
  harmless_count: number | null;
  unsupported_count: number | null;
  undetected_count: number | null;
  detection_ratio: number | null;
  country: string | null;
  asn: string | null;
  isp: string | null;
  network_json: string | null;
  related_json: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  raw_excerpt: string | null;
  error_code: string | null;
  error_message: string | null;
  duration_ms: number;
  created_at: string;
}

const emptyRelated = (): RelatedIntel => ({
  domains: [], urls: [], hashes: [], ipAddresses: [], emails: [],
  categories: [], malware: [], actors: [], campaigns: [], behaviours: [],
});

/** Rebuild a ProviderVerdict from its stored row. */
export const verdictFromRow = (row: EnrichmentRow): ProviderVerdict => {
  const total = (row.malicious_count ?? 0) + (row.suspicious_count ?? 0) + (row.harmless_count ?? 0);
  const detections: DetectionStats | null = total > 0 || row.unsupported_count
    ? {
        malicious: row.malicious_count ?? 0,
        suspicious: row.suspicious_count ?? 0,
        harmless: row.harmless_count ?? 0,
        unsupported: row.unsupported_count ?? 0,
        undetected: row.undetected_count ?? 0,
        total,
        ratio: row.detection_ratio,
        lastAnalysisAt: row.last_seen_at,
      }
    : null;

  return {
    providerId: row.provider_id,
    providerName: row.provider_name,
    origin: row.origin,
    status: row.status,
    error: row.error_code
      ? { code: row.error_code, message: row.error_message ?? 'Unknown provider error', retryable: false }
      : undefined,
    verdict: row.verdict,
    reputationScore: row.reputation_score,
    reports: row.report_count,
    detections,
    network: fromJson<NetworkIntel | null>(row.network_json, null),
    related: fromJson<RelatedIntel | null>(row.related_json, null) ?? emptyRelated(),
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    rawExcerpt: row.raw_excerpt,
    durationMs: row.duration_ms,
    url: null,
  };
};

export const listEnrichment = (investigationId: number): EnrichmentRow[] =>
  q.all<EnrichmentRow>('SELECT * FROM enrichment_results WHERE investigation_id = ? ORDER BY id ASC', [investigationId]);

export const rebuildVerdicts = (investigationId: number): ProviderVerdict[] =>
  listEnrichment(investigationId).map(verdictFromRow);

// ----------------------------------------------------------------- create
export function nextReference(): string {
  const year = new Date().getUTCFullYear();
  const prefix = `INV-${year}-`;
  const last = q.get<{ reference: string }>(
    'SELECT reference FROM investigations WHERE reference LIKE ? ORDER BY id DESC LIMIT 1',
    [`${prefix}%`],
  );
  const seq = last ? Number.parseInt(last.reference.slice(prefix.length), 10) + 1 : 1;
  return `${prefix}${String(seq).padStart(6, '0')}`;
}

export function createInvestigation(input: {
  iocId: number;
  requestedBy: number | null;
  mode: 'live' | 'demo';
  startedAt?: string;
}): InvestigationRow {
  const reference = nextReference();
  const id = q.insert(
    `INSERT INTO investigations (reference, ioc_id, requested_by, status, mode, started_at, created_at, updated_at)
     VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)`,
    [reference, input.iocId, input.requestedBy, input.mode, input.startedAt ?? nowIso(), input.startedAt ?? nowIso(), input.startedAt ?? nowIso()],
  );
  return q.get<InvestigationRow>('SELECT * FROM investigations WHERE id = ?', [id])!;
}

export const findInvestigation = (id: number): InvestigationRow | undefined =>
  q.get<InvestigationRow>('SELECT * FROM investigations WHERE id = ?', [id]);

export const findInvestigationByRef = (reference: string): InvestigationRow | undefined =>
  q.get<InvestigationRow>('SELECT * FROM investigations WHERE reference = ?', [reference]);

export function updateInvestigation(id: number, patch: Partial<InvestigationRow>): void {
  const map: Record<string, string> = {
    status: 'status',
    risk_score: 'risk_score',
    risk_level: 'risk_level',
    confidence_score: 'confidence_score',
    verdict: 'verdict',
    providers_ok: 'providers_ok',
    providers_failed: 'providers_failed',
    providers_skipped: 'providers_skipped',
    duration_ms: 'duration_ms',
    error_code: 'error_code',
    error_message: 'error_message',
    analyst_notes: 'analyst_notes',
    analyst_assessment: 'analyst_assessment',
    analyst_rating: 'analyst_rating',
    completed_at: 'completed_at',
    updated_at: 'updated_at',
  };
  const sets: string[] = [];
  const params: unknown[] = [];
  for (const [key, column] of Object.entries(map)) {
    if (!(key in patch)) continue;
    sets.push(`${column} = ?`);
    const value = (patch as Record<string, unknown>)[key];
    params.push(value === undefined ? null : value);
  }
  if (sets.length === 0) return;
  q.run(`UPDATE investigations SET ${sets.join(', ')} WHERE id = ?`, [...params, id]);
}

// -------------------------------------------------------------- enrichment
export function insertEnrichment(input: {
  investigationId: number;
  iocId: number;
  verdict: ProviderVerdict;
}): void {
  const v = input.verdict;
  const network = v.network;
  q.run(
    `INSERT INTO enrichment_results
       (investigation_id, ioc_id, provider_id, provider_name, origin, status, verdict, reputation_score, report_count,
        malicious_count, suspicious_count, harmless_count, unsupported_count, undetected_count, detection_ratio,
        country, asn, isp, network_json, related_json, first_seen_at, last_seen_at, raw_excerpt,
        error_code, error_message, duration_ms, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      input.investigationId,
      input.iocId,
      v.providerId,
      v.providerName,
      v.origin,
      v.status,
      v.verdict,
      v.reputationScore,
      v.reports,
      v.detections?.malicious ?? null,
      v.detections?.suspicious ?? null,
      v.detections?.harmless ?? null,
      v.detections?.unsupported ?? null,
      v.detections?.undetected ?? null,
      v.detections?.ratio ?? null,
      network?.country ?? null,
      network?.asn ?? null,
      network?.isp ?? null,
      JSON.stringify(network ?? null),
      JSON.stringify(v.related ?? emptyRelated()),
      v.firstSeenAt,
      v.lastSeenAt,
      v.rawExcerpt,
      v.error?.code ?? null,
      v.error?.message ?? null,
      v.durationMs,
      nowIso(),
    ],
  );
}

// ------------------------------------------------------------- risk factors
export function replaceRiskFactors(investigationId: number, factors: Array<{ id: string; label: string; points: number; category: string; evidence: string; sources: string[] }>): void {
  q.run('DELETE FROM risk_factors WHERE investigation_id = ?', [investigationId]);
  const stmt = getDb().prepare(
    `INSERT INTO risk_factors (investigation_id, seq, factor_id, label, points, category, evidence, sources_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const run = getDb().transaction(() => {
    factors.forEach((f, index) => {
      stmt.run(investigationId, index + 1, f.id, f.label, f.points, f.category, f.evidence, JSON.stringify(f.sources));
    });
  });
  run();
}

export const riskFactorsFor = (investigationId: number) =>
  q.all<{ factor_id: string; label: string; points: number; category: string; evidence: string; sources_json: string; seq: number }>(
    'SELECT * FROM risk_factors WHERE investigation_id = ? ORDER BY seq ASC',
    [investigationId],
  ).map((r) => ({ ...r, sources: fromJson<string[]>(r.sources_json, []) }));

// ---------------------------------------------------------------- timeline
export interface TimelineRow {
  id: number;
  investigation_id: number;
  seq: number;
  at: string;
  kind: string;
  title: string;
  description: string;
  source: string | null;
  meta_json: string | null;
}

export function addTimelineEvent(input: {
  investigationId: number;
  seq: number;
  kind: string;
  title: string;
  description: string;
  source?: string | null;
  meta?: Record<string, unknown> | null;
  at?: string;
}): void {
  q.run(
    `INSERT INTO investigation_timeline (investigation_id, seq, at, kind, title, description, source, meta_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      input.investigationId,
      input.seq,
      input.at ?? nowIso(),
      input.kind,
      input.title,
      input.description,
      input.source ?? null,
      input.meta ? JSON.stringify(input.meta) : null,
    ],
  );
}

export const timelineFor = (investigationId: number): TimelineRow[] =>
  q.all<TimelineRow>('SELECT * FROM investigation_timeline WHERE investigation_id = ? ORDER BY seq ASC', [investigationId]);

export const nextTimelineSeq = (investigationId: number): number =>
  (q.get<{ n: number | null }>('SELECT MAX(seq) AS n FROM investigation_timeline WHERE investigation_id = ?', [investigationId])?.n ?? 0) + 1;

// ------------------------------------------------------------------ listing
export interface InvestigationListItem {
  id: number;
  reference: string;
  status: InvestigationStatus;
  mode: 'live' | 'demo';
  iocValue: string;
  iocType: IocType;
  iocTypeLabel: string;
  isDocumentation: number;
  riskScore: number | null;
  riskLevel: RiskLevel | null;
  confidenceScore: number | null;
  verdict: Verdict | null;
  providersOk: number;
  providersFailed: number;
  durationMs: number | null;
  createdAt: string;
  completedAt: string | null;
  requestedBy: string | null;
  techniqueCount: number;
  malwareCount: number;
  actorCount: number;
  description: string;
}

export interface HistoryQuery {
  search?: string;
  types?: IocType[];
  levels?: RiskLevel[];
  statuses?: InvestigationStatus[];
  modes?: Array<'live' | 'demo'>;
  from?: string;
  to?: string;
  sort?: 'newest' | 'oldest' | 'risk_desc' | 'risk_asc' | 'ioc_asc';
  limit?: number;
  offset?: number;
}

export function listInvestigations(query: HistoryQuery): { items: InvestigationListItem[]; total: number } {
  const where: string[] = [];
  const params: unknown[] = [];

  if (query.search) {
    where.push('i.value LIKE ?');
    params.push(`%${query.search.trim()}%`);
  }
  if (query.types?.length) {
    where.push(`i.type IN (${query.types.map(() => '?').join(',')})`);
    params.push(...query.types);
  }
  if (query.levels?.length) {
    where.push(`inv.risk_level IN (${query.levels.map(() => '?').join(',')})`);
    params.push(...query.levels);
  }
  if (query.statuses?.length) {
    where.push(`inv.status IN (${query.statuses.map(() => '?').join(',')})`);
    params.push(...query.statuses);
  }
  if (query.modes?.length) {
    where.push(`inv.mode IN (${query.modes.map(() => '?').join(',')})`);
    params.push(...query.modes);
  }
  if (query.from) {
    where.push('inv.created_at >= ?');
    params.push(query.from);
  }
  if (query.to) {
    where.push('inv.created_at <= ?');
    params.push(`${query.to}T23:59:59.999Z`);
  }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const orderSql = {
    newest: 'inv.created_at DESC, inv.id DESC',
    oldest: 'inv.created_at ASC, inv.id ASC',
    risk_desc: 'inv.risk_score DESC NULLS LAST, inv.created_at DESC',
    risk_asc: 'inv.risk_score ASC NULLS LAST, inv.created_at DESC',
    ioc_asc: 'i.value ASC',
  }[query.sort ?? 'newest'];

  const total = q.get<{ n: number }>(
    `SELECT COUNT(*) AS n FROM investigations inv JOIN iocs i ON i.id = inv.ioc_id ${whereSql}`,
    params,
  )?.n ?? 0;

  const rows = q.all<
    InvestigationRow & { ioc_value: string; ioc_type: IocType; is_documentation: number; requested_by_name: string | null; technique_count: number; malware_count: number; actor_count: number }
  >(
    `SELECT inv.*, i.value AS ioc_value, i.type AS ioc_type, i.is_documentation,
            u.display_name AS requested_by_name,
            (SELECT COUNT(*) FROM investigation_techniques it WHERE it.investigation_id = inv.id) AS technique_count,
            (SELECT COUNT(*) FROM investigation_malware im WHERE im.investigation_id = inv.id) AS malware_count,
            (SELECT COUNT(*) FROM investigation_actors ia WHERE ia.investigation_id = inv.id) AS actor_count
       FROM investigations inv
       JOIN iocs i ON i.id = inv.ioc_id
       LEFT JOIN users u ON u.id = inv.requested_by
       ${whereSql}
      ORDER BY ${orderSql}
      LIMIT ? OFFSET ?`,
    [...params, query.limit ?? 50, query.offset ?? 0],
  );

  return {
    total,
    items: rows.map((r) => ({
      id: r.id,
      reference: r.reference,
      status: r.status,
      mode: r.mode,
      iocValue: r.ioc_value,
      iocType: r.ioc_type,
      iocTypeLabel: IOC_TYPE_LABEL[r.ioc_type],
      isDocumentation: r.is_documentation,
      riskScore: r.risk_score,
      riskLevel: r.risk_level,
      confidenceScore: r.confidence_score,
      verdict: r.verdict,
      providersOk: r.providers_ok,
      providersFailed: r.providers_failed,
      durationMs: r.duration_ms,
      createdAt: r.created_at,
      completedAt: r.completed_at,
      requestedBy: r.requested_by_name,
      techniqueCount: r.technique_count,
      malwareCount: r.malware_count,
      actorCount: r.actor_count,
      description: describeIoc({
        value: r.ioc_value,
        raw: r.ioc_value,
        type: r.ioc_type,
        parsed: {},
      }),
    })),
  };
}

export const deleteInvestigation = (id: number): boolean => {
  const existing = findInvestigation(id);
  if (!existing) return false;
  // CASCADE removes enrichment_results, risk_factors, timeline, junctions and
  // related-ioc links. The `iocs` row is intentionally kept (it is a shared
  // indicator entity and may be referenced by other investigations).
  q.run('DELETE FROM investigations WHERE id = ?', [id]);
  return true;
};

export const countInvestigations = (): number => q.get<{ n: number }>('SELECT COUNT(*) AS n FROM investigations')?.n ?? 0;

export const investigationStats = () =>
  q.get<{
    total: number;
    completed: number;
    partial: number;
    failed: number;
    pending: number;
    malicious: number;
    suspicious: number;
    clean: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    cleanLevel: number;
    thisWeek: number;
  }>(
    `SELECT
       COUNT(*) AS total,
       SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
       SUM(CASE WHEN status = 'partial' THEN 1 ELSE 0 END) AS partial,
       SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
       SUM(CASE WHEN status IN ('pending','enriching','analyzing') THEN 1 ELSE 0 END) AS pending,
       SUM(CASE WHEN verdict = 'malicious' THEN 1 ELSE 0 END) AS malicious,
       SUM(CASE WHEN verdict = 'suspicious' THEN 1 ELSE 0 END) AS suspicious,
       SUM(CASE WHEN verdict IN ('clean','harmless') THEN 1 ELSE 0 END) AS clean,
       SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
       SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) AS high,
       SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) AS medium,
       SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) AS low,
       SUM(CASE WHEN risk_level = 'CLEAN' THEN 1 ELSE 0 END) AS cleanLevel,
       SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) AS thisWeek
     FROM investigations`,
  ) ?? ({} as never);

export const iocById = (id: number) => q.get<{ id: number; type: IocType; value: string; is_documentation: number; times_seen: number; first_seen_at: string; last_seen_at: string; notes: string | null }>(
  'SELECT id, type, value, is_documentation, times_seen, first_seen_at, last_seen_at, notes FROM iocs WHERE id = ?',
  [id],
);

/** Reconstruct a minimal NormalizedIoc from a stored row (for derived views). */
export const normalizedFromRow = (row: { type: IocType; value: string }): NormalizedIoc => ({
  value: row.value,
  raw: row.value,
  type: row.type,
  parsed: {},
});
