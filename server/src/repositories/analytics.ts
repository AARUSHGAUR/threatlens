/**
 * Analytics repository: the aggregate queries behind the dashboard charts.
 *
 * All queries are read-only GROUP BYs over the normalised schema - the
 * dashboards are never backed by a pre-computed cache, so the numbers can never
 * drift from the stored evidence. That is an important trustworthiness property
 * for a CTI tool: what you see is what is in the database.
 */
import { q } from '../db/index.js';
import type { IocType, RiskLevel } from '../core/types.js';

export interface CountRow {
  key: string;
  label: string;
  count: number;
}

export const iocTypeDistribution = (): CountRow[] =>
  q.all<{ type: IocType; n: number }>(
    `SELECT i.type, COUNT(*) AS n
       FROM investigations inv JOIN iocs i ON i.id = inv.ioc_id
      GROUP BY i.type ORDER BY n DESC`,
  ).map((r) => ({ key: r.type, label: r.type.toUpperCase(), count: r.n }));

export const riskDistribution = (): CountRow[] =>
  q.all<{ risk_level: RiskLevel; n: number }>(
    `SELECT risk_level, COUNT(*) AS n FROM investigations
      WHERE risk_level IS NOT NULL GROUP BY risk_level`,
  ).map((r) => ({ key: r.risk_level, label: r.risk_level, count: r.n }));

export const verdictDistribution = (): CountRow[] =>
  q.all<{ verdict: string; n: number }>(
    `SELECT verdict, COUNT(*) AS n FROM investigations
      WHERE verdict IS NOT NULL GROUP BY verdict`,
  ).map((r) => ({ key: r.verdict, label: r.verdict.toUpperCase(), count: r.n }));

/** Investigations per day for the last `days` days (zero-filled). */
export const investigationsOverTime = (days = 14): Array<{ date: string; count: number; critical: number; high: number }> => {
  const rows = q.all<{ date: string; n: number; critical: number; high: number }>(
    `SELECT substr(created_at, 1, 10) AS date,
            COUNT(*) AS n,
            SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
            SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) AS high
       FROM investigations
      WHERE created_at >= datetime('now', ?)
      GROUP BY date ORDER BY date ASC`,
    [`-${days} days`],
  );
  const map = new Map(rows.map((r) => [r.date, r]));
  const out: Array<{ date: string; count: number; critical: number; high: number }> = [];
  for (let i = days - 1; i >= 0; i -= 1) {
    const d = new Date(Date.now() - i * 86_400_000);
    const key = d.toISOString().slice(0, 10);
    const row = map.get(key);
    out.push({ date: key, count: row?.n ?? 0, critical: row?.critical ?? 0, high: row?.high ?? 0 });
  }
  return out;
};

/**
 * Threat categories are stored inside the JSON `related_json` blob, so we use
 * SQLite's json_each(). Failures on malformed JSON are impossible because the
 * writer always stores valid JSON, but json_valid() is kept as a guard.
 */
export const threatCategories = (limit = 10): CountRow[] =>
  q.all<{ category: string; n: number }>(
    `SELECT je.value AS category, COUNT(*) AS n
       FROM enrichment_results e, json_each(e.related_json, '$.categories') je
      WHERE json_valid(e.related_json)
      GROUP BY lower(je.value)
      ORDER BY n DESC, category ASC
      LIMIT ?`,
    [limit],
  ).map((r) => ({ key: r.category, label: r.category, count: r.n }));

export const topCountries = (limit = 8): CountRow[] =>
  q.all<{ country: string; n: number; malicious: number }>(
    `SELECT country, COUNT(*) AS n, SUM(CASE WHEN verdict IN ('malicious','suspicious') THEN 1 ELSE 0 END) AS malicious
       FROM enrichment_results
      WHERE country IS NOT NULL AND country <> '' AND country <> '-'
      GROUP BY country ORDER BY malicious DESC, n DESC LIMIT ?`,
    [limit],
  ).map((r) => ({ key: r.country, label: r.country, count: r.malicious }));

export const topAsns = (limit = 8): CountRow[] =>
  q.all<{ asn: string; n: number }>(
    `SELECT asn, COUNT(*) AS n FROM enrichment_results
      WHERE asn IS NOT NULL AND asn <> '' GROUP BY asn ORDER BY n DESC LIMIT ?`,
    [limit],
  ).map((r) => ({ key: r.asn, label: r.asn, count: r.n }));

export const topMalware = (limit = 8): CountRow[] =>
  q.all<{ family: string; n: number }>(
    `SELECT je.value AS family, COUNT(*) AS n
       FROM enrichment_results e, json_each(e.related_json, '$.malware') je
      WHERE json_valid(e.related_json)
      GROUP BY lower(je.value) ORDER BY n DESC LIMIT ?`,
    [limit],
  ).map((r) => ({ key: r.family, label: r.family, count: r.n }));

export const providerUsage = (): Array<CountRow & { errors: number; ok: number }> =>
  q.all<{ provider_name: string; n: number; errors: number; ok: number }>(
    `SELECT provider_name,
            COUNT(*) AS n,
            SUM(CASE WHEN status IN ('error','timeout','rate_limited') THEN 1 ELSE 0 END) AS errors,
            SUM(CASE WHEN status = 'ok' THEN 1 ELSE 0 END) AS ok
       FROM enrichment_results GROUP BY provider_name ORDER BY n DESC`,
  ).map((r) => ({ key: r.provider_name, label: r.provider_name, count: r.n, errors: r.errors, ok: r.ok }));

/** Most frequently investigated indicators (analyst interest signal). */
export const mostInvestigated = (limit = 8) =>
  q.all<{ value: string; type: IocType; n: number; risk_level: RiskLevel | null; risk_score: number | null }>(
    `SELECT i.value, i.type, COUNT(*) AS n, MAX(inv.risk_level) AS risk_level, MAX(inv.risk_score) AS risk_score
       FROM investigations inv JOIN iocs i ON i.id = inv.ioc_id
      GROUP BY i.id ORDER BY n DESC, MAX(inv.risk_score) DESC LIMIT ?`,
    [limit],
  ).map((r) => ({ value: r.value, type: r.type, count: r.n, riskLevel: r.risk_level, riskScore: r.risk_score }));

/** Average score for completed investigations, used on the dashboard header. */
export const averageRisk = (): number | null => {
  const row = q.get<{ avg: number | null }>(
    'SELECT AVG(risk_score) AS avg FROM investigations WHERE risk_score IS NOT NULL',
  );
  return row?.avg ? Number(row.avg.toFixed(1)) : null;
};

export const dashboardSummary = () => ({
  stats: {
    totalIocsInvestigated: 0,
    malicious: 0,
    suspicious: 0,
    clean: 0,
    critical: 0,
    thisWeek: 0,
  },
});
