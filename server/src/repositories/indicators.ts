/**
 * Indicator (IOC) repository.
 *
 * An indicator is a first-class, reusable entity: investigating the same
 * indicator twice updates one row and creates two investigations (two
 * intelligence snapshots over time). This is how a real CTI platform keeps an
 * indicator "case file".
 */
import { createHash } from 'node:crypto';
import { fromJson, nowIso, q } from '../db/index.js';
import type { IocType } from '../core/types.js';

export interface IocRow {
  id: number;
  type: IocType;
  value: string;
  value_hash: string;
  is_documentation: number;
  is_private: number;
  times_seen: number;
  first_seen_at: string;
  last_seen_at: string;
  notes: string | null;
  created_at: string;
}

/** Stable hash used for case/whitespace-insensitive uniqueness. */
export const valueHash = (type: IocType, value: string): string =>
  createHash('sha256').update(`${type}:${value.trim().toLowerCase()}`).digest('hex');

export interface IocInput {
  type: IocType;
  value: string;
  isDocumentation?: boolean;
  isPrivate?: boolean;
}

/** Insert or fetch the indicator row, incrementing `times_seen`. */
export function upsertIoc(input: IocInput): IocRow {
  const hash = valueHash(input.type, input.value);
  const existing = q.get<IocRow>('SELECT * FROM iocs WHERE type = ? AND value_hash = ?', [input.type, hash]);
  const now = nowIso();
  if (existing) {
    q.run('UPDATE iocs SET times_seen = times_seen + 1, last_seen_at = ?, is_documentation = MAX(is_documentation, ?), is_private = MAX(is_private, ?) WHERE id = ?', [
      now,
      input.isDocumentation ? 1 : 0,
      input.isPrivate ? 1 : 0,
      existing.id,
    ]);
    return q.get<IocRow>('SELECT * FROM iocs WHERE id = ?', [existing.id])!;
  }
  const id = q.insert(
    `INSERT INTO iocs (type, value, value_hash, is_documentation, is_private, times_seen, first_seen_at, last_seen_at, created_at)
     VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)`,
    [input.type, input.value, hash, input.isDocumentation ? 1 : 0, input.isPrivate ? 1 : 0, now, now, now],
  );
  return q.get<IocRow>('SELECT * FROM iocs WHERE id = ?', [id])!;
}

export const findIoc = (id: number): IocRow | undefined => q.get<IocRow>('SELECT * FROM iocs WHERE id = ?', [id]);

export const findIocByValue = (type: IocType, value: string): IocRow | undefined =>
  q.get<IocRow>('SELECT * FROM iocs WHERE type = ? AND value_hash = ?', [type, valueHash(type, value)]);

export const listIocs = (limit = 100, offset = 0): IocRow[] =>
  q.all<IocRow>('SELECT * FROM iocs ORDER BY last_seen_at DESC LIMIT ? OFFSET ?', [limit, offset]);

export const countIocs = (): number => q.get<{ n: number }>('SELECT COUNT(*) AS n FROM iocs')?.n ?? 0;

export const setIocNotes = (id: number, notes: string): void => {
  q.run('UPDATE iocs SET notes = ? WHERE id = ?', [notes.slice(0, 4000), id]);
};

// ============================================================ relationships
export interface IocRelationshipRow {
  id: number;
  source_ioc_id: number;
  target_ioc_id: number;
  relation: string;
  direction: 'directed' | 'undirected';
  confidence: 'high' | 'medium' | 'low';
  source_provider: string;
  observation_count: number;
  first_observed_at: string;
  last_observed_at: string;
  meta_json: string;
}

/** Record (or reinforce) a relationship observed by a provider. */
export function recordRelationship(input: {
  sourceIocId: number;
  targetIocId: number;
  relation: string;
  confidence: 'high' | 'medium' | 'low';
  sourceProvider: string;
  meta?: Record<string, unknown>;
}): void {
  if (input.sourceIocId === input.targetIocId) return;
  const existing = q.get<IocRelationshipRow>(
    'SELECT * FROM ioc_relationships WHERE source_ioc_id = ? AND target_ioc_id = ? AND relation = ?',
    [input.sourceIocId, input.targetIocId, input.relation],
  );
  const now = nowIso();
  if (existing) {
    q.run('UPDATE ioc_relationships SET observation_count = observation_count + 1, last_observed_at = ?, confidence = ? WHERE id = ?', [
      now,
      input.confidence,
      existing.id,
    ]);
    return;
  }
  q.insert(
    `INSERT INTO ioc_relationships
       (source_ioc_id, target_ioc_id, relation, direction, confidence, source_provider, observation_count, first_observed_at, last_observed_at, meta_json)
     VALUES (?, ?, ?, 'directed', ?, ?, 1, ?, ?, ?)`,
    [
      input.sourceIocId,
      input.targetIocId,
      input.relation,
      input.confidence,
      input.sourceProvider,
      now,
      now,
      JSON.stringify(input.meta ?? {}),
    ],
  );
}

export interface LearnedEdge {
  otherValue: string;
  otherType: IocType;
  relation: string;
  confidence: 'high' | 'medium' | 'low';
  sourceProvider: string;
  sourceInvestigationId: number | null;
  sourceIocId: number;
  subjectIocId: number;
  meta: Record<string, unknown>;
  lastObservedAt: string;
  observationCount: number;
}

/**
 * Relationships learned in *earlier* investigations where this indicator was
 * one side of the edge. Powers the correlation graph's cross-investigation
 * memory.
 */
export function learnedRelationshipsFor(iocId: number, limit = 40): LearnedEdge[] {
  const rows = q.all<
    IocRelationshipRow & { other_id: number; other_value: string; other_type: IocType; inv_id: number | null }
  >(
    `SELECT r.*, o.id AS other_id, o.value AS other_value, o.type AS other_type,
            (SELECT id FROM investigations WHERE ioc_id = r.source_ioc_id ORDER BY id DESC LIMIT 1) AS inv_id
       FROM ioc_relationships r
       JOIN iocs o ON o.id = r.target_ioc_id
      WHERE r.source_ioc_id = ?
      UNION ALL
     SELECT r.*, o.id AS other_id, o.value AS other_value, o.type AS other_type,
            (SELECT id FROM investigations WHERE ioc_id = r.target_ioc_id ORDER BY id DESC LIMIT 1) AS inv_id
       FROM ioc_relationships r
       JOIN iocs o ON o.id = r.source_ioc_id
      WHERE r.target_ioc_id = ?
      LIMIT ?`,
    [iocId, iocId, limit],
  );
  return rows.map((r) => ({
    otherValue: r.other_value,
    otherType: r.other_type,
    relation: r.relation,
    confidence: r.confidence,
    sourceProvider: r.source_provider,
    sourceInvestigationId: r.inv_id,
    sourceIocId: r.source_ioc_id,
    subjectIocId: iocId,
    meta: fromJson<Record<string, unknown>>(r.meta_json, {}),
    lastObservedAt: r.last_observed_at,
    observationCount: r.observation_count,
  }));
}

export const relationshipsForIoc = (iocId: number, limit = 60) =>
  q.all<
    IocRelationshipRow & { other_id: number; other_value: string; other_type: IocType; inv_id: number | null }
  >(
    `SELECT r.*, o.id AS other_id, o.value AS other_value, o.type AS other_type,
            (SELECT id FROM investigations WHERE ioc_id = r.source_ioc_id ORDER BY id DESC LIMIT 1) AS inv_id
       FROM ioc_relationships r
       JOIN iocs o ON o.id = r.target_ioc_id
      WHERE r.source_ioc_id = ?
      UNION ALL
     SELECT r.*, o.id AS other_id, o.value AS other_value, o.type AS other_type,
            (SELECT id FROM investigations WHERE ioc_id = r.target_ioc_id ORDER BY id DESC LIMIT 1) AS inv_id
       FROM ioc_relationships r
       JOIN iocs o ON o.id = r.source_ioc_id
      WHERE r.target_ioc_id = ?
      LIMIT ?`,
    [iocId, iocId, limit],
  );
