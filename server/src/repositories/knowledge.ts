/**
 * Threat knowledge repository: MITRE techniques, threat actors, malware families
 * and campaigns, plus the junction tables that link them to investigations.
 *
 * Normalisation rationale: an actor, a malware family and a campaign are
 * reference entities that appear in many investigations. They are upserted by
 * their external id, so investigating the same malware family twice does not
 * duplicate it, and the /threat-actors page can aggregate "how many of our
 * investigations touched this actor" with a simple join.
 */
import { fromJson, getDb, nowIso, q } from '../db/index.js';
import { attackUrl, TECHNIQUES, type TechniqueSeed } from '../providers/mitre/index.js';
import type { Confidence, IocType } from '../core/types.js';

// ------------------------------------------------------------- techniques
export interface TechniqueRow {
  id: number;
  external_id: string;
  name: string;
  is_subtechnique: number;
  parent_external_id: string | null;
  tactic: string;
  tactics_json: string;
  description: string | null;
  platforms_json: string;
  data_sources_json: string;
  detection_json: string;
  reference_url: string;
  attack_version: string | null;
}

export const ATTACK_VERSION = 'v14.1 (curated subset)';

export function seedTechniques(seeds: TechniqueSeed[] = TECHNIQUES): number {
  let created = 0;
  const insert = getDb().prepare(
    `INSERT INTO mitre_techniques
       (external_id, name, is_subtechnique, parent_external_id, tactic, tactics_json, description, platforms_json, data_sources_json, detection_json, reference_url, attack_version, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(external_id) DO UPDATE SET
       name = excluded.name,
       tactic = excluded.tactic,
       tactics_json = excluded.tactics_json,
       description = excluded.description,
       platforms_json = excluded.platforms_json,
       data_sources_json = excluded.data_sources_json,
       reference_url = excluded.reference_url,
       attack_version = excluded.attack_version`,
  );
  const run = getDb().transaction((list: TechniqueSeed[]) => {
    for (const t of list) {
      const info = insert.run(
        t.externalId,
        t.name,
        t.isSubtechnique ? 1 : 0,
        t.parentExternalId ?? null,
        t.tactics[0] ?? 'unknown',
        JSON.stringify(t.tactics),
        t.description ?? null,
        JSON.stringify(t.platforms ?? []),
        JSON.stringify(t.dataSources ?? []),
        JSON.stringify([]),
        attackUrl(t.externalId),
        ATTACK_VERSION,
        nowIso(),
      );
      if (info.changes > 0) created += 1;
    }
  });
  run(seeds);
  return created;
}

export const findTechniqueByExternalId = (externalId: string): TechniqueRow | undefined =>
  q.get<TechniqueRow>('SELECT * FROM mitre_techniques WHERE external_id = ?', [externalId]);

export const listTechniques = (): TechniqueRow[] =>
  q.all<TechniqueRow>('SELECT * FROM mitre_techniques ORDER BY external_id ASC');

export const countTechniques = (): number => q.get<{ n: number }>('SELECT COUNT(*) AS n FROM mitre_techniques')?.n ?? 0;

/** Techniques observed across investigations, with usage counts. */
export const techniqueUsage = () =>
  q.all<{ external_id: string; name: string; tactic: string; count: number; last_seen: string }>(
    `SELECT t.external_id, t.name, t.tactic, COUNT(*) AS count, MAX(i.completed_at) AS last_seen
       FROM investigation_techniques it
       JOIN mitre_techniques t ON t.id = it.technique_id
       JOIN investigations i ON i.id = it.investigation_id
      GROUP BY t.id
      ORDER BY count DESC, t.external_id ASC`,
  );

// ----------------------------------------------------------------- actors
export interface ActorRow {
  id: number;
  external_id: string;
  name: string;
  aliases_json: string;
  origin: 'live' | 'demo' | 'community';
  sophistication: string | null;
  motivation_json: string;
  first_seen_year: number | null;
  description: string | null;
  reference_url: string | null;
  created_at: string;
}

export function upsertActor(input: Omit<ActorRow, 'id' | 'created_at'>): number {
  const existing = q.get<{ id: number }>('SELECT id FROM threat_actors WHERE external_id = ?', [input.external_id]);
  if (existing) {
    q.run(
      `UPDATE threat_actors SET name = ?, aliases_json = ?, origin = ?, sophistication = ?, motivation_json = ?,
              first_seen_year = ?, description = ?, reference_url = ? WHERE id = ?`,
      [
        input.name,
        JSON.stringify(input.aliases_json ? JSON.parse(input.aliases_json) : []),
        input.origin,
        input.sophistication,
        input.motivation_json,
        input.first_seen_year,
        input.description,
        input.reference_url,
        existing.id,
      ],
    );
    return existing.id;
  }
  return q.insert(
    `INSERT INTO threat_actors (external_id, name, aliases_json, origin, sophistication, motivation_json, first_seen_year, description, reference_url, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      input.external_id,
      input.name,
      input.aliases_json,
      input.origin,
      input.sophistication,
      input.motivation_json,
      input.first_seen_year,
      input.description,
      input.reference_url,
      nowIso(),
    ],
  );
}

export const findActorByName = (name: string): ActorRow | undefined =>
  q.get<ActorRow>('SELECT * FROM threat_actors WHERE name = ? COLLATE NOCASE OR external_id = ? COLLATE NOCASE', [name, name]);

export const listActors = () =>
  q.all<
    ActorRow & { investigation_count: number; indicator_count: number; malware_count: number; campaign_count: number; last_seen: string | null }
  >(
    `SELECT a.*,
            (SELECT COUNT(DISTINCT it.investigation_id) FROM investigation_actors it WHERE it.actor_id = a.id) AS investigation_count,
            (SELECT COUNT(DISTINCT i.ioc_id) FROM investigation_actors it JOIN investigations i ON i.id = it.investigation_id WHERE it.actor_id = a.id) AS indicator_count,
            (SELECT COUNT(DISTINCT im.malware_id) FROM investigation_actors it2 JOIN investigation_malware im ON im.investigation_id = it2.investigation_id WHERE it2.actor_id = a.id) AS malware_count,
            (SELECT COUNT(DISTINCT ic.campaign_id) FROM investigation_actors it3 JOIN investigation_campaigns ic ON ic.investigation_id = it3.investigation_id WHERE it3.actor_id = a.id) AS campaign_count,
            (SELECT MAX(i.completed_at) FROM investigation_actors it4 JOIN investigations i ON i.id = it4.investigation_id WHERE it4.actor_id = a.id) AS last_seen
       FROM threat_actors a
      ORDER BY investigation_count DESC, a.name ASC`,
  );

export const actorsForInvestigation = (investigationId: number) =>
  q.all<ActorRow & { confidence: Confidence; basis: string }>(
    `SELECT a.*, ia.confidence, ia.basis
       FROM investigation_actors ia JOIN threat_actors a ON a.id = ia.actor_id
      WHERE ia.investigation_id = ?`,
    [investigationId],
  );

export const malwareForInvestigation = (investigationId: number) =>
  q.all<MalwareRow & { confidence: Confidence; basis: string; detections: number | null }>(
    `SELECT m.*, im.confidence, im.basis, im.detections
       FROM investigation_malware im JOIN malware m ON m.id = im.malware_id
      WHERE im.investigation_id = ?`,
    [investigationId],
  );

export const campaignsForInvestigation = (investigationId: number) =>
  q.all<CampaignRow & { confidence: Confidence; basis: string }>(
    `SELECT c.*, ic.confidence, ic.basis
       FROM investigation_campaigns ic JOIN campaigns c ON c.id = ic.campaign_id
      WHERE ic.investigation_id = ?`,
    [investigationId],
  );

export const techniquesForInvestigation = (investigationId: number) =>
  q.all<
    TechniqueRow & { relationship: string; confidence: Confidence; mapping_basis: string; rationale: string }
  >(
    `SELECT t.*, it.relationship, it.confidence, it.mapping_basis, it.rationale
       FROM investigation_techniques it JOIN mitre_techniques t ON t.id = it.technique_id
      WHERE it.investigation_id = ?
      ORDER BY it.sort_order ASC, t.external_id ASC`,
    [investigationId],
  );

export const linkTechnique = (input: {
  investigationId: number;
  techniqueId: number;
  relationship: string;
  confidence: Confidence;
  mappingBasis: string;
  rationale: string;
  sortOrder: number;
}): void => {
  q.run(
    `INSERT INTO investigation_techniques (investigation_id, technique_id, relationship, confidence, mapping_basis, rationale, sort_order)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(investigation_id, technique_id) DO UPDATE SET
       relationship = excluded.relationship, confidence = excluded.confidence,
       mapping_basis = excluded.mapping_basis, rationale = excluded.rationale`,
    [input.investigationId, input.techniqueId, input.relationship, input.confidence, input.mappingBasis, input.rationale, input.sortOrder],
  );
};

export const linkActor = (input: { investigationId: number; actorId: number; confidence: Confidence; basis: string }): void => {
  q.run(
    `INSERT INTO investigation_actors (investigation_id, actor_id, confidence, basis) VALUES (?, ?, ?, ?)
     ON CONFLICT(investigation_id, actor_id) DO UPDATE SET confidence = excluded.confidence, basis = excluded.basis`,
    [input.investigationId, input.actorId, input.confidence, input.basis],
  );
};

// --------------------------------------------------------------- malware
export interface MalwareRow {
  id: number;
  external_id: string;
  name: string;
  aliases_json: string;
  malware_type: string | null;
  platform_json: string;
  capabilities_json: string;
  origin: 'live' | 'demo' | 'community';
  description: string | null;
  reference_url: string | null;
  created_at: string;
}

export function upsertMalware(input: Omit<MalwareRow, 'id' | 'created_at'>): number {
  const existing = q.get<{ id: number }>('SELECT id FROM malware WHERE external_id = ?', [input.external_id]);
  if (existing) {
    q.run(
      `UPDATE malware SET name = ?, aliases_json = ?, malware_type = ?, platform_json = ?, capabilities_json = ?,
              origin = ?, description = ?, reference_url = ? WHERE id = ?`,
      [input.name, input.aliases_json, input.malware_type, input.platform_json, input.capabilities_json, input.origin, input.description, input.reference_url, existing.id],
    );
    return existing.id;
  }
  return q.insert(
    `INSERT INTO malware (external_id, name, aliases_json, malware_type, platform_json, capabilities_json, origin, description, reference_url, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [input.external_id, input.name, input.aliases_json, input.malware_type, input.platform_json, input.capabilities_json, input.origin, input.description, input.reference_url, nowIso()],
  );
}

export const findMalwareByName = (name: string): MalwareRow | undefined =>
  q.get<MalwareRow>('SELECT * FROM malware WHERE name = ? COLLATE NOCASE', [name]);

export const listMalware = () =>
  q.all<MalwareRow & { investigation_count: number; actor_count: number; last_seen: string | null }>(
    `SELECT m.*,
            (SELECT COUNT(DISTINCT investigation_id) FROM investigation_malware WHERE malware_id = m.id) AS investigation_count,
            (SELECT COUNT(DISTINCT actor_id) FROM investigation_malware im JOIN investigation_actors ia ON ia.investigation_id = im.investigation_id WHERE im.malware_id = m.id) AS actor_count,
            (SELECT MAX(i.completed_at) FROM investigation_malware im JOIN investigations i ON i.id = im.investigation_id WHERE im.malware_id = m.id) AS last_seen
       FROM malware m
      ORDER BY investigation_count DESC, m.name ASC`,
  );

export const linkMalware = (input: {
  investigationId: number;
  malwareId: number;
  confidence: Confidence;
  basis: string;
  detections: number | null;
}): void => {
  q.run(
    `INSERT INTO investigation_malware (investigation_id, malware_id, confidence, basis, detections) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(investigation_id, malware_id) DO UPDATE SET confidence = excluded.confidence, basis = excluded.basis, detections = excluded.detections`,
    [input.investigationId, input.malwareId, input.confidence, input.basis, input.detections],
  );
};

// ------------------------------------------------------------- campaigns
export interface CampaignRow {
  id: number;
  external_id: string;
  name: string;
  origin: 'live' | 'demo' | 'community';
  first_seen: string | null;
  description: string | null;
  reference_url: string | null;
  created_at: string;
}

export function upsertCampaign(input: Omit<CampaignRow, 'id' | 'created_at'>): number {
  const existing = q.get<{ id: number }>('SELECT id FROM campaigns WHERE external_id = ?', [input.external_id]);
  if (existing) {
    q.run('UPDATE campaigns SET name = ?, origin = ?, first_seen = ?, description = ?, reference_url = ? WHERE id = ?', [
      input.name, input.origin, input.first_seen, input.description, input.reference_url, existing.id,
    ]);
    return existing.id;
  }
  return q.insert(
    `INSERT INTO campaigns (external_id, name, origin, first_seen, description, reference_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [input.external_id, input.name, input.origin, input.first_seen, input.description, input.reference_url, nowIso()],
  );
}

export const findCampaignByName = (name: string): CampaignRow | undefined =>
  q.get<CampaignRow>('SELECT * FROM campaigns WHERE name = ? COLLATE NOCASE OR external_id = ? COLLATE NOCASE', [name, name]);

export const listCampaigns = () =>
  q.all<CampaignRow & { investigation_count: number; last_seen: string | null }>(
    `SELECT c.*,
            (SELECT COUNT(DISTINCT investigation_id) FROM investigation_campaigns WHERE campaign_id = c.id) AS investigation_count,
            (SELECT MAX(i.completed_at) FROM investigation_campaigns ic JOIN investigations i ON i.id = ic.investigation_id WHERE ic.campaign_id = c.id) AS last_seen
       FROM campaigns c ORDER BY investigation_count DESC, c.name ASC`,
  );

export const linkCampaign = (input: { investigationId: number; campaignId: number; confidence: Confidence; basis: string }): void => {
  q.run(
    `INSERT INTO investigation_campaigns (investigation_id, campaign_id, confidence, basis) VALUES (?, ?, ?, ?)
     ON CONFLICT(investigation_id, campaign_id) DO UPDATE SET confidence = excluded.confidence, basis = excluded.basis`,
    [input.investigationId, input.campaignId, input.confidence, input.basis],
  );
};

// ------------------------------------------------------- related indicators
export function linkRelatedIoc(input: {
  investigationId: number;
  relatedIocId: number;
  relation: string;
  confidence: Confidence;
  source: string;
}): void {
  q.run(
    `INSERT INTO investigation_related_iocs (investigation_id, related_ioc_id, relation, confidence, source) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(investigation_id, related_ioc_id, relation) DO UPDATE SET confidence = excluded.confidence, source = excluded.source`,
    [input.investigationId, input.relatedIocId, input.relation, input.confidence, input.source],
  );
}

export const relatedIocsForInvestigation = (investigationId: number) =>
  q.all<{
    relation: string;
    confidence: Confidence;
    source: string;
    ioc_id: number;
    value: string;
    type: IocType;
    is_documentation: number;
  }>(
    `SELECT ir.relation, ir.confidence, ir.source, o.id AS ioc_id, o.value, o.type, o.is_documentation
       FROM investigation_related_iocs ir JOIN iocs o ON o.id = ir.related_ioc_id
      WHERE ir.investigation_id = ?
      ORDER BY ir.relation ASC, o.value ASC`,
    [investigationId],
  );

// ---------------------------------------------------------------- helpers
export const parseJsonArray = (value: string | null | undefined): string[] =>
  fromJson<string[]>(value, []).filter((v): v is string => typeof v === 'string');

export const topCategories = (limit = 10) =>
  q.all<{ category: string; count: number }>(
    `SELECT category, COUNT(*) AS count
       FROM (
         SELECT je.value AS category
           FROM enrichment_results e, json_each(e.related_json, '$.categories') je
          WHERE json_valid(e.related_json)
       )
      GROUP BY category
      ORDER BY count DESC
      LIMIT ?`,
    [limit],
  );
