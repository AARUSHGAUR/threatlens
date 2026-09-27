/**
 * ============================================================================
 * IOC CORRELATION ENGINE  (CTI lifecycle: "Correlation")
 * ============================================================================
 *
 * Takes the aggregated intelligence for one indicator and turns it into a
 * graph of entities and *typed, explained* relationships. Every edge carries a
 * relation name, a human description and a confidence, because an unexplained
 * edge in a CTI graph is worse than no edge at all.
 *
 * EDGE CONSTRUCTION RULES (deterministic, evidence-based):
 *  - Indicator <-> indicator edges are typed by the *entity types involved*
 *    (ip -> domain is "reverse-resolves-to", domain -> ip is "resolves-to",
 *    url -> domain/ip is "served-by", hash -> host is "staged-on", ...).
 *  - Malware / actor / campaign / technique nodes are attached to the subject
 *    indicator with the relation that the source actually asserted.
 *  - Actor -> malware and actor -> campaign edges are only emitted when BOTH
 *    entities were reported by the *same* source verdict. That is a sound
 *    inference ("this source links this actor, this campaign and this malware
 *    to the same indicator") and is labelled as such in the description.
 *  - Edges learned during previous investigations (persisted in
 *    `ioc_relationships`) are merged in, which is what makes the graph grow
 *    into a real intelligence base over time.
 */
import type {
  Confidence,
  CorrelationEdge,
  CorrelationGraph,
  CorrelationNode,
  IocType,
  NormalizedIoc,
  RiskLevel,
  TechniqueMapping,
} from '../types.js';
import type { AggregatedIntel } from '../aggregate.js';

const edgeId = (source: string, target: string, relation: string): string =>
  `${source}::${relation}::${target}`.replace(/\s+/g, '_');

const nodeId = (type: string, label: string): string => `${type}:${label.toLowerCase()}`;

/** Guess the entity type of a bare string (used for related entities). */
export function inferType(value: string): CorrelationNode['type'] {
  const v = value.trim();
  if (/^[0-9a-f]{64}$/i.test(v)) return 'hash';
  if (/^[0-9a-f]{40}$/i.test(v)) return 'hash';
  if (/^[0-9a-f]{32}$/i.test(v)) return 'hash';
  if (/^https?:\/\//i.test(v)) return 'url';
  if (/^[0-9a-f:]+$/i.test(v) && v.includes(':') && /^[0-9a-f:.]+$/i.test(v)) return 'ip';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ip';
  if (v.includes('@')) return 'email';
  return 'domain';
}

/**
 * Map a stored IOC type onto the graph's entity-type vocabulary.
 *
 * This MUST be exhaustive: the graph vocabulary is coarser than the IOC types
 * (every hash algorithm collapses to `hash`, both address families to `ip`), and
 * leaking an unmapped value would produce a node type the UI has no styling for.
 */
export function iocTypeToNodeType(type: IocType): CorrelationNode['type'] {
  switch (type) {
    case 'ipv4':
    case 'ipv6':
      return 'ip';
    case 'md5':
    case 'sha1':
    case 'sha256':
      return 'hash';
    case 'domain':
      return 'domain';
    case 'url':
      return 'url';
    case 'email':
      return 'email';
    default:
      return 'ioc';
  }
}

const RELATION_BY_PAIR: Partial<Record<`${CorrelationNode['type']}->${CorrelationNode['type']}`, { relation: string; description: string }>> = {
  'ip->domain': { relation: 'reverse-resolves-to', description: 'Passive DNS / reverse DNS observation linking the host to this domain.' },
  'domain->ip': { relation: 'resolves-to', description: 'Passive DNS observation: this domain resolved to the address.' },
  'url->domain': { relation: 'served-by', description: 'The URL was served from this host.' },
  'url->ip': { relation: 'served-by', description: 'The URL was served from this address.' },
  'hash->domain': { relation: 'staged-on', description: 'The sample was downloaded from this host.' },
  'hash->ip': { relation: 'staged-on', description: 'The sample was downloaded from this address.' },
  'hash->url': { relation: 'retrieved-from', description: 'The sample was downloaded from this URL.' },
  'email->domain': { relation: 'sent-from', description: 'The address was observed sending from this domain.' },
  'domain->email': { relation: 'sender-domain', description: 'Addresses at this domain were observed as senders.' },
  'ip->ip': { relation: 'communicates-with', description: 'Observed communication between these two addresses.' },
  'domain->domain': { relation: 'related-domain', description: 'Both domains appear together in the same intelligence context.' },
  'url->url': { relation: 'related-url', description: 'Both URLs appear together in the same intelligence context.' },
  'hash->hash': { relation: 'related-sample', description: 'Both samples appear together in the same intelligence context.' },
  'email->email': { relation: 'related-address', description: 'Both addresses appear together in the same intelligence context.' },
  'ip->url': { relation: 'served', description: 'This address served this URL.' },
  'ip->hash': { relation: 'downloaded', description: 'This address distributed this sample.' },
  'domain->url': { relation: 'hosts', description: 'This domain hosted this URL.' },
  'domain->hash': { relation: 'staged', description: 'This domain staged this sample.' },
  'url->hash': { relation: 'delivers', description: 'This URL delivered this sample.' },
  'url->email': { relation: 'delivered-to', description: 'This URL was delivered to recipients in this domain.' },
  'ip->email': { relation: 'delivered-to', description: 'This address served content delivered to this mailbox domain.' },
};

export interface CorrelateInput {
  ioc: NormalizedIoc;
  intel: AggregatedIntel;
  riskLevel: RiskLevel;
  techniques: TechniqueMapping[];
  /** Relationships learned during previous investigations of other indicators. */
  learnedEdges: LearnedRelationship[];
}

export interface LearnedRelationship {
  otherValue: string;
  otherType: IocType;
  relation: string;
  confidence: Confidence;
  sourceProvider: string;
  sourceInvestigationId: number | null;
  /** Only the edge whose source is the current subject indicator is rendered. */
  sourceIocId: number;
  subjectIocId: number;
}

export function buildCorrelationGraph(input: CorrelateInput): CorrelationGraph {
  const { ioc, intel, techniques } = input;
  const subjectType: CorrelationNode['type'] = iocTypeToNodeType(ioc.type);

  const nodes = new Map<string, CorrelationNode>();
  const edges = new Map<string, CorrelationEdge>();

  const subjectNodeId = nodeId('ioc', ioc.value);
  nodes.set(subjectNodeId, {
    id: subjectNodeId,
    label: ioc.value,
    type: subjectType,
    isSubject: true,
    riskLevel: input.riskLevel,
    meta: { iocType: ioc.type, verdict: intel.verdict },
  });

  const addEdge = (
    source: string,
    target: string,
    relation: string,
    description: string,
    confidence: Confidence,
  ): void => {
    if (source === target) return;
    const id = edgeId(source, target, relation);
    if (edges.has(id)) return;
    edges.set(id, { id, source, target, relation, description, confidence });
  };

  const addNode = (
    type: CorrelationNode['type'],
    label: string,
    meta?: Record<string, string | number | null>,
  ): string => {
    const id = nodeId(type, label);
    if (!nodes.has(id)) nodes.set(id, { id, label, type, isSubject: false, meta });
    return id;
  };

  // ------------------------------------------------------------- 1. network
  const asnLabel = intel.network?.asnOrg ?? intel.network?.isp;
  if (asnLabel) {
    const id = addNode('asn', asnLabel, {
      asn: intel.network?.asn ?? null,
      isp: intel.network?.isp ?? null,
      country: intel.network?.country ?? null,
    });
    addEdge(subjectNodeId, id, 'hosted-in', `Attributed to the network operator reported by intelligence sources.`, 'medium');
  }

  // ------------------------------------------------------- 2. related IOCs
  const relatedGroups: Array<{ values: string[]; type: CorrelationNode['type'] }> = [
    { values: intel.related.domains, type: 'domain' },
    { values: intel.related.ipAddresses, type: 'ip' },
    { values: intel.related.urls, type: 'url' },
    { values: intel.related.hashes, type: 'hash' },
    { values: intel.related.emails, type: 'email' },
  ];

  for (const group of relatedGroups) {
    for (const value of group.values.slice(0, 12)) {
      const clean = value.trim();
      if (!clean) continue;
      const targetType = inferType(clean);
      const id = addNode(targetType, clean);
      const key = `${subjectType}->${targetType}` as keyof typeof RELATION_BY_PAIR;
      const spec = RELATION_BY_PAIR[key] ?? {
        relation: 'related-to',
        description: 'Reported by intelligence sources in the same context as the subject indicator.',
      };
      addEdge(subjectNodeId, id, spec.relation, spec.description, 'medium');
    }
  }

  // ---------------------------------------- 3. malware / actors / campaigns
  const providersByEntity = new Map<string, string[]>();
  for (const verdict of intel.providers) {
    for (const m of verdict.related.malware) providersByEntity.set(`malware:${m.toLowerCase()}`, [...(providersByEntity.get(`malware:${m.toLowerCase()}`) ?? []), verdict.providerName]);
    for (const a of verdict.related.actors) providersByEntity.set(`actor:${a.toLowerCase()}`, [...(providersByEntity.get(`actor:${a.toLowerCase()}`) ?? []), verdict.providerName]);
    for (const c of verdict.related.campaigns) providersByEntity.set(`campaign:${c.toLowerCase()}`, [...(providersByEntity.get(`campaign:${c.toLowerCase()}`) ?? []), verdict.providerName]);
  }

  for (const family of intel.malware.slice(0, 10)) {
    const id = addNode('malware', family, { type: 'family' });
    addEdge(subjectNodeId, id, 'associated-malware', `Sources identify this indicator as infrastructure or artefact of "${family}".`, 'medium');
  }
  for (const actor of intel.actors.slice(0, 8)) {
    const id = addNode('actor', actor);
    addEdge(subjectNodeId, id, 'attributed-to', `Community intelligence attributes this indicator to "${actor}".`, 'medium');
  }
  for (const campaign of intel.campaigns.slice(0, 8)) {
    const id = addNode('campaign', campaign);
    addEdge(subjectNodeId, id, 'part-of-campaign', `Reported in the context of campaign "${campaign}".`, 'medium');
  }

  // Actor -> malware / campaign edges ONLY when one source reported both.
  for (const verdict of intel.providers) {
    const { actors, malware, campaigns } = verdict.related;
    for (const actor of actors.slice(0, 3)) {
      const actorId = addNode('actor', actor);
      for (const family of malware.slice(0, 5)) {
        const malwareId = addNode('malware', family, { type: 'family' });
        addEdge(
          actorId,
          malwareId,
          'contextually-associated',
          `${verdict.providerName} reported this actor and this malware family for the same indicator, which supports - but does not prove - a direct relationship.`,
          'low',
        );
      }
      for (const campaign of campaigns.slice(0, 3)) {
        const campaignId = addNode('campaign', campaign);
        addEdge(
          actorId,
          campaignId,
          'contextually-associated',
          `${verdict.providerName} reported this actor together with this campaign for the same indicator.`,
          'low',
        );
      }
    }
  }

  // ------------------------------------------------- 4. ATT&CK technique nodes
  for (const technique of techniques) {
    const id = addNode('campaign', `ATT&CK ${technique.techniqueId}`, {
      techniqueId: technique.techniqueId,
      technique: technique.name,
      tactic: technique.tactic,
    });
    addEdge(
      subjectNodeId,
      id,
      'mapped-technique',
      `${technique.techniqueId} - ${technique.name} (${technique.tactic}): ${technique.relationship}`,
      technique.confidence,
    );
  }

  // --------------------------------------- 5. relationships from prior runs
  // The correlation layer's "memory": edges learned during previous
  // investigations of *other* indicators. They are rendered with lower
  // confidence because the observation is second-hand.
  for (const learned of input.learnedEdges) {
    if (learned.subjectIocId !== learned.sourceIocId) continue;
    const id = addNode(iocTypeToNodeType(learned.otherType), learned.otherValue, { learned: 'true' });
    const otherType = iocTypeToNodeType(learned.otherType);
    const key = `${subjectType}->${otherType}` as keyof typeof RELATION_BY_PAIR;
    const spec = RELATION_BY_PAIR[key] ?? {
      relation: 'related-to',
      description: 'Observed together in an earlier ThreatLens investigation.',
    };
    addEdge(
      subjectNodeId,
      id,
      spec.relation,
      `${spec.description} (learned from investigation #${learned.sourceInvestigationId ?? 'n/a'}, provider: ${learned.sourceProvider}).`,
      'low',
    );
  }

  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}

/**
 * Persist the indicator-to-indicator relationships discovered during a run so
 * future investigations of *other* indicators can reuse them (the correlation
 * layer's memory).
 */
export function extractPersistableRelationships(
  ioc: NormalizedIoc,
  intel: AggregatedIntel,
  providerId: string,
): Array<{ value: string; type: IocType; relation: string; confidence: Confidence; meta: Record<string, unknown> }> {
  const out: Array<{ value: string; type: IocType; relation: string; confidence: Confidence; meta: Record<string, unknown> }> = [];
  const push = (value: string, type: IocType, relation: string, confidence: Confidence) => {
    const clean = value.trim();
    if (!clean) return;
    out.push({ value: clean, type, relation, confidence, meta: { sourceProvider: providerId } });
  };

  for (const d of intel.related.domains.slice(0, 10)) push(d, 'domain', 'related_domain', 'medium');
  for (const ip of intel.related.ipAddresses.slice(0, 10)) push(ip, ipTypeFor(ip), 'related_ip', 'medium');
  for (const u of intel.related.urls.slice(0, 10)) push(u, 'url', 'related_url', 'medium');
  for (const h of intel.related.hashes.slice(0, 10)) push(h, hashTypeFor(h), 'related_hash', 'medium');
  for (const e of intel.related.emails.slice(0, 5)) push(e, 'email', 'related_email', 'medium');

  void ioc;
  return out;
}

/** Map a bare address string onto the correct IOC type. */
export function ipTypeFor(value: string): IocType {
  const v = value.trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ipv4';
  return 'ipv6';
}

export function hashTypeFor(value: string): IocType {
  const v = value.trim();
  if (v.length === 32) return 'md5';
  if (v.length === 40) return 'sha1';
  return 'sha256';
}
