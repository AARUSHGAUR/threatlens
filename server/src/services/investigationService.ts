/**
 * ============================================================================
 * INVESTIGATION ORCHESTRATION SERVICE  (the CTI pipeline)
 * ============================================================================
 *
 * Implements the full lifecycle for a single indicator:
 *
 *   1. COLLECTION     - accept the indicator, normalise it, record provenance
 *   2. PROCESSING     - detect the type, validate, flag documentation/private
 *   3. ENRICHMENT     - query every applicable provider (live or demo)
 *   4. CORRELATION    - merge provider verdicts, build the entity graph
 *   5. ANALYSIS       - explainable risk score + ATT&CK mapping
 *   6. PRODUCTION     - persist evidence, timeline, recommendations, entities
 *   7. DISSEMINATION  - expose through REST/report (handled by routes/reports)
 *
 * IMPORTANT: providers are called OUTSIDE any database transaction, and the
 * write phase is a single short transaction. The UI polls
 * `GET /investigations/:id/progress`, whose timeline is written incrementally -
 * so the analyst sees real progress, not a fake spinner.
 */
import { randomUUID } from 'node:crypto';
import { getDb, q } from '../db/index.js';
import { logger } from '../config/logger.js';
import type {
  IocType,
  NormalizedIoc,
  ProviderVerdict,
  RiskFactor,
  TechniqueMapping,
} from '../core/types.js';
import { aggregateIntelligence, type AggregatedIntel } from '../core/aggregate.js';
import { scoreRisk, type RiskSignals } from '../core/risk/engine.js';
import { mapTechniques } from '../core/mitre/mapper.js';
import { extractPersistableRelationships } from '../core/correlation/correlator.js';
import { buildDefensiveActions } from '../core/recommendations/engine.js';
import { shannonEntropy, validateIoc, type ValidationWarning } from '../core/ioc/validate.js';
import { DEMO_ACTORS, DEMO_CAMPAIGNS, DEMO_MALWARE } from '../providers/demo/dataset.js';
import { DemoProvider, primeDemoLabels } from '../providers/demo/index.js';
import { planProviderRuns, providerSupports, recordProviderStatus, resolveMode, type ResolvedMode } from '../providers/registry.js';
import { upsertIoc, recordRelationship, type IocRow } from '../repositories/indicators.js';
import {
  addTimelineEvent,
  createInvestigation,
  findInvestigation,
  insertEnrichment,
  nextTimelineSeq,
  replaceRiskFactors,
  updateInvestigation,
  type InvestigationRow,
} from '../repositories/investigations.js';
import {
  findMalwareByName,
  findTechniqueByExternalId,
  linkActor,
  linkCampaign,
  linkMalware,
  linkRelatedIoc,
  linkTechnique,
  upsertActor,
  upsertCampaign,
  upsertMalware,
} from '../repositories/knowledge.js';
import { audit } from '../repositories/users.js';

// Prime the demo label maps once (breaks the circular import cleanly).
primeDemoLabels({
  malware: new Map(DEMO_MALWARE.map((m) => [m.externalId, m.name])),
  actors: new Map(DEMO_ACTORS.map((a) => [a.externalId, a.name])),
  campaigns: new Map(DEMO_CAMPAIGNS.map((c) => [c.externalId, c.name])),
});

export interface StartResult {
  ok: true;
  investigation: InvestigationRow;
  ioc: IocRow;
  warnings: ValidationWarning[];
  mode: ResolvedMode;
}

export interface StartError {
  ok: false;
  error: { code: string; message: string; hint?: string };
}

export type StartOutcome = StartResult | StartError;

/** Static signals derived from the indicator itself (no external data). */
export function computeSignals(ioc: NormalizedIoc, intel: AggregatedIntel, warnings: ValidationWarning[]): RiskSignals {
  const hostname = ioc.parsed.hostname ?? '';
  const firstLabel = hostname.split('.')[0] ?? '';
  const nonStandardFromUrl = Boolean(ioc.parsed.port) && ![80, 443, 8080, 8443].includes(ioc.parsed.port as number);
  const nonStandardFromShodan = intel.behaviours.includes('non-standard-port-exposed');
  return {
    nonStandardPort: ioc.type === 'url' ? nonStandardFromUrl : nonStandardFromShodan,
    punycode: Boolean(ioc.parsed.isPunycode) || warnings.some((w) => w.code === 'PUNYCODE'),
    highEntropy:
      firstLabel.length >= 10 && shannonEntropy(firstLabel) >= 3.4
      ? true
      : warnings.some((w) => w.code === 'HIGH_ENTROPY_LABEL') || intel.behaviours.includes('dga-like-hosting'),
    deepSubdomain: Boolean(ioc.parsed.subdomainDepth && ioc.parsed.subdomainDepth >= 4),
    newlyRegistered: intel.categories.some((c) => /newly-registered|fresh|just-registered/i.test(c)),
    documentationRange: warnings.some((w) => w.code === 'DOCUMENTATION_RANGE'),
  };
}

export async function startInvestigation(
  input: {
    indicator: string;
    userId: string | number | null;
    forceMode?: ResolvedMode;
  },
  /** Seeding uses `awaitCompletion` so the dashboard is populated deterministically. */
  options: { awaitCompletion?: boolean } = {},
): Promise<StartOutcome> {
  const validation = validateIoc(input.indicator);
  if (!validation.ok) {
    return { ok: false, error: validation.error };
  }

  const { ioc, warnings, notes } = validation;
  const mode = input.forceMode ?? resolveMode();

  const iocRow = upsertIoc({
    type: ioc.type,
    value: ioc.value,
    isDocumentation: warnings.some((w) => w.code === 'DOCUMENTATION_RANGE'),
    isPrivate: warnings.some((w) => w.code === 'PRIVATE_ADDRESS' || w.code === 'LINK_LOCAL'),
  });

  const investigation = createInvestigation({
    iocId: iocRow.id,
    requestedBy: typeof input.userId === 'number' ? input.userId : null,
    mode,
  });

  // Timeline seed events (the "processing" stage is already complete).
  addTimelineEvent({
    investigationId: investigation.id,
    seq: 1,
    kind: 'investigation',
    title: 'Investigation opened',
    description: `Analyst submitted indicator "${ioc.value}" for enrichment in ${mode === 'demo' ? 'DEMO MODE (simulated intelligence)' : 'LIVE INTELLIGENCE mode'}.`,
    source: 'threatlens:analyst',
    meta: { reference: investigation.reference, mode },
  });
  addTimelineEvent({
    investigationId: investigation.id,
    seq: 2,
    kind: 'validation',
    title: `Indicator validated as ${ioc.type.toUpperCase()}`,
    description: notes.join(' '),
    source: 'threatlens:validation',
    meta: {
      type: ioc.type,
      canonicalValue: ioc.value,
      warnings: warnings.map((w) => ({ code: w.code, message: w.message })),
    },
  });

  updateInvestigation(investigation.id, { status: 'enriching' });
  audit({
    userId: typeof input.userId === 'number' ? input.userId : null,
    action: 'investigation.start',
    entity: 'investigation',
    entityId: String(investigation.id),
    meta: { value: ioc.value, type: ioc.type, mode },
  });

  const runArgs = {
    investigationId: investigation.id,
    ioc,
    iocRow,
    warnings,
    mode,
    userId: typeof input.userId === 'number' ? input.userId : null,
  };

  if (options.awaitCompletion) {
    // Synchronous path (used by `npm run seed`). Errors are already contained
    // inside runPipeline, so a failure here still yields a stored row.
    await runPipeline(runArgs);
    const finished = findInvestigation(investigation.id)!;
    return { ok: true, investigation: finished, ioc: iocRow, warnings, mode };
  }

  // Fire and forget: the client polls /progress while this runs.
  void runPipeline(runArgs).catch((err) => {
    logger.error('pipeline failed', { investigationId: investigation.id, error: String(err) });
  });

  return { ok: true, investigation: findInvestigation(investigation.id)!, ioc: iocRow, warnings, mode };
}

/** Emit a timeline event with the next sequence number. */
function event(
  investigationId: number,
  kind: string,
  title: string,
  description: string,
  source?: string | null,
  meta?: Record<string, unknown> | null,
): void {
  addTimelineEvent({ investigationId, seq: nextTimelineSeq(investigationId), kind, title, description, source, meta });
}

async function runPipeline(input: {
  investigationId: number;
  ioc: NormalizedIoc;
  iocRow: IocRow;
  warnings: ValidationWarning[];
  mode: ResolvedMode;
  userId: number | null;
}): Promise<void> {
  const { investigationId, ioc, iocRow, warnings, mode } = input;
  const started = Date.now();

  try {
    // ------------------------------------------------------- 3. ENRICHMENT
    const runs = planProviderRuns(ioc.type, mode);
    event(
      investigationId,
      'provider',
      'Enrichment started',
      `Dispatching the indicator to ${runs.length} intelligence source${runs.length === 1 ? '' : 's'}.`,
      'threatlens:orchestrator',
      { sources: runs.map((r) => r.id) },
    );

    const collected: ProviderVerdict[] = [];

    if (mode === 'demo') {
      const demoProvider = new DemoProvider();
      const verdicts = demoProvider.lookupAll(ioc, { mode });
      if (verdicts.length === 0) {
        collected.push(demoProvider.notFound(ioc));
        event(
          investigationId,
          'provider-error',
          'No demonstration intelligence available',
          'This indicator is not part of the built-in demo dataset. ThreatLens does not invent intelligence for unknown indicators - configure provider API keys and switch to LIVE INTELLIGENCE for real enrichment.',
          'threatlens:demo',
        );
      } else {
        collected.push(...verdicts);
        for (const v of verdicts) {
          recordProviderStatus(v.providerId, 'ok', 'Demo dataset (simulated).');
          event(
            investigationId,
            'provider',
            `Enriched by ${v.providerName}`,
            v.verdict === 'unknown'
              ? 'Source responded but holds no reputation opinion for this indicator.'
              : `Verdict: ${v.verdict.toUpperCase()}${
                  v.detections ? ` (${v.detections.malicious}/${v.detections.total} engines)` : ''
                }${v.reports !== null ? `, ${v.reports} report(s)` : ''}.`,
            v.providerName,
            {
              verdict: v.verdict,
              detections: v.detections,
              reports: v.reports,
              origin: v.origin,
              durationMs: v.durationMs,
            },
          );
        }
      }
    } else {
      // Live mode: run every configured provider in parallel. Providers that
      // are unconfigured or do not support this type still produce a verdict so
      // the failure is visible instead of silent.
      const tasks = runs.map(async (run) => {
        if (!run.provider.isConfigured()) {
          const v: ProviderVerdict = {
            providerId: run.id,
            providerName: run.name,
            origin: 'live',
            status: 'unconfigured',
            verdict: 'unknown',
            reputationScore: null,
            reports: null,
            detections: null,
            network: null,
            related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [], categories: [], malware: [], actors: [], campaigns: [], behaviours: [] },
            firstSeenAt: null,
            lastSeenAt: null,
            rawExcerpt: null,
            durationMs: 0,
            error: {
              code: 'unconfigured',
              message: `${run.name} has no API key configured. Add the corresponding environment variable to .env to enable it.`,
              retryable: false,
            },
          };
          return v;
        }
        if (!providerSupports(run, ioc.type)) {
          const v: ProviderVerdict = {
            providerId: run.id,
            providerName: run.name,
            origin: 'live',
            status: 'not_found',
            verdict: 'unknown',
            reputationScore: null,
            reports: null,
            detections: null,
            network: null,
            related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [], categories: [], malware: [], actors: [], campaigns: [], behaviours: [] },
            firstSeenAt: null,
            lastSeenAt: null,
            rawExcerpt: null,
            durationMs: 0,
            error: {
              code: 'unsupported_indicator',
              message: `${run.name} does not support ${ioc.type.toUpperCase()} indicators.`,
              retryable: false,
            },
          };
          return v;
        }
        try {
          return await run.provider.lookup(ioc, { mode });
        } catch (err) {
          // Defensive: providers are contractually not allowed to throw, but if
          // one does we must not lose the whole investigation.
          logger.error('provider threw', { provider: run.id, error: String(err) });
          const v: ProviderVerdict = {
            providerId: run.id,
            providerName: run.name,
            origin: 'live',
            status: 'error',
            verdict: 'unknown',
            reputationScore: null,
            reports: null,
            detections: null,
            network: null,
            related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [], categories: [], malware: [], actors: [], campaigns: [], behaviours: [] },
            firstSeenAt: null,
            lastSeenAt: null,
            rawExcerpt: null,
            durationMs: 0,
            error: { code: 'provider_exception', message: 'Provider adapter raised an unexpected error and was skipped.', retryable: false },
          };
          return v;
        }
      });

      const results = await Promise.all(tasks);
      collected.push(...results);

      for (const v of results) {
        recordProviderStatus(v.providerId, v.status === 'ok' ? 'ok' : v.status === 'unconfigured' ? 'unconfigured' : v.status === 'rate_limited' ? 'rate_limited' : 'error', v.error?.message ?? null);
        if (v.status === 'ok') {
          event(
            investigationId,
            'provider',
            `Enriched by ${v.providerName}`,
            v.verdict === 'unknown'
              ? 'Source responded but holds no reputation opinion for this indicator.'
              : `Verdict: ${v.verdict.toUpperCase()}${v.detections ? ` (${v.detections.malicious}/${v.detections.total} engines)` : ''}${v.reports !== null ? `, ${v.reports} report(s)` : ''}.`,
            v.providerName,
            { verdict: v.verdict, detections: v.detections, reports: v.reports, durationMs: v.durationMs },
          );
        } else {
          event(
            investigationId,
            'provider-error',
            `${v.providerName}: ${v.status.replace('_', ' ')}`,
            v.error?.message ?? 'The provider did not return usable intelligence for this indicator.',
            v.providerName,
            { status: v.status, code: v.error?.code, retryable: v.error?.retryable },
          );
        }
      }
    }

    // ------------------------------------------------------ 4. CORRELATION
    updateInvestigation(investigationId, { status: 'analyzing' });
    const intel = aggregateIntelligence(ioc, collected);
    const signals = computeSignals(ioc, intel, warnings);

    event(
      investigationId,
      'correlation',
      'Intelligence correlated',
      `${intel.corroborationCount} independent source(s) expressed a reputation verdict (${intel.maliciousSources.length} malicious, ${intel.suspiciousSources.length} suspicious, ${intel.cleanSources.length} clean). ${intel.related.domains.length + intel.related.ipAddresses.length + intel.related.urls.length + intel.related.hashes.length + intel.related.emails.length} related indicator(s), ${intel.malware.length} malware association(s), ${intel.actors.length} actor attribution(s).`,
      'threatlens:correlation',
      {
        corroboration: intel.corroborationCount,
        related: {
          domains: intel.related.domains.length,
          ips: intel.related.ipAddresses.length,
          urls: intel.related.urls.length,
          hashes: intel.related.hashes.length,
          emails: intel.related.emails.length,
        },
        malware: intel.malware,
        actors: intel.actors,
        campaigns: intel.campaigns,
      },
    );

    // ---------------------------------------------------------- 5. ANALYSIS
    const assessment = scoreRisk({ ioc, intel, signals, mode });

    event(
      investigationId,
      'scoring',
      `Risk score computed: ${assessment.score}/100 (${assessment.level})`,
      `Confidence ${assessment.confidenceScore}% (${assessment.confidenceLabel}). ${assessment.factors.length} positive factor(s) and ${assessment.offsets.length} offset(s) were applied.`,
      'threatlens:risk-engine',
      {
        score: assessment.score,
        level: assessment.level,
        confidence: assessment.confidenceScore,
        factors: assessment.factors.map((f) => ({ id: f.id, points: f.points, label: f.label })),
        offsets: assessment.offsets.map((f) => ({ id: f.id, points: f.points, label: f.label })),
      },
    );

    const techniques = mapTechniques({
      ioc,
      verdicts: collected,
      behaviours: intel.behaviours,
      categories: intel.categories,
      malwareNames: intel.malware,
      actorNames: intel.actors,
      signals: {
        nonStandardPort: signals.nonStandardPort,
        punycode: signals.punycode,
        highEntropy: signals.highEntropy,
        deepSubdomain: signals.deepSubdomain,
        newlyRegistered: signals.newlyRegistered,
        documentationRange: signals.documentationRange,
      },
    });

    if (techniques.length > 0) {
      event(
        investigationId,
        'attack',
        `${techniques.length} MITRE ATT&CK technique(s) mapped`,
        techniques.map((t) => `${t.techniqueId} ${t.name} (${t.tactic}, ${t.confidence} confidence)`).join('; '),
        'threatlens:attack-mapper',
        { techniques: techniques.map((t) => ({ id: t.techniqueId, name: t.name, tactic: t.tactic, confidence: t.confidence, basis: t.mappingBasis })) },
      );
    } else {
      event(
        investigationId,
        'attack',
        'No MITRE ATT&CK technique identified',
        'No documented, evidence-based mapping rule matched this indicator. ThreatLens reports "No MITRE ATT&CK technique identified." rather than guessing.',
        'threatlens:attack-mapper',
      );
    }

    // ------------------------------------------------------- 6. PRODUCTION
    const db = getDb();
    const persist = db.transaction(() => {
      // 6a. evidence
      for (const verdict of collected) insertEnrichment({ investigationId, iocId: iocRow.id, verdict });

      // 6b. risk explanation
      const allFactors: RiskFactor[] = [...assessment.factors, ...assessment.offsets];
      replaceRiskFactors(
        investigationId,
        allFactors.map((f) => ({ id: f.id, label: f.label, points: f.points, category: f.category, evidence: f.evidence, sources: f.sources })),
      );

      // 6c. techniques
      techniques.forEach((t: TechniqueMapping, index) => {
        const row = findTechniqueByExternalId(t.techniqueId);
        if (!row) return;
        linkTechnique({
          investigationId,
          techniqueId: row.id,
          relationship: t.relationship,
          confidence: t.confidence,
          mappingBasis: t.mappingBasis,
          // The mapping basis is surfaced separately in the UI; storing it in the
          // rationale as well would duplicate it on the analyst-facing card.
          rationale: t.relationship,
          sortOrder: index,
        });
      });

      // 6d. actors (resolve the fictional demo actors first, then upsert)
      for (const actorName of intel.actors.slice(0, 10)) {
        const demoActor = DEMO_ACTORS.find((a) => a.name === actorName || a.externalId === actorName);
        const actorId = demoActor
          ? upsertActor({
              external_id: demoActor.externalId,
              name: demoActor.name,
              aliases_json: JSON.stringify(demoActor.aliases),
              origin: 'demo',
              sophistication: demoActor.sophistication,
              motivation_json: JSON.stringify(demoActor.motivation),
              first_seen_year: demoActor.firstSeenYear,
              description: demoActor.description,
              reference_url: null,
            })
          : upsertActor({
              external_id: `COMMUNITY-${actorName.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 48)}`,
              name: actorName,
              aliases_json: '[]',
              origin: 'community',
              sophistication: null,
              motivation_json: '[]',
              first_seen_year: null,
              description: `Attributed by community intelligence during ${ioc.value} investigation.`,
              reference_url: null,
            });
        linkActor({ investigationId, actorId, confidence: 'medium', basis: `Reported as the adversary for this indicator by ${intel.providers.filter((p) => p.related.actors.includes(actorName)).map((p) => p.providerName).join(', ') || 'community intelligence'}.` });
      }

      // 6e. malware
      for (const family of intel.malware.slice(0, 15)) {
        const demoMalware = DEMO_MALWARE.find((m) => m.name === family || m.externalId === family || m.families.includes(family));
        const malwareId = demoMalware
          ? upsertMalware({
              external_id: demoMalware.externalId,
              name: demoMalware.name,
              aliases_json: JSON.stringify(demoMalware.aliases),
              malware_type: demoMalware.malwareType,
              platform_json: JSON.stringify(demoMalware.platform),
              capabilities_json: JSON.stringify(demoMalware.capabilities),
              origin: 'demo',
              description: demoMalware.description,
              reference_url: null,
            })
          : upsertMalware({
              external_id: `FAMILY-${family.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 48)}`,
              name: family,
              aliases_json: '[]',
              malware_type: null,
              platform_json: '[]',
              capabilities_json: '[]',
              origin: 'community',
              description: `Identified in relation to ${ioc.value} by threat intelligence providers.`,
              reference_url: null,
            });
        const detectionsForFamily = collected.reduce(
          (acc, p) => acc + (p.related.malware.includes(family) ? (p.detections?.malicious ?? 0) : 0),
          0,
        );
        linkMalware({
          investigationId,
          malwareId,
          confidence: demoMalware ? 'high' : 'medium',
          basis: demoMalware
            ? `Resolved to the built-in demonstration catalog entry ${demoMalware.externalId}.`
            : 'Reported by threat intelligence providers as a malware family associated with this indicator.',
          detections: detectionsForFamily || null,
        });
      }

      // 6f. campaigns
      for (const campaignName of intel.campaigns.slice(0, 10)) {
        const demoCampaign = DEMO_CAMPAIGNS.find((c) => c.name === campaignName || c.externalId === campaignName);
        const campaignId = demoCampaign
          ? upsertCampaign({
              external_id: demoCampaign.externalId,
              name: demoCampaign.name,
              origin: 'demo',
              first_seen: demoCampaign.firstSeen,
              description: demoCampaign.description,
              reference_url: null,
            })
          : upsertCampaign({
              external_id: `COMMUNITY-CAMPAIGN-${campaignName.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 40)}`,
              name: campaignName,
              origin: 'community',
              first_seen: null,
              description: `Referenced by community intelligence for ${ioc.value}.`,
              reference_url: null,
            });
        linkCampaign({ investigationId, campaignId, confidence: demoCampaign ? 'high' : 'medium', basis: 'Campaign context reported by intelligence sources for this indicator.' });
      }

      // 6g. related indicators + persisted relationships (correlation memory)
      for (const verdict of collected) {
        for (const rel of extractPersistableRelationships(ioc, intel, verdict.providerId)) {
          const target = upsertIoc({ type: rel.type, value: rel.value });
          if (target.id === iocRow.id) continue;
          linkRelatedIoc({
            investigationId,
            relatedIocId: target.id,
            relation: rel.relation,
            confidence: rel.confidence,
            source: verdict.providerId,
          });
          recordRelationship({
            sourceIocId: iocRow.id,
            targetIocId: target.id,
            relation: rel.relation,
            confidence: rel.confidence,
            sourceProvider: verdict.providerId,
            meta: { sourceInvestigation: investigationId },
          });
        }
      }

      // 6h. final status
      const usable = collected.filter((v) => v.status === 'ok');
      const failed = collected.filter((v) => v.status === 'error' || v.status === 'timeout' || v.status === 'rate_limited');
      const status: InvestigationRow['status'] =
        usable.length === 0 ? 'failed' : failed.length > 0 || collected.some((v) => v.status === 'unconfigured') ? 'partial' : 'completed';

      updateInvestigation(investigationId, {
        status,
        risk_score: assessment.score,
        risk_level: assessment.level,
        confidence_score: assessment.confidenceScore,
        verdict: intel.verdict,
        providers_ok: usable.length,
        providers_failed: failed.length,
        providers_skipped: collected.length - usable.length - failed.length,
        duration_ms: Date.now() - started,
        completed_at: new Date().toISOString(),
        error_code: usable.length === 0 ? 'no_intelligence' : null,
        error_message:
          usable.length === 0
            ? 'No intelligence source returned usable data. Review the per-source errors in the enrichment panel and check provider configuration.'
            : null,
      });
    });

    persist();

    event(
      investigationId,
      'investigation',
      'Investigation completed',
      `Status: ${findInvestigation(investigationId)?.status}. Risk ${assessment.score}/100 (${assessment.level}), confidence ${assessment.confidenceScore}%. ${usable_count(collected)} source(s) returned intelligence, ${failed_count(collected)} failed.`,
      'threatlens:orchestrator',
      { score: assessment.score, level: assessment.level, durationMs: Date.now() - started },
    );

    audit({
      userId: input.userId,
      action: 'investigation.complete',
      entity: 'investigation',
      entityId: String(investigationId),
      meta: { score: assessment.score, level: assessment.level, mode },
    });
  } catch (err) {
    logger.error('investigation pipeline crashed', { investigationId, error: String(err) });
    updateInvestigation(investigationId, {
      status: 'failed',
      error_code: 'internal_error',
      error_message: 'The investigation pipeline failed unexpectedly. Check the server log for details.',
      completed_at: new Date().toISOString(),
      duration_ms: Date.now() - started,
    });
    event(investigationId, 'investigation', 'Investigation failed', 'An internal error interrupted the investigation. The evidence collected so far has been preserved.', 'threatlens:orchestrator');
  }
}

const usable_count = (verdicts: ProviderVerdict[]): number => verdicts.filter((v) => v.status === 'ok').length;
const failed_count = (verdicts: ProviderVerdict[]): number =>
  verdicts.filter((v) => v.status === 'error' || v.status === 'timeout' || v.status === 'rate_limited').length;

/**
 * Fail an investigation that has been left in a non-terminal state (for example
 * after a server restart). Called on boot.
 */
export function reconcileStaleInvestigations(): number {
  const stale = q.all<{ id: number }>(
    "SELECT id FROM investigations WHERE status IN ('pending','enriching','analyzing')",
  );
  for (const row of stale) {
    updateInvestigation(row.id, {
      status: 'failed',
      error_code: 'interrupted',
      error_message: 'The server restarted while this investigation was running. Re-run the investigation to collect fresh intelligence.',
      completed_at: new Date().toISOString(),
    });
    event(row.id, 'investigation', 'Investigation interrupted', 'The server restarted during enrichment. No partial results are presented as complete intelligence.', 'threatlens:orchestrator');
  }
  return stale.length;
}

export { randomUUID };
export type { IocType };
