/**
 * ============================================================================
 * EXPLAINABLE RISK SCORING ENGINE  (CTI lifecycle: "Analysis")
 * ============================================================================
 *
 * GOAL: a deterministic, auditable 0-100 risk score where the analyst can see
 * *exactly* why a number was produced.
 *
 * DESIGN
 * ------
 * The score is the sum of independent, weighted FACTORS. Each factor is a pure
 * function of the aggregated intelligence, contributes a documented number of
 * points, and records:
 *   - the evidence string that triggered it (with the actual numbers),
 *   - the provider ids the evidence came from,
 *   - the rule id so the methodology can be cited in a report.
 *
 * Positive factors are capped (see FACTOR_CAPS) and the total is clamped to
 * 100. Negative factors ("offsets") can only reduce the score, never push it
 * below 0. There is NO randomness, NO time-of-day dependence and NO dependence
 * on a provider's availability beyond what the evidence states.
 *
 * TOTAL POSSIBLE: 30 + 20 + 15 + 15 + 10 + 10 + 10 + 10 = 120 -> clamped to 100.
 *
 * Risk levels: 0-19 CLEAN | 20-39 LOW | 40-59 MEDIUM | 60-79 HIGH | 80-100 CRITICAL
 */
import type { Confidence, NormalizedIoc, RiskAssessment, RiskFactor, RiskLevel } from '../types.js';
import { confidenceLabel, type AggregatedIntel } from '../aggregate.js';

export const FACTOR_CAPS = {
  maliciousReputation: 30,
  abuseConfidence: 20,
  malwareAssociation: 15,
  c2Association: 15,
  sourceCorroboration: 10,
  recentActivity: 10,
  actorAttribution: 10,
  infrastructureAnomaly: 10,
  multiEngineConsensus: 12,
  trustedInfrastructure: 20,
  cleanConsensus: 10,
} as const;

export const METHODOLOGY = [
  'Malicious reputation (max +30): engine/reputation consensus, scaled by the malicious detection ratio.',
  'High abuse confidence (max +20): crowd-sourced abuse confidence score banded by severity.',
  'Multi-engine consensus (max +12): absolute number of independent engines flagging the indicator.',
  'Known malware association (max +15): +10 for one family, +13 for two, +15 for three or more.',
  'Known C2 association (max +15): +15 confirmed C2, +8 adjacent (botnet / C&C hosting / beacon).',
  'Multiple intelligence sources (max +10): +4 for two, +7 for three, +10 for four or more corroborating sources.',
  'Recent malicious activity (max +10): 7 days +10, 30 days +7, 90 days +4, 180 days +2.',
  'Threat actor attribution (max +10): named actor in community intelligence.',
  'Infrastructure anomaly (max +10): non-standard port, punycode, DGA-like entropy, deep subdomain chain.',
  'Trusted infrastructure offset (max -20): recognised public service infrastructure that produces benign traffic by volume.',
  'Clean consensus offset (max -10): multiple independent sources explicitly report the indicator as clean.',
].join(' ');

const factor = (
  id: string,
  label: string,
  points: number,
  evidence: string,
  sources: string[],
  category: RiskFactor['category'],
): RiskFactor => ({ id, label, points, evidence, sources, category });

export interface RiskSignals {
  nonStandardPort: boolean;
  punycode: boolean;
  highEntropy: boolean;
  deepSubdomain: boolean;
  newlyRegistered: boolean;
  documentationRange: boolean;
}

export interface RiskInput {
  ioc: NormalizedIoc;
  intel: AggregatedIntel;
  signals: RiskSignals;
  mode: 'live' | 'demo';
  /** Non-standard port observed on the indicator itself (e.g. 8443). */
  observedPort?: number | null;
}

const daysSince = (iso: string | null, now: number): number | null => {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return (now - t) / 86_400_000;
};

/**
 * Well-known public service infrastructure.
 *
 * A CTI analyst must be able to say "this address is Google Public DNS, high
 * traffic is expected" - otherwise report volume dominates every dashboard.
 * Keyed by a small, publicly documented list of resolver anycast prefixes.
 * Recorded as an explicit, visible offset so it can be challenged in review.
 */
const TRUSTED_RANGES: Array<{ cidr: string; label: string }> = [
  { cidr: '8.8.8.0/24', label: 'Google Public DNS (AS15169)' },
  { cidr: '8.8.4.0/24', label: 'Google Public DNS (AS15169)' },
  { cidr: '1.1.1.0/24', label: 'Cloudflare Public DNS (AS13335)' },
  { cidr: '1.0.0.0/24', label: 'Cloudflare Public DNS (AS13335)' },
  { cidr: '9.9.9.0/24', label: 'Quad9 Public DNS (AS19281)' },
  { cidr: '208.67.222.0/24', label: 'OpenDNS (AS36692)' },
];

const ipv4ToInt = (ip: string): number =>
  ip.split('.').reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;

export function trustedInfrastructureMatch(value: string): string | null {
  for (const range of TRUSTED_RANGES) {
    const [net, bitsRaw] = range.cidr.split('/');
    const bits = Number(bitsRaw);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if (((ipv4ToInt(value) & mask) >>> 0) === ((ipv4ToInt(net) & mask) >>> 0)) {
      return range.label;
    }
  }
  return null;
}

export function riskLevelFor(score: number): RiskLevel {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  if (score >= 20) return 'LOW';
  return 'CLEAN';
}

export function scoreRisk(input: RiskInput): RiskAssessment {
  const { ioc, intel, signals, mode } = input;
  const now = Date.now();
  const factors: RiskFactor[] = [];

  const sourceNames = new Map(
    intel.providers.map((v) => [v.providerId, v.providerName]),
  );
  const src = (ids: string[]): string[] => ids.map((id) => sourceNames.get(id) ?? id);

  const detections = intel.detections;
  const hasMalicious = intel.maliciousSources.length > 0;
  const hasSuspicious = intel.suspiciousSources.length > 0;
  const c2Signals = intel.behaviours.filter((b) =>
    /(^|[-_])(c2|beacon|botnet|command|cnc)([-_]|$)/i.test(b),
  );

  // ---------------------------------------------------------------- 1. reputation
  if (detections && detections.malicious > 0) {
    const ratio = detections.ratio ?? 0;
    // Scale the 30 points by consensus: 10% malicious ratio saturates the factor.
    const scaled = Math.min(FACTOR_CAPS.maliciousReputation, Math.round(20 + 10 * Math.min(1, ratio / 0.1)));
    factors.push(
      factor(
        'malicious_reputation',
        'Malicious reputation',
        scaled,
        `${detections.malicious} of ${detections.total} engines flagged this indicator as malicious (${(ratio * 100).toFixed(1)}% ratio)${
          detections.suspicious > 0 ? `, ${detections.suspicious} further engines marked it suspicious` : ''
        }.`,
        src([...intel.maliciousSources, ...intel.suspiciousSources]),
        'reputation',
      ),
    );
  } else if (hasSuspicious) {
    factors.push(
      factor(
        'suspicious_reputation',
        'Suspicious reputation',
        12,
        `No engine consensus yet, but ${intel.suspiciousSources.length} source(s) classify the indicator as suspicious.`,
        src(intel.suspiciousSources),
        'reputation',
      ),
    );
  } else if (hasMalicious) {
    factors.push(
      factor(
        'malicious_verdict',
        'Confirmed malicious verdict',
        FACTOR_CAPS.maliciousReputation,
        `${intel.maliciousSources.length} source(s) returned a malicious verdict.`,
        src(intel.maliciousSources),
        'reputation',
      ),
    );
  }

  // ------------------------------------------------------- 2. abuse confidence
  const abuse = intel.network?.abuseConfidenceScore;
  if (typeof abuse === 'number' && abuse > 0) {
    let points = 0;
    let band = '';
    if (abuse >= 90) { points = 20; band = 'near-certain abuse'; }
    else if (abuse >= 75) { points = 16; band = 'high confidence abuse'; }
    else if (abuse >= 50) { points = 12; band = 'moderate confidence abuse'; }
    else if (abuse >= 25) { points = 8; band = 'some reported abuse'; }
    else { points = 4; band = 'low-volume abuse reports'; }
    const reports = intel.network?.totalReports;
    factors.push(
      factor(
        'abuse_confidence',
        'Abuse confidence score',
        points,
        `Abuse confidence ${abuse}/100 (${band})${reports ? ` with ${reports} community report${reports === 1 ? '' : 's'}` : ''}.`,
        src(intel.providers.filter((p) => p.network?.abuseConfidenceScore !== null && p.network?.abuseConfidenceScore !== undefined).map((p) => p.providerId)),
        'abuse',
      ),
    );
  }

  // ----------------------------------------------------- 3. multi-engine count
  if (detections && detections.malicious >= 5) {
    const points = Math.min(FACTOR_CAPS.multiEngineConsensus, 4 + detections.malicious);
    factors.push(
      factor(
        'multi_engine_consensus',
        'Broad engine consensus',
        points,
        `${detections.malicious} independent detection engines flagged this indicator; broad consensus is stronger evidence than a single signature.`,
        src(intel.maliciousSources),
        'reputation',
      ),
    );
  }

  // ----------------------------------------------------- 4. malware association
  const malwareCount = intel.malware.length;
  if (malwareCount > 0) {
    const points = malwareCount >= 3 ? 15 : malwareCount === 2 ? 13 : 10;
    factors.push(
      factor(
        'malware_association',
        'Known malware association',
        points,
        `Associated with ${malwareCount} malware famil${malwareCount === 1 ? 'y' : 'ies'}: ${intel.malware.slice(0, 4).join(', ')}${malwareCount > 4 ? ` (+${malwareCount - 4} more)` : ''}.`,
        src(intel.providers.filter((p) => p.related.malware.length > 0).map((p) => p.providerId)),
        'association',
      ),
    );
  }

  // -------------------------------------------------------- 5. C2 association
  if (c2Signals.length > 0) {
    const confirmed = c2Signals.some((b) => /(^|-)c2$|-c2$|^c2$/.test(b) || b === 'c2');
    const points = confirmed ? FACTOR_CAPS.c2Association : 8;
    factors.push(
      factor(
        'c2_association',
        confirmed ? 'Command-and-control association' : 'Botnet / C2-adjacent behaviour',
        points,
        confirmed
          ? 'Intelligence sources explicitly identify this indicator as command-and-control infrastructure.'
          : `Sources report C2-adjacent behaviour (${c2Signals.slice(0, 3).join(', ')}) without explicit C2 confirmation.`,
        src(intel.providers.filter((p) => p.related.behaviours.some((b) => b.includes('c2'))).map((p) => p.providerId)),
        'behaviour',
      ),
    );
  }

  // ----------------------------------------------------- 6. source corroboration
  if (intel.corroborationCount >= 2) {
    const points = intel.corroborationCount >= 4 ? 10 : intel.corroborationCount === 3 ? 7 : 4;
    factors.push(
      factor(
        'multi_source_corroboration',
        'Multiple intelligence sources',
        points,
        `${intel.corroborationCount} independent source${intel.corroborationCount === 1 ? '' : 's'} returned a reputation verdict (${[
          ...src(intel.maliciousSources),
          ...src(intel.suspiciousSources),
          ...src(intel.cleanSources),
        ].join(', ')}).`,
        src([...intel.maliciousSources, ...intel.suspiciousSources, ...intel.cleanSources]),
        'context',
      ),
    );
  }

  // --------------------------------------------------------- 7. recent activity
  const lastSeen = intel.lastSeenAt;
  const days = daysSince(lastSeen, now);
  if (days !== null && intel.verdict !== 'clean') {
    let points = 0;
    let band = '';
    if (days <= 7) { points = 10; band = 'within the last 7 days'; }
    else if (days <= 30) { points = 7; band = 'within the last 30 days'; }
    else if (days <= 90) { points = 4; band = 'within the last 90 days'; }
    else if (days <= 180) { points = 2; band = 'within the last 6 months'; }
    if (points > 0) {
      factors.push(
        factor(
          'recent_activity',
          'Recent malicious activity',
          points,
          `Most recent sighting ${band} (${lastSeen}).`,
          src(intel.providers.filter((p) => p.lastSeenAt).map((p) => p.providerId)),
          'context',
        ),
      );
    }
  }

  // ------------------------------------------------------ 8. actor attribution
  if (intel.actors.length > 0) {
    factors.push(
      factor(
        'actor_attribution',
        'Threat actor attribution',
        FACTOR_CAPS.actorAttribution,
        `Community intelligence attributes this indicator to ${intel.actors.slice(0, 3).join(', ')}${
          intel.campaigns.length ? ` in campaign(s) ${intel.campaigns.slice(0, 2).join(', ')}` : ''
        }.`,
        src(intel.providers.filter((p) => p.related.actors.length > 0).map((p) => p.providerId)),
        'association',
      ),
    );
  }

  // ------------------------------------------------- 9. infrastructure anomaly
  const anomalies: string[] = [];
  let anomalyPoints = 0;
  if (signals.nonStandardPort) {
    anomalies.push(`non-standard port ${input.observedPort ?? '(observed)'}`);
    anomalyPoints += 4;
  }
  if (signals.punycode) { anomalies.push('punycode (IDN) hostname'); anomalyPoints += 3; }
  if (signals.highEntropy) { anomalies.push('high-entropy hostname label (DGA-like)'); anomalyPoints += 3; }
  if (signals.deepSubdomain) { anomalies.push(`deep subdomain chain (${ioc.parsed.subdomainDepth} levels)`); anomalyPoints += 2; }
  if (anomalies.length > 0) {
    anomalyPoints = Math.min(FACTOR_CAPS.infrastructureAnomaly, anomalyPoints);
    factors.push(
      factor(
        'infrastructure_anomaly',
        'Suspicious infrastructure characteristics',
        anomalyPoints,
        `Static analysis of the indicator itself flags: ${anomalies.join('; ')}. These are properties of the indicator, independent of reputation.`,
        ['threatlens:static-analysis'],
        'infrastructure',
      ),
    );
  }

  // ----------------------------------------------------------------- OFFSETS
  const offsets: RiskFactor[] = [];
  const trusted = trustedInfrastructureMatch(ioc.value);
  const trustedViaBehaviour = intel.behaviours.includes('known-benign-scanner') || intel.behaviours.includes('public-dns-resolver');
  if (trusted || trustedViaBehaviour) {
    const labelText = trusted ?? 'Infrastructure classified as a known-benign public service';
    offsets.push(
      factor(
        'trusted_infrastructure',
        'Trusted / known-good infrastructure',
        -FACTOR_CAPS.trustedInfrastructure,
        `${labelText}: high connection volume and report count are expected for this class of infrastructure, so raw report volume is discounted.`,
        src(intel.providers.filter((p) => p.related.behaviours.includes('known-benign-scanner')).map((p) => p.providerId)),
        'offset',
      ),
    );
  }
  if (intel.cleanSources.length >= 2 && intel.maliciousSources.length === 0) {
    offsets.push(
      factor(
        'clean_consensus',
        'Clean consensus across sources',
        -FACTOR_CAPS.cleanConsensus,
        `${intel.cleanSources.length} independent sources report this indicator as clean with no malicious detections.`,
        src(intel.cleanSources),
        'offset',
      ),
    );
  }

  // --------------------------------------------------------------- total score
  const positiveTotal = factors.reduce((acc, f) => acc + Math.max(0, f.points), 0);
  const offsetTotal = offsets.reduce((acc, f) => acc + f.points, 0);
  const raw = positiveTotal + offsetTotal;
  const score = Math.max(0, Math.min(100, Math.round(raw)));

  // ------------------------------------------------------------- confidence
  const confidence = computeConfidence({ intel, mode, hasPositiveFactors: factors.length > 0 });

  return {
    score,
    rawScore: Math.round(raw),
    level: riskLevelFor(score),
    confidenceScore: confidence.score,
    confidenceLabel: confidenceLabel(confidence.score),
    factors,
    positives: factors,
    offsets,
    methodology: METHODOLOGY,
    scoredAt: new Date().toISOString(),
  };
}

/**
 * CONFIDENCE is a different question from RISK: it answers "how much do we
 * actually know?", not "how dangerous is it?". A clean indicator can have low
 * confidence, and a critical indicator with one source can have medium
 * confidence. Mixing the two is the most common mistake in CTI dashboards.
 */
export function computeConfidence(input: {
  intel: AggregatedIntel;
  mode: 'live' | 'demo';
  hasPositiveFactors: boolean;
}): { score: number; reasons: string[] } {
  const { intel, mode } = input;
  const reasons: string[] = [];
  let score = 0;

  const usable = intel.providers.filter((v) => v.status === 'ok');
  const opinionated = intel.providers.filter((v) => v.status === 'ok' && v.verdict !== 'unknown');

  if (usable.length > 0) {
    score += 40;
    reasons.push('At least one source responded successfully (+40).');
  }
  if (usable.length > 1) score += Math.min(24, (usable.length - 1) * 8);

  if (intel.detections && intel.detections.total >= 10) { score += 8; reasons.push('Multi-engine detection statistics available (+8).'); }
  if (intel.network) { score += 10; reasons.push('Network attribution data available (+10).'); }
  if (intel.malware.length > 0 || intel.categories.length > 0) { score += 6; reasons.push('Threat categorisation / malware associations available (+6).'); }
  if (intel.lastSeenAt) { score += 5; reasons.push('Last-seen timestamp available (+5).'); }
  if (opinionated.length >= 2) { score += 5; reasons.push('Multiple sources expressed a reputation opinion (+5).'); }

  if (intel.failedCount > 0) { score -= 20 * Math.min(2, intel.failedCount); reasons.push(`${intel.failedCount} source(s) failed or were rate limited (-${20 * Math.min(2, intel.failedCount)}).`); }
  if (mode === 'demo') { score -= 5; reasons.push('Intelligence came from the demonstration dataset rather than a live source (-5).'); }

  // Cap below 100: absolute certainty is never an honest claim.
  const clamped = Math.max(5, Math.min(97, Math.round(score)));
  return { score: clamped, reasons };
}

export type { Confidence };
