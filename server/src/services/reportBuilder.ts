/**
 * ============================================================================
 * THREAT INTELLIGENCE REPORT BUILDER  (CTI lifecycle: "Intelligence production")
 * ============================================================================
 *
 * Produces a professional CTI investigation report in three representations:
 *   - a structured JSON object (machine readable, diffable, re-ingestable)
 *   - a Markdown document (easy to paste into a wiki or a report template)
 *   - a PDF (PDFKit) for submission/hand-off
 *
 * CRITICAL REQUIREMENT IMPLEMENTED HERE: the report must clearly separate
 *   (a) OBSERVED FACTS              - what we directly measured
 *   (b) EXTERNAL INTELLIGENCE        - what a third party told us (with source)
 *   (c) ANALYST ASSESSMENT          - our own reasoning (risk, ATT&CK, actions)
 * Every section is labelled accordingly, and every external claim carries its
 * provider attribution. This is what separates a CTI report from a log dump.
 */
import type { InvestigationDetail } from './resultService.js';
import type { DefensiveAction, RiskFactor, TechniqueMapping } from '../core/types.js';
import { DEMO_MARKER } from '../providers/demo/index.js';
import { ATTACK_VERSION } from '../providers/mitre/index.js';

export const CLASSIFICATION = 'TLP:AMBER';
export const CLASSIFICATION_NOTE =
  'TLP:AMBER - limited to participants who need to know. Share only with teams that require the indicator to defend their own assets.';

export interface ReportSection {
  id: string;
  title: string;
  classification: 'observed-fact' | 'external-intelligence' | 'analyst-assessment' | 'context';
  body: string;
  bullets?: string[];
  table?: { headers: string[]; rows: string[][] };
}

export interface InvestigationReport {
  schema: 'threatlens.cti.report/v1';
  generatedAt: string;
  generator: { name: string; version: string; mode: 'live' | 'demo' };
  classification: { label: string; note: string };
  reportId: string;
  title: string;
  investigation: {
    reference: string;
    id: number;
    status: string;
    mode: 'live' | 'demo';
    openedAt: string;
    completedAt: string | null;
    durationMs: number | null;
    analyst: string | null;
  };
  indicator: {
    value: string;
    type: string;
    typeLabel: string;
    description: string;
    isDocumentation: boolean;
    timesSeen: number;
    firstSeen: string;
    lastSeen: string;
  };
  executiveSummary: {
    verdict: string;
    riskScore: number;
    riskLevel: string;
    confidenceScore: number;
    confidenceLabel: string;
    /** True when no source returned usable data; the score must not be read as clean. */
    insufficientIntelligence: boolean;
    narrative: string;
    keyFindings: string[];
  };
  sections: ReportSection[];
  riskScore: {
    score: number;
    level: string;
    confidence: number;
    factors: Array<Pick<RiskFactor, 'id' | 'label' | 'points' | 'evidence' | 'sources' | 'category'>>;
    methodology: string;
  };
  attack: {
    techniques: Array<Pick<TechniqueMapping, 'techniqueId' | 'name' | 'tactic' | 'relationship' | 'confidence' | 'reference' | 'mappingBasis'>>;
    statement: string;
  };
  relatedIndicators: Array<{ value: string; type: string; relation: string; confidence: string; source: string }>;
  enrichment: Array<{
    provider: string;
    origin: string;
    status: string;
    verdict: string;
    malicious: number | null;
    total: number | null;
    ratio: number | null;
    reports: number | null;
    reputationScore: number | null;
    lastSeen: string | null;
    error: string | null;
  }>;
  timeline: Array<{ at: string; kind: string; title: string; description: string; source: string | null }>;
  recommendations: DefensiveAction[];
  provenance: {
    dataOrigin: string;
    demoDataUsed: boolean;
    providers: string[];
    notes: string[];
  };
}

const pct = (ratio: number | null): string => (ratio === null ? 'n/a' : `${(ratio * 100).toFixed(1)}%`);

const levelWord = (level: string): string => {
  switch (level) {
    case 'CRITICAL':
      return 'an active, high-confidence threat that requires immediate containment';
    case 'HIGH':
      return 'a likely threat requiring same-day defensive action';
    case 'MEDIUM':
      return 'a questionable indicator that warrants monitoring and scoped hunting';
    case 'LOW':
      return 'a weakly suspicious indicator; monitor but do not block';
    default:
      return 'no actionable threat identified';
  }
};

export function buildReport(detail: InvestigationDetail, analystName: string | null): InvestigationReport {
  const { assessment, ioc, reputation, threatIntel, techniques, providers } = detail;

  const insufficient = detail.assessment.insufficientIntelligence;

  const keyFindings: string[] = [];
  keyFindings.push(
    insufficient
      ? `Indicator classified as ${ioc.typeLabel}. NO RISK SCORE WAS ASSIGNED because no intelligence source returned usable data.`
      : `Indicator classified as ${ioc.typeLabel} and assessed at risk ${assessment.score}/100 (${assessment.level}) with ${assessment.confidenceScore}% confidence.`,
  );
  if (reputation.detections) {
    keyFindings.push(
      `Detection consensus: ${reputation.detections.malicious} malicious of ${reputation.detections.total} engines (${pct(reputation.detections.ratio)}).`,
    );
  }
  keyFindings.push(`${reputation.corroborationCount} independent source(s) expressed a reputation verdict (${reputation.maliciousSources.length} malicious, ${reputation.suspiciousSources.length} suspicious, ${reputation.cleanSources.length} clean).`);
  if (detail.network.fields.length) {
    const net = detail.network.fields.filter((f) => ['Country', 'ASN', 'ISP', 'Usage type'].includes(f.label)).map((f) => `${f.label}: ${f.value}`);
    if (net.length) keyFindings.push(`Network attribution - ${net.join('; ')}.`);
  }
  if (threatIntel.actors.length) keyFindings.push(`Attributed to ${threatIntel.actors.map((a) => a.name).join(', ')}.`);
  if (threatIntel.malware.length) keyFindings.push(`Associated malware: ${threatIntel.malware.map((m) => m.name).join(', ')}.`);
  if (techniques.length) keyFindings.push(`${techniques.length} MITRE ATT&CK technique(s) mapped, primary tactic ${techniques[0].tactic}.`);
  const relatedCount = detail.relatedIocs.length;
  if (relatedCount) keyFindings.push(`${relatedCount} related indicator(s) recovered for correlation and blocking.`);
  if (detail.counts.failed) keyFindings.push(`${detail.counts.failed} intelligence source(s) failed - coverage is incomplete and the confidence score reflects that.`);
  if (detail.demo) keyFindings.push(`DEMO DATA: this investigation used the built-in simulated dataset for "${detail.demo.title}".`);

  const sections: ReportSection[] = [];

  // 2. IOC information (observed fact)
  sections.push({
    id: 'ioc-information',
    title: '2. Indicator Information',
    classification: 'observed-fact',
    body: describeObservedIoc(detail),
    table: {
      headers: ['Attribute', 'Value'],
      rows: [
        ['Indicator', ioc.value],
        ['Type', `${ioc.typeLabel} (${ioc.type})`],
        ['Canonical form', ioc.value],
        ['Description', ioc.description],
        ['First stored', ioc.firstSeenAt],
        ['Last stored', ioc.lastSeenAt],
        ['Times investigated', String(ioc.timesSeen)],
        ['Reserved range', ioc.isDocumentation ? 'Yes - RFC documentation range / reserved namespace' : 'No'],
        ...(ioc.parsed.hostname ? [['Resolved host', ioc.parsed.hostname]] : []),
        ...(ioc.parsed.registrableDomain ? [['Registrable domain', ioc.parsed.registrableDomain]] : []),
        ...(ioc.parsed.scheme ? [['Scheme', ioc.parsed.scheme]] : []),
        ...(ioc.parsed.port ? [['Port', String(ioc.parsed.port)]] : []),
        ...(ioc.parsed.path ? [['Path', ioc.parsed.path]] : []),
        ...(ioc.parsed.subdomainDepth ? [['Subdomain depth', String(ioc.parsed.subdomainDepth)]] : []),
        ...(ioc.parsed.isPunycode ? [['IDN / punycode', 'Yes']] : []),
      ],
    },
  });

  // 3. Threat reputation (external intelligence)
  const reputationRows: string[][] = [];
  reputationRows.push(['Verdict', reputation.verdict.toUpperCase()]);
  reputationRows.push(['Malicious detections', reputation.detections ? String(reputation.detections.malicious) : 'n/a']);
  reputationRows.push(['Suspicious detections', reputation.detections ? String(reputation.detections.suspicious) : 'n/a']);
  reputationRows.push(['Total engines', reputation.detections ? String(reputation.detections.total) : 'n/a']);
  reputationRows.push(['Detection ratio', pct(reputation.detections?.ratio ?? null)]);
  reputationRows.push(['Total reports', reputation.reports === null ? 'n/a' : String(reputation.reports)]);
  reputationRows.push(['Reputation score (0-100)', reputation.reputationScore === null ? 'n/a' : String(reputation.reputationScore)]);
  reputationRows.push(['First seen', reputation.firstSeenAt ?? 'n/a']);
  reputationRows.push(['Last seen', reputation.lastSeenAt ?? 'n/a']);
  reputationRows.push(['Corroborating sources', String(reputation.corroborationCount)]);

  sections.push({
    id: 'threat-reputation',
    title: '3. Threat Reputation',
    classification: 'external-intelligence',
    body:
      'All values in this section were reported by third-party intelligence providers. ThreatLens does not modify or synthesise them; where a source had no opinion, the field is reported as "n/a" rather than estimated.',
    table: { headers: ['Attribute', 'Value'], rows: reputationRows },
  });

  // 4. Enrichment results (external intelligence, per source)
  sections.push({
    id: 'enrichment-results',
    title: '4. Enrichment Results by Source',
    classification: 'external-intelligence',
    body:
      'One row per intelligence source. Failed and unconfigured sources are listed explicitly rather than omitted, so the reader can judge the coverage of this assessment.',
    table: {
      headers: ['Source', 'Origin', 'Status', 'Verdict', 'Malicious/Total', 'Ratio', 'Reports', 'Reputation', 'Last seen', 'Error'],
      rows: providers.map((p) => [
        p.name,
        p.origin === 'demo' ? 'DEMO' : 'LIVE',
        p.status,
        p.verdict.toUpperCase(),
        p.detections ? `${p.detections.malicious}/${p.detections.total}` : 'n/a',
        p.detections ? pct(p.detections.ratio) : 'n/a',
        p.reports === null ? 'n/a' : String(p.reports),
        p.reputationScore === null ? 'n/a' : String(p.reputationScore),
        p.lastAnalysisAt ?? 'n/a',
        p.error ? `${p.error.code}: ${p.error.message}` : '-',
      ]),
    },
  });

  if (detail.network.fields.length) {
    sections.push({
      id: 'network-intelligence',
      title: '4b. Network Intelligence',
      classification: 'external-intelligence',
      body: 'Attribution fields with the source that reported each value.',
      table: { headers: ['Field', 'Value', 'Reported by'], rows: detail.network.fields.map((f) => [f.label, f.value ?? '', f.source ?? 'merged']) },
    });
  }

  // 5 & 6. Risk score + explanation (analyst assessment)
  const positive = assessment.factors.filter((f) => f.points > 0);
  const offsets = assessment.factors.filter((f) => f.points <= 0);
  sections.push({
    id: 'risk-score',
    title: '5. Risk Score',
    classification: 'analyst-assessment',
    body: insufficient
      ? 'Risk score NOT ASSIGNED. No intelligence source returned usable data for this indicator, so the scoring engine had no evidence to evaluate. Reporting a score of 0 here would be actively misleading, because a zero normally means "checked and found benign". The correct output is an explicit statement of missing intelligence.'
      : `Risk score ${assessment.score}/100 -> risk level ${assessment.level}. This is ThreatLens's own assessment, computed by the deterministic scoring engine; it is not an output of any provider.`,
    table: {
      headers: ['Component', 'Value'],
      rows: [
        ['Risk score', insufficient ? 'not assigned' : `${assessment.score}/100`],
        ['Risk level', insufficient ? 'insufficient intelligence' : assessment.level],
        ['Confidence', `${assessment.confidenceScore}% (${assessment.confidenceLabel})`],
        ['Positive factors', String(positive.length)],
        ['Offsets', String(offsets.length)],
      ],
    },
  });

  sections.push({
    id: 'risk-explanation',
    title: '6. Risk Score Explanation',
    classification: 'analyst-assessment',
    body: 'Every point in the score is attributed to a documented rule and to the evidence that triggered it. The arithmetic is shown in full so the score can be challenged or reproduced.',
    bullets: [
      ...positive.map((f) => `+${f.points} - ${f.label}: ${f.evidence} [sources: ${f.sources.join(', ') || 'ThreatLens static analysis'}]`),
      ...offsets.map((f) => `${f.points} - ${f.label}: ${f.evidence} [sources: ${f.sources.join(', ') || 'ThreatLens'}]`),
      `= ${assessment.score}/100 (raw sum clamped to the 0-100 range) -> ${assessment.level}`,
    ],
    table: {
      headers: ['Rule id', 'Category', 'Points', 'Evidence'],
      rows: assessment.factors.map((f) => [f.id, f.category, String(f.points), f.evidence]),
    },
  });

  // 7. Related IOCs (mixed: observed by providers)
  sections.push({
    id: 'related-iocs',
    title: '7. Related Indicators',
    classification: 'external-intelligence',
    body:
      'Indicators observed alongside the subject indicator. Relationship types are typed, and each carries the source that reported it, so a relationship can always be traced back to evidence.',
    table: {
      headers: ['Indicator', 'Type', 'Relation', 'Confidence', 'Reported by'],
      rows: detail.relatedIocs.map((r) => [r.value, r.typeLabel, r.relation, r.confidence, r.source]),
    },
  });

  // 8. MITRE ATT&CK (analyst assessment built on external intel)
  sections.push({
    id: 'attack-mapping',
    title: '8. MITRE ATT&CK Mapping',
    classification: 'analyst-assessment',
    body: techniques.length
      ? 'Techniques below were mapped by documented rules only (provider-published technique ids, documented malware-family behaviour, or behavioural rules over normalised intelligence). No technique is assigned without a recorded rationale.'
      : 'No MITRE ATT&CK technique identified. No mapping rule matched the evidence for this indicator, and ThreatLens does not assign techniques speculatively.',
    table: {
      headers: ['Technique', 'Name', 'Tactic', 'Confidence', 'Mapping basis', 'Rationale', 'Reference'],
      rows: techniques.map((t) => [t.techniqueId, t.name, t.tactic, t.confidence, t.mappingBasis, t.relationship, t.reference]),
    },
  });

  // 9. Timeline (observed)
  sections.push({
    id: 'timeline',
    title: '9. Investigation Timeline',
    classification: 'observed-fact',
    body: 'Chronological record of the investigation pipeline. Provider rows are external intelligence; the pipeline rows are ThreatLens processing.',
    table: {
      headers: ['Timestamp', 'Stage', 'Event', 'Source'],
      rows: detail.timeline.map((t) => [t.at, t.kind, `${t.title} - ${t.description}`, t.source ?? '-']),
    },
  });

  // 10. Analyst assessment
  sections.push({
    id: 'analyst-assessment',
    title: '10. Analyst Assessment',
    classification: 'analyst-assessment',
    body: buildAnalystNarrative(detail, analystName),
  });

  // 11. Defensive actions
  sections.push({
    id: 'defensive-actions',
    title: '11. Recommended Defensive Actions',
    classification: 'analyst-assessment',
    body: 'Defensive, containment and detection-engineering actions only. Priority 1 actions should be executed before end of shift.',
    bullets: detail.recommendations.map((r) => `[P${r.priority}/${r.category}] ${r.title}: ${r.detail}${r.searchQuery ? ` Search: ${r.searchQuery}` : ''}`),
  });

  if (detail.warnings.length) {
    sections.push({
      id: 'data-quality',
      title: '12. Data Quality and Caveats',
      classification: 'context',
      body: 'Caveats that materially affect how this assessment should be read.',
      bullets: detail.warnings.map((w) => `${w.code}: ${w.message}`),
    });
  }

  const reportId = `TL-${detail.reference}-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}`;

  return {
    schema: 'threatlens.cti.report/v1',
    generatedAt: new Date().toISOString(),
    generator: { name: 'ThreatLens', version: '1.0.0', mode: detail.mode },
    classification: { label: CLASSIFICATION, note: CLASSIFICATION_NOTE },
    reportId,
    title: `Threat Intelligence Investigation Report - ${ioc.value} (${ioc.typeLabel})`,
    investigation: {
      reference: detail.reference,
      id: detail.id,
      status: detail.status,
      mode: detail.mode,
      openedAt: detail.startedAt,
      completedAt: detail.completedAt,
      durationMs: detail.durationMs,
      analyst: analystName ?? detail.requestedBy?.name ?? 'Unknown analyst',
    },
    indicator: {
      value: ioc.value,
      type: ioc.type,
      typeLabel: ioc.typeLabel,
      description: ioc.description,
      isDocumentation: ioc.isDocumentation,
      timesSeen: ioc.timesSeen,
      firstSeen: ioc.firstSeenAt,
      lastSeen: ioc.lastSeenAt,
    },
    executiveSummary: {
      verdict: insufficient ? 'unknown' : reputation.verdict,
      riskScore: insufficient ? 0 : assessment.score,
      riskLevel: insufficient ? 'CLEAN' : assessment.level,
      insufficientIntelligence: insufficient,
      confidenceScore: assessment.confidenceScore,
      confidenceLabel: assessment.confidenceLabel,
      narrative: insufficient
        ? `Investigation ${detail.reference} could not produce an intelligence-based assessment for ${ioc.value} (${ioc.typeLabel}). None of the ${detail.counts.providers} queried source(s) returned usable data, so no risk score, verdict or ATT&CK mapping is asserted. A score of zero is NOT reported as a clean verdict: the correct conclusion is that the platform does not know. ${detail.counts.failed} source(s) failed and should be checked before re-running.`
        : `Investigation ${detail.reference} assessed indicator ${ioc.value} (${ioc.typeLabel}) as ${levelWord(assessment.level)}: risk ${assessment.score}/100 (${assessment.level}) at ${assessment.confidenceScore}% confidence, based on ${reputation.corroborationCount} corroborating intelligence source(s) and ${assessment.factors.length} documented scoring factor(s). ${techniques.length} MITRE ATT&CK technique(s) were mapped. ${detail.counts.failed > 0 ? `${detail.counts.failed} source(s) failed, so coverage is partial.` : 'All configured sources responded.'}`,
      keyFindings,
    },
    sections,
    riskScore: {
      score: assessment.score,
      level: assessment.level,
      confidence: assessment.confidenceScore,
      factors: assessment.factors,
      methodology: assessment.methodology,
    },
    attack: {
      techniques,
      statement: techniques.length
        ? `${techniques.length} technique(s) mapped with documented rationale.`
        : 'No MITRE ATT&CK technique identified for this indicator.',
    },
    relatedIndicators: detail.relatedIocs.map((r) => ({
      value: r.value,
      type: r.type,
      relation: r.relation,
      confidence: r.confidence,
      source: r.source,
    })),
    enrichment: providers.map((p) => ({
      provider: p.name,
      origin: p.origin,
      status: p.status,
      verdict: p.verdict,
      malicious: p.detections?.malicious ?? null,
      total: p.detections?.total ?? null,
      ratio: p.detections?.ratio ?? null,
      reports: p.reports,
      reputationScore: p.reputationScore,
      lastSeen: p.lastAnalysisAt,
      error: p.error?.message ?? null,
    })),
    timeline: detail.timeline.map((t) => ({ at: t.at, kind: t.kind, title: t.title, description: t.description, source: t.source })),
    recommendations: detail.recommendations,
    provenance: {
      dataOrigin:
        detail.mode === 'demo'
          ? `ThreatLens built-in demonstration dataset (${DEMO_MARKER})`
          : 'Live third-party threat intelligence providers',
      demoDataUsed: detail.mode === 'demo' || providers.some((p) => p.origin === 'demo'),
      providers: providers.map((p) => `${p.name} (${p.origin === 'demo' ? 'simulated' : 'live'})`),
      notes: [
        'Observed facts are values ThreatLens measured directly (indicator parsing, pipeline events, timing).',
        'External intelligence is third-party data, attributed per field; it is reported verbatim.',
        'Analyst assessment covers the risk score, ATT&CK mapping and recommended actions.',
        ...(detail.mode === 'demo'
          ? ['THIS REPORT USES SIMULATED DEMONSTRATION DATA. It must not be used for operational decisions.']
          : []),
        `Report engine: ThreatLens 1.0.0. MITRE ATT&CK knowledge base: ${ATTACK_VERSION}.`,
      ],
    },
  };
}

function describeObservedIoc(detail: InvestigationDetail): string {
  const { ioc } = detail;
  const parts = [`${ioc.typeLabel} indicator "${ioc.value}".`];
  if (ioc.parsed.hostname && ioc.type !== 'ipv4' && ioc.type !== 'ipv6') parts.push(`Host component: ${ioc.parsed.hostname}.`);
  if (ioc.parsed.registrableDomain && ioc.type !== 'ipv4' && ioc.type !== 'ipv6') {
    parts.push(`Registrable domain: ${ioc.parsed.registrableDomain}.`);
  }
  if (ioc.parsed.scheme) parts.push(`Scheme: ${ioc.parsed.scheme}.`);
  if (ioc.parsed.port) parts.push(`Destination port: ${ioc.parsed.port}.`);
  if (ioc.parsed.path && ioc.parsed.path !== '/') parts.push(`Path: ${ioc.parsed.path}.`);
  if (ioc.parsed.query) parts.push(`Query string present (${ioc.parsed.query.length} characters).`);
  if (ioc.isDocumentation) {
    parts.push('This indicator belongs to a reserved documentation range (RFC 5737 / RFC 3849) or reserved namespace (RFC 2606), so it cannot be live infrastructure.');
  }
  if (ioc.timesSeen > 1) parts.push(`The indicator has been investigated ${ioc.timesSeen} times in this platform.`);
  return parts.join(' ');
}

function buildAnalystNarrative(detail: InvestigationDetail, analystName: string | null): string {
  const { assessment, ioc, reputation, threatIntel, techniques } = detail;
  const lines: string[] = [];
  const who = analystName ? `Prepared by ${analystName}.` : '';

  lines.push(
    `${who} The indicator ${ioc.value} was assessed at ${assessment.score}/100 (${assessment.level}) with ${assessment.confidenceScore}% confidence. `,
  );
  lines.push(
    `The score is driven by ${assessment.factors.filter((f) => f.points > 0).length} positive factor(s) and reduced by ${assessment.factors.filter((f) => f.points <= 0).length} offset(s); the full arithmetic is in section 6. `,
  );

  if (reputation.maliciousSources.length) {
    lines.push(
      `${reputation.maliciousSources.length} source(s) returned a malicious verdict, which is the primary driver of the score. `,
    );
  } else if (reputation.cleanSources.length >= 2) {
    lines.push(
      `${reputation.cleanSources.length} independent sources report the indicator as clean, and no source reported malicious activity; this is why the score is low. `,
    );
  } else {
    lines.push('No source produced a decisive reputation verdict, so the score is driven by structural and behavioural signals only. ');
  }

  if (threatIntel.actors.length) {
    lines.push(
      `Attribution to ${threatIntel.actors.map((a) => a.name).join(', ')} is based on community intelligence rather than first-hand evidence and should be treated as an assessment, not a fact. `,
    );
  }
  if (threatIntel.malware.length) {
    lines.push(`Malware association with ${threatIntel.malware.map((m) => m.name).join(', ')} suggests the indicator is part of that tooling's infrastructure. `);
  }
  if (techniques.length) {
    lines.push(
      `The indicator maps to ${techniques.length} ATT&CK technique(s) (${techniques.map((t) => t.techniqueId).join(', ')}); the primary phase is ${techniques[0].tactic}. `,
    );
  } else {
    lines.push('No ATT&CK technique could be mapped from the available evidence; absence of mapping is not evidence of benign intent. ');
  }
  if (detail.counts.failed) {
    lines.push(
      `Coverage is incomplete: ${detail.counts.failed} source(s) failed. The confidence score has been reduced accordingly, and the assessment should be revisited once those sources are reachable. `,
    );
  }
  if (detail.demo) {
    lines.push(
      `NOTE: this investigation ran against the ThreatLens demonstration dataset, so the "intelligence" is simulated. The pipeline, scoring and reporting behaviour are real; the data is not. `,
    );
  }
  return lines.join('').trim();
}

// ------------------------------------------------------------------ markdown
export function reportToMarkdown(report: InvestigationReport): string {
  const lines: string[] = [];
  lines.push(`# ${report.title}`);
  lines.push('');
  lines.push(`**Classification:** ${report.classification.note}`);
  lines.push(`**Report ID:** ${report.reportId}  |  **Investigation:** ${report.investigation.reference}  |  **Generated:** ${report.generatedAt}`);
  lines.push(`**Intelligence mode:** ${report.generator.mode.toUpperCase()}${report.provenance.demoDataUsed ? ' (contains SIMULATED DEMO DATA)' : ''}`);
  lines.push('');
  lines.push('## 1. Executive Summary');
  lines.push('');
  lines.push(report.executiveSummary.narrative);
  lines.push('');
  for (const finding of report.executiveSummary.keyFindings) lines.push(`- ${finding}`);
  lines.push('');
  lines.push('### Provenance of this report');
  lines.push('');
  for (const note of report.provenance.notes) lines.push(`- ${note}`);
  lines.push('');
  for (const section of report.sections) {
    lines.push(`## ${section.title}`);
    lines.push('');
    lines.push(`*Evidence class: ${section.classification}*`);
    lines.push('');
    lines.push(section.body);
    lines.push('');
    if (section.table) {
      lines.push(`| ${section.table.headers.join(' | ')} |`);
      lines.push(`| ${section.table.headers.map(() => '---').join(' | ')} |`);
      for (const row of section.table.rows) {
        lines.push(`| ${row.map((c) => String(c).replace(/\|/g, '\\|').replace(/\n/g, ' ')).join(' | ')} |`);
      }
      lines.push('');
    }
    if (section.bullets) {
      for (const bullet of section.bullets) lines.push(`- ${bullet}`);
      lines.push('');
    }
  }
  return lines.join('\n');
}
