/**
 * Core domain model for ThreatLens.
 *
 * These types are the contract between every layer:
 *   detection -> validation -> providers -> aggregation -> risk -> persistence -> API
 *
 * Keeping them in one module makes it obvious during a viva that every layer
 * speaks the same language, and it prevents the classic "provider returns a
 * slightly different shape" bug class.
 */

export type IocType =
  | 'ipv4'
  | 'ipv6'
  | 'domain'
  | 'url'
  | 'md5'
  | 'sha1'
  | 'sha256'
  | 'email';

export const IOC_TYPES: IocType[] = [
  'ipv4',
  'ipv6',
  'domain',
  'url',
  'md5',
  'sha1',
  'sha256',
  'email',
];

export type Verdict = 'malicious' | 'suspicious' | 'clean' | 'harmless' | 'unknown';

export type RiskLevel = 'CLEAN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type InvestigationStatus =
  | 'pending'
  | 'enriching'
  | 'analyzing'
  | 'completed'
  | 'partial'
  | 'failed';

export type Confidence = 'high' | 'medium' | 'low';

/** A validated indicator of compromise. */
export interface NormalizedIoc {
  /** Canonical value used for lookups (e.g. lower-cased host, raw URL). */
  value: string;
  /** Exactly what the analyst typed. */
  raw: string;
  type: IocType;
  /** Extra parsed fields, present depending on `type`. */
  parsed: {
    hostname?: string;
    port?: number;
    scheme?: string;
    path?: string;
    query?: string;
    /** Registrable domain approximation (public-suffix aware for common cases). */
    registrableDomain?: string;
    tld?: string;
    isPunycode?: boolean;
    subdomainDepth?: number;
    emailDomain?: string;
    emailLocalPart?: string;
  };
}

export interface DetectionStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  unsupported: number;
  /** Engines that returned "no detection" (VirusTotal `undetected`). */
  undetected?: number;
  total: number;
  /** malicious / (total engines) - the classic VirusTotal ratio. */
  ratio: number | null;
  lastAnalysisAt: string | null;
}

export interface NetworkIntel {
  country?: string | null;
  countryCode?: string | null;
  city?: string | null;
  region?: string | null;
  asn?: number | string | null;
  asnOrg?: string | null;
  isp?: string | null;
  org?: string | null;
  reverseDns?: string[] | null;
  hostingProvider?: string | null;
  usageType?: string | null;
  domain?: string | null;
  ispDomain?: string | null;
  totalReports?: number | null;
  lastReportedAt?: string | null;
  abuseConfidenceScore?: number | null;
}

export interface RelatedIntel {
  domains: string[];
  urls: string[];
  hashes: string[];
  ipAddresses: string[];
  emails: string[];
  /** Free-text threat categories, e.g. "phishing", "c2", "botnet". */
  categories: string[];
  malware: string[];
  actors: string[];
  campaigns: string[];
  /** Behavioural tags used by the C2 / behavioural correlation rules. */
  behaviours: string[];
}

/** Normalised intelligence returned by *every* provider adapter. */
export interface ProviderVerdict {
  providerId: string;
  providerName: string;
  /** `live` = real API response, `demo` = built-in fictional dataset. */
  origin: 'live' | 'demo';
  status: 'ok' | 'not_found' | 'unconfigured' | 'error' | 'rate_limited' | 'timeout';
  error?: {
    code: string;
    message: string;
    httpStatus?: number;
    retryable: boolean;
  };
  verdict: Verdict;
  /** 0-100, higher = more malicious. Provider-native, not risk-engine input. */
  reputationScore: number | null;
  reports: number | null;
  detections: DetectionStats | null;
  network: NetworkIntel | null;
  related: RelatedIntel;
  /** First/last time the provider believes it saw the indicator. */
  firstSeenAt: string | null;
  lastSeenAt: string | null;
  /** Truncated raw payload (max 8 KB) for analyst auditability. */
  rawExcerpt: string | null;
  /** How long the upstream call took - surfaced in the UI. */
  durationMs: number;
  url?: string | null;
}

export interface RiskFactor {
  id: string;
  label: string;
  /** Signed contribution to the final score. */
  points: number;
  /** The concrete observation that triggered the rule. */
  evidence: string;
  /** Where the evidence came from. */
  sources: string[];
  category: 'reputation' | 'abuse' | 'association' | 'behaviour' | 'infrastructure' | 'context' | 'offset';
}

export interface RiskAssessment {
  score: number;
  /** Sum of factors before the 0-100 clamp. Surfaced so clamping is never hidden. */
  rawScore: number;
  level: RiskLevel;
  confidenceScore: number;
  confidenceLabel: Confidence;
  factors: RiskFactor[];
  positives: RiskFactor[];
  offsets: RiskFactor[];
  methodology: string;
  scoredAt: string;
}

export type TechniqueRelation = 'initial-access' | 'command-and-control' | 'execution' | 'defense-evasion' | 'impact' | 'delivery' | 'resource-development' | 'collection' | 'exfiltration' | 'persistence' | 'discovery' | 'lateral-movement' | 'credential-access' | 'privilege-escalation' | 'evasion';

export interface TechniqueMapping {
  techniqueId: string;
  name: string;
  tactic: string;
  tacticPhase: string;
  description: string;
  /** Why this technique is relevant to *this* indicator. */
  relationship: string;
  confidence: Confidence;
  /** ATT&CK url, built from the technique id. */
  reference: string;
  mappingBasis: 'provider-signal' | 'behavioural-rule' | 'malware-family-intel';
}

export type CorrelationNodeType =
  | 'ioc'
  | 'domain'
  | 'ip'
  | 'url'
  | 'hash'
  | 'email'
  | 'malware'
  | 'actor'
  | 'campaign'
  | 'asn';

export interface CorrelationNode {
  id: string;
  label: string;
  type: CorrelationNodeType;
  /** True for the indicator the analyst submitted. */
  isSubject: boolean;
  riskLevel?: RiskLevel | null;
  meta?: Record<string, string | number | null>;
}

export interface CorrelationEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  description: string;
  confidence: Confidence;
}

export interface CorrelationGraph {
  nodes: CorrelationNode[];
  edges: CorrelationEdge[];
}

export interface DefensiveAction {
  id: string;
  title: string;
  detail: string;
  category: 'containment' | 'detection' | 'eradication' | 'hunting' | 'monitoring';
  priority: 1 | 2 | 3;
  /** Concrete search string an analyst can paste into a SIEM/EDR. */
  searchQuery?: string;
}

export type TimelineEventKind =
  | 'investigation'
  | 'validation'
  | 'provider'
  | 'provider-error'
  | 'correlation'
  | 'scoring'
  | 'attack'
  | 'report'
  | 'note';

export interface TimelineEvent {
  id?: number;
  investigationId?: number;
  seq: number;
  at: string;
  kind: TimelineEventKind;
  title: string;
  description: string;
  source?: string | null;
  meta?: Record<string, unknown> | null;
}
