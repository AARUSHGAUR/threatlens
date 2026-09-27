/** Shared client-side types (mirrors the server contract in core/types.ts). */
export type IocType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'email';
export type Verdict = 'malicious' | 'suspicious' | 'clean' | 'harmless' | 'unknown';
export type RiskLevel = 'CLEAN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type InvestigationStatus = 'pending' | 'enriching' | 'analyzing' | 'completed' | 'partial' | 'failed';
export type Confidence = 'high' | 'medium' | 'low';
export type TimelineEventKind =
  | 'investigation' | 'validation' | 'provider' | 'provider-error'
  | 'correlation' | 'scoring' | 'attack' | 'report' | 'note';

export type CorrelationNodeType =
  | 'ioc' | 'domain' | 'ip' | 'url' | 'hash' | 'email'
  | 'malware' | 'actor' | 'campaign' | 'asn';

export interface CorrelationNode {
  id: string;
  label: string;
  type: CorrelationNodeType;
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
  searchQuery?: string;
}

export interface TechniqueMapping {
  techniqueId: string;
  name: string;
  tactic: string;
  tacticPhase: string;
  description: string;
  relationship: string;
  confidence: Confidence;
  reference: string;
  mappingBasis: 'provider-signal' | 'behavioural-rule' | 'malware-family-intel';
}

export interface RiskFactor {
  id: string;
  label: string;
  points: number;
  evidence: string;
  sources: string[];
  category: string;
}
