/**
 * Typed API client.
 *
 * SECURITY: this module only ever talks to our own backend (`/api`). No
 * provider credential, URL or key is referenced in the browser bundle - the
 * browser cannot reach VirusTotal/AbuseIPDB directly even with a valid session.
 * The session is an httpOnly cookie, so there is no token in JS to steal.
 */
import type {
  IocType,
  InvestigationStatus,
  RiskLevel,
  Verdict,
  Confidence,
  CorrelationGraph,
  DefensiveAction,
  TechniqueMapping,
  TimelineEventKind,
} from './types';

export type {
  IocType, InvestigationStatus, RiskLevel, Verdict, Confidence,
  CorrelationGraph, CorrelationNode, CorrelationEdge, CorrelationNodeType,
  DefensiveAction, TechniqueMapping, RiskFactor, TimelineEventKind,
} from './types';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly hint?: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`/api${path}`, {
      credentials: 'same-origin',
      headers: {
        accept: 'application/json',
        ...(init.body ? { 'content-type': 'application/json' } : {}),
        ...(init.headers ?? {}),
      },
      ...init,
    });
  } catch {
    throw new ApiError(0, 'network_error', 'Cannot reach the ThreatLens API. Check that the server is running.');
  }

  if (response.status === 204) return undefined as T;

  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!response.ok) {
    const err = (payload as { error?: { code?: string; message?: string; hint?: string } } | null)?.error;
    throw new ApiError(
      response.status,
      err?.code ?? 'http_error',
      err?.message ?? `Request failed with status ${response.status}.`,
      err?.hint,
    );
  }
  return payload as T;
}

const post = <T>(path: string, body?: unknown): Promise<T> =>
  request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });

const patch = <T>(path: string, body: unknown): Promise<T> =>
  request<T>(path, { method: 'PATCH', body: JSON.stringify(body) });

const del = <T>(path: string): Promise<T> => request<T>(path, { method: 'DELETE' });

// ============================================================== types (wire)
export interface PublicUser {
  id: number;
  email: string;
  displayName: string;
  role: 'analyst' | 'senior_analyst' | 'admin';
  organisation: string | null;
  createdAt: string;
  lastLoginAt: string | null;
}

export interface ProviderHealth {
  id: string;
  name: string;
  description: string;
  homepage: string;
  documentationUrl: string;
  requiresKey: boolean;
  configured: boolean;
  supports: IocType[];
  lastCheckedAt: string | null;
  lastStatus: 'unknown' | 'ok' | 'error' | 'unconfigured' | 'rate_limited';
  lastMessage: string | null;
}

export interface RegistrySnapshot {
  mode: 'live' | 'demo';
  modeSource: 'override' | 'environment';
  modeLabel: string;
  hasLiveKeys: boolean;
  providers: ProviderHealth[];
  notice: string | null;
}

export interface Bootstrap {
  appName: string;
  version: string;
  environment: string;
  registry: RegistrySnapshot;
  demoCatalog: DemoCatalogEntry[];
  iocTypes: Array<{ value: IocType; label: string }>;
}

export interface DemoCatalogEntry {
  value: string;
  type: IocType;
  title: string;
  summary: string;
  expectedLevel: string;
  expectedScoreHint: string;
}

export interface DetectionResponse {
  detection: {
    type: IocType;
    typeLabel: string;
    value: string;
    rule: string;
    defanged: boolean;
    notes: string[];
  } | null;
  valid: boolean;
  error: { code: string; message: string; hint?: string } | null;
  warnings: Array<{ code: string; message: string }>;
  isDocumentationExample: boolean;
}

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

export interface DashboardData {
  stats: {
    totalIocsInvestigated: number;
    uniqueIndicators: number;
    malicious: number;
    suspicious: number;
    clean: number;
    critical: number;
    high: number;
    thisWeek: number;
    completed: number;
    partial: number;
    failed: number;
    pending: number;
    averageRisk: number | null;
  };
  charts: {
    iocTypes: CountRow[];
    riskDistribution: CountRow[];
    verdicts: CountRow[];
    timeline: Array<{ date: string; count: number; critical: number; high: number }>;
    categories: CountRow[];
    countries: CountRow[];
    asns: CountRow[];
    malware: CountRow[];
    providers: Array<CountRow & { errors: number; ok: number }>;
  };
  techniques: Array<{ external_id: string; name: string; tactic: string; count: number; last_seen: string }>;
  mostInvestigated: Array<{ value: string; type: IocType; count: number; riskLevel: RiskLevel | null; riskScore: number | null }>;
  recent: InvestigationListItem[];
  mode: RegistrySnapshot;
}

export interface CountRow {
  key: string;
  label: string;
  count: number;
}

export interface StartInvestigationResponse {
  investigationId: number;
  reference: string;
  status: InvestigationStatus;
  mode: 'live' | 'demo';
  ioc: { id: number; value: string; type: IocType; typeLabel: string };
  warnings: Array<{ code: string; message: string }>;
}

export interface ProgressResponse {
  id: number;
  reference: string;
  status: InvestigationStatus;
  riskScore: number | null;
  riskLevel: RiskLevel | null;
  progress: { completed: number; lastEventAt: string | null };
  timeline: Array<{ seq: number; at: string; kind: string; title: string; description: string; source: string | null }>;
}

export interface NetworkField {
  label: string;
  value: string | null;
  source: string | null;
}

export interface ProviderSummary {
  id: string;
  name: string;
  origin: 'live' | 'demo';
  status: string;
  verdict: Verdict;
  reputationScore: number | null;
  reports: number | null;
  detections: {
    malicious: number;
    suspicious: number;
    harmless: number;
    unsupported: number;
    undetected: number;
    total: number;
    ratio: number | null;
  } | null;
  lastAnalysisAt: string | null;
  firstSeenAt: string | null;
  durationMs: number;
  error: { code: string; message: string; retryable: boolean } | null;
  network: Record<string, unknown> | null;
  related: {
    domains: string[];
    urls: string[];
    hashes: string[];
    ipAddresses: string[];
    emails: string[];
    categories: string[];
    malware: string[];
    actors: string[];
    campaigns: string[];
    behaviours: string[];
  };
  rawExcerpt: string | null;
  url: string | null;
}

export interface InvestigationDetail {
  id: number;
  reference: string;
  status: InvestigationStatus;
  mode: 'live' | 'demo';
  createdAt: string;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  requestedBy: { id: number; name: string } | null;
  ioc: {
    id: number;
    value: string;
    raw: string;
    type: IocType;
    typeLabel: string;
    description: string;
    parsed: Record<string, string | number | boolean | undefined>;
    isDocumentation: boolean;
    isPrivate: boolean;
    timesSeen: number;
    firstSeenAt: string;
    lastSeenAt: string;
    notes: string | null;
  };
  assessment: {
    score: number;
    rawScore: number;
    clamped: boolean;
    level: RiskLevel;
    confidenceScore: number;
    confidenceLabel: Confidence;
    verdict: Verdict;
    factors: Array<{
      id: string;
      label: string;
      points: number;
      evidence: string;
      sources: string[];
      category: string;
    }>;
    methodology: string;
  };
  reputation: {
    verdict: Verdict;
    detections: {
      malicious: number;
      suspicious: number;
      harmless: number;
      unsupported: number;
      undetected: number;
      total: number;
      ratio: number | null;
      lastAnalysisAt: string | null;
    } | null;
    reports: number | null;
    reputationScore: number | null;
    lastSeenAt: string | null;
    firstSeenAt: string | null;
    maliciousSources: string[];
    suspiciousSources: string[];
    cleanSources: string[];
    neutralSources: string[];
    corroborationCount: number;
  };
  network: { fields: NetworkField[]; raw: Record<string, unknown> | null };
  threatIntel: {
    malware: Array<{
      name: string;
      type: string | null;
      platform: string[];
      capabilities: string[];
      origin: string;
      confidence: Confidence;
      basis: string;
      description: string | null;
      techniqueIds: string[];
    }>;
    actors: Array<{
      name: string;
      externalId: string;
      origin: string;
      sophistication: string | null;
      motivation: string[];
      description: string | null;
      firstSeenYear: number | null;
      aliases: string[];
      confidence: Confidence;
      basis: string;
    }>;
    campaigns: Array<{ name: string; externalId: string; origin: string; description: string | null; firstSeen: string | null; confidence: Confidence }>;
    categories: string[];
    behaviours: string[];
    relatedDomains: string[];
    relatedUrls: string[];
    relatedHashes: string[];
    relatedIps: string[];
    relatedEmails: string[];
  };
  techniques: TechniqueMapping[];
  providers: ProviderSummary[];
  graph: CorrelationGraph;
  recommendations: DefensiveAction[];
  timeline: Array<{
    seq: number;
    at: string;
    kind: TimelineEventKind | string;
    title: string;
    description: string;
    source: string | null;
    meta: Record<string, unknown> | null;
  }>;
  relatedIocs: Array<{
    iocId: number;
    value: string;
    type: IocType;
    typeLabel: string;
    relation: string;
    confidence: Confidence;
    source: string;
    isDocumentation: boolean;
  }>;
  analyst: { notes: string | null; assessment: string | null; rating: string | null };
  demo: null | { title: string; summary: string; analystNote: string };
  warnings: Array<{ code: string; message: string }>;
  counts: { providers: number; ok: number; failed: number; techniques: number; related: number; timeline: number };
}

export interface HistoryResponse {
  total: number;
  items: InvestigationListItem[];
}

export interface HistoryQuery {
  search?: string;
  type?: string[];
  level?: string[];
  status?: string[];
  mode?: string[];
  sort?: string;
  limit?: number;
  offset?: number;
}

export interface TechniqueRecord {
  id: string;
  name: string;
  tactic: string;
  tactics: string[];
  description: string | null;
  platforms: string[];
  dataSources: string[];
  isSubtechnique: boolean;
  parentId: string | null;
  reference: string;
  investigationCount: number;
  lastObserved: string | null;
}

export interface ActorRecord {
  id: string;
  name: string;
  aliases: string[];
  origin: 'live' | 'demo' | 'community';
  sophistication: string | null;
  motivation: string[];
  firstSeenYear: number | null;
  description: string | null;
  investigationCount: number;
  indicatorCount: number;
  malwareCount: number;
  campaignCount: number;
  lastSeen: string | null;
}

export interface MalwareRecord {
  id: string;
  name: string;
  aliases: string[];
  type: string | null;
  platforms: string[];
  capabilities: string[];
  origin: 'live' | 'demo' | 'community';
  description: string | null;
  investigationCount: number;
  actorCount: number;
  lastSeen: string | null;
}

export interface CampaignRecord {
  id: string;
  name: string;
  origin: 'live' | 'demo' | 'community';
  firstSeen: string | null;
  description: string | null;
  investigationCount: number;
  lastSeen: string | null;
}

export interface SettingsData {
  registry: RegistrySnapshot;
  modeOverride: 'live' | 'demo' | null;
  environment: {
    nodeEnv: string;
    port: number;
    database: string;
    providerMinIntervalMs: number;
    providerTimeoutMs: number;
    showDemoBadge: boolean;
  };
  riskMethodology: string;
  apiKeys: Record<string, boolean>;
  analyst: PublicUser;
  totals: { users: number; investigations: number };
  audit: Array<{ id: number; userId: number | null; action: string; entity: string | null; entityId: string | null; at: string; meta: Record<string, unknown> }>;
}

export interface ReportsData {
  investigations: Array<{
    id: number;
    reference: string;
    ioc: string;
    iocType: string;
    riskScore: number | null;
    riskLevel: RiskLevel | null;
    status: InvestigationStatus;
    mode: 'live' | 'demo';
    createdAt: string;
  }>;
  generated: Array<{
    id: number;
    investigation_id: number;
    title: string;
    classification: string;
    generated_at: string;
    format: string;
    byte_size: number | null;
  }>;
}

// ================================================================== endpoints
export const api = {
  bootstrap: () => request<Bootstrap>('/public/bootstrap'),
  me: () => request<{ user: PublicUser | null }>('/auth/me'),
  login: (email: string, password: string) => post<{ user: PublicUser }>('/auth/login', { email, password }),
  logout: () => post<{ ok: true }>('/auth/logout'),
  updateProfile: (body: { displayName?: string; organisation?: string | null }) => patch<{ user: PublicUser }>('/auth/me', body),
  changePassword: (body: { currentPassword: string; newPassword: string }) => post<{ ok: true }>('/auth/password', body),

  dashboard: () => request<DashboardData>('/dashboard'),

  detect: (indicator: string) => post<DetectionResponse>('/iocs/detect', { indicator }),
  startInvestigation: (indicator: string, mode?: 'live' | 'demo') => post<StartInvestigationResponse>('/investigations', { indicator, mode }),
  progress: (id: number) => request<ProgressResponse>(`/investigations/${id}/progress`),
  investigation: (id: number) => request<InvestigationDetail>(`/investigations/${id}`),
  history: (query: HistoryQuery = {}) => {
    const params = new URLSearchParams();
    if (query.search) params.set('search', query.search);
    for (const t of query.type ?? []) params.append('type', t);
    for (const l of query.level ?? []) params.append('level', l);
    for (const s of query.status ?? []) params.append('status', s);
    for (const m of query.mode ?? []) params.append('mode', m);
    if (query.sort) params.set('sort', query.sort);
    if (query.limit) params.set('limit', String(query.limit));
    if (query.offset) params.set('offset', String(query.offset));
    const qs = params.toString();
    return request<HistoryResponse>(`/investigations${qs ? `?${qs}` : ''}`);
  },
  deleteInvestigation: (id: number) => del<{ ok: true; deleted: number }>(`/investigations/${id}`),
  saveAnalystNotes: (id: number, body: { notes?: string | null; assessment?: string | null; rating?: string | null }) =>
    patch<{ ok: true }>(`/investigations/${id}/analyst-notes`, body),
  reanalyse: (id: number) => post<{ investigationId: number; reference: string }>(`/investigations/${id}/reanalyse`),

  indicators: (limit = 100, offset = 0) =>
    request<{ total: number; items: Array<{ id: number; type: IocType; value: string; is_documentation: number; is_private: number; times_seen: number; first_seen_at: string; last_seen_at: string; notes: string | null }> }>(
      `/iocs?limit=${limit}&offset=${offset}`,
    ),

  mitre: () => request<{ version: string; total: number; techniques: TechniqueRecord[] }>('/knowledge/mitre'),
  actors: () => request<{ actors: ActorRecord[] }>('/knowledge/actors'),
  malware: () => request<{ malware: MalwareRecord[] }>('/knowledge/malware'),
  campaigns: () => request<{ campaigns: CampaignRecord[] }>('/knowledge/campaigns'),

  reports: () => request<ReportsData>('/reports'),
  report: (id: number) => request<Record<string, unknown>>(`/reports/${id}`),
  exportUrl: (id: number, format: 'json' | 'pdf' | 'md') => `/api/reports/${id}/export.${format}`,

  settings: () => request<SettingsData>('/settings'),
  setMode: (mode: 'live' | 'demo' | 'auto') => post<{ mode: 'live' | 'demo'; override: 'live' | 'demo' | null; registry: RegistrySnapshot }>('/settings/mode', { mode }),
  health: () => request<{ status: string; database: boolean; mode: string; uptimeSeconds: number }>('/health'),
};
