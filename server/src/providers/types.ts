/**
 * ============================================================================
 * THREAT INTELLIGENCE PROVIDER INTERFACE
 * ============================================================================
 *
 * Every source of intelligence - a live HTTP API or the built-in demo dataset -
 * implements this single interface. That is what allows the CTI service layer
 * to be provider-agnostic: adding GreyNoise tomorrow only means writing one new
 * file and registering it; no investigation, scoring, UI or report code changes.
 *
 * A provider MUST:
 *   - never throw (errors are returned as `status` + `error` so one dead
 *     provider can never fail an entire investigation),
 *   - never fabricate data (if it does not know something, it returns null /
 *     an empty list and says so),
 *   - label the origin of the data ('live' vs 'demo') so the UI can be honest
 *     about the provenance of every field.
 */
import type { IocType, NormalizedIoc, ProviderVerdict } from '../core/types.js';

export interface ProviderContext {
  /** Which intelligence mode the request is running in. */
  mode: 'live' | 'demo';
  /** Free-form progress reporter, used to build the investigation timeline. */
  onProgress?: (message: string, meta?: Record<string, unknown>) => void;
  signal?: AbortSignal;
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
  /** Populated by the self-test in /api/providers/health. */
  lastCheckedAt: string | null;
  lastStatus: 'unknown' | 'ok' | 'error' | 'unconfigured' | 'rate_limited';
  lastMessage: string | null;
}

export interface ThreatIntelProvider {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly homepage: string;
  readonly documentationUrl: string;
  readonly requiresKey: boolean;
  readonly supports: readonly IocType[];
  /** True when credentials for this provider exist in the environment. */
  isConfigured(): boolean;
  /**
   * Look up one indicator. Must resolve (never reject) with a ProviderVerdict.
   */
  lookup(ioc: NormalizedIoc, ctx: ProviderContext): Promise<ProviderVerdict>;
}

/** Factory for a verdict shell so providers only fill in what they know. */
export function emptyVerdict(
  provider: Pick<ThreatIntelProvider, 'id' | 'name'>,
  origin: 'live' | 'demo',
  status: ProviderVerdict['status'] = 'ok',
): ProviderVerdict {
  return {
    providerId: provider.id,
    providerName: provider.name,
    origin,
    status,
    verdict: 'unknown',
    reputationScore: null,
    reports: null,
    detections: null,
    network: null,
    related: {
      domains: [],
      urls: [],
      hashes: [],
      ipAddresses: [],
      emails: [],
      categories: [],
      malware: [],
      actors: [],
      campaigns: [],
      behaviours: [],
    },
    firstSeenAt: null,
    lastSeenAt: null,
    rawExcerpt: null,
    durationMs: 0,
    url: null,
  };
}
