/**
 * ============================================================================
 * PROVIDER REGISTRY & INTELLIGENCE MODE RESOLUTION
 * ============================================================================
 *
 * Single place that decides *which* providers run and *in which mode*.
 *
 * MODE RESOLUTION ORDER (first match wins):
 *   1. runtime override set from the Settings page (persisted in `settings`)
 *   2. INTELLIGENCE_MODE from the environment: demo | live | auto
 *   3. auto  -> live when at least one provider key is present, otherwise demo
 *
 * Honesty rule: forcing LIVE mode with no credentials does NOT silently fall back
 * to demo data. The investigation completes with every provider reporting
 * `unconfigured` and an explicit error message, because presenting simulated
 * data as live intelligence is the worst possible failure mode for a CTI tool.
 */
import { config } from '../config/env.js';
import { fromJson, q } from '../db/index.js';
import type { IocType } from '../core/types.js';
import type { ProviderContext, ProviderHealth, ThreatIntelProvider } from './types.js';
import { AbuseIPDBProvider } from './abuseipdb/index.js';
import { DemoProvider, DEMO_SOURCE_SPECS } from './demo/index.js';
import { GreyNoiseProvider } from './greynoise/index.js';
import { OtxProvider } from './otx/index.js';
import { ShodanProvider } from './shodan/index.js';
import { UrlhausProvider } from './urlhaus/index.js';
import { VirusTotalProvider } from './virustotal/index.js';

export type ResolvedMode = 'live' | 'demo';

const SETTINGS_KEY = 'intelligence_mode';

export function getModeOverride(): ResolvedMode | null {
  const row = q.get<{ value_json: string }>('SELECT value_json FROM settings WHERE key = ?', [SETTINGS_KEY]);
  if (!row) return null;
  const value = fromJson<{ mode?: string } | null>(row.value_json, null);
  if (value?.mode === 'live' || value?.mode === 'demo') return value.mode;
  return null;
}

export function setModeOverride(mode: ResolvedMode | null): void {
  if (mode === null) {
    q.run('DELETE FROM settings WHERE key = ?', [SETTINGS_KEY]);
    return;
  }
  q.run(
    `INSERT INTO settings (key, value_json, updated_at) VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
     ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
    [SETTINGS_KEY, JSON.stringify({ mode })],
  );
}

export function resolveMode(): ResolvedMode {
  const override = getModeOverride();
  if (override) return override;
  if (config.intelligenceMode === 'demo') return 'demo';
  if (config.intelligenceMode === 'live') return 'live';
  return config.hasAnyLiveKey ? 'live' : 'demo';
}

/** All live providers, regardless of whether a key is configured. */
export function buildLiveProviders(): ThreatIntelProvider[] {
  return [
    new VirusTotalProvider(),
    new AbuseIPDBProvider(),
    new OtxProvider(),
    new UrlhausProvider(),
    new GreyNoiseProvider(),
    new ShodanProvider(),
  ];
}

export interface RegistrySnapshot {
  mode: ResolvedMode;
  modeSource: 'override' | 'environment';
  modeLabel: string;
  hasLiveKeys: boolean;
  providers: ProviderHealth[];
  notice: string | null;
}

const lastStatus = new Map<string, { at: string; status: ProviderHealth['lastStatus']; message: string | null }>();

export function recordProviderStatus(providerId: string, status: ProviderHealth['lastStatus'], message: string | null): void {
  lastStatus.set(providerId, { at: new Date().toISOString(), status, message });
}

/** Health table shown on the Settings page ("Provider Health"). */
export function providerHealth(mode: ResolvedMode = resolveMode()): ProviderHealth[] {
  const live = buildLiveProviders();

  if (mode === 'demo') {
    const demoSources: ProviderHealth[] = Object.values(DEMO_SOURCE_SPECS).map((spec) => ({
      id: spec.id,
      name: spec.name,
      description: spec.description,
      homepage: spec.homepage,
      documentationUrl: spec.documentationUrl,
      requiresKey: spec.requiresKey,
      configured: true,
      supports: spec.supports,
      lastCheckedAt: null,
      lastStatus: 'ok',
      lastMessage: 'Built-in demonstration dataset (simulated).',
    }));
    const demoBase: ProviderHealth = {
      id: 'demo',
      name: 'ThreatLens Demo Intelligence',
      description:
        'Fictional dataset used because no API keys are configured. Indicators are synthetic and clearly labelled DEMO DATA.',
      homepage: 'internal',
      documentationUrl: 'internal',
      requiresKey: false,
      configured: true,
      supports: ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email'],
      lastCheckedAt: null,
      lastStatus: 'ok',
      lastMessage: null,
    };
    const liveStatus = live.map((p) => ({
      id: p.id,
      name: p.name,
      description: p.description,
      homepage: p.homepage,
      documentationUrl: p.documentationUrl,
      requiresKey: p.requiresKey,
      configured: p.isConfigured(),
      supports: p.supports as IocType[],
      lastCheckedAt: lastStatus.get(p.id)?.at ?? null,
      lastStatus: lastStatus.get(p.id)?.status ?? 'unknown',
      lastMessage: lastStatus.get(p.id)?.message ?? null,
    }));
    return [demoBase, ...demoSources, ...liveStatus.map((p) => ({ ...p, lastMessage: p.lastMessage ?? 'Not used while DEMO MODE is active.' }))];
  }

  return live.map((p) => ({
    id: p.id,
    name: p.name,
    description: p.description,
    homepage: p.homepage,
    documentationUrl: p.documentationUrl,
    requiresKey: p.requiresKey,
    configured: p.isConfigured(),
    supports: p.supports as IocType[],
    lastCheckedAt: lastStatus.get(p.id)?.at ?? null,
    lastStatus: p.isConfigured() ? (lastStatus.get(p.id)?.status ?? 'unknown') : 'unconfigured',
    lastMessage: lastStatus.get(p.id)?.message ?? (p.isConfigured() ? null : 'No API key configured for this provider.'),
  }));
}

export function registrySnapshot(): RegistrySnapshot {
  const mode = resolveMode();
  const override = getModeOverride();
  const notice =
    mode === 'demo'
      ? config.hasAnyLiveKey
        ? 'DEMO MODE is active. Provider keys are configured, but the demonstration dataset is being used so the demo is reproducible.'
        : 'DEMO MODE is active because no provider API keys were found. All intelligence shown is SIMULATED and labelled DEMO DATA.'
      : config.hasAnyLiveKey
        ? 'LIVE INTELLIGENCE is active. Real provider responses are stored as evidence.'
        : 'LIVE INTELLIGENCE is active but NO API KEYS are configured, so every provider will report "unconfigured". Add keys to .env - ThreatLens will not substitute demo data for live intelligence.';

  return {
    mode,
    modeSource: override ? 'override' : 'environment',
    modeLabel: mode === 'demo' ? 'DEMO MODE' : 'LIVE INTELLIGENCE',
    hasLiveKeys: config.hasAnyLiveKey,
    providers: providerHealth(mode),
    notice,
  };
}

export interface ProviderRun {
  provider: ThreatIntelProvider;
  id: string;
  name: string;
}

/**
 * Decide the provider work list for one indicator.
 * - Demo mode: the demo provider expands into several simulated sources.
 * - Live mode: every live provider is included so that unconfigured providers
 *   are reported explicitly instead of silently disappearing.
 */
export function planProviderRuns(iocType: IocType, mode: ResolvedMode): ProviderRun[] {
  if (mode === 'demo') {
    return [{ provider: new DemoProvider(), id: 'demo', name: 'ThreatLens Demo Intelligence' }];
  }
  return buildLiveProviders().map((p) => ({ provider: p, id: p.id, name: p.name }));
}

export const providerSupports = (run: ProviderRun, iocType: IocType): boolean =>
  run.id === 'demo' ? true : run.provider.supports.includes(iocType);

export type { ProviderContext };
