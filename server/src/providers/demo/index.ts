/**
 * ============================================================================
 * DEMO INTELLIGENCE PROVIDER
 * ============================================================================
 *
 * Implements the *same* provider interface as the live adapters, but expands a
 * single fictional profile into several independent "source" verdicts
 * (multi-engine reputation, abuse reports, community pulses, distribution
 * feed, scanner index, service exposure).
 *
 * Why several? Because the risk engine's corroboration factor measures how many
 * *independent* sources agree. Simulating a single opaque blob would make the
 * risk model look fake and would hide the most interesting part of the design.
 *
 * HONESTY RULES ENFORCED HERE:
 *  - every verdict carries `origin: 'demo'`,
 *  - provider names are suffixed with "(DEMO)",
 *  - an indicator that is not in the catalog returns `not_found` with an
 *    explanation - we never invent intelligence for unknown indicators,
 *  - `rawExcerpt` embeds the literal string "SIMULATED DEMO DATA - NOT A REAL API RESPONSE".
 */
import type { IocType, NormalizedIoc, ProviderVerdict } from '../../core/types.js';
import { emptyVerdict, type ProviderContext, type ThreatIntelProvider } from '../types.js';
import { buildDetectionStats, safeStr, toIso, uniq, verdictFromStats } from '../normalize.js';
import {
  DEMO_CATALOG,
  DEMO_PROFILE_BY_VALUE,
  demoNowIso,
  type DemoProfile,
} from './dataset.js';

const DEMO_MARKER = 'SIMULATED DEMO DATA - NOT A REAL API RESPONSE';

interface SourceSpec {
  id: string;
  name: string;
  description: string;
  homepage: string;
  documentationUrl: string;
  requiresKey: boolean;
  supports: IocType[];
}

const SOURCES: Record<string, SourceSpec> = {
  reputation: {
    id: 'demo:reputation',
    name: 'Multi-Engine Reputation (DEMO)',
    description: 'Simulated multi-engine AV consensus feed modelled on VirusTotal response shape.',
    homepage: 'https://www.virustotal.com',
    documentationUrl: 'https://docs.virustotal.com/reference/overview',
    requiresKey: false,
    supports: ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'],
  },
  abuse: {
    id: 'demo:abuse',
    name: 'Abuse Reporting Network (DEMO)',
    description: 'Simulated crowd-sourced abuse report source modelled on AbuseIPDB response shape.',
    homepage: 'https://www.abuseipdb.com',
    documentationUrl: 'https://docs.abuseipdb.com/',
    requiresKey: false,
    supports: ['ipv4', 'ipv6'],
  },
  pulses: {
    id: 'demo:otx',
    name: 'Community Pulse Platform (DEMO)',
    description: 'Simulated pulse/collection platform modelled on AlienVault OTX response shape.',
    homepage: 'https://otx.alienvault.com',
    documentationUrl: 'https://otx.alienvault.com/api',
    requiresKey: false,
    supports: ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email'],
  },
  distribution: {
    id: 'demo:urlhaus',
    name: 'Malware Distribution Feed (DEMO)',
    description: 'Simulated payload-hosting feed modelled on URLhaus response shape.',
    homepage: 'https://urlhaus.abuse.ch',
    documentationUrl: 'https://urlhaus.abuse.ch/api/',
    requiresKey: false,
    supports: ['ipv4', 'ipv6', 'domain', 'url'],
  },
  scanner: {
    id: 'demo:greynoise',
    name: 'Internet Scanner Index (DEMO)',
    description: 'Simulated background-noise index modelled on GreyNoise response shape.',
    homepage: 'https://www.greynoise.io',
    documentationUrl: 'https://docs.greynoise.io/',
    requiresKey: false,
    supports: ['ipv4', 'ipv6'],
  },
  exposure: {
    id: 'demo:shodan',
    name: 'Service Exposure Database (DEMO)',
    description: 'Simulated host-exposure source modelled on Shodan response shape.',
    homepage: 'https://www.shodan.io',
    documentationUrl: 'https://developer.shodan.io/api',
    requiresKey: false,
    supports: ['ipv4', 'ipv6', 'domain'],
  },
};

export const DEMO_SOURCE_IDS = Object.keys(SOURCES);

const baseVerdict = (source: SourceSpec, ioc: NormalizedIoc): ProviderVerdict => {
  const v = emptyVerdict({ id: source.id, name: source.name }, 'demo');
  v.url = null;
  v.rawExcerpt = JSON.stringify({ warning: DEMO_MARKER, indicator: ioc.value, type: ioc.type });
  return v;
};

/** Simulated multi-engine reputation source. */
function reputationVerdict(profile: DemoProfile, ioc: NormalizedIoc): ProviderVerdict {
  const source = SOURCES.reputation;
  const v = baseVerdict(source, ioc);
  const lastSeen = demoNowIso(profile.lastSeenDaysAgo);
  v.status = 'ok';
  v.durationMs = 40 + ((ioc.value.length * 7) % 60);
  v.detections = buildDetectionStats({
    malicious: profile.detections.malicious,
    suspicious: profile.detections.suspicious,
    harmless: profile.detections.harmless,
    undetected: profile.detections.undetected,
    lastAnalysisAt: lastSeen,
  });
  v.verdict = verdictFromStats(v.detections);
  v.reputationScore = Math.min(100, profile.detections.malicious * 5 + profile.detections.suspicious * 2);
  v.reports = profile.reports;
  v.firstSeenAt = demoNowIso(profile.firstSeenDaysAgo);
  v.lastSeenAt = lastSeen;
  v.network = profile.network;
  v.related.categories = uniq([...profile.categories, ...(v.verdict === 'malicious' ? ['malicious'] : [])]);
  v.related.behaviours = uniq(profile.behaviours);
  v.related.malware = uniq(profile.malware.map((id) => DEMO_MALWARE_LABELS.get(id) ?? id));
  v.related.actors = uniq(profile.actors.map((id) => DEMO_ACTOR_LABELS.get(id) ?? id));
  v.related.campaigns = uniq(profile.campaigns.map((id) => DEMO_CAMP_LABELS.get(id) ?? id));
  v.related.domains = profile.related.domains;
  v.related.urls = profile.related.urls;
  v.related.hashes = profile.related.hashes;
  v.related.ipAddresses = profile.related.ipAddresses;
  v.related.emails = profile.related.emails;
  v.url = null;
  v.rawExcerpt = JSON.stringify({
    warning: DEMO_MARKER,
    last_analysis_stats: {
      malicious: profile.detections.malicious,
      suspicious: profile.detections.suspicious,
      harmless: profile.detections.harmless,
      undetected: profile.detections.undetected,
    },
    reputation: profile.communityReputation,
    meaningful_name: profile.title,
    tags: profile.categories,
  });
  return v;
}

/** Simulated abuse-reporting source (IP only). */
function abuseVerdict(profile: DemoProfile, ioc: NormalizedIoc): ProviderVerdict | null {
  if (!profile.abuse || (ioc.type !== 'ipv4' && ioc.type !== 'ipv6')) return null;
  const source = SOURCES.abuse;
  const v = baseVerdict(source, ioc);
  const score = profile.abuse.score;
  const syntheticMalicious = Math.min(5, Math.round(score / 20));
  const lastReported = demoNowIso(profile.lastSeenDaysAgo);
  v.status = 'ok';
  v.durationMs = 30 + ((ioc.value.length * 5) % 40);
  v.detections = buildDetectionStats({
    malicious: syntheticMalicious,
    suspicious: score > 0 && score < 30 ? 1 : 0,
    harmless: 70 - syntheticMalicious,
    lastAnalysisAt: lastReported,
  });
  v.verdict = verdictFromStats(v.detections);
  v.reputationScore = Math.min(100, score);
  v.reports = profile.abuse.reports;
  v.lastSeenAt = lastReported;
  v.network = profile.network
    ? {
        ...profile.network,
        totalReports: profile.abuse.reports,
        lastReportedAt: lastReported,
        abuseConfidenceScore: score,
      }
    : {
        country: null,
        countryCode: null,
        city: null,
        region: null,
        asn: null,
        asnOrg: null,
        isp: null,
        org: null,
        reverseDns: null,
        hostingProvider: null,
        usageType: profile.abuse.usageType,
        domain: null,
        ispDomain: null,
        totalReports: profile.abuse.reports,
        lastReportedAt: lastReported,
        abuseConfidenceScore: score,
      };

  const usage = profile.abuse.usageType.toLowerCase();
  v.related.behaviours = uniq([
    profile.abuse.reports > 0 ? 'reported-by-community' : null,
    score >= 90 ? 'high-abuse-confidence' : score >= 50 ? 'moderate-abuse-confidence' : null,
    /data center|hosting|transit/.test(usage) ? 'hosted-infrastructure' : null,
    /command & control/.test(usage) ? 'c2' : null,
    /content delivery network/.test(usage) ? 'cdn' : null,
  ]);
  v.related.categories = uniq([...v.related.behaviours, ...(score === 0 ? ['no-abuse-reports'] : [])]);
  v.related.domains = profile.network?.reverseDns ?? [];
  v.rawExcerpt = JSON.stringify({
    warning: DEMO_MARKER,
    abuseConfidenceScore: score,
    totalReports: profile.abuse.reports,
    numDistinctUsers: profile.abuse.distinctUsers,
    usageType: profile.abuse.usageType,
    isp: profile.network?.isp ?? null,
    countryCode: profile.network?.countryCode ?? null,
  });
  return v;
}

/** Simulated community pulse source (actors, campaigns, malware families). */
function pulseVerdict(profile: DemoProfile, ioc: NormalizedIoc): ProviderVerdict | null {
  if (profile.pulses.length === 0) return null;
  const source = SOURCES.pulses;
  const v = baseVerdict(source, ioc);
  const dates = profile.pulses.map((p) => demoNowIso(p.daysAgo)).sort();
  v.status = 'ok';
  v.durationMs = 55 + ((ioc.value.length * 3) % 50);
  v.reports = profile.pulses.length;
  v.firstSeenAt = dates[0] ?? null;
  v.lastSeenAt = dates[dates.length - 1] ?? null;
  v.verdict = 'suspicious';
  v.reputationScore = Math.min(100, profile.pulses.length * 8);
  v.detections = buildDetectionStats({
    malicious: 0,
    suspicious: 1,
    harmless: 69,
    lastAnalysisAt: v.lastSeenAt,
  });
  v.detections.ratio = 0;
  v.related.actors = uniq(profile.pulses.map((p) => p.adversary));
  v.related.campaigns = uniq(profile.pulses.map((p) => p.name));
  v.related.malware = uniq(profile.pulses.flatMap((p) => p.malware));
  v.related.categories = uniq([
    ...profile.pulses.flatMap((p) => p.tags),
    'community-pulse-reference',
  ]);
  v.related.behaviours = uniq(profile.pulses.flatMap((p) => p.tags).filter((t) => /c2|command|beacon|botnet/.test(t)).map(() => 'c2'));
  v.rawExcerpt = JSON.stringify({
    warning: DEMO_MARKER,
    pulse_count: profile.pulses.length,
    pulses: profile.pulses.map((p) => ({ name: p.name, adversary: p.adversary, tags: p.tags, malware_families: p.malware })),
  });
  return v;
}

/** Simulated malware distribution feed. */
function distributionVerdict(profile: DemoProfile, ioc: NormalizedIoc): ProviderVerdict | null {
  if (!profile.urlhaus) return null;
  const source = SOURCES.distribution;
  const v = baseVerdict(source, ioc);
  const listingCount = Math.max(1, profile.urlhaus.urls.length);
  const added = demoNowIso(profile.lastSeenDaysAgo);
  v.status = 'ok';
  v.durationMs = 35 + ((ioc.value.length * 4) % 45);
  v.detections = buildDetectionStats({
    malicious: Math.min(20, 3 + Math.floor(listingCount / 2)),
    suspicious: 0,
    harmless: 70,
    lastAnalysisAt: added,
  });
  v.verdict = verdictFromStats(v.detections);
  v.reputationScore = Math.min(100, 40 + listingCount * 5);
  v.reports = listingCount;
  v.lastSeenAt = added;
  v.related.malware = uniq([profile.urlhaus.threat]);
  v.related.urls = profile.urlhaus.urls;
  v.related.ipAddresses = profile.urlhaus.ip ? [profile.urlhaus.ip] : [];
  v.related.categories = uniq([profile.urlhaus.threat, ...profile.urlhaus.tags, 'listed-on-distribution-feed']);
  v.related.behaviours = uniq([
    'malware-distribution',
    profile.urlhaus.status === 'offline' ? 'payload-offline' : 'payload-online',
    ...(profile.urlhaus.tags.some((t) => /c2|command/.test(t)) ? ['c2'] : []),
  ]);
  v.rawExcerpt = JSON.stringify({
    warning: DEMO_MARKER,
    threat: profile.urlhaus.threat,
    url_status: profile.urlhaus.status,
    date_added: added,
    tags: profile.urlhaus.tags,
    urls: profile.urlhaus.urls,
  });
  return v;
}

/** Simulated scanner index. */
function scannerVerdict(profile: DemoProfile, ioc: NormalizedIoc): ProviderVerdict | null {
  if (!profile.greynoise) return null;
  if (ioc.type !== 'ipv4' && ioc.type !== 'ipv6') return null;
  const source = SOURCES.scanner;
  const v = baseVerdict(source, ioc);
  const classification = profile.greynoise.classification;
  v.status = 'ok';
  v.durationMs = 25 + ((ioc.value.length * 2) % 35);
  v.detections = buildDetectionStats({
    malicious: classification === 'malicious' ? 4 : 0,
    suspicious: 0,
    harmless: classification === 'malicious' ? 66 : 70,
    lastAnalysisAt: demoNowIso(profile.lastSeenDaysAgo),
  });
  v.verdict = classification === 'malicious' ? 'malicious' : 'unknown';
  v.reputationScore = classification === 'malicious' ? 60 : null;
  v.reports = profile.greynoise.noise ? 1 : 0;
  v.lastSeenAt = demoNowIso(profile.lastSeenDaysAgo);
  v.related.categories = uniq([`greynoise-${classification}`, profile.greynoise.noise ? 'background-noise' : null]);
  v.related.behaviours = uniq([
    profile.greynoise.noise ? 'internet-scanner' : null,
    classification === 'malicious' ? 'known-malicious-scanner' : null,
    classification === 'benign' || classification === 'educational' ? 'known-benign-scanner' : null,
  ]);
  if (classification === 'malicious' && profile.greynoise.name) v.related.actors = [profile.greynoise.name];
  v.rawExcerpt = JSON.stringify({
    warning: DEMO_MARKER,
    noise: profile.greynoise.noise,
    classification,
    name: profile.greynoise.name,
    last_seen: demoNowIso(profile.lastSeenDaysAgo),
  });
  return v;
}

/** Simulated service exposure source. */
function exposureVerdict(profile: DemoProfile, ioc: NormalizedIoc): ProviderVerdict | null {
  if (!profile.shodan) return null;
  const source = SOURCES.exposure;
  const v = baseVerdict(source, ioc);
  v.status = 'ok';
  v.durationMs = 45 + ((ioc.value.length * 3) % 40);
  v.verdict = 'unknown';
  v.reports = profile.shodan.ports.length;
  v.lastSeenAt = demoNowIso(1);
  v.network = profile.network
    ? {
        ...profile.network,
        city: profile.shodan.city,
        country: profile.shodan.country,
        reverseDns: profile.shodan.hostnames,
      }
    : null;
  const knownPorts = new Set([21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5900, 6379, 8080, 8443, 27017]);
  const unusual = profile.shodan.ports.filter((p) => !knownPorts.has(p));
  v.related.behaviours = uniq([
    ...profile.shodan.tags.map((t) => t.toLowerCase()),
    ...(unusual.length ? ['non-standard-port-exposed'] : []),
  ]);
  v.related.categories = uniq([...profile.shodan.tags.map((t) => t.toLowerCase()), 'service-exposure']);
  v.related.domains = profile.shodan.hostnames;
  v.rawExcerpt = JSON.stringify({
    warning: DEMO_MARKER,
    ports: profile.shodan.ports,
    tags: profile.shodan.tags,
    hostnames: profile.shodan.hostnames,
    last_update: demoNowIso(1),
  });
  return v;
}

// Label maps are built lazily to avoid a circular import with the dataset module.
let DEMO_MALWARE_LABELS = new Map<string, string>();
let DEMO_ACTOR_LABELS = new Map<string, string>();
let DEMO_CAMP_LABELS = new Map<string, string>();

export function primeDemoLabels(labels: { malware: Map<string, string>; actors: Map<string, string>; campaigns: Map<string, string> }): void {
  DEMO_MALWARE_LABELS = labels.malware;
  DEMO_ACTOR_LABELS = labels.actors;
  DEMO_CAMP_LABELS = labels.campaigns;
}

/** Human-readable note shown on the demo hint panel. */
export function demoProfileFor(ioc: NormalizedIoc): DemoProfile | null {
  return DEMO_PROFILE_BY_VALUE.get(ioc.value.toLowerCase()) ?? null;
}

export function demoCatalog() {
  return DEMO_CATALOG;
}

export function demoMarker(): string {
  return DEMO_MARKER;
}

/**
 * The demo provider set. `lookupAll` returns one verdict per simulated source,
 * which is what the orchestrator consumes in demo mode.
 */
export class DemoProvider implements ThreatIntelProvider {
  readonly id = 'demo';
  readonly name = 'ThreatLens Demo Intelligence';
  readonly description =
    'Built-in fictional intelligence dataset. Every value is simulated and labelled DEMO DATA - it is never presented as a real API response.';
  readonly homepage = 'https://github.com/ (capstone project)';
  readonly documentationUrl = 'https://attack.mitre.org/';
  readonly requiresKey = false;
  readonly supports: readonly IocType[] = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email'];

  isConfigured(): boolean {
    return true;
  }

  /** Single-source view required by the ThreatIntelProvider interface. */
  async lookup(ioc: NormalizedIoc, ctx: ProviderContext): Promise<ProviderVerdict> {
    const verdicts = this.lookupAll(ioc, ctx);
    return verdicts[0] ?? this.notFound(ioc);
  }

  notFound(ioc: NormalizedIoc): ProviderVerdict {
    const v = emptyVerdict({ id: 'demo:catalog', name: 'ThreatLens Demo Catalog' }, 'demo');
    v.status = 'not_found';
    v.verdict = 'unknown';
    v.error = {
      code: 'not_in_demo_dataset',
      message:
        'No demonstration intelligence exists for this indicator. ThreatLens never invents data for unknown indicators - add provider API keys to .env and switch to LIVE INTELLIGENCE to enrich it for real.',
      retryable: false,
    };
    v.durationMs = 3;
    v.rawExcerpt = JSON.stringify({ warning: DEMO_MARKER, indicator: ioc.value, result: 'not_in_catalog' });
    return v;
  }

  /**
   * Expand a demo profile into independent per-source verdicts.
   * Returns an empty array when the indicator is not in the catalog.
   */
  lookupAll(ioc: NormalizedIoc, ctx: ProviderContext): ProviderVerdict[] {
    const profile = demoProfileFor(ioc);
    if (!profile) return [];

    const verdicts: ProviderVerdict[] = [];
    // Each builder is paired with its SourceSpec key so the "does this source
    // cover this indicator type" test is applied to the right spec.
    const builders: Array<[keyof typeof SOURCES, (p: DemoProfile, i: NormalizedIoc) => ProviderVerdict | null]> = [
      ['reputation', reputationVerdict],
      ['abuse', abuseVerdict],
      ['pulses', pulseVerdict],
      ['distribution', distributionVerdict],
      ['scanner', scannerVerdict],
      ['exposure', exposureVerdict],
    ];

    for (const [key, build] of builders) {
      if (!SOURCES[key].supports.includes(ioc.type)) continue;
      const verdict = build(profile, ioc);
      if (!verdict) continue;
      verdicts.push(verdict);
    }

    ctx.onProgress?.(
      `Demo dataset matched indicator (${verdicts.length} simulated source${verdicts.length === 1 ? '' : 's'})`,
    );
    return verdicts;
  }

  /** Health entry for the Settings page. */
  static health() {
    return {
      id: 'demo',
      name: 'ThreatLens Demo Intelligence',
      description:
        'Fictional dataset (documentation IP ranges, RFC 2606 domains, synthetic hashes) used when no API keys are configured.',
      homepage: 'internal',
      documentationUrl: 'internal',
      requiresKey: false,
      configured: true,
      supports: ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email'] as IocType[],
    };
  }
}

export { DEMO_MARKER, SOURCES as DEMO_SOURCE_SPECS };
export const demoVerdictSourceIds = DEMO_SOURCE_IDS;
export const demoIso = demoNowIso;
export const safeDemoStr = safeStr;
export const demoToIso = toIso;
