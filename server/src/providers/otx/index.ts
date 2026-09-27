/**
 * AlienVault OTX adapter (community pulses).
 *
 * Docs: https://otx.alienvault.com/api
 * Endpoint: GET https://otx.alienvault.com/api/v1/indicators/{type}/{value}/general
 *
 * OTX is *context* intelligence rather than reputation: it tells us which
 * pulses (curated collections of IOCs per campaign/actor) reference the
 * indicator, which malware families and adversaries those pulses are about.
 * That is exactly what the correlation layer and the ATT&CK mapper consume.
 */
import { config } from '../../config/env.js';
import type { IocType, NormalizedIoc, ProviderVerdict } from '../../core/types.js';
import { emptyVerdict, type ProviderContext, type ThreatIntelProvider } from '../types.js';
import { UpstreamError, excerpt, httpJson } from '../http.js';
import { buildDetectionStats, safeInt, safeStr, toIso, uniq } from '../../providers/normalize.js';

const BASE = 'https://otx.alienvault.com/api/v1';

/** Translate our IOC type into an OTX indicator type. */
const OTX_TYPE: Record<IocType, string | null> = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  domain: 'domain',
  url: 'URL',
  md5: 'FileHash-Md5',
  sha1: 'FileHash-Sha1',
  sha256: 'FileHash-Sha256',
  email: 'Email',
};

interface OtxPulse {
  name?: string;
  description?: string;
  tags?: string[] | string;
  adversary?: string;
  malware_families?: Array<{ display_name?: string; id?: string }>;
  created?: string;
  modified?: string;
  indicator_count?: number;
  references?: string[];
}

interface OtxResponse {
  indicator?: string;
  type?: string;
  pulse_info?: {
    count?: number;
    pulses?: OtxPulse[];
    references?: string[];
  };
  reputation?: number;
  validation?: Array<{ result?: string }>;
  validation_info?: Record<string, unknown>;
  error?: string;
  errors?: Array<string>;
}

const C2_TAG_RE = /(^|[\s_-])(c2|c&c|cnc|command[\s_-]?and[\s_-]?control|beacon|callback|botnet)([\s_-]|$)/i;

export class OtxProvider implements ThreatIntelProvider {
  readonly id = 'otx';
  readonly name = 'AlienVault OTX';
  readonly description =
    'Community-driven pulse platform. Links indicators to campaigns, adversaries, malware families and tags - the primary source for actor attribution.';
  readonly homepage = 'https://otx.alienvault.com';
  readonly documentationUrl = 'https://otx.alienvault.com/api';
  readonly requiresKey = true;
  readonly supports: readonly IocType[] = [
    'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email',
  ];

  private readonly apiKey: string;

  constructor(apiKey: string = config.providerKeys.otx) {
    this.apiKey = apiKey;
  }

  isConfigured(): boolean {
    return Boolean(this.apiKey);
  }

  async lookup(ioc: NormalizedIoc, ctx: ProviderContext): Promise<ProviderVerdict> {
    const verdict = emptyVerdict(this, 'live');
    const started = Date.now();

    if (!this.isConfigured()) {
      verdict.status = 'unconfigured';
      verdict.error = {
        code: 'unconfigured',
        message: 'OTX_API_KEY is not set. Add it to .env to enable AlienVault OTX enrichment.',
        retryable: false,
      };
      return verdict;
    }

    const otxType = OTX_TYPE[ioc.type];
    if (!otxType) {
      verdict.status = 'not_found';
      verdict.error = { code: 'unsupported_indicator', message: `OTX does not index ${ioc.type} indicators.`, retryable: false };
      verdict.durationMs = Date.now() - started;
      return verdict;
    }

    let data: OtxResponse;
    try {
      ctx.onProgress?.('Querying AlienVault OTX pulse index');
      const url = `${BASE}/indicators/${otxType}/${encodeURIComponent(ioc.value)}/general`;
      const { data: body } = await httpJson<OtxResponse>(this.id, url, { headers: { 'X-OTX-API-KEY': this.apiKey } });
      data = body;
    } catch (err) {
      const up = err instanceof UpstreamError
        ? err
        : new UpstreamError({ code: 'network_error', message: String(err), retryable: true });
      const statusMap: Record<string, ProviderVerdict['status']> = {
        not_found: 'not_found', rate_limited: 'rate_limited', quota_exceeded: 'rate_limited', timeout: 'timeout',
      };
      verdict.status = statusMap[up.code] ?? 'error';
      verdict.error = { code: up.code, message: up.message, httpStatus: up.httpStatus, retryable: up.retryable };
      verdict.durationMs = Date.now() - started;
      return verdict;
    }

    const pulseInfo = data.pulse_info ?? {};
    const pulses: OtxPulse[] = Array.isArray(pulseInfo.pulses) ? pulseInfo.pulses : [];
    const pulseCount = safeInt(pulseInfo.count) ?? pulses.length;

    verdict.status = 'ok';
    verdict.durationMs = Date.now() - started;
    verdict.reports = pulseCount;
    verdict.url = `https://otx.alienvault.com/indicator/${otxType}/${encodeURIComponent(ioc.value)}`;

    const tags = uniq(
      pulses.flatMap((p) => (Array.isArray(p.tags) ? p.tags : typeof p.tags === 'string' ? [p.tags] : [])),
    );
    const adversaries = uniq(pulses.map((p) => safeStr(p.adversary)));
    const malwareFamilies = uniq(
      pulses.flatMap((p) => (p.malware_families ?? []).map((m) => safeStr(m.display_name ?? m.id))),
    );
    const campaignNames = uniq(pulses.map((p) => safeStr(p.name)));

    verdict.related.actors = adversaries;
    verdict.related.malware = malwareFamilies;
    verdict.related.campaigns = campaignNames;
    verdict.related.categories = uniq([
      ...tags.map((t) => t.toLowerCase()),
      ...(pulseCount > 0 ? ['community-pulse-reference'] : []),
    ]);
    verdict.related.behaviours = uniq(
      tags
        .filter((t) => C2_TAG_RE.test(t))
        .map((t) => 'c2')
        .concat(
          tags.some((t) => /phish/i.test(t)) ? ['phishing'] : [],
          tags.some((t) => /exploit|malware|dropper|payload/i.test(t)) ? ['malware-delivery'] : [],
          tags.some((t) => /ransom/i.test(t)) ? ['ransomware'] : [],
          tags.some((t) => /ddos|botnet/i.test(t)) ? ['botnet'] : [],
        ),
    );

    // OTX is a *context* source: pulse references alone are not proof of
    // maliciousness, so we report the evidence but keep the verdict neutral.
    // A "malicious" verdict is only returned when OTX community validation
    // explicitly marks the indicator as malicious.
    const communityMalicious = (data.validation ?? []).some((v) => (v.result ?? '').toLowerCase() === 'malicious');
    const detectionRatio = pulses.length ? Math.min(1, pulses.length / 20) : 0;
    verdict.detections = buildDetectionStats({
      malicious: communityMalicious ? 3 : 0,
      suspicious: pulseCount >= 3 ? 1 : 0,
      harmless: Math.max(0, 70 - (communityMalicious ? 3 : 0)),
      lastAnalysisAt: toIso(pulses[0]?.modified ?? pulses[0]?.created),
    });
    verdict.detections.ratio = Number(detectionRatio.toFixed(4));
    verdict.verdict = communityMalicious ? 'malicious' : pulseCount >= 3 ? 'suspicious' : 'unknown';
    verdict.reputationScore = Math.min(100, Math.round(pulseCount * 2 + (communityMalicious ? 30 : 0)));
    verdict.lastSeenAt = toIso(pulses.map((p) => p.modified ?? p.created).filter(Boolean).sort().reverse()[0] ?? null);
    verdict.firstSeenAt = toIso(pulses.map((p) => p.created).filter(Boolean).sort()[0] ?? null);

    verdict.rawExcerpt = excerpt({
      indicator: data.indicator,
      type: data.type,
      pulse_count: pulseCount,
      pulses: pulses.slice(0, 10).map((p) => ({
        name: p.name,
        adversary: p.adversary,
        tags: p.tags,
        malware_families: p.malware_families,
        created: p.created,
      })),
      reputation: data.reputation,
    });

    return verdict;
  }
}
