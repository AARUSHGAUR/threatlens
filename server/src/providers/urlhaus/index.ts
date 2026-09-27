/**
 * URLhaus adapter (abuse.ch).
 *
 * Docs: https://urlhaus.abuse.ch/api/
 * Endpoints:
 *   GET  /v1/host/{host}/  - malware distribution URLs served by a host
 *   GET  /v1/url/{url_id}/ - a single URL lookup
 *
 * URLhaus is one of the highest-signal, lowest-noise feeds available: an entry
 * means a URL was observed distributing malware. No key is required for the
 * public API (we still send the optional Auth-Key header when configured).
 */
import { config } from '../../config/env.js';
import type { IocType, NormalizedIoc, ProviderVerdict } from '../../core/types.js';
import { emptyVerdict, type ProviderContext, type ThreatIntelProvider } from '../types.js';
import { UpstreamError, excerpt, httpJson } from '../http.js';
import { buildDetectionStats, safeInt, safeStr, toIso, uniq, verdictFromStats } from '../normalize.js';

const BASE = 'https://urlhaus-api.abuse.ch/v1';

interface UrlhausResponse {
  query_status: 'ok' | 'no_results' | 'invalid_url' | 'invalid_host';
  url?: string;
  urlhaus_url?: string;
  url_status?: string;
  threat?: string;
  date_added?: string;
  reporter?: string;
  tags?: string[] | string;
  blacklists?: string[] | string;
  host?: string;
  ip?: string;
  url_count?: number;
  blacklist_count?: number;
  urls?: Array<{
    url?: string;
    url_status?: string;
    date_added?: string;
    threat?: string;
    reporter?: string;
    tags?: string[] | string;
    ip?: string;
  }>;
  signature?: string;
}

const asArray = (v: string[] | string | undefined): string[] => {
  if (Array.isArray(v)) return v;
  if (typeof v === 'string' && v.length) return v.split(',').map((s) => s.trim());
  return [];
};

export class UrlhausProvider implements ThreatIntelProvider {
  readonly id = 'urlhaus';
  readonly name = 'URLhaus (abuse.ch)';
  readonly description =
    'Malware distribution feed. A listed host or URL is direct evidence of a payload being served, which is why it drives the C2/delivery risk factors.';
  readonly homepage = 'https://urlhaus.abuse.ch';
  readonly documentationUrl = 'https://urlhaus.abuse.ch/api/';
  readonly requiresKey = false;
  readonly supports: readonly IocType[] = ['ipv4', 'ipv6', 'domain', 'url'];

  private readonly enabled: boolean;
  private readonly authKey: string;

  constructor(enabled: string = config.providerKeys.urlhaus, authKey = process.env.ABUSECH_AUTH_KEY ?? '') {
    this.enabled = Boolean(enabled);
    this.authKey = authKey;
  }

  isConfigured(): boolean {
    return this.enabled;
  }

  async lookup(ioc: NormalizedIoc, ctx: ProviderContext): Promise<ProviderVerdict> {
    const verdict = emptyVerdict(this, 'live');
    const started = Date.now();

    if (!this.enabled) {
      verdict.status = 'unconfigured';
      verdict.error = { code: 'unconfigured', message: 'URLhaus is disabled (URLHAUS_ENABLED=false).', retryable: false };
      return verdict;
    }

    const headers: Record<string, string> = {};
    if (this.authKey) headers.Auth = this.authKey;

    let body: UrlhausResponse;
    let endpoint: string;
    try {
      if (ioc.type === 'url') {
        // URLhaus expects the URL id (sha256 of the URL) in the path, but the
        // public API also accepts a raw URL for lookups on the "url" endpoint.
        endpoint = `url/?url=${encodeURIComponent(ioc.value)}`;
      } else {
        const host = ioc.type === 'domain' ? ioc.value : ioc.value;
        endpoint = `host/${encodeURIComponent(host)}/`;
      }
      ctx.onProgress?.(`Querying URLhaus ${ioc.type} endpoint`);
      const { data } = await httpJson<UrlhausResponse>(this.id, `${BASE}/${endpoint}`, { headers });
      body = data;
    } catch (err) {
      const up = err instanceof UpstreamError
        ? err
        : new UpstreamError({ code: 'network_error', message: String(err), retryable: true });
      const statusMap: Record<string, ProviderVerdict['status']> = {
        rate_limited: 'rate_limited', quota_exceeded: 'rate_limited', timeout: 'timeout',
      };
      verdict.status = statusMap[up.code] ?? (up.code === 'not_found' ? 'not_found' : 'error');
      verdict.error = { code: up.code, message: up.message, httpStatus: up.httpStatus, retryable: up.retryable };
      verdict.durationMs = Date.now() - started;
      return verdict;
    }

    if (body.query_status === 'no_results' || body.query_status === 'invalid_url' || body.query_status === 'invalid_host') {
      verdict.status = 'not_found';
      verdict.verdict = 'clean';
      verdict.durationMs = Date.now() - started;
      verdict.rawExcerpt = excerpt({ query_status: body.query_status });
      return verdict;
    }

    const urls = body.urls ?? [];
    const threats = uniq([safeStr(body.threat), ...urls.map((u) => safeStr(u.threat))]);
    const tags = uniq([...asArray(body.tags), ...urls.flatMap((u) => asArray(u.tags))]);
    const blacklists = uniq([...asArray(body.blacklists)]);
    const urlsList = uniq([safeStr(body.url), ...urls.map((u) => safeStr(u.url))]);
    const ips = uniq([safeStr(body.ip), ...urls.map((u) => safeStr(u.ip))]);
    const dates = urls.map((u) => toIso(u.date_added)).filter((d): d is string => Boolean(d)).sort();

    // A single URLhaus listing is a confirmed malicious artefact, so we model it
    // as 3 malicious engines - matching VirusTotal's "confirmed" threshold.
    const listingCount = Math.max(urlsList.length, 1);
    verdict.detections = buildDetectionStats({
      malicious: Math.min(20, 3 + Math.floor(listingCount / 2)),
      suspicious: 0,
      harmless: 70,
      lastAnalysisAt: dates[dates.length - 1] ?? toIso(body.date_added),
    });
    verdict.verdict = verdictFromStats(verdict.detections);
    verdict.reputationScore = Math.min(100, 40 + listingCount * 5);
    verdict.reports = safeInt(body.url_count) ?? listingCount;
    verdict.lastSeenAt = toIso(body.date_added) ?? dates[dates.length - 1] ?? null;
    verdict.firstSeenAt = dates[0] ?? null;
    verdict.status = 'ok';
    verdict.durationMs = Date.now() - started;
    verdict.url = body.urlhaus_url ?? 'https://urlhaus.abuse.ch/';

    verdict.related.malware = threats;
    verdict.related.urls = urlsList.slice(0, 25);
    verdict.related.ipAddresses = ips;
    verdict.related.categories = uniq([
      ...threats.map((t) => t?.toLowerCase() ?? ''),
      ...tags,
      ...(blacklists.length ? ['listed-on-blacklist'] : []),
    ]);
    verdict.related.behaviours = uniq([
      'malware-distribution',
      ...(body.url_status === 'offline' || urls.some((u) => u.url_status === 'offline') ? ['payload-offline'] : ['payload-online']),
      ...(tags.some((t) => /c2|command|cc\b/i.test(t)) ? ['c2'] : []),
    ]);

    if (ioc.type === 'url' && body.signature) {
      verdict.related.malware = uniq([...verdict.related.malware, safeStr(body.signature)]);
    }

    verdict.rawExcerpt = excerpt({
      query_status: body.query_status,
      url: body.url,
      url_status: body.url_status,
      threat: body.threat,
      date_added: body.date_added,
      reporter: body.reporter,
      tags,
      blacklists,
      host: body.host,
      ip: body.ip,
      url_count: body.url_count,
      signature: body.signature,
    });

    return verdict;
  }
}
