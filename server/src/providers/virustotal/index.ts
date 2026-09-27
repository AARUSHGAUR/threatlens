/**
 * VirusTotal API v3 adapter.
 *
 * Docs: https://docs.virustotal.com/reference/overview
 * Endpoint map used here (one call per indicator, plus one optional
 * "resolutions" call to build the correlation graph):
 *   ip_addresses/{ip}  -> /api/v3/ip_addresses/{ip}
 *   domains/{domain}   -> /api/v3/domains/{domain}
 *   urls/{id}          -> /api/v3/urls/{base64url(url)}
 *   files/{hash}       -> /api/v3/files/{hash}
 *
 * The API key is read from configuration only - it is never returned to the
 * client, never logged and never stored in the database.
 */
import { config } from '../../config/env.js';
import type { IocType, NetworkIntel, NormalizedIoc, ProviderVerdict } from '../../core/types.js';
import { emptyVerdict, type ProviderContext, type ThreatIntelProvider } from '../types.js';
import { UpstreamError, excerpt, httpJson } from '../http.js';
import {
  buildDetectionStats,
  clamp,
  reputationScoreFromStats,
  safeInt,
  safeStr,
  toIso,
  uniq,
  verdictFromStats,
} from '../normalize.js';

const BASE = 'https://www.virustotal.com/api/v3';

interface VtLastAnalysisStats {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  timeout?: number;
  failure?: number;
  type_unsupported?: number;
}

interface VtObject {
  id?: string;
  type?: string;
  attributes?: Record<string, unknown>;
}

interface VtResponse {
  data?: VtObject;
  error?: { code?: string; message?: string };
}

/** VirusTotal identifies URLs by a base64url-encoded (unpadded) URL. */
const urlId = (url: string): string => Buffer.from(url, 'utf8').toString('base64url');

/** Map our IOC type onto a VirusTotal collection + identifier. */
function endpointFor(ioc: NormalizedIoc): { path: string; relationship?: string } | null {
  switch (ioc.type) {
    case 'ipv4':
    case 'ipv6':
      return { path: `ip_addresses/${encodeURIComponent(ioc.value)}`, relationship: 'resolutions' };
    case 'domain':
      return { path: `domains/${encodeURIComponent(ioc.value)}`, relationship: 'resolutions' };
    case 'url':
      return { path: `urls/${urlId(ioc.value)}` };
    case 'md5':
    case 'sha1':
    case 'sha256':
      return { path: `files/${encodeURIComponent(ioc.value)}` };
    default:
      // VirusTotal v3 has no email collection; the adapter reports this
      // explicitly instead of guessing.
      return null;
  }
}

const toCollection = (ioc: NormalizedIoc): string => {
  const map: Record<string, string> = {
    ipv4: 'ip_addresses',
    ipv6: 'ip_addresses',
    domain: 'domains',
    url: 'urls',
    md5: 'files',
    sha1: 'files',
    sha256: 'files',
  };
  return map[ioc.type] ?? 'domains';
};

function extractNetwork(attrs: Record<string, unknown>): NetworkIntel | null {
  const network = attrs.network as Record<string, unknown> | undefined;
  const asn = safeInt(attrs.asn);
  const org = safeStr(network?.org ?? attrs.owner);
  const isp = safeStr(network?.isp ?? attrs.isp);
  const country = safeStr(attrs.country);
  const city = safeStr(network?.city);
  const hasAny =
    asn !== null || org || isp || country || city || attrs.last_analysis_date !== undefined;
  if (!hasAny) return null;
  return {
    country,
    countryCode: safeStr(attrs.country_code),
    city,
    region: safeStr(attrs.region ?? network?.region),
    asn,
    asnOrg: org,
    isp,
    org,
    reverseDns: Array.isArray(attrs.reverse_dns_links) ? (attrs.reverse_dns_links as unknown[]).map(String) : null,
    hostingProvider: safeStr(network?.host_name ?? attrs.host_name),
    usageType: safeStr(network?.category ?? network?.service),
    domain: safeStr(attrs.domain),
    ispDomain: safeStr(network?.whois_organization) ?? null,
    totalReports: null,
    lastReportedAt: null,
    abuseConfidenceScore: null,
  };
}

const VT_TYPE_TO_IOC_TYPE: Partial<Record<IocType, IocType>> = {};

/** Read the "meaningful_name"/"names" lists VT returns for related objects. */
function collectTags(attrs: Record<string, unknown>): string[] {
  const tags = attrs.tags as string[] | undefined;
  const meaningfulName = safeStr(attrs.meaningful_name);
  const categories = (attrs.categories as Record<string, string> | undefined) ?? {};
  return uniq([
    ...(Array.isArray(tags) ? tags : []),
    ...Object.values(categories).filter((v): v is string => typeof v === 'string'),
    ...(meaningfulName ? [meaningfulName] : []),
  ]);
}

export class VirusTotalProvider implements ThreatIntelProvider {
  readonly id = 'virustotal';
  readonly name = 'VirusTotal';
  readonly description =
    'Multi-engine reputation service (70+ AV engines) plus crowd-sourced relationships between files, URLs, domains and IP addresses.';
  readonly homepage = 'https://www.virustotal.com';
  readonly documentationUrl = 'https://docs.virustotal.com/reference/overview';
  readonly requiresKey = true;
  readonly supports: readonly IocType[] = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'];

  private readonly apiKey: string;

  constructor(apiKey: string = config.providerKeys.virustotal) {
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
        message: 'VIRUSTOTAL_API_KEY is not set. Add it to .env to enable VirusTotal enrichment.',
        retryable: false,
      };
      return verdict;
    }

    const endpoint = endpointFor(ioc);
    if (!endpoint) {
      verdict.status = 'not_found';
      verdict.error = {
        code: 'unsupported_indicator',
        message: `VirusTotal API v3 has no public collection for ${ioc.type} indicators.`,
        retryable: false,
      };
      verdict.durationMs = Date.now() - started;
      return verdict;
    }

    const headers = { 'x-apikey': this.apiKey };
    let payload: VtResponse | null = null;

    try {
      ctx.onProgress?.(`Querying VirusTotal ${toCollection(ioc)} endpoint`);
      const { data } = await httpJson<VtResponse>(this.id, `${BASE}/${endpoint.path}`, { headers });
      payload = data;
    } catch (err) {
      return this.toErrorVerdict(verdict, err, started, ioc);
    }

    const attrs = (payload?.data?.attributes ?? {}) as Record<string, unknown>;
    const stats = attrs.last_analysis_stats as VtLastAnalysisStats | undefined;

    const detections = stats
      ? buildDetectionStats({
          malicious: stats.malicious ?? 0,
          suspicious: stats.suspicious ?? 0,
          harmless: stats.harmless ?? 0,
          undetected: stats.undetected ?? 0,
          unsupported: stats.type_unsupported ?? 0,
          lastAnalysisAt: toIso(attrs.last_analysis_date),
        })
      : null;

    const votes = (attrs.total_votes as { harmless?: number; malicious?: number } | undefined) ?? {};
    const communityReputation = safeInt(attrs.reputation);

    verdict.detections = detections;
    verdict.verdict = verdictFromStats(detections);
    verdict.reputationScore = reputationScoreFromStats(detections, communityReputation);
    verdict.reports = communityReputation !== null ? Math.abs(communityReputation) : detections?.total ?? null;
    verdict.network = extractNetwork(attrs);
    verdict.lastSeenAt = toIso(attrs.last_analysis_date) ?? detections?.lastAnalysisAt ?? null;
    verdict.firstSeenAt = toIso(attrs.first_submission_date);
    verdict.url = payload?.data?.type
      ? `https://www.virustotal.com/gui/${payload.data.type}/${payload.data.id ?? ''}`
      : null;
    verdict.status = 'ok';
    verdict.durationMs = Date.now() - started;

    const tags = collectTags(attrs);
    const categories = tags.filter((t) => !/^(informational|uncommon business|signer|expanded|undetected|low_vendor_score)$/i.test(t));

    verdict.related.categories = uniq([
      ...categories,
      ...(verdict.verdict === 'malicious' ? ['malicious'] : []),
    ]);

    // Behavioural tags are what the C2 / infrastructure rules consume.
    verdict.related.behaviours = uniq(
      tags.filter((t) => /c2|command|control|botnet|cnc|exploit|kits|phish|rat|trojan|stealer|ransom|dropper|downloader|miner|backdoor|rootkit|worm|keylog|ransomware/i.test(t)),
    );

    const sigNames = Array.isArray(attrs.sig_names) ? (attrs.sig_names as unknown[]).map((n) => safeStr(n)) : [];
    // VT returns engine signature names ("Trojan.GenericKD", "Emotet"), which is
    // a strong malware signal. Keep the distinctive part only.
    verdict.related.malware = uniq(
      sigNames
        .map((n) => (n ? n.split(':').pop()!.split('.').slice(0, 2).join('.') : null))
        .filter((n): n is string => Boolean(n)),
    ).slice(0, 25);

    // --- Optional second call: resolutions (adds related IPs/domains) -------
    if (endpoint.relationship) {
      try {
        ctx.onProgress?.(`Resolving VirusTotal ${endpoint.relationship} for correlation graph`);
        const { data: rel } = await httpJson<{ data?: Array<{ attributes?: Record<string, unknown> }> }>(
          this.id,
          `${BASE}/${endpoint.path}/${endpoint.relationship}`,
          { headers },
        );
        const entries = rel?.data ?? [];
        for (const entry of entries.slice(0, 25)) {
          const a = entry.attributes ?? {};
          const host = safeStr(a.host_name);
          const ip = safeStr(a.ip_address);
          if (ioc.type === 'ipv4' || ioc.type === 'ipv6') verdict.related.domains.push(host ?? '');
          else verdict.related.ipAddresses.push(ip ?? '');
        }
        verdict.related.domains = uniq(verdict.related.domains);
        verdict.related.ipAddresses = uniq(verdict.related.ipAddresses);
      } catch (err) {
        // A failed enrichment sub-call must not fail the whole verdict; record it.
        if (err instanceof UpstreamError && err.code === 'rate_limited') {
          verdict.related.behaviours = uniq([...verdict.related.behaviours, 'resolution-lookup-rate-limited']);
        }
      }
    }

    verdict.rawExcerpt = excerpt({
      id: payload?.data?.id,
      type: payload?.data?.type,
      last_analysis_stats: stats,
      reputation: communityReputation,
      total_votes: votes,
      meaningful_name: safeStr(attrs.meaningful_name),
      names: (attrs.names as string[] | undefined)?.slice?.(0, 10),
      tags,
      asn: attrs.asn,
      country: attrs.country,
    });

    // Votes are informational only - a heavily down-voted object is surfaced
    // in the UI but does not affect the risk score directly.
    void votes;
    void VT_TYPE_TO_IOC_TYPE;
    return verdict;
  }

  private toErrorVerdict(
    verdict: ProviderVerdict,
    err: unknown,
    started: number,
    ioc: NormalizedIoc,
  ): ProviderVerdict {
    const up = err instanceof UpstreamError ? err : new UpstreamError({ code: 'network_error', message: String(err), retryable: true });
    const statusMap: Record<string, ProviderVerdict['status']> = {
      not_found: 'not_found',
      rate_limited: 'rate_limited',
      timeout: 'timeout',
    };
    verdict.status = statusMap[up.code] ?? (up.code === 'auth_error' || up.code === 'forbidden' || up.code === 'quota_exceeded' ? 'error' : 'error');
    if (up.code === 'quota_exceeded') verdict.status = 'rate_limited';
    verdict.verdict = 'unknown';
    verdict.error = {
      code: up.code,
      message: up.message,
      httpStatus: up.httpStatus,
      retryable: up.retryable,
    };
    verdict.durationMs = Date.now() - started;
    void ioc;
    return verdict;
  }
}

export { clamp };
