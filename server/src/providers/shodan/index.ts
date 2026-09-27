/**
 * Shodan adapter (optional enrichment source).
 *
 * Docs: https://developer.shodan.io/api
 * Endpoints:
 *   GET /shodan/host/{ip}?key=  - exposed services, banners, tags
 *   GET /dns/domain/{domain}?key= - subdomains, A records
 *
 * Shodan contributes *infrastructure* context: which ports/services are
 * exposed and whether the host is tagged as malware/C2 - which is how we learn
 * about non-standard ports (ATT&CK T1571) without guessing.
 */
import { config } from '../../config/env.js';
import type { IocType, NormalizedIoc, ProviderVerdict } from '../../core/types.js';
import { emptyVerdict, type ProviderContext, type ThreatIntelProvider } from '../types.js';
import { UpstreamError, excerpt, httpJson } from '../http.js';
import { safeInt, safeStr, toIso, uniq } from '../normalize.js';

const BASE = 'https://api.shodan.io';

interface ShodanHost {
  ip_str?: string;
  hostnames?: string[];
  domains?: string[];
  org?: string;
  isp?: string;
  asn?: string;
  country_name?: string;
  city?: string;
  region_code?: string;
  last_update?: string;
  ports?: number[];
  tags?: string[];
  vulns?: string[];
  opts?: Record<string, unknown>;
}

interface ShodanDomain {
  subdomains?: string[];
  tags?: string[];
  domains?: Array<{ domain?: string; hostname?: string; type?: string[]; data?: string[] }>;
}

export class ShodanProvider implements ThreatIntelProvider {
  readonly id = 'shodan';
  readonly name = 'Shodan';
  readonly description =
    'Internet-wide service exposure database. Adds open ports, service banners, hosting ASN and malware/C2 tags for infrastructure indicators.';
  readonly homepage = 'https://www.shodan.io';
  readonly documentationUrl = 'https://developer.shodan.io/api';
  readonly requiresKey = true;
  readonly supports: readonly IocType[] = ['ipv4', 'ipv6', 'domain'];

  private readonly apiKey: string;

  constructor(apiKey: string = config.providerKeys.shodan) {
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
      verdict.error = { code: 'unconfigured', message: 'SHODAN_API_KEY is not set.', retryable: false };
      return verdict;
    }

    let body: ShodanHost | ShodanDomain;
    let url: string;
    try {
      if (ioc.type === 'domain') {
        ctx.onProgress?.('Querying Shodan DNS domain endpoint');
        url = `${BASE}/dns/domain/${encodeURIComponent(ioc.value)}?key=${encodeURIComponent(this.apiKey)}`;
        const { data } = await httpJson<ShodanDomain>(this.id, url);
        body = data;
      } else {
        ctx.onProgress?.('Querying Shodan host endpoint');
        url = `${BASE}/shodan/host/${encodeURIComponent(ioc.value)}?key=${encodeURIComponent(this.apiKey)}`;
        const { data } = await httpJson<ShodanHost>(this.id, url);
        body = data;
      }
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

    const host = body as ShodanHost;
    const domain = body as ShodanDomain;
    const tags = uniq([...(host.tags ?? []), ...(domain.tags ?? [])]);

    verdict.status = 'ok';
    verdict.durationMs = Date.now() - started;
    verdict.url = `https://www.shodan.io/host/${ioc.value}`;
    verdict.lastSeenAt = toIso(host.last_update);
    verdict.firstSeenAt = null;
    // Shodan is context-only: we never let it alone decide a verdict.
    verdict.verdict = 'unknown';
    verdict.reports = host.ports?.length ?? null;

    const ports = (host.ports ?? []).map((p) => safeInt(p)).filter((p): p is number => p !== null);

    verdict.network = {
      country: safeStr(host.country_name),
      countryCode: null,
      city: safeStr(host.city),
      region: safeStr(host.region_code),
      asn: safeStr(host.asn),
      asnOrg: safeStr(host.org),
      isp: safeStr(host.isp),
      org: safeStr(host.org),
      reverseDns: (host.hostnames ?? []).slice(0, 10),
      hostingProvider: safeStr(host.isp),
      usageType: null,
      domain: safeStr(host.domains?.[0]),
      ispDomain: null,
      totalReports: null,
      lastReportedAt: toIso(host.last_update),
      abuseConfidenceScore: null,
    };

    const knownPorts = new Set([80, 443, 22, 25, 53, 21, 23, 110, 143, 445, 3306, 3389, 8080, 8443, 5900, 6379, 27017]);
    const unusualPorts = ports.filter((p) => !knownPorts.has(p));
    verdict.related.behaviours = uniq([
      ...(tags.length ? tags.map((t) => t.toLowerCase()) : []),
      ...(unusualPorts.length ? ['non-standard-port-exposed'] : []),
      ...(tags.some((t) => /malware|bot|c2|cnc|command/i.test(t)) ? ['malware-tagged'] : []),
      ...(tags.some((t) => /honeypot|iot|scanner|research/i.test(t)) ? ['scanner-or-research'] : []),
    ]);
    verdict.related.categories = uniq([...tags.map((t) => t.toLowerCase()), 'service-exposure']);
    verdict.related.domains = uniq([
      ...(host.hostnames ?? []),
      ...(domain.subdomains ?? []),
      ...(domain.domains ?? []).map((d) => safeStr(d.hostname) ?? safeStr(d.domain)),
    ]);
    if (unusualPorts.length) {
      verdict.related.behaviours = uniq([...verdict.related.behaviours]);
    }

    verdict.rawExcerpt = excerpt({
      ip_str: host.ip_str,
      hostnames: (host.hostnames ?? []).slice(0, 10),
      org: host.org,
      isp: host.isp,
      asn: host.asn,
      country_name: host.country_name,
      city: host.city,
      ports: ports.slice(0, 30),
      tags,
      last_update: host.last_update,
    });

    return verdict;
  }
}
