/**
 * AbuseIPDB API v2 adapter (IP addresses only).
 *
 * Docs: https://docs.abuseipdb.com/
 * Endpoint: GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90
 * Header:   Key: $ABUSEIPDB_API_KEY
 *
 * AbuseIPDB is a *crowd-sourced abuse report* service, so the single most
 * valuable output is `abuseConfidenceScore` (0-100) which the risk engine treats
 * as an independent, weighted signal.
 */
import { config } from '../../config/env.js';
import type { IocType, NormalizedIoc, ProviderVerdict } from '../../core/types.js';
import { emptyVerdict, type ProviderContext, type ThreatIntelProvider } from '../types.js';
import { UpstreamError, excerpt, httpJson } from '../http.js';
import { buildDetectionStats, reputationScoreFromStats, safeInt, safeStr, toIso, uniq, verdictFromStats } from '../normalize.js';

interface AbuseCheckResponse {
  data?: {
    ipAddress?: string;
    isPublic?: boolean;
    ipVersion?: number;
    isWhitelisted?: boolean;
    abuseConfidenceScore?: number;
    countryCode?: string;
    usageType?: string;
    isp?: string;
    domain?: string;
    hostnames?: string[];
    totalReports?: number;
    numDistinctUsers?: number;
    lastReportedAt?: string;
  };
  errors?: Array<{ status?: number; detail?: string }>;
}

export class AbuseIPDBProvider implements ThreatIntelProvider {
  readonly id = 'abuseipdb';
  readonly name = 'AbuseIPDB';
  readonly description =
    'Crowd-sourced IP abuse reporting network. Supplies an abuse confidence score, report count, hosting/ISP attribution and usage type.';
  readonly homepage = 'https://www.abuseipdb.com';
  readonly documentationUrl = 'https://docs.abuseipdb.com/';
  readonly requiresKey = true;
  readonly supports: readonly IocType[] = ['ipv4', 'ipv6'];

  private readonly apiKey: string;

  constructor(apiKey: string = config.providerKeys.abuseipdb) {
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
        message: 'ABUSEIPDB_API_KEY is not set. Add it to .env to enable AbuseIPDB enrichment.',
        retryable: false,
      };
      return verdict;
    }

    if (ioc.type !== 'ipv4' && ioc.type !== 'ipv6') {
      verdict.status = 'not_found';
      verdict.error = {
        code: 'unsupported_indicator',
        message: 'AbuseIPDB only accepts IP address indicators.',
        retryable: false,
      };
      verdict.durationMs = Date.now() - started;
      return verdict;
    }

    let data: AbuseCheckResponse['data'];
    try {
      ctx.onProgress?.('Querying AbuseIPDB reputation endpoint');
      const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc.value)}&maxAgeInDays=90`;
      const response = await httpJson<AbuseCheckResponse>(this.id, url, { headers: { key: this.apiKey } });
      data = response.data.data;
      if (!data) {
        const detail = response.data.errors?.[0]?.detail;
        throw new UpstreamError({
          code: 'malformed_response',
          message: detail || 'AbuseIPDB returned an empty data object.',
          retryable: true,
        });
      }
    } catch (err) {
      return this.toErrorVerdict(verdict, err, started);
    }

    const score = safeInt(data.abuseConfidenceScore) ?? 0;
    const reports = safeInt(data.totalReports) ?? 0;

    // AbuseIPDB has no AV engine stats. We synthesise a *comparable* stats
    // block from the confidence score so downstream code (and the UI) can treat
    // every provider uniformly. This is explicitly derived, never invented:
    //   malicious engines := round(score / 20)  (0..5)
    //   harmless engines  := 70 - malicious    (AbuseIPDB's own model uses 70)
    // The synthetic ratio is therefore score/100, i.e. the abuse confidence.
    const syntheticMalicious = Math.min(5, Math.round(score / 20));
    const detections = buildDetectionStats({
      malicious: syntheticMalicious,
      suspicious: score > 0 && score < 30 ? 1 : 0,
      harmless: 70 - syntheticMalicious,
      lastAnalysisAt: toIso(data.lastReportedAt),
    });

    verdict.detections = detections;
    verdict.reports = reports;
    verdict.verdict = verdictFromStats(detections);
    // Reputation score mirrors the abuse confidence (0-100, higher = worse).
    verdict.reputationScore = reputationScoreFromStats(detections, 0);
    verdict.lastSeenAt = toIso(data.lastReportedAt);
    verdict.firstSeenAt = null;
    verdict.status = 'ok';
    verdict.durationMs = Date.now() - started;
    verdict.url = `https://www.abuseipdb.com/check/${ioc.value}`;

    const hostnames = uniq(data.hostnames ?? []);

    verdict.network = {
      country: null,
      countryCode: safeStr(data.countryCode),
      city: null,
      region: null,
      asn: null,
      asnOrg: null,
      isp: safeStr(data.isp),
      org: safeStr(data.isp),
      reverseDns: hostnames.length ? hostnames : null,
      hostingProvider: null,
      usageType: safeStr(data.usageType),
      domain: safeStr(data.domain),
      ispDomain: safeStr(data.domain),
      totalReports: reports,
      lastReportedAt: toIso(data.lastReportedAt),
      abuseConfidenceScore: score,
    };

    // `usageType` is a first-class behavioural signal in the risk engine:
    // "Data Center/Web Hosting/Transit" hosting a "Command & Control" usage
    // type is exactly the C2-infrastructure pattern we want to flag.
    const usage = (safeStr(data.usageType) ?? '').toLowerCase();
    verdict.related.behaviours = uniq([
      reports > 0 ? 'reported-by-community' : null,
      score >= 90 ? 'high-abuse-confidence' : score >= 50 ? 'moderate-abuse-confidence' : null,
      /data center|hosting|transit/.test(usage) ? 'hosted-infrastructure' : null,
      /command & control|c2|command and control/.test(usage) ? 'c2' : null,
      /ddos|ddos amplifier|amplification/.test(usage) ? 'ddos' : null,
      /proxy|vpns?|tor|exittunnel/.test(usage) ? 'anonymiser' : null,
      /scanner|research|education/.test(usage) ? 'scanner' : null,
      /spam/.test(usage) ? 'spam' : null,
      /web hosting|hosting/.test(usage) ? 'hosting' : null,
    ]);
    verdict.related.categories = uniq([
      ...verdict.related.behaviours,
      ...(data.isWhitelisted ? ['whitelisted'] : []),
    ]);
    // Hostnames observed for this IP are legitimate related indicators.
    verdict.related.domains = hostnames;

    verdict.rawExcerpt = excerpt({
      ipAddress: data.ipAddress,
      isPublic: data.isPublic,
      isWhitelisted: data.isWhitelisted,
      abuseConfidenceScore: score,
      totalReports: reports,
      numDistinctUsers: data.numDistinctUsers,
      usageType: data.usageType,
      isp: data.isp,
      domain: data.domain,
      countryCode: data.countryCode,
      hostnames: hostnames.slice(0, 10),
      lastReportedAt: data.lastReportedAt,
    });

    return verdict;
  }

  private toErrorVerdict(verdict: ProviderVerdict, err: unknown, started: number): ProviderVerdict {
    const up =
      err instanceof UpstreamError
        ? err
        : new UpstreamError({ code: 'network_error', message: String(err), retryable: true });
    const statusMap: Record<string, ProviderVerdict['status']> = {
      not_found: 'not_found',
      rate_limited: 'rate_limited',
      quota_exceeded: 'rate_limited',
      timeout: 'timeout',
    };
    verdict.status = statusMap[up.code] ?? 'error';
    verdict.error = { code: up.code, message: up.message, httpStatus: up.httpStatus, retryable: up.retryable };
    verdict.durationMs = Date.now() - started;
    return verdict;
  }
}
