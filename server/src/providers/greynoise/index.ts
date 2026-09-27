/**
 * GreyNoise Community API adapter (IP addresses only).
 *
 * Docs: https://docs.greynoise.io/reference/get-community-ip-context
 * Endpoint: GET https://api.greynoise.io/v3/community/{ip}
 *
 * GreyNoise answers a very specific question: "does this IP scan the internet?"
 * That is different from "is this IP malicious?", and the risk engine treats it
 * as a *context* factor (modest weight) rather than a reputation verdict - an
 * important nuance we call out in the risk breakdown.
 */
import { config } from '../../config/env.js';
import type { IocType, NormalizedIoc, ProviderVerdict } from '../../core/types.js';
import { emptyVerdict, type ProviderContext, type ThreatIntelProvider } from '../types.js';
import { UpstreamError, excerpt, httpJson } from '../http.js';
import { buildDetectionStats, safeInt, safeStr, toIso, uniq } from '../normalize.js';

interface GreyNoiseResponse {
  ip?: string;
  noise?: boolean;
  riot?: boolean;
  classification?: 'benign' | 'educational' | 'malicious' | 'unknown';
  name?: string;
  link?: string;
  last_seen?: string;
  message?: string;
}

export class GreyNoiseProvider implements ThreatIntelProvider {
  readonly id = 'greynoise';
  readonly name = 'GreyNoise';
  readonly description =
    'Internet background-noise scanner index. Classifies whether an internet-facing host opportunistically scans or is a known malicious scanner.';
  readonly homepage = 'https://www.greynoise.io';
  readonly documentationUrl = 'https://docs.greynoise.io/';
  readonly requiresKey = true;
  readonly supports: readonly IocType[] = ['ipv4', 'ipv6'];

  private readonly apiKey: string;

  constructor(apiKey: string = config.providerKeys.greynoise) {
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
      verdict.error = { code: 'unconfigured', message: 'GREYNOISE_API_KEY is not set.', retryable: false };
      return verdict;
    }
    if (ioc.type !== 'ipv4' && ioc.type !== 'ipv6') {
      verdict.status = 'not_found';
      verdict.error = { code: 'unsupported_indicator', message: 'GreyNoise only indexes IP addresses.', retryable: false };
      verdict.durationMs = Date.now() - started;
      return verdict;
    }

    let data: GreyNoiseResponse;
    try {
      ctx.onProgress?.('Querying GreyNoise community context');
      const { data: body } = await httpJson<GreyNoiseResponse>(
        this.id,
        `https://api.greynoise.io/v3/community/${encodeURIComponent(ioc.value)}`,
        { headers: { key: this.apiKey } },
      );
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

    // GreyNoise returns 404 with a `message` for "IP not in the dataset" - that
    // is a *legitimate negative* answer, not a failure.
    if (data.message && !data.classification) {
      verdict.status = 'not_found';
      verdict.verdict = 'unknown';
      verdict.rawExcerpt = excerpt({ message: data.message });
      verdict.durationMs = Date.now() - started;
      return verdict;
    }

    const classification = (data.classification ?? 'unknown').toLowerCase();
    const lastSeen = toIso(data.last_seen);

    // Encode the classification into a comparable detection block:
    //   malicious    -> 4 malicious engines
    //   unknown      -> 0 malicious, 0 suspicious (not in the index at all)
    //   benign/edu   -> treated as a *negative* context signal, not an engine hit
    const malicious = classification === 'malicious' ? 4 : 0;
    verdict.detections = buildDetectionStats({
      malicious,
      suspicious: 0,
      harmless: classification === 'benign' || classification === 'educational' ? 70 : 70 - malicious,
      lastAnalysisAt: lastSeen,
    });
    verdict.verdict = classification === 'malicious' ? 'malicious' : 'unknown';
    verdict.reputationScore = classification === 'malicious' ? 60 : null;
    verdict.reports = data.noise ? 1 : 0;
    verdict.lastSeenAt = lastSeen;
    verdict.firstSeenAt = lastSeen;
    verdict.status = 'ok';
    verdict.durationMs = Date.now() - started;
    verdict.url = data.link ?? `https://viz.greynoise.io/ip/${ioc.value}`;

    verdict.related.categories = uniq([`greynoise-${classification}`, data.noise ? 'background-noise' : null]);
    verdict.related.behaviours = uniq([
      data.noise ? 'internet-scanner' : null,
      data.riot ? 'common-service' : null,
      classification === 'malicious' ? 'known-malicious-scanner' : null,
      classification === 'educational' ? 'educational-scanner' : null,
    ]);
    if (classification === 'malicious' && safeStr(data.name)) {
      verdict.related.actors = uniq([safeStr(data.name)]);
    }
    if (classification === 'benign' || classification === 'educational') {
      // Loud, explicit trust signal - surfaced as a negative risk offset.
      verdict.related.behaviours = uniq([...verdict.related.behaviours, 'known-benign-scanner']);
    }

    verdict.rawExcerpt = excerpt({
      ip: data.ip,
      noise: data.noise,
      riot: data.riot,
      classification: data.classification,
      name: data.name,
      link: data.link,
      last_seen: data.last_seen,
    });

    void safeInt;
    return verdict;
  }
}
