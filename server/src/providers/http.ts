/**
 * Shared HTTP client for threat-intelligence providers.
 *
 * Provides the three cross-cutting concerns every provider would otherwise
 * re-implement (and re-break):
 *
 *  1. TIMEOUTS      - AbortController based hard timeout, so a hanging upstream
 *                     can never stall an investigation forever.
 *  2. CLIENT-SIDE RATE LIMITING - a per-provider minimum interval. Free tiers
 *                     are extremely tight (VirusTotal: 4 req/min,
 *                     AbuseIPDB: 1000 checks/day, OTX: 10 req/s). Exceeding them
 *                     gets the key suspended, so we throttle *before* sending.
 *  3. ERROR CLASSIFICATION - a single taxonomy (auth_error, rate_limited,
 *                     not_found, upstream_error, network_error, timeout) that the
 *                     UI, the timeline and the risk engine all understand.
 */
import { config } from '../config/env.js';
import { logger } from '../config/logger.js';

export type UpstreamErrorCode =
  | 'auth_error'
  | 'forbidden'
  | 'rate_limited'
  | 'not_found'
  | 'upstream_error'
  | 'network_error'
  | 'timeout'
  | 'bad_request'
  | 'quota_exceeded'
  | 'malformed_response';

export interface UpstreamErrorInfo {
  code: UpstreamErrorCode;
  message: string;
  httpStatus?: number;
  retryable: boolean;
}

export class UpstreamError extends Error {
  readonly code: UpstreamErrorCode;
  readonly httpStatus?: number;
  readonly retryable: boolean;

  constructor(err: UpstreamErrorInfo) {
    super(err.message);
    this.name = 'UpstreamError';
    this.code = err.code;
    this.httpStatus = err.httpStatus;
    this.retryable = err.retryable;
  }
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** Last request timestamp per provider id, used to space requests out. */
const lastRequestAt = new Map<string, number>();

export interface HttpOptions {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: unknown;
  timeoutMs?: number;
  /** Skip the client-side throttle (used by the provider self-test). */
  noThrottle?: boolean;
}

function classifyStatus(status: number, bodyText: string): UpstreamError {
  const build = (info: UpstreamErrorInfo) => new UpstreamError(info);
  const snippet = bodyText.slice(0, 200).replace(/\s+/g, ' ');
  switch (status) {
    case 400:
      return build({ code: 'bad_request', message: `Provider rejected the request (400). ${snippet}`, httpStatus: 400, retryable: false });
    case 401:
      return build({ code: 'auth_error', message: `Provider rejected the API key (401). Check the key in your .env file.`, httpStatus: 401, retryable: false });
    case 403:
      return build({ code: 'forbidden', message: `Provider denied access (403) - the key may lack the required scope or quota.`, httpStatus: 403, retryable: false });
    case 404:
      return build({ code: 'not_found', message: 'Indicator is not present in this provider\'s dataset.', httpStatus: 404, retryable: false });
    case 429:
      return build({ code: 'rate_limited', message: 'Provider rate limit or daily quota reached. Try again later.', httpStatus: 429, retryable: true });
    default:
      if (status >= 500) {
        return build({ code: 'upstream_error', message: `Provider is temporarily unavailable (HTTP ${status}).`, httpStatus: status, retryable: true });
      }
      return build({ code: 'upstream_error', message: `Unexpected provider response (HTTP ${status}). ${snippet}`, httpStatus: status, retryable: false });
  }
}

/**
 * Perform a JSON API call with timeout, throttling and normalised errors.
 * Throws `UpstreamError`; callers convert that into a ProviderVerdict.
 */
export async function httpJson<T = unknown>(
  providerId: string,
  url: string,
  options: HttpOptions = {},
): Promise<{ data: T; status: number }> {
  const timeoutMs = options.timeoutMs ?? config.providerTimeoutMs;
  const minInterval = Math.max(0, config.providerMinIntervalMs);

  if (!options.noThrottle && minInterval > 0) {
    const last = lastRequestAt.get(providerId) ?? 0;
    const waitFor = last + minInterval - Date.now();
    if (waitFor > 0) await sleep(waitFor);
  }
  lastRequestAt.set(providerId, Date.now());

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();

  try {
    const response = await fetch(url, {
      method: options.method ?? 'GET',
      headers: {
        accept: 'application/json',
        'user-agent': 'ThreatLens/1.0 (capstone CTI platform)',
        ...(options.body ? { 'content-type': 'application/json' } : {}),
        ...(options.headers ?? {}),
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal: controller.signal,
      redirect: 'follow',
    });

    const text = await response.text();

    if (!response.ok) {
      const classified = classifyStatus(response.status, text);
      // Quota errors are sometimes reported as 403 by AbuseIPDB.
      if (classified.httpStatus === 403 && /quota|rate limit|too many requests/i.test(text)) {
        throw new UpstreamError({ code: 'quota_exceeded', message: 'Provider quota exhausted for this key.', httpStatus: 403, retryable: true });
      }
      throw new UpstreamError(classified);
    }

    try {
      return { data: JSON.parse(text) as T, status: response.status };
    } catch {
      throw new UpstreamError({ code: 'malformed_response', message: 'Provider returned a non-JSON response.', httpStatus: response.status, retryable: true });
    }
  } catch (err) {
    if (err instanceof UpstreamError) throw err;
    if (err instanceof Error && err.name === 'AbortError') {
      throw new UpstreamError({ code: 'timeout', message: `Provider did not respond within ${timeoutMs} ms.`, retryable: true });
    }
    const message = err instanceof Error ? err.message : String(err);
    logger.warn('provider request failed', { providerId, message });
    throw new UpstreamError({ code: 'network_error', message: `Network error contacting provider: ${message}`, retryable: true });
  } finally {
    clearTimeout(timer);
    void started;
  }
}

/** Truncate a raw provider payload so the database never stores huge blobs. */
export function excerpt(value: unknown, maxBytes = 8192): string | null {
  if (value === null || value === undefined) return null;
  let text: string;
  try {
    text = JSON.stringify(value);
  } catch {
    text = String(value);
  }
  if (text === 'undefined') return null;
  return text.length <= maxBytes ? text : `${text.slice(0, maxBytes)}...[truncated]`;
}

/** Reset throttling state (used by tests). */
export function __resetThrottle(): void {
  lastRequestAt.clear();
}
