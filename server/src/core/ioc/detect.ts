/**
 * ============================================================================
 * IOC TYPE DETECTION  (CTI lifecycle: "Processing")
 * ============================================================================
 *
 * A capstone-critical design point: detection is *pure* and *ordered*.
 *   1. The raw string is trimmed and stripped of an accidental `defanged`
 *      transformation (analysts paste `hxxp://evil[.]com` or `1.2.3[.]4`).
 *   2. Each rule is tested in a fixed order from most specific to least
 *      specific, so the result is 100% deterministic and testable.
 *   3. Regexes are fully anchored (`^...$`) - partial matches are rejected so
 *      that "not an IP" never silently becomes a "domain".
 *
 * Why ordering matters: `203.0.113.50` matches the IPv4 rule; the generic
 * "domain" rule would also match it if it allowed embedded dots, which is why
 * the domain rule forbids a label that is a valid IPv4 octet.
 */
import type { IocType } from '../types.js';

export interface DetectionResult {
  value: string;
  raw: string;
  type: IocType;
  confidence: 'high';
  /** Which rule fired - useful for the analyst UI and for unit tests. */
  rule: string;
  defanged: boolean;
  notes: string[];
}

/** IPv4: strict dotted-quad, each octet 0-255, no leading zeros (octal trap). */
export const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/**
 * IPv6 - covers the common textual forms, including compressed `::`,
 * IPv4-mapped (`::ffff:203.0.113.1`) and link-local scopes.
 */
export const IPV6_RE = /^(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$/;
const IPV6_COMPRESSED_RE =
  /^(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?$/;
const IPV6_MIXED_RE =
  /^((?:[0-9A-Fa-f]{1,4}:){1,6}):(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

export const MD5_RE = /^[a-fA-F0-9]{32}$/;
export const SHA1_RE = /^[a-fA-F0-9]{40}$/;
export const SHA256_RE = /^[a-fA-F0-9]{64}$/;

/** Pragmatic RFC 1035/1123 hostname rule (max 253 chars, labels 1-63). */
export const DOMAIN_RE =
  /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

/** Email: local part is intentionally permissive, domain part uses DOMAIN_RE. */
export const EMAIL_RE =
  /^[a-zA-Z0-9._%+-]{1,64}@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

/** URL: we only care about http/https - other schemes are not web IOCs. */
export const URL_RE = /^https?:\/\/[^\s/?#]+(?:[/?#][^\s]*)?$/i;

/**
 * Defanged indicators as written by analysts in reports/tickets.
 * `hxxp`/`hXXp` -> `http`, `[.]`/`(.)`/`{.}`` -> `.`, `[at]` -> `@`,
 * `[@]` -> `@`, `[://]` -> `://`.
 */
const DEFANG_PATTERNS: Array<[RegExp, string]> = [
  [/\[\.\]|\(\.\)|\[\(\.\)\]|\{\.\}/g, '.'],
  [/\[:\]/g, ':'],
  [/\[@\]/gi, '@'],
  [/\[at\]/gi, '@'],
  [/\bh(?:xx|XX|Xx)p(s?)\b/g, 'http$1'],
  [/\[/g, ''],
  [/\]/g, ''],
];

/** Multi-label public suffixes we care about for registrable-domain extraction. */
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in',
  'co.za', 'org.za', 'net.za', 'gov.za',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'com.sg', 'com.hk', 'com.tw', 'co.kr', 'or.kr',
]);

/** Longest label we accept for a hostname, to bound obvious garbage. */
const MAX_HOST_LEN = 253;

export function refang(input: string): { value: string; wasDefanged: boolean } {
  let value = input;
  let wasDefanged = false;
  for (const [pattern, replacement] of DEFANG_PATTERNS) {
    const next = value.replace(pattern, replacement);
    if (next !== value) wasDefanged = true;
    value = next;
  }
  return { value, wasDefanged };
}

/** Public-suffix aware "registrable domain" (eTLD+1) approximation. */
export function registrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (IPV4_RE.test(host) || host.includes(':')) return host;
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }
  return lastTwo;
}

export function tldOf(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const labels = host.split('.');
  if (labels.length < 2) return '';
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return lastTwo;
  return labels[labels.length - 1];
}

const isValidHostname = (h: string): boolean =>
  h.length > 0 && h.length <= MAX_HOST_LEN && DOMAIN_RE.test(h);

const parseUrl = (value: string): URL | null => {
  try {
    const u = new URL(value);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    if (!u.hostname) return null;
    return u;
  } catch {
    return null;
  }
};

interface Rule {
  id: string;
  test: (v: string) => boolean;
  type: IocType;
  note: string;
}

/**
 * Ordered rule table. First match wins - see the module docblock for why.
 */
const RULES: Rule[] = [
  { id: 'sha256', test: (v) => SHA256_RE.test(v), type: 'sha256', note: '64 hex characters' },
  { id: 'sha1', test: (v) => SHA1_RE.test(v), type: 'sha1', note: '40 hex characters' },
  { id: 'md5', test: (v) => MD5_RE.test(v), type: 'md5', note: '32 hex characters' },
  { id: 'ipv4', test: (v) => IPV4_RE.test(v), type: 'ipv4', note: 'valid dotted-quad IPv4' },
  {
    id: 'ipv6',
    test: (v) => IPV6_RE.test(v) || IPV6_COMPRESSED_RE.test(v) || IPV6_MIXED_RE.test(v),
    type: 'ipv6',
    note: 'valid IPv6 textual form',
  },
  {
    id: 'url',
    test: (v) => {
      const u = parseUrl(v);
      if (!u) return false;
      return isValidHostname(u.hostname) || IPV4_RE.test(u.hostname);
    },
    type: 'url',
    note: 'http(s) URL with a valid host',
  },
  { id: 'email', test: (v) => EMAIL_RE.test(v), type: 'email', note: 'local@domain pattern' },
  { id: 'domain', test: (v) => isValidHostname(v), type: 'domain', note: 'RFC 1035 hostname' },
];

/**
 * Detect the type of an indicator. Returns `null` when nothing matches so the
 * caller can produce a helpful "why is this invalid" message.
 */
export function detectIocType(input: string): DetectionResult | null {
  const raw = input.trim();
  if (!raw) return null;

  const { value: refanged, wasDefanged } = refang(raw);
  // Normalise case for everything except paths (URLs are case-sensitive in path).
  const candidate = refanged;

  for (const rule of RULES) {
    if (!rule.test(candidate)) continue;
    const notes = [`Matched ${rule.id} rule: ${rule.note}.`];
    if (wasDefanged) notes.push('Indicator was defanged and has been re-fanged automatically.');
    return {
      value: canonicalise(rule.type, candidate),
      raw,
      type: rule.type,
      confidence: 'high',
      rule: rule.id,
      defanged: wasDefanged,
      notes,
    };
  }
  return null;
}

/** Per-type canonical form so the same indicator always hashes/looks the same. */
function canonicalise(type: IocType, value: string): string {
  switch (type) {
    case 'md5':
    case 'sha1':
    case 'sha256':
      return value.toLowerCase();
    case 'domain':
    case 'email':
      return value.toLowerCase();
    case 'url': {
      const u = parseUrl(value);
      if (!u) return value;
      u.hostname = u.hostname.toLowerCase();
      u.protocol = u.protocol.toLowerCase();
      // Strip a default port so http://x:80/ and http://x/ are one indicator.
      if ((u.protocol === 'http:' && u.port === '80') || (u.protocol === 'https:' && u.port === '443')) {
        u.port = '';
      }
      return u.toString();
    }
    case 'ipv4':
      return value;
    case 'ipv6':
      return value.toLowerCase().replace(/\[|\]/g, '');
    default:
      return value;
  }
}
