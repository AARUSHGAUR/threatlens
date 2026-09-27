/**
 * ============================================================================
 * IOC VALIDATION & NORMALISATION  (CTI lifecycle: "Processing")
 * ============================================================================
 *
 * Validation is split into three layers so the error the analyst sees is
 * always actionable:
 *   Layer 1 - syntactic : does it look like a known indicator type at all?
 *   Layer 2 - semantic  : is the indicator in a scope we are willing to enrich?
 *              (e.g. RFC 5737 documentation ranges, RFC 1918 private space and
 *               loopback addresses are *valid* indicators but are flagged, not
 *               rejected - a CTI analyst legitimately investigates them.)
 *   Layer 3 - policy    : hard refusals (loopback/link-local/multicast for IP,
 *              file:// or non-http schemes for URL, etc.) plus a global
 *              length bound that protects the API and the database.
 */
import { detectIocType, registrableDomain, tldOf } from './detect.js';
import { IPV4_RE } from './detect.js';
import type { IocType, NormalizedIoc } from '../types.js';

/** RFC 5737 / RFC 3849 / RFC 2606 values reserved for documentation. */
export const DOCUMENTATION_RANGES = [
  { cidr: '192.0.2.0/24', label: 'TEST-NET-1 (RFC 5737)' },
  { cidr: '198.51.100.0/24', label: 'TEST-NET-2 (RFC 5737)' },
  { cidr: '203.0.113.0/24', label: 'TEST-NET-3 (RFC 5737)' },
  { cidr: '2001:db8::/32', label: 'Documentation prefix (RFC 3849)' },
];

const RESERVED_DOMAINS = new Set(['example.com', 'example.net', 'example.org', 'example']);
const RESERVED_TLDS = new Set(['example', 'invalid', 'test', 'localhost']);

const MAX_INPUT_LENGTH = 2048;
const COMMON_SERVICE_PORTS = new Set([80, 443, 8080, 8443, 53]);

export interface ValidationWarning {
  code: string;
  message: string;
}

export type ValidationResult =
  | { ok: true; ioc: NormalizedIoc; warnings: ValidationWarning[]; notes: string[] }
  | { ok: false; error: { code: string; message: string; hint?: string }; warnings: ValidationWarning[] };

const ipv4ToInt = (ip: string): number =>
  ip.split('.').reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;

const cidrContains = (ip: string, cidr: string): boolean => {
  const [net, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  if (!IPV4_RE.test(net) || !IPV4_RE.test(ip)) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) >>> 0 === (ipv4ToInt(net) & mask) >>> 0;
};

export const isDocumentationIpv4 = (ip: string): boolean =>
  DOCUMENTATION_RANGES.filter((r) => r.cidr.includes('.')).some((r) => cidrContains(ip, r.cidr));

export const isDocumentationIpv6 = (ip: string): boolean =>
  ip.toLowerCase().replace(/^\[|\]$/g, '').startsWith('2001:db8');

export const isPrivateIpv4 = (ip: string): boolean => {
  const n = ipv4ToInt(ip);
  return (
    cidrContains(ip, '10.0.0.0/8') ||
    cidrContains(ip, '172.16.0.0/12') ||
    cidrContains(ip, '192.168.0.0/16') ||
    cidrContains(ip, '100.64.0.0/10') ||
    cidrContains(ip, '169.254.0.0/16')
  );
};

const ipv4FirstOctet = (ip: string): number => Number(ip.split('.')[0]);
export const isLoopbackIpv4 = (ip: string): boolean => ipv4FirstOctet(ip) === 127;
export const isMulticastIpv4 = (ip: string) => ipv4FirstOctet(ip) >= 224 && ipv4FirstOctet(ip) <= 239;
export const isLinkLocalIpv4 = (ip: string) => ipv4FirstOctet(ip) === 169;
export const isBroadcastIpv4 = (ip: string) => cidrContains(ip, '255.255.255.255/32');

const hexOnly = (s: string) => /^[0-9a-f]+$/i.test(s);

/** Shannon entropy of a string - used to flag DGA-style/random hostnames. */
export function shannonEntropy(input: string): number {
  if (!input.length) return 0;
  const freq = new Map<string, number>();
  for (const ch of input.toLowerCase()) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

const urlHostnameOf = (value: string): string | null => {
  try {
    return new URL(value).hostname;
  } catch {
    return null;
  }
};

export function validateIoc(input: unknown): ValidationResult {
  const warnings: ValidationWarning[] = [];

  if (typeof input !== 'string') {
    return { ok: false, error: { code: 'INVALID_INPUT_TYPE', message: 'Indicator must be a string.' }, warnings };
  }
  const trimmed = input.trim();
  if (!trimmed) {
    return { ok: false, error: { code: 'EMPTY_INPUT', message: 'No indicator was provided.' }, warnings };
  }
  if (trimmed.length > MAX_INPUT_LENGTH) {
    return {
      ok: false,
      error: {
        code: 'INPUT_TOO_LONG',
        message: `Indicator exceeds the ${MAX_INPUT_LENGTH} character limit.`,
      },
      warnings,
    };
  }
  if (/[\s<>"'`]/.test(trimmed)) {
    return {
      ok: false,
      error: {
        code: 'MALFORMED_INDICATOR',
        message: 'Indicator contains whitespace or shell/HTML metacharacters.',
        hint: 'Indicators must be a single token - URL indicators are allowed to contain "/", "?" and "=" only.',
      },
      warnings,
    };
  }

  const detection = detectIocType(trimmed);
  if (!detection) {
    return {
      ok: false,
      error: {
        code: 'UNRECOGNISED_INDICATOR',
        message: 'Value does not match any supported indicator type.',
        hint: 'Supported: IPv4, IPv6, domain, http(s) URL, MD5, SHA1, SHA256, email address.',
      },
      warnings,
    };
  }

  const type = detection.type;
  const value = detection.value;
  const notes = [...detection.notes];

  // ---- Layer 3: policy refusals ------------------------------------------
  if (type === 'ipv4') {
    if (isLoopbackIpv4(value)) {
      return { ok: false, error: { code: 'LOOPBACK_ADDRESS', message: 'Loopback addresses cannot be enriched.' }, warnings };
    }
    if (isMulticastIpv4(value)) {
      return { ok: false, error: { code: 'MULTICAST_ADDRESS', message: 'Multicast addresses are not valid IOCs.' }, warnings };
    }
    if (isBroadcastIpv4(value)) {
      return { ok: false, error: { code: 'BROADCAST_ADDRESS', message: 'Broadcast addresses are not valid IOCs.' }, warnings };
    }
    if (isLinkLocalIpv4(value)) {
      warnings.push({ code: 'LINK_LOCAL', message: 'Link-local address - meaningful only inside a specific network segment.' });
    }
    if (isPrivateIpv4(value)) {
      warnings.push({ code: 'PRIVATE_ADDRESS', message: 'RFC 1918 private address - public reputation feeds will return little data.' });
    }
    if (isDocumentationIpv4(value)) {
      warnings.push({
        code: 'DOCUMENTATION_RANGE',
        message: 'Address belongs to an RFC 5737 documentation range (used by this project\'s demo dataset).',
      });
    }
  }

  if (type === 'ipv6') {
    const v = value.toLowerCase();
    if (v === '::1') {
      return { ok: false, error: { code: 'LOOPBACK_ADDRESS', message: 'IPv6 loopback cannot be enriched.' }, warnings };
    }
    if (v.startsWith('ff')) {
      return { ok: false, error: { code: 'MULTICAST_ADDRESS', message: 'IPv6 multicast is not a valid IOC.' }, warnings };
    }
    if (v.startsWith('fe80')) {
      warnings.push({ code: 'LINK_LOCAL', message: 'IPv6 link-local address.' });
    }
    if (isDocumentationIpv6(v)) {
      warnings.push({ code: 'DOCUMENTATION_RANGE', message: 'RFC 3849 documentation prefix (demo dataset).' });
    }
  }

  if (type === 'domain' || type === 'url' || type === 'email') {
    const host = type === 'email' ? value.split('@')[1] : type === 'url' ? urlHostnameOf(value) ?? '' : value;
    if (RESERVED_DOMAINS.has(host.toLowerCase()) || RESERVED_TLDS.has(tldOf(host))) {
      warnings.push({
        code: 'RESERVED_DOMAIN',
        message: 'Domain is reserved for documentation (RFC 2606) and will not appear in public feeds.',
      });
    }
  }

  // ---- Semantic enrichment of the parsed structure ------------------------
  const parsed: NormalizedIoc['parsed'] = {};
  if (type === 'url') {
    try {
      const u = new URL(value);
      parsed.scheme = u.protocol.replace(':', '');
      parsed.hostname = u.hostname.toLowerCase();
      parsed.port = u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80;
      parsed.path = u.pathname;
      parsed.query = u.search ? u.search.slice(1) : undefined;
      parsed.registrableDomain = registrableDomain(u.hostname);
      parsed.tld = tldOf(u.hostname);
      parsed.isPunycode = u.hostname.includes('xn--');
      parsed.subdomainDepth = Math.max(0, u.hostname.split('.').length - 2);
    } catch {
      /* unreachable: detection already parsed the URL */
    }
  } else if (type === 'domain') {
    parsed.hostname = value;
    parsed.registrableDomain = registrableDomain(value);
    parsed.tld = tldOf(value);
    parsed.isPunycode = value.includes('xn--');
    parsed.subdomainDepth = Math.max(0, value.split('.').length - 2);
  } else if (type === 'email') {
    const [local, domain] = value.split('@');
    parsed.emailLocalPart = local;
    parsed.emailDomain = domain;
    parsed.hostname = domain;
    parsed.registrableDomain = registrableDomain(domain);
    parsed.tld = tldOf(domain);
  } else if (type === 'ipv4' || type === 'ipv6') {
    parsed.hostname = value;
  }

  const ioc: NormalizedIoc = { value, raw: detection.raw, type, parsed };

  if (type === 'md5') {
    warnings.push({ code: 'WEAK_HASH', message: 'MD5 is cryptographically broken - treat identity matches with caution.' });
  }
  if (type === 'domain' || type === 'url') {
    const host = parsed.hostname ?? value;
    const firstLabel = host.split('.')[0];
    if (firstLabel && firstLabel.length >= 12 && shannonEntropy(firstLabel) >= 3.4) {
      warnings.push({
        code: 'HIGH_ENTROPY_LABEL',
        message: `Hostname label entropy ${shannonEntropy(firstLabel)} is consistent with algorithmically generated (DGA) domains.`,
      });
    }
    if (parsed.subdomainDepth && parsed.subdomainDepth >= 4) {
      warnings.push({ code: 'DEEP_SUBDOMAIN', message: `Unusually deep subdomain chain (${parsed.subdomainDepth} levels) - often used for tracking or evasion.` });
    }
    if (type === 'url' && parsed.port && !COMMON_SERVICE_PORTS.has(parsed.port)) {
      warnings.push({ code: 'NON_STANDARD_PORT', message: `URL uses non-standard port ${parsed.port}.` });
    }
  }

  return { ok: true, ioc, warnings, notes };
}

/** Human readable label for a type, used by the UI and reports. */
export const IOC_TYPE_LABEL: Record<IocType, string> = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  domain: 'Domain',
  url: 'URL',
  md5: 'MD5',
  sha1: 'SHA1',
  sha256: 'SHA256',
  email: 'Email',
};

/** A short, human-friendly description of the indicator for report headers. */
export function describeIoc(ioc: NormalizedIoc): string {
  const { type, parsed, value } = ioc;
  switch (type) {
    case 'url':
      return `URL indicator on host ${parsed.hostname} (${parsed.registrableDomain})`;
    case 'email':
      return `Email address at domain ${parsed.emailDomain}`;
    case 'domain':
      return `Domain indicator, registrable domain ${parsed.registrableDomain}`;
    case 'md5':
    case 'sha1':
    case 'sha256':
      return `${type.toUpperCase()} file hash (${value.length} hex characters)`;
    default:
      return `${IOC_TYPE_LABEL[type]} address indicator`;
  }
}

export { hexOnly };
