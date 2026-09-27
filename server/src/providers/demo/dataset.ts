/**
 * ============================================================================
 * DEMO DATASET  (ThreatLens demonstration intelligence)
 * ============================================================================
 *
 * EVERYTHING IN THIS FILE IS FICTIONAL AND LABELLED AS SUCH.
 *
 * Safety rules enforced by this dataset (a hard requirement of the project):
 *  1. All IP indicators live inside the IETF documentation ranges
 *     (RFC 5737 TEST-NET-1/2/3 and RFC 3849 2001:db8::/32) so no real host is
 *     ever named. 8.8.8.8 / 1.1.1.1 appear once, correctly labelled as public
 *     resolvers, purely to demonstrate the CLEAN verdict path.
 *  2. All domains use the RFC 2606 reserved namespaces (example.com,
 *     example.net, example.org) - they can never resolve.
 *  3. Every file hash is a SHA-256 digest of a ThreatLens-specific label, so
 *     it cannot collide with a real malware sample.
 *  4. Malware families, threat actors and campaigns are invented and carry a
 *     `DEMO-` prefix in their external id. No real actor or malware is
 *     impersonated.
 *  5. Values are consumed ONLY through the demo provider, which stamps every
 *     verdict with `origin: 'demo'`; the UI then renders a "DEMO DATA" badge.
 *
 * Dates are stored as *relative day offsets* (`lastSeenDaysAgo`) instead of
 * fixed timestamps so that "recent activity" stays meaningful whenever the
 * project is demonstrated, while remaining fully deterministic.
 */
import { createHash } from 'node:crypto';
import type { IocType } from '../../core/types.js';

export interface DemoEntityRef {
  externalId: string;
  name: string;
}

export interface DemoActor extends DemoEntityRef {
  aliases: string[];
  origin: 'demo';
  sophistication: string;
  motivation: string[];
  firstSeenYear: number;
  description: string;
}

export interface DemoMalware extends DemoEntityRef {
  aliases: string[];
  origin: 'demo';
  malwareType: string;
  platform: string[];
  capabilities: string[];
  description: string;
  /** Documented technique behaviour used by the ATT&CK mapper. */
  techniques: string[];
  families: string[];
}

export interface DemoCampaign extends DemoEntityRef {
  origin: 'demo';
  firstSeen: string;
  description: string;
  actorExternalId: string;
}

export const DEMO_ACTORS: DemoActor[] = [
  {
    externalId: 'DEMO-TA-001',
    name: 'Nightfall Jackal (fictional)',
    aliases: ['DEMO-NIGHTFALL', 'Jackal-9'],
    origin: 'demo',
    sophistication: 'High',
    motivation: ['Espionage'],
    firstSeenYear: 2021,
    description:
      'Fictional state-sponsored cluster modelled on publicly reported TTP patterns. Attaches to supply-chain vendors and logistics firms, stages a custom RAT over HTTPS, then exfiltrates over the same channel to avoid anomaly-based detection.',
  },
  {
    externalId: 'DEMO-TA-002',
    name: 'Silent Meridian (fictional)',
    origin: 'demo',
    aliases: ['DEMO-MERIDIAN'],
    sophistication: 'Medium',
    motivation: ['Financial gain'],
    firstSeenYear: 2022,
    description:
      'Fictional financially motivated access-broker ecosystem. Operates malvertising infrastructure and an information stealer sold under several names; infrastructure is frequently re-registered, which produces the short-lived domain pattern in this dataset.',
  },
  {
    externalId: 'DEMO-TA-003',
    name: 'Copper Kite (fictional)',
    origin: 'demo',
    aliases: ['DEMO-KITE'],
    sophistication: 'Low',
    motivation: ['Ideological'],
    firstSeenYear: 2023,
    description:
      'Fictional hacktivist persona used in this dataset to demonstrate low-sophistication attribution: commodity tooling, public infrastructure, little defence evasion.',
  },
];

export const DEMO_MALWARE: DemoMalware[] = [
  {
    externalId: 'DEMO-MAL-001',
    name: 'Nightfall RAT (fictional)',
    aliases: ['DEMO-NFRAT', 'Nightfall Remote Access Trojan'],
    origin: 'demo',
    malwareType: 'RAT',
    platform: ['Windows'],
    capabilities: ['C2 over HTTPS', 'Process injection', 'Keylogging', 'File transfer'],
    description:
      'Fictional implant. Uses PowerShell for post-exploitation scripting, injects into a signed host process, transfers additional tooling over HTTPS and deletes its staging files after execution.',
    techniques: ['T1059.001', 'T1071.001', 'T1105', 'T1055', 'T1070.004', 'T1041'],
    families: ['Nightfall', 'NightfallRAT', 'DEMO-NFRAT'],
  },
  {
    externalId: 'DEMO-MAL-002',
    name: 'Sablefish Stealer (fictional)',
    aliases: ['DEMO-SABLEFISH', 'SableFish'],
    origin: 'demo',
    malwareType: 'Information stealer',
    platform: ['Windows'],
    capabilities: ['Credential harvesting', 'Browser cookie theft', 'System fingerprinting', 'Exfiltration over C2'],
    description:
      'Fictional commodity stealer. Collects credentials and browser data, fingerprints the host, then exfiltrates the archive over the same HTTP(S) channel it was delivered on.',
    techniques: ['T1555.003', 'T1005', 'T1082', 'T1041', 'T1071.001', 'T1105'],
    families: ['Sablefish', 'SableFish', 'DEMO-SABLEFISH'],
  },
  {
    externalId: 'DEMO-MAL-003',
    name: 'Wraithdrop Loader (fictional)',
    aliases: ['DEMO-WRAITHDROP'],
    origin: 'demo',
    malwareType: 'Downloader / loader',
    platform: ['Windows', 'Linux'],
    capabilities: ['Payload download', 'Process launch', 'Persistence via scheduled task'],
    description:
      'Fictional first-stage loader. Downloads the real payload from hard-coded hosts, writes it to a temporary path and launches it, leaving a scheduled task for persistence.',
    techniques: ['T1105', 'T1204.002', 'T1059.003', 'T1053.005'],
    families: ['Wraithdrop', 'DEMO-WRAITHDROP'],
  },
  {
    externalId: 'DEMO-MAL-004',
    name: 'Paper Lantern Kit (fictional)',
    aliases: ['DEMO-PAPERLANTERN'],
    origin: 'demo',
    malwareType: 'Phishing kit',
    platform: ['Windows', 'macOS'],
    capabilities: ['Credential harvesting page', 'Link redirection', 'Cookie injection'],
    description:
      'Fictional phishing kit used with spearphishing emails. Harvests credentials on a cloned login page and redirects the victim to the legitimate site to reduce suspicion.',
    techniques: ['T1566.002', 'T1056.003', 'T1185'],
    families: ['PaperLantern', 'DEMO-PAPERLANTERN'],
  },
];

export const DEMO_CAMPAIGNS: DemoCampaign[] = [
  {
    externalId: 'DEMO-CAMP-001',
    name: 'Operation Paper Lantern (fictional)',
    origin: 'demo',
    firstSeen: '2024-02-01',
    description:
      'Fictional spearphishing campaign against European logistics and freight companies. Delivers the Paper Lantern kit, drops Wraithdrop, and stages the Nightfall RAT on the resulting foothold.',
    actorExternalId: 'DEMO-TA-001',
  },
  {
    externalId: 'DEMO-CAMP-002',
    name: 'Operation Glass Kettle (fictional)',
    origin: 'demo',
    firstSeen: '2024-09-12',
    description:
      'Fictional malvertising and fake-update campaign distributing the Sablefish stealer through compromised consumer sites.',
    actorExternalId: 'DEMO-TA-002',
  },
];

/** Deterministic, non-real file hashes derived from ThreatLens-specific labels. */
const demoHash = (algorithm: 'md5' | 'sha1' | 'sha256', label: string): string =>
  createHash(algorithm).update(`threatlens-demo-sample-${label}`).digest('hex');

export const DEMO_HASHES = {
  /** Nightfall RAT main implant */
  nightfallRAT: demoHash('sha256', 'malware/nightfall-rat/main'),
  /** Sablefish stealer dropper */
  sablefishStealer: demoHash('md5', 'malware/sablefish-stealer/dropper'),
  sablefishStealerSha1: demoHash('sha1', 'malware/sablefish-stealer/dropper'),
  /** Wraithdrop loader binary */
  wraithdropLoader: demoHash('sha256', 'malware/wraithdrop-loader/stage1'),
  /** PowerShell one-liner used by the Nightfall operator */
  nightfallScript: demoHash('sha256', 'script/nightfall/operator-ps1'),
  /** Benign sample: signed text editor (clean control indicator) */
  benignEditor: demoHash('sha256', 'benign/text-editor/release'),
};

/** Domain / host / IP / URL constants, all inside reserved namespaces. */
export const DEMO_INFRA = {
  c2Domain: 'c2-nightfall.example.com',
  loaderDomain: 'update-sablefish.example.net',
  phishDomain: 'login-portal-lantern.example.com',
  redirectDomain: 'tracking-lantern.example.org',
  statsDomain: 'telemetry-meridian.example.net',
  c2Ip: '203.0.113.50',
  c2Ip2: '203.0.113.51',
  loaderIp: '198.51.100.23',
  phishIp: '198.51.100.77',
  benignResolver: '8.8.8.8',
  benignResolver2: '1.1.1.1',
  benignQuad9: '9.9.9.9',
  docIpv6: '2001:db8::50',
  payloadUrl: 'http://cdn-update.example.net/stage/wraithdrop.bin',
  phishUrl: 'http://login-portal-lantern.example.com/session/verify?id=a8f1',
  updateUrl: 'https://telemetry-meridian.example.net/lib/main.js',
  c2Url: 'https://c2-nightfall.example.com/gate.php',
  cleanDomain: 'example.com',
  cleanUrl: 'https://example.com/index.html',
  mail: 'no-reply@updates-lantern.example.com',
};

/** Behavioural/technical tags used by the C2 + ATT&CK rules. */
export const DEMO_BEHAVIOURS = {
  c2: 'c2',
  c2OverHttps: 'c2',
  malwareDelivery: 'malware-delivery',
  phishing: 'phishing',
  dga: 'dga-like-hosting',
  credentialHarvesting: 'credential-harvesting',
  fastFlux: 'fast-flux-like',
  payloadOnline: 'payload-online',
  scanner: 'internet-scanner',
  cleanResolver: 'public-dns-resolver',
};

export interface DemoNetwork {
  country: string;
  countryCode: string;
  city: string;
  region: string;
  asn: string;
  asnOrg: string;
  isp: string;
  org: string;
  reverseDns: string[];
  hostingProvider: string;
  usageType: string;
  domain: string;
  ispDomain: string;
}

export interface DemoProfile {
  value: string;
  type: IocType;
  title: string;
  summary: string;
  /** VirusTotal-style multi-engine statistics. */
  detections: { malicious: number; suspicious: number; harmless: number; undetected: number };
  communityReputation: number | null;
  reports: number;
  lastSeenDaysAgo: number;
  firstSeenDaysAgo: number;
  network: DemoNetwork | null;
  abuse: { score: number; reports: number; usageType: string; distinctUsers: number } | null;
  pulses: Array<{
    name: string;
    adversary: string;
    malware: string[];
    tags: string[];
    daysAgo: number;
  }>;
  urlhaus: { threat: string; tags: string[]; urls: string[]; ip: string; status: 'online' | 'offline' } | null;
  greynoise: { classification: 'benign' | 'educational' | 'malicious' | 'unknown'; noise: boolean; name: string } | null;
  shodan: { ports: number[]; tags: string[]; hostnames: string[]; city: string; country: string } | null;
  related: {
    domains: string[];
    urls: string[];
    hashes: string[];
    ipAddresses: string[];
    emails: string[];
  };
  actors: string[];
  malware: string[];
  campaigns: string[];
  behaviours: string[];
  categories: string[];
  /** Explicit reasoning shown to the analyst on the demo hint panel. */
  analystNote: string;
}

const NET = {
  c2: {
    country: 'Netherlands',
    countryCode: 'NL',
    city: 'Amsterdam',
    region: 'North Holland',
    asn: 'AS64500',
    asnOrg: 'Example Hosting BV (DEMO)',
    isp: 'Example Hosting BV (DEMO)',
    org: 'Example Hosting BV (DEMO)',
    reverseDns: ['c2-nightfall.example.com'],
    hostingProvider: 'Example Hosting BV (DEMO)',
    usageType: 'Data Center/Web Hosting/Transit',
    domain: 'example.net',
    ispDomain: 'example.net',
  },
  loader: {
    country: 'Germany',
    countryCode: 'DE',
    city: 'Frankfurt',
    region: 'Hesse',
    asn: 'AS64501',
    asnOrg: 'Example Transit GmbH (DEMO)',
    isp: 'Example Transit GmbH (DEMO)',
    org: 'Example Transit GmbH (DEMO)',
    reverseDns: ['update-sablefish.example.net'],
    hostingProvider: 'Example Transit GmbH (DEMO)',
    usageType: 'Data Center/Web Hosting/Transit',
    domain: 'example.net',
    ispDomain: 'example.net',
  },
  phish: {
    country: 'Bulgaria',
    countryCode: 'BG',
    city: 'Sofia',
    region: 'Sofia-Capital',
    asn: 'AS64502',
    asnOrg: 'Example Cloud EOOD (DEMO)',
    isp: 'Example Cloud EOOD (DEMO)',
    org: 'Example Cloud EOOD (DEMO)',
    reverseDns: ['login-portal-lantern.example.com', 'tracking-lantern.example.org'],
    hostingProvider: 'Example Cloud EOOD (DEMO)',
    usageType: 'Data Center/Web Hosting/Transit',
    domain: 'example.org',
    ispDomain: 'example.org',
  },
  resolver: {
    country: 'United States',
    countryCode: 'US',
    city: 'Mountain View',
    region: 'California',
    asn: 'AS15169',
    asnOrg: 'Google LLC',
    isp: 'Google LLC',
    org: 'Google LLC',
    reverseDns: ['dns.google'],
    hostingProvider: 'Google LLC',
    usageType: 'Content Delivery Network',
    domain: 'google.com',
    ispDomain: 'google.net',
  },
  resolver2: {
    country: 'Australia',
    countryCode: 'AU',
    city: 'Sydney',
    region: 'New South Wales',
    asn: 'AS13335',
    asnOrg: 'Cloudflare, Inc.',
    isp: 'Cloudflare, Inc.',
    org: 'Cloudflare, Inc.',
    reverseDns: ['one.one.one.one'],
    hostingProvider: 'Cloudflare, Inc.',
    usageType: 'Content Delivery Network',
    domain: 'one.one.one.one',
    ispDomain: 'cloudflare.com',
  },
  docv6: {
    country: 'Documentation (RFC 3849)',
    countryCode: 'ZZ',
    city: '-',
    region: '-',
    asn: '-',
    asnOrg: 'Documentation prefix',
    isp: '-',
    org: '-',
    reverseDns: [],
    hostingProvider: '-',
    usageType: 'Reserved for documentation',
    domain: '-',
    ispDomain: '-',
  },
  none: null,
};

/**
 * The demo catalog. Keys are canonical IOC values.
 * Note how each profile is internally consistent: the abuse score, the engine
 * detections, the OTX pulses and the URLhaus listing all corroborate, so the
 * risk engine produces a defensible score.
 */
export const DEMO_PROFILES: DemoProfile[] = [
  // ------------------------------------------------------------ C2 IP (CRITICAL)
  {
    value: DEMO_INFRA.c2Ip,
    type: 'ipv4',
    title: 'Command-and-control server (fictional)',
    summary:
      'Primary C2 node of the fictional Nightfall cluster. Listed on a malware distribution feed, high abuse confidence, and observed on a non-standard HTTPS port.',
    detections: { malicious: 14, suspicious: 3, harmless: 51, undetected: 2 },
    communityReputation: -37,
    reports: 64,
    lastSeenDaysAgo: 1,
    firstSeenDaysAgo: 210,
    network: NET.c2,
    abuse: { score: 96, reports: 47, usageType: 'Data Center/Web Hosting/Transit', distinctUsers: 23 },
    pulses: [
      {
        name: 'Operation Paper Lantern (fictional)',
        adversary: 'Nightfall Jackal (fictional)',
        malware: ['Nightfall RAT (fictional)', 'Wraithdrop Loader (fictional)'],
        tags: ['c2', 'command-and-control', 'rat', 'nightfall'],
        daysAgo: 3,
      },
      {
        name: 'Vendor impersonation cluster (fictional)',
        adversary: 'Nightfall Jackal (fictional)',
        malware: ['Nightfall RAT (fictional)'],
        tags: ['c2', 'supply-chain'],
        daysAgo: 40,
      },
    ],
    urlhaus: {
      threat: 'nightfallrat',
      tags: ['c2', 'nightfall'],
      urls: ['https://c2-nightfall.example.com/gate.php'],
      ip: DEMO_INFRA.c2Ip,
      status: 'online',
    },
    greynoise: { classification: 'malicious', noise: true, name: 'DEMO-Nightfall Scanner' },
    shodan: { ports: [443, 8443], tags: ['malware', 'c2'], hostnames: ['c2-nightfall.example.com'], city: 'Amsterdam', country: 'Netherlands' },
    related: {
      domains: [DEMO_INFRA.c2Domain],
      urls: [DEMO_INFRA.c2Url],
      hashes: [DEMO_HASHES.nightfallRAT, DEMO_HASHES.nightfallScript],
      ipAddresses: [DEMO_INFRA.c2Ip2],
      emails: [],
    },
    actors: ['DEMO-TA-001'],
    malware: ['DEMO-MAL-001', 'DEMO-MAL-003'],
    campaigns: ['DEMO-CAMP-001'],
    behaviours: [DEMO_BEHAVIOURS.c2, DEMO_BEHAVIOURS.malwareDelivery],
    categories: ['c2', 'command-and-control', 'rat', 'malware', 'non-standard-port'],
    analystNote:
      'Corroborated across four independent sources (multi-engine reputation, abuse reporting, malware distribution feed, OTX pulses) - the strongest evidence pattern ThreatLens can produce.',
  },

  // ------------------------------------------------------ C2 IP, second node
  {
    value: DEMO_INFRA.c2Ip2,
    type: 'ipv4',
    title: 'Backup C2 node (fictional)',
    summary: 'Failover C2 address for the same fictional cluster, rotated in when the primary was sinkholed.',
    detections: { malicious: 8, suspicious: 2, harmless: 58, undetected: 2 },
    communityReputation: -18,
    reports: 27,
    lastSeenDaysAgo: 6,
    firstSeenDaysAgo: 120,
    network: NET.c2,
    abuse: { score: 88, reports: 19, usageType: 'Data Center/Web Hosting/Transit', distinctUsers: 11 },
    pulses: [
      {
        name: 'Operation Paper Lantern (fictional)',
        adversary: 'Nightfall Jackal (fictional)',
        malware: ['Nightfall RAT (fictional)'],
        tags: ['c2', 'nightfall'],
        daysAgo: 6,
      },
    ],
    urlhaus: null,
    greynoise: { classification: 'malicious', noise: true, name: 'DEMO-Nightfall Scanner' },
    shodan: { ports: [443], tags: ['c2'], hostnames: [], city: 'Amsterdam', country: 'Netherlands' },
    related: {
      domains: [DEMO_INFRA.c2Domain],
      urls: [],
      hashes: [DEMO_HASHES.nightfallRAT],
      ipAddresses: [DEMO_INFRA.c2Ip],
      emails: [],
    },
    actors: ['DEMO-TA-001'],
    malware: ['DEMO-MAL-001'],
    campaigns: ['DEMO-CAMP-001'],
    behaviours: [DEMO_BEHAVIOURS.c2],
    categories: ['c2', 'command-and-control'],
    analystNote: 'Infrastructure continuity evidence: two C2 nodes 1 address apart indicates an actively maintained estate.',
  },

  // ------------------------------------------------------ loader host (HIGH)
  {
    value: DEMO_INFRA.loaderIp,
    type: 'ipv4',
    title: 'Payload staging server (fictional)',
    summary: 'Hosts first-stage loader downloads. Abuse reports are moderate; the host is not itself a C2.',
    detections: { malicious: 6, suspicious: 1, harmless: 61, undetected: 2 },
    communityReputation: -9,
    reports: 18,
    lastSeenDaysAgo: 2,
    firstSeenDaysAgo: 90,
    network: NET.loader,
    abuse: { score: 72, reports: 14, usageType: 'Data Center/Web Hosting/Transit', distinctUsers: 9 },
    pulses: [
      {
        name: 'Operation Glass Kettle (fictional)',
        adversary: 'Silent Meridian (fictional)',
        malware: ['Wraithdrop Loader (fictional)', 'Sablefish Stealer (fictional)'],
        tags: ['malware', 'downloader', 'malvertising'],
        daysAgo: 4,
      },
    ],
    urlhaus: {
      threat: 'wraithdrop',
      tags: ['downloader', 'payload'],
      urls: [DEMO_INFRA.payloadUrl],
      ip: DEMO_INFRA.loaderIp,
      status: 'online',
    },
    greynoise: { classification: 'unknown', noise: false, name: '' },
    shodan: { ports: [80, 443], tags: ['malware'], hostnames: ['update-sablefish.example.net'], city: 'Frankfurt', country: 'Germany' },
    related: {
      domains: [DEMO_INFRA.loaderDomain],
      urls: [DEMO_INFRA.payloadUrl],
      hashes: [DEMO_HASHES.wraithdropLoader],
      ipAddresses: [],
      emails: [],
    },
    actors: ['DEMO-TA-002'],
    malware: ['DEMO-MAL-003', 'DEMO-MAL-002'],
    campaigns: ['DEMO-CAMP-002'],
    behaviours: [DEMO_BEHAVIOURS.malwareDelivery, DEMO_BEHAVIOURS.payloadOnline],
    categories: ['malware', 'downloader', 'payload-hosting'],
    analystNote:
      'Distribution-only infrastructure: worth blocking and hunting, but it is a weaker indicator of operator control than a C2 node.',
  },

  // ------------------------------------------------------------ phishing host
  {
    value: DEMO_INFRA.phishIp,
    type: 'ipv4',
    title: 'Phishing site host (fictional)',
    summary: 'Serves a credential-harvesting clone of a customer portal. Short-lived, frequently rotated.',
    detections: { malicious: 9, suspicious: 2, harmless: 56, undetected: 3 },
    communityReputation: -22,
    reports: 33,
    lastSeenDaysAgo: 4,
    firstSeenDaysAgo: 45,
    network: NET.phish,
    abuse: { score: 81, reports: 26, usageType: 'Data Center/Web Hosting/Transit', distinctUsers: 17 },
    pulses: [
      {
        name: 'Operation Paper Lantern (fictional)',
        adversary: 'Nightfall Jackal (fictional)',
        malware: ['Paper Lantern Kit (fictional)'],
        tags: ['phishing', 'credential-harvesting', 'spearphishing'],
        daysAgo: 4,
      },
    ],
    urlhaus: null,
    greynoise: { classification: 'unknown', noise: false, name: '' },
    shodan: { ports: [80, 443], tags: ['phishing'], hostnames: ['login-portal-lantern.example.com'], city: 'Sofia', country: 'Bulgaria' },
    related: {
      domains: [DEMO_INFRA.phishDomain, DEMO_INFRA.redirectDomain],
      urls: [DEMO_INFRA.phishUrl],
      hashes: [],
      ipAddresses: [],
      emails: [DEMO_INFRA.mail],
    },
    actors: ['DEMO-TA-001'],
    malware: ['DEMO-MAL-004'],
    campaigns: ['DEMO-CAMP-001'],
    behaviours: [DEMO_BEHAVIOURS.phishing, DEMO_BEHAVIOURS.credentialHarvesting],
    categories: ['phishing', 'credential-harvesting', 'spearphishing'],
    analystNote:
      'Phishing infrastructure: the defensive priority is mail and DNS blocking plus credential-reset for anyone who submitted data.',
  },

  // ------------------------------------------------------------------- IPv6
  {
    value: DEMO_INFRA.docIpv6,
    type: 'ipv6',
    title: 'Documentation IPv6 address (no intelligence)',
    summary:
      'RFC 3849 documentation prefix. Demonstrates the "no intelligence available" path so the UI never shows an empty card.',
    detections: { malicious: 0, suspicious: 0, harmless: 68, undetected: 2 },
    communityReputation: 0,
    reports: 0,
    lastSeenDaysAgo: 30,
    firstSeenDaysAgo: 30,
    network: NET.docv6,
    abuse: null,
    pulses: [],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [] },
    actors: [],
    malware: [],
    campaigns: [],
    behaviours: [],
    categories: ['reserved-documentation-prefix'],
    analystNote: 'Reserved address space: no public feed can hold intelligence about it by design.',
  },

  // ---------------------------------------------------------- C2 domain (HIGH)
  {
    value: DEMO_INFRA.c2Domain,
    type: 'domain',
    title: 'C2 domain (fictional)',
    summary: 'Domain fronting-style C2 hostname. High subdomain entropy and a very young registration age in the demo dataset.',
    detections: { malicious: 11, suspicious: 4, harmless: 52, undetected: 3 },
    communityReputation: -25,
    reports: 41,
    lastSeenDaysAgo: 1,
    firstSeenDaysAgo: 190,
    network: NET.c2,
    abuse: null,
    pulses: [
      {
        name: 'Operation Paper Lantern (fictional)',
        adversary: 'Nightfall Jackal (fictional)',
        malware: ['Nightfall RAT (fictional)'],
        tags: ['c2', 'command-and-control', 'beacon'],
        daysAgo: 2,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [],
      urls: [DEMO_INFRA.c2Url],
      hashes: [DEMO_HASHES.nightfallRAT],
      ipAddresses: [DEMO_INFRA.c2Ip, DEMO_INFRA.c2Ip2],
      emails: [],
    },
    actors: ['DEMO-TA-001'],
    malware: ['DEMO-MAL-001'],
    campaigns: ['DEMO-CAMP-001'],
    behaviours: [DEMO_BEHAVIOURS.c2, DEMO_BEHAVIOURS.dga],
    categories: ['c2', 'command-and-control', 'beacon', 'newly-registered'],
    analystNote: 'Domain-based C2 survives blocklisting of the IP only for hours - sinkholing and DNS blocking must happen together.',
  },

  // -------------------------------------------------------- phishing domain
  {
    value: DEMO_INFRA.phishDomain,
    type: 'domain',
    title: 'Credential harvesting domain (fictional)',
    summary: 'Hosts a cloned login page delivered through spearphishing emails.',
    detections: { malicious: 7, suspicious: 5, harmless: 55, undetected: 3 },
    communityReputation: -14,
    reports: 29,
    lastSeenDaysAgo: 3,
    firstSeenDaysAgo: 44,
    network: NET.phish,
    abuse: null,
    pulses: [
      {
        name: 'Operation Paper Lantern (fictional)',
        adversary: 'Nightfall Jackal (fictional)',
        malware: ['Paper Lantern Kit (fictional)'],
        tags: ['phishing', 'credential-harvesting'],
        daysAgo: 3,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [DEMO_INFRA.redirectDomain],
      urls: [DEMO_INFRA.phishUrl],
      hashes: [],
      ipAddresses: [DEMO_INFRA.phishIp],
      emails: [DEMO_INFRA.mail],
    },
    actors: ['DEMO-TA-001'],
    malware: ['DEMO-MAL-004'],
    campaigns: ['DEMO-CAMP-001'],
    behaviours: [DEMO_BEHAVIOURS.phishing, DEMO_BEHAVIOURS.credentialHarvesting, DEMO_BEHAVIOURS.fastFlux],
    categories: ['phishing', 'credential-harvesting', 'spearphishing', 'fast-flux-like'],
    analystNote: 'Three behaviours co-occur: phishing, credential harvesting and fast-flux-like hosting.',
  },

  // ------------------------------------------------------------- loader domain
  {
    value: DEMO_INFRA.loaderDomain,
    type: 'domain',
    title: 'Fake update domain (fictional)',
    summary: 'Masquerades as a software update host; serves the first-stage loader.',
    detections: { malicious: 5, suspicious: 3, harmless: 60, undetected: 2 },
    communityReputation: -6,
    reports: 15,
    lastSeenDaysAgo: 5,
    firstSeenDaysAgo: 80,
    network: NET.loader,
    abuse: null,
    pulses: [
      {
        name: 'Operation Glass Kettle (fictional)',
        adversary: 'Silent Meridian (fictional)',
        malware: ['Wraithdrop Loader (fictional)'],
        tags: ['malware', 'downloader', 'fake-update'],
        daysAgo: 9,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [],
      urls: [DEMO_INFRA.payloadUrl],
      hashes: [DEMO_HASHES.wraithdropLoader],
      ipAddresses: [DEMO_INFRA.loaderIp],
      emails: [],
    },
    actors: ['DEMO-TA-002'],
    malware: ['DEMO-MAL-003'],
    campaigns: ['DEMO-CAMP-002'],
    behaviours: [DEMO_BEHAVIOURS.malwareDelivery],
    categories: ['malware', 'downloader', 'fake-update'],
    analystNote: 'Typical commodity pattern: one loader, many downstream victims, short domain lifetime.',
  },

  // ------------------------------------------------------------------ payloads
  {
    value: DEMO_INFRA.payloadUrl,
    type: 'url',
    title: 'Loader download URL (fictional)',
    summary: 'Direct link to the first-stage loader binary. Listed on a malware distribution feed.',
    detections: { malicious: 16, suspicious: 2, harmless: 48, undetected: 4 },
    communityReputation: -41,
    reports: 52,
    lastSeenDaysAgo: 2,
    firstSeenDaysAgo: 60,
    network: NET.loader,
    abuse: null,
    pulses: [
      {
        name: 'Operation Glass Kettle (fictional)',
        adversary: 'Silent Meridian (fictional)',
        malware: ['Wraithdrop Loader (fictional)'],
        tags: ['malware', 'downloader', 'payload'],
        daysAgo: 2,
      },
    ],
    urlhaus: {
      threat: 'wraithdrop',
      tags: ['downloader', 'payload'],
      urls: [DEMO_INFRA.payloadUrl],
      ip: DEMO_INFRA.loaderIp,
      status: 'online',
    },
    greynoise: null,
    shodan: null,
    related: {
      domains: [DEMO_INFRA.loaderDomain],
      urls: [],
      hashes: [DEMO_HASHES.wraithdropLoader],
      ipAddresses: [DEMO_INFRA.loaderIp],
      emails: [],
    },
    actors: ['DEMO-TA-002'],
    malware: ['DEMO-MAL-003'],
    campaigns: ['DEMO-CAMP-002'],
    behaviours: [DEMO_BEHAVIOURS.malwareDelivery, DEMO_BEHAVIOURS.payloadOnline],
    categories: ['malware', 'downloader', 'payload', 'trojan'],
    analystNote: 'A download URL is high-confidence evidence: it is not a proxy for a host, it is the payload itself.',
  },

  {
    value: DEMO_INFRA.c2Url,
    type: 'url',
    title: 'C2 gate URL (fictional)',
    summary: 'Tasking endpoint contacted by the implant; uses a benign-looking query string to blend in.',
    detections: { malicious: 9, suspicious: 4, harmless: 55, undetected: 2 },
    communityReputation: -19,
    reports: 24,
    lastSeenDaysAgo: 1,
    firstSeenDaysAgo: 150,
    network: NET.c2,
    abuse: null,
    pulses: [
      {
        name: 'Operation Paper Lantern (fictional)',
        adversary: 'Nightfall Jackal (fictional)',
        malware: ['Nightfall RAT (fictional)'],
        tags: ['c2', 'beacon', 'command-and-control'],
        daysAgo: 1,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [DEMO_INFRA.c2Domain],
      urls: [],
      hashes: [DEMO_HASHES.nightfallRAT],
      ipAddresses: [DEMO_INFRA.c2Ip],
      emails: [],
    },
    actors: ['DEMO-TA-001'],
    malware: ['DEMO-MAL-001'],
    campaigns: ['DEMO-CAMP-001'],
    behaviours: [DEMO_BEHAVIOURS.c2, DEMO_BEHAVIOURS.c2OverHttps],
    categories: ['c2', 'command-and-control', 'beacon'],
    analystNote: 'Beacon URL: hunting for this exact path in proxy logs is high-signal, low-volume.',
  },

  {
    value: DEMO_INFRA.phishUrl,
    type: 'url',
    title: 'Phishing landing URL (fictional)',
    summary: 'Landing URL of a credential-harvesting page, delivered by spearphishing email.',
    detections: { malicious: 6, suspicious: 6, harmless: 56, undetected: 2 },
    communityReputation: -11,
    reports: 21,
    lastSeenDaysAgo: 3,
    firstSeenDaysAgo: 40,
    network: NET.phish,
    abuse: null,
    pulses: [
      {
        name: 'Operation Paper Lantern (fictional)',
        adversary: 'Nightfall Jackal (fictional)',
        malware: ['Paper Lantern Kit (fictional)'],
        tags: ['phishing', 'credential-harvesting'],
        daysAgo: 3,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [DEMO_INFRA.phishDomain, DEMO_INFRA.redirectDomain],
      urls: [],
      hashes: [],
      ipAddresses: [DEMO_INFRA.phishIp],
      emails: [DEMO_INFRA.mail],
    },
    actors: ['DEMO-TA-001'],
    malware: ['DEMO-MAL-004'],
    campaigns: ['DEMO-CAMP-001'],
    behaviours: [DEMO_BEHAVIOURS.phishing, DEMO_BEHAVIOURS.credentialHarvesting],
    categories: ['phishing', 'credential-harvesting'],
    analystNote: 'Contains a session token in the query string - useful for retro-hunting mail and proxy logs.',
  },

  // -------------------------------------------------------------------- hashes
  {
    value: DEMO_HASHES.nightfallRAT,
    type: 'sha256',
    title: 'Nightfall RAT implant (fictional)',
    summary: 'Main implant binary. Attributed to a fictional actor through demo pulses.',
    detections: { malicious: 21, suspicious: 1, harmless: 46, undetected: 2 },
    communityReputation: -55,
    reports: 78,
    lastSeenDaysAgo: 3,
    firstSeenDaysAgo: 205,
    network: null,
    abuse: null,
    pulses: [
      {
        name: 'Operation Paper Lantern (fictional)',
        adversary: 'Nightfall Jackal (fictional)',
        malware: ['Nightfall RAT (fictional)'],
        tags: ['rat', 'c2', 'nightfall', 'implant'],
        daysAgo: 3,
      },
      {
        name: 'Vendor impersonation cluster (fictional)',
        adversary: 'Nightfall Jackal (fictional)',
        malware: ['Nightfall RAT (fictional)'],
        tags: ['implant', 'supply-chain'],
        daysAgo: 55,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [DEMO_INFRA.c2Domain],
      urls: [DEMO_INFRA.c2Url],
      hashes: [],
      ipAddresses: [DEMO_INFRA.c2Ip],
      emails: [],
    },
    actors: ['DEMO-TA-001'],
    malware: ['DEMO-MAL-001'],
    campaigns: ['DEMO-CAMP-001'],
    behaviours: [DEMO_BEHAVIOURS.c2, DEMO_BEHAVIOURS.c2OverHttps, DEMO_BEHAVIOURS.malwareDelivery],
    categories: ['rat', 'c2', 'implant', 'trojan'],
    analystNote: 'Actor attribution for a file hash is much stronger than for an IP: the same file across victims is the pivot.',
  },

  {
    value: DEMO_HASHES.wraithdropLoader,
    type: 'sha256',
    title: 'Wraithdrop first-stage loader (fictional)',
    summary: 'Downloader binary distributed via malvertising and fake updates.',
    detections: { malicious: 12, suspicious: 2, harmless: 54, undetected: 2 },
    communityReputation: -28,
    reports: 39,
    lastSeenDaysAgo: 4,
    firstSeenDaysAgo: 95,
    network: null,
    abuse: null,
    pulses: [
      {
        name: 'Operation Glass Kettle (fictional)',
        adversary: 'Silent Meridian (fictional)',
        malware: ['Wraithdrop Loader (fictional)'],
        tags: ['downloader', 'loader', 'malvertising'],
        daysAgo: 4,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [DEMO_INFRA.loaderDomain],
      urls: [DEMO_INFRA.payloadUrl],
      hashes: [],
      ipAddresses: [DEMO_INFRA.loaderIp],
      emails: [],
    },
    actors: ['DEMO-TA-002'],
    malware: ['DEMO-MAL-003'],
    campaigns: ['DEMO-CAMP-002'],
    behaviours: [DEMO_BEHAVIOURS.malwareDelivery],
    categories: ['downloader', 'loader', 'malware'],
    analystNote: 'Loader families are the highest-value blocking target: they are specific and rarely used by benign software.',
  },

  {
    value: DEMO_HASHES.sablefishStealer,
    type: 'md5',
    title: 'Sablefish stealer dropper (fictional)',
    summary: 'MD5-hashed stealer component. Fewer engine hits than the loader, and older sightings.',
    detections: { malicious: 5, suspicious: 1, harmless: 62, undetected: 2 },
    communityReputation: -4,
    reports: 12,
    lastSeenDaysAgo: 65,
    firstSeenDaysAgo: 140,
    network: null,
    abuse: null,
    pulses: [
      {
        name: 'Operation Glass Kettle (fictional)',
        adversary: 'Silent Meridian (fictional)',
        malware: ['Sablefish Stealer (fictional)'],
        tags: ['infostealer', 'credential-theft'],
        daysAgo: 65,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [DEMO_INFRA.loaderDomain],
      urls: [],
      hashes: [],
      ipAddresses: [],
      emails: [],
    },
    actors: ['DEMO-TA-002'],
    malware: ['DEMO-MAL-002'],
    campaigns: ['DEMO-CAMP-002'],
    behaviours: [],
    categories: ['infostealer', 'credential-theft'],
    analystNote:
      'Engine consensus is low and the sighting is old: this is a MEDIUM, not a CRITICAL, indicator - the score is meant to be honest about that.',
  },

  {
    value: DEMO_HASHES.nightfallScript,
    type: 'sha256',
    title: 'Operator PowerShell one-liner (fictional)',
    summary: 'Hash of a PowerShell script fragment used for post-exploitation. Scripts are high-fidelity behavioural evidence.',
    detections: { malicious: 3, suspicious: 2, harmless: 60, undetected: 5 },
    communityReputation: -2,
    reports: 8,
    lastSeenDaysAgo: 12,
    firstSeenDaysAgo: 30,
    network: null,
    abuse: null,
    pulses: [
      {
        name: 'Operation Paper Lantern (fictional)',
        adversary: 'Nightfall Jackal (fictional)',
        malware: ['Nightfall RAT (fictional)'],
        tags: ['powershell', 'script', 'execution'],
        daysAgo: 12,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [],
      urls: [],
      hashes: [],
      ipAddresses: [DEMO_INFRA.c2Ip],
      emails: [],
    },
    actors: ['DEMO-TA-001'],
    malware: ['DEMO-MAL-001'],
    campaigns: ['DEMO-CAMP-001'],
    behaviours: [],
    categories: ['script', 'powershell', 'execution'],
    analystNote: 'Script-based indicators give ATT&CK mapping (T1059.001) that IP indicators cannot support.',
  },

  {
    value: DEMO_HASHES.benignEditor,
    type: 'sha256',
    title: 'Benign control sample (fictional signed editor)',
    summary: 'Clean control indicator used to demonstrate the CLEAN verdict and zero-point offset path.',
    detections: { malicious: 0, suspicious: 0, harmless: 68, undetected: 2 },
    communityReputation: 4,
    reports: 0,
    lastSeenDaysAgo: 20,
    firstSeenDaysAgo: 300,
    network: null,
    abuse: null,
    pulses: [],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [] },
    actors: [],
    malware: [],
    campaigns: [],
    behaviours: [],
    categories: ['clean-control'],
    analystNote: 'A CLEAN result must still be evidenced: zero malicious engines across 70 is the reason for the score.',
  },

  // -------------------------------------------------------------------- email
  {
    value: DEMO_INFRA.mail,
    type: 'email',
    title: 'Sender address used in spearphishing (fictional)',
    summary: 'Observed as the envelope sender of Operation Paper Lantern spearphishing messages.',
    detections: { malicious: 4, suspicious: 3, harmless: 55, undetected: 8 },
    communityReputation: -12,
    reports: 16,
    lastSeenDaysAgo: 3,
    firstSeenDaysAgo: 38,
    network: null,
    abuse: null,
    pulses: [
      {
        name: 'Operation Paper Lantern (fictional)',
        adversary: 'Nightfall Jackal (fictional)',
        malware: ['Paper Lantern Kit (fictional)'],
        tags: ['phishing', 'spearphishing', 'email'],
        daysAgo: 3,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [DEMO_INFRA.phishDomain, DEMO_INFRA.redirectDomain],
      urls: [DEMO_INFRA.phishUrl],
      hashes: [],
      ipAddresses: [DEMO_INFRA.phishIp],
      emails: [DEMO_INFRA.mail],
    },
    actors: ['DEMO-TA-001'],
    malware: ['DEMO-MAL-004'],
    campaigns: ['DEMO-CAMP-001'],
    behaviours: [DEMO_BEHAVIOURS.phishing],
    categories: ['phishing', 'spearphishing', 'sender-address'],
    analystNote: 'Sender addresses are volatile (mailboxes are disposable) - block, but hunt on the link/domain too.',
  },

  // ------------------------------------------------------------------ benign
  {
    value: DEMO_INFRA.benignResolver,
    type: 'ipv4',
    title: 'Public DNS resolver (benign control)',
    summary:
      'Correctly identified as widely used public resolver infrastructure with a clean reputation - demonstrates the CLEAN verdict and the trusted-infrastructure offset.',
    detections: { malicious: 0, suspicious: 0, harmless: 70, undetected: 0 },
    communityReputation: 12,
    reports: 0,
    lastSeenDaysAgo: 0,
    firstSeenDaysAgo: 900,
    network: NET.resolver,
    abuse: { score: 0, reports: 0, usageType: 'Content Delivery Network', distinctUsers: 0 },
    pulses: [],
    urlhaus: null,
    greynoise: { classification: 'benign', noise: true, name: 'Google Public DNS' },
    shodan: { ports: [53, 443], tags: ['dns'], hostnames: ['dns.google'], city: 'Mountain View', country: 'United States' },
    related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [] },
    actors: [],
    malware: [],
    campaigns: [],
    behaviours: [DEMO_BEHAVIOURS.cleanResolver],
    categories: ['public-dns-resolver', 'benign-infrastructure'],
    analystNote:
      'Important analyst lesson: a high report count is not the same as maliciousness. This address is ubiquitous, so the risk engine applies a documented trusted-infrastructure offset.',
  },

  {
    value: DEMO_INFRA.benignResolver2,
    type: 'ipv4',
    title: 'Public DNS resolver (benign control)',
    summary: 'Second clean control indicator, different ASN, to show the offset is infrastructure-based rather than hard-coded per address.',
    detections: { malicious: 0, suspicious: 0, harmless: 69, undetected: 1 },
    communityReputation: 8,
    reports: 0,
    lastSeenDaysAgo: 0,
    firstSeenDaysAgo: 1100,
    network: NET.resolver2,
    abuse: { score: 0, reports: 0, usageType: 'Content Delivery Network', distinctUsers: 0 },
    pulses: [],
    urlhaus: null,
    greynoise: { classification: 'benign', noise: true, name: 'Cloudflare Public DNS' },
    shodan: { ports: [53, 443], tags: ['dns'], hostnames: ['one.one.one.one'], city: 'Sydney', country: 'Australia' },
    related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [] },
    actors: [],
    malware: [],
    campaigns: [],
    behaviours: [DEMO_BEHAVIOURS.cleanResolver],
    categories: ['public-dns-resolver', 'benign-infrastructure'],
    analystNote: 'Same outcome as the other resolver: the offset keys off the resolved network role, not a hard-coded address.',
  },

  {
    value: DEMO_INFRA.benignQuad9,
    type: 'ipv4',
    title: 'Public DNS resolver, low-reputation ASN (benign control)',
    summary:
      'Resolver with only two supporting sources and an unknown community reputation - still clean, but with a lower confidence score, which is the honest outcome.',
    detections: { malicious: 0, suspicious: 0, harmless: 64, undetected: 2 },
    communityReputation: null,
    reports: 0,
    lastSeenDaysAgo: 0,
    firstSeenDaysAgo: 700,
    network: NET.resolver2,
    abuse: null,
    pulses: [],
    urlhaus: null,
    greynoise: { classification: 'educational', noise: true, name: 'Quad9 Public DNS' },
    shodan: null,
    related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [] },
    actors: [],
    malware: [],
    campaigns: [],
    behaviours: [DEMO_BEHAVIOURS.cleanResolver],
    categories: ['public-dns-resolver', 'benign-infrastructure'],
    analystNote:
      'Shows how confidence differs from risk: the risk is CLEAN, but with fewer corroborating sources the confidence score is lower. These are different questions.',
  },

  // ------------------------------------------- alternate hash of the stealer
  {
    value: DEMO_HASHES.sablefishStealerSha1,
    type: 'sha1',
    title: 'Sablefish stealer component, SHA-1 form (fictional)',
    summary:
      'The same stealer component identified by SHA-1 rather than MD5. Demonstrates why a blocklist should cover every hash algorithm an EDR can report.',
    detections: { malicious: 4, suspicious: 1, harmless: 61, undetected: 3 },
    communityReputation: -3,
    reports: 9,
    lastSeenDaysAgo: 70,
    firstSeenDaysAgo: 145,
    network: null,
    abuse: null,
    pulses: [
      {
        name: 'Operation Glass Kettle (fictional)',
        adversary: 'Silent Meridian (fictional)',
        malware: ['Sablefish Stealer (fictional)'],
        tags: ['infostealer', 'credential-theft'],
        daysAgo: 70,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [DEMO_INFRA.loaderDomain],
      urls: [],
      hashes: [DEMO_HASHES.sablefishStealer],
      ipAddresses: [],
      emails: [],
    },
    actors: ['DEMO-TA-002'],
    malware: ['DEMO-MAL-002'],
    campaigns: ['DEMO-CAMP-002'],
    behaviours: [],
    categories: ['infostealer', 'credential-theft'],
    analystNote: 'Cross-algorithm link: the same artefact in MD5 and SHA-1 lets an analyst deduplicate sightings.',
  },

  // ------------------------------------------------- telemetry script URL
  {
    value: DEMO_INFRA.updateUrl,
    type: 'url',
    title: 'Fake telemetry library (fictional)',
    summary:
      'Retrieved from a sandbox report during a previous engagement. Low-volume script hosting with a deceptive path - the kind of indicator a human must triage rather than a feed to auto-block.',
    detections: { malicious: 2, suspicious: 2, harmless: 64, undetected: 2 },
    communityReputation: 0,
    reports: 3,
    lastSeenDaysAgo: 5,
    firstSeenDaysAgo: 6,
    network: NET.loader,
    abuse: null,
    pulses: [
      {
        name: 'Operation Glass Kettle (fictional)',
        adversary: 'Silent Meridian (fictional)',
        malware: ['Sablefish Stealer (fictional)'],
        tags: ['script', 'telemetry-abuse'],
        daysAgo: 5,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [],
      urls: [],
      hashes: [DEMO_HASHES.sablefishStealerSha1],
      ipAddresses: [DEMO_INFRA.loaderIp],
      emails: [],
    },
    actors: ['DEMO-TA-002'],
    malware: ['DEMO-MAL-002'],
    campaigns: ['DEMO-CAMP-002'],
    behaviours: ['script-hosting'],
    categories: ['script', 'telemetry-abuse'],
    analystNote:
      'Deliberately ambiguous: two engines flag it, which is not consensus. Left unclassified pending human triage - the platform should not turn weak evidence into an automatic verdict.',
  },

  // ------------------------------------------------------ reserved controls
  // ======================================================================
  // AMBIGUOUS / SUSPICIOUS BAND
  //
  // Real analyst queues are full of "probably bad, not proven" indicators.
  // These profiles exist so the risk engine's granularity is demonstrable and
  // so the dashboard shows all five risk bands. They are the most interesting
  // cases for a viva: weak evidence must NOT produce a critical verdict.
  // ======================================================================

  // IDN / punycode lookalike - drives the "infrastructure anomaly" factor.
  {
    value: 'xn--pple-43d.example.com',
    type: 'domain',
    title: 'IDN lookalike domain (suspicious, unproven)',
    summary:
      'A punycode hostname that visually mimics a well-known brand. Two sources flag it as suspicious, but no source has confirmed it as malicious, so the score stays in the LOW band.',
    detections: { malicious: 0, suspicious: 3, harmless: 63, undetected: 1 },
    communityReputation: -2,
    reports: 4,
    lastSeenDaysAgo: 3,
    firstSeenDaysAgo: 6,
    network: NET.phish,
    abuse: null,
    pulses: [
      {
        name: 'Brand impersonation reports (fictional)',
        adversary: 'Copper Kite (fictional)',
        malware: [],
        tags: ['phishing', 'impersonation', 'lookalike-domain'],
        daysAgo: 3,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [],
      urls: [],
      hashes: [],
      ipAddresses: [DEMO_INFRA.phishIp],
      emails: [],
    },
    actors: ['DEMO-TA-003'],
    malware: [],
    campaigns: [],
    behaviours: [DEMO_BEHAVIOURS.phishing],
    categories: ['phishing', 'impersonation', 'lookalike-domain', 'newly-registered'],
    analystNote:
      'Two suspicious verdicts plus an IDN hostname is a pattern worth watching, but it is not proof. A critical verdict here would be an over-call; the honest output is LOW with elevated monitoring.',
  },

  // DGA-style high-entropy label - drives the entropy signal.
  {
    value: 'k3yv9q2zx7m4p1n8b6w3.example.net',
    type: 'domain',
    title: 'High-entropy hostname (algorithmically generated pattern)',
    summary:
      'A 20-character random-looking label. Two sources are suspicious; the label entropy is consistent with a domain generation algorithm but is not conclusive on its own.',
    detections: { malicious: 0, suspicious: 2, harmless: 64, undetected: 1 },
    communityReputation: 0,
    reports: 2,
    lastSeenDaysAgo: 9,
    firstSeenDaysAgo: 11,
    network: NET.loader,
    abuse: null,
    pulses: [
      {
        name: 'DGA pattern observation (fictional)',
        adversary: 'Silent Meridian (fictional)',
        malware: ['Wraithdrop Loader (fictional)'],
        tags: ['dga', 'dynamic-resolution'],
        daysAgo: 9,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [DEMO_INFRA.loaderDomain],
      urls: [],
      hashes: [],
      ipAddresses: [DEMO_INFRA.loaderIp],
      emails: [],
    },
    actors: ['DEMO-TA-002'],
    malware: ['DEMO-MAL-003'],
    campaigns: [],
    behaviours: [DEMO_BEHAVIOURS.dga],
    categories: ['dga', 'dynamic-resolution', 'newly-registered'],
    analystNote:
      'Entropy is a weak signal on its own - plenty of legitimate CDNs use long random labels. It is reported as a structural indicator, not as reputation.',
  },

  // Subdomain of a malicious campaign's namespace - deep chain signal.
  {
    value: 'a.b.c.secure.login-portal-lantern.example.com',
    type: 'domain',
    title: 'Deeply nested subdomain of a phishing namespace',
    summary:
      'A four-level subdomain chain under a namespace already associated with phishing. The namespace is known bad, but this specific host has almost no reporting of its own.',
    detections: { malicious: 0, suspicious: 2, harmless: 60, undetected: 1 },
    communityReputation: -1,
    reports: 3,
    lastSeenDaysAgo: 2,
    firstSeenDaysAgo: 3,
    network: NET.phish,
    abuse: null,
    pulses: [
      {
        name: 'Operation Paper Lantern (fictional)',
        adversary: 'Nightfall Jackal (fictional)',
        malware: [],
        tags: ['phishing', 'credential-harvesting'],
        daysAgo: 2,
      },
    ],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: {
      domains: [DEMO_INFRA.phishDomain],
      urls: [],
      hashes: [],
      ipAddresses: [DEMO_INFRA.phishIp],
      emails: [DEMO_INFRA.mail],
    },
    actors: ['DEMO-TA-001'],
    malware: [],
    campaigns: ['DEMO-CAMP-001'],
    behaviours: [DEMO_BEHAVIOURS.phishing, DEMO_BEHAVIOURS.credentialHarvesting],
    categories: ['phishing', 'credential-harvesting'],
    analystNote:
      'Infrastructure inheritance: a child host of a known-bad namespace is more suspicious than an unrelated domain, but the score reflects only the evidence attached to THIS host.',
  },

  // Hash with a single engine hit - the "do not over-call" case.
  {
    value: 'b81f4c2d90a7e63517cd82fb5e0a49173d6c2b8e5f04a91c37d2e6b580af31c7',
    type: 'sha256',
    title: 'Poorly detected sample (single engine hit)',
    summary:
      'One engine flags the sample and one marks it suspicious. This is exactly the case where an automated platform must not declare a verdict, because a single signature is frequently a false positive.',
    detections: { malicious: 1, suspicious: 1, harmless: 64, undetected: 4 },
    communityReputation: 0,
    reports: 2,
    lastSeenDaysAgo: 22,
    firstSeenDaysAgo: 24,
    network: null,
    abuse: null,
    pulses: [],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [] },
    actors: [],
    malware: [],
    campaigns: [],
    behaviours: [],
    categories: ['low-confidence-detection'],
    analystNote:
      'A textbook case for the multi-engine threshold: one engine cannot carry a critical verdict. Submitted to the internal sandbox for a definitive answer.',
  },

  // Hosting provider with light abuse reporting - LOW.
  {
    value: '203.0.113.140',
    type: 'ipv4',
    title: 'Shared hosting address with minor abuse history',
    summary:
      'A bulk-hosting address with a handful of abuse reports and no malicious detections. Common false-positive source: other tenants on the same address misbehaving.',
    detections: { malicious: 0, suspicious: 0, harmless: 68, undetected: 1 },
    communityReputation: -1,
    reports: 5,
    lastSeenDaysAgo: 11,
    firstSeenDaysAgo: 400,
    network: NET.c2,
    abuse: { score: 18, reports: 5, usageType: 'Data Center/Web Hosting/Transit', distinctUsers: 4 },
    pulses: [],
    urlhaus: null,
    greynoise: { classification: 'unknown', noise: false, name: '' },
    shodan: { ports: [80, 443, 22], tags: ['cloud'], hostnames: [], city: 'Amsterdam', country: 'Netherlands' },
    related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [] },
    actors: [],
    malware: [],
    campaigns: [],
    behaviours: ['hosted-infrastructure'],
    categories: ['shared-hosting', 'low-volume-abuse-reports'],
    analystNote:
      'Shared hosting is the classic false-positive generator. The platform scores it LOW and explicitly recommends monitoring rather than blocking, because blocking a shared address can deny service to legitimate tenants.',
  },

  // ======================================================================
  // RESERVED / BENIGN CONTROLS
  // ======================================================================
  {
    value: DEMO_INFRA.cleanDomain,
    type: 'domain',
    title: 'Reserved documentation domain (benign control)',
    summary:
      'RFC 2606 reserved namespace. No public intelligence feed can hold data about it, so the platform reports the absence of data instead of inventing it.',
    detections: { malicious: 0, suspicious: 0, harmless: 66, undetected: 1 },
    communityReputation: 0,
    reports: 0,
    lastSeenDaysAgo: 0,
    firstSeenDaysAgo: 900,
    network: NET.resolver,
    abuse: null,
    pulses: [],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [] },
    actors: [],
    malware: [],
    campaigns: [],
    behaviours: [],
    categories: ['reserved-namespace', 'benign-infrastructure'],
    analystNote: 'Reserved namespace control case: the correct output is "no intelligence", not an empty card.',
  },
  {
    value: DEMO_INFRA.cleanUrl,
    type: 'url',
    title: 'Reserved documentation URL (benign control)',
    summary: 'Clean control for URL indicators, mirroring the domain control case.',
    detections: { malicious: 0, suspicious: 0, harmless: 67, undetected: 1 },
    communityReputation: 0,
    reports: 0,
    lastSeenDaysAgo: 0,
    firstSeenDaysAgo: 900,
    network: NET.resolver,
    abuse: null,
    pulses: [],
    urlhaus: null,
    greynoise: null,
    shodan: null,
    related: { domains: [DEMO_INFRA.cleanDomain], urls: [], hashes: [], ipAddresses: [], emails: [] },
    actors: [],
    malware: [],
    campaigns: [],
    behaviours: [],
    categories: ['reserved-namespace', 'benign-infrastructure'],
    analystNote: 'Clean control: zero malicious engines is the evidence for a zero-point score.',
  },
];

/** Fast lookup by canonical value. */
export const DEMO_PROFILE_BY_VALUE = new Map<string, DemoProfile>(
  DEMO_PROFILES.map((p) => [p.value.toLowerCase(), p]),
);

export const demoNowIso = (daysAgo: number): string =>
  new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000).toISOString();

/** Compact catalogue surfaced on the /investigate page for the demo walkthrough. */
export interface DemoCatalogEntry {
  value: string;
  type: IocType;
  title: string;
  summary: string;
  expectedLevel: string;
  expectedScoreHint: string;
}

export const DEMO_CATALOG: DemoCatalogEntry[] = [
  {
    value: DEMO_INFRA.c2Ip,
    type: 'ipv4',
    title: 'Command-and-control server',
    summary: 'Four-source corroboration, abuse score 96, listed on a distribution feed.',
    expectedLevel: 'CRITICAL',
    expectedScoreHint: 'Expected: CRITICAL (80-100)',
  },
  {
    value: DEMO_INFRA.phishDomain,
    type: 'domain',
    title: 'Credential harvesting domain',
    summary: 'Phishing + credential harvesting + fast-flux-like hosting behaviours.',
    expectedLevel: 'HIGH',
    expectedScoreHint: 'Expected: HIGH (60-79)',
  },
  {
    value: DEMO_INFRA.payloadUrl,
    type: 'url',
    title: 'Loader download URL',
    summary: 'Direct payload link listed on a malware distribution feed.',
    expectedLevel: 'CRITICAL',
    expectedScoreHint: 'Expected: CRITICAL (80-100)',
  },
  {
    value: DEMO_HASHES.nightfallRAT,
    type: 'sha256',
    title: 'Nightfall RAT implant',
    summary: 'Actor-attributed implant hash with strong engine consensus.',
    expectedLevel: 'CRITICAL',
    expectedScoreHint: 'Expected: CRITICAL (80-100)',
  },
  {
    value: DEMO_HASHES.sablefishStealer,
    type: 'md5',
    title: 'Sablefish stealer dropper',
    summary: 'Modest engine consensus and an older last-seen date - deliberately not critical.',
    expectedLevel: 'MEDIUM',
    expectedScoreHint: 'Expected: MEDIUM (40-59)',
  },
  {
    value: DEMO_INFRA.mail,
    type: 'email',
    title: 'Spearphishing sender',
    summary: 'Envelope sender tied to a phishing campaign in demo pulses.',
    expectedLevel: 'MEDIUM',
    expectedScoreHint: 'Expected: MEDIUM (40-59)',
  },
  {
    value: DEMO_INFRA.docIpv6,
    type: 'ipv6',
    title: 'Documentation IPv6 (no intelligence)',
    summary: 'Demonstrates the honest "nothing known" path.',
    expectedLevel: 'CLEAN',
    expectedScoreHint: 'Expected: CLEAN (0-19)',
  },
  {
    value: DEMO_INFRA.benignResolver,
    type: 'ipv4',
    title: 'Public DNS resolver',
    summary: 'Clean verdict plus a documented trusted-infrastructure offset.',
    expectedLevel: 'CLEAN',
    expectedScoreHint: 'Expected: CLEAN (0-19)',
  },
];

/** Pre-computed hashes are exported so the UI can show them as demo samples. */
export const DEMO_SAMPLE_HASHES = DEMO_HASHES;
