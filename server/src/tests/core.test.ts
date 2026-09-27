/**
 * Unit tests for the deterministic core of ThreatLens.
 *
 * Run with:  npm test --workspace server
 *
 * These cover the parts a reviewer is most likely to challenge:
 *   1. IOC type detection / validation
 *   2. risk scoring determinism and the 0-100 clamp
 *   3. the "never fabricate intelligence" and ATT&CK safety gates
 *   4. defensive recommendations are defensive in nature
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { detectIocType, registrableDomain, refang } from '../core/ioc/detect.js';
import { validateIoc, isDocumentationIpv4, shannonEntropy } from '../core/ioc/validate.js';
import { scoreRisk, riskLevelFor, trustedInfrastructureMatch } from '../core/risk/engine.js';
import { aggregateIntelligence } from '../core/aggregate.js';
import { mapTechniques } from '../core/mitre/mapper.js';
import { buildDefensiveActions } from '../core/recommendations/engine.js';
import { buildCorrelationGraph } from '../core/correlation/correlator.js';
import { normalizeIocForTest, emptyVerdict } from './testHelpers.js';
import type { ProviderVerdict } from '../core/types.js';

const riskLevelCases: Array<[number, string]> = [
  [0, 'CLEAN'], [19, 'CLEAN'], [20, 'LOW'], [39, 'LOW'], [40, 'MEDIUM'],
  [59, 'MEDIUM'], [60, 'HIGH'], [79, 'HIGH'], [80, 'CRITICAL'], [100, 'CRITICAL'],
];
for (const [score, level] of riskLevelCases) {
  test(`risk level boundaries: ${score} -> ${level}`, () => {
    assert.equal(riskLevelFor(score), level);
  });
}

test('detects every supported IOC type', () => {
  const cases: Array<[string, string]> = [
    ['203.0.113.50', 'ipv4'],
    ['2001:db8::50', 'ipv6'],
    ['c2-nightfall.example.com', 'domain'],
    ['https://c2-nightfall.example.com/gate.php', 'url'],
    ['d41d8cd98f00b204e9800998ecf8427e', 'md5'],
    ['da39a3ee5e6b4b0d3255bfef95601890afd80709', 'sha1'],
    ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'sha256'],
    ['no-reply@updates-lantern.example.com', 'email'],
  ];
  for (const [value, expected] of cases) {
    assert.equal(detectIocType(value)?.type, expected, `expected ${value} to be ${expected}`);
  }
});

test('rejects out-of-range IPv4 and does not silently treat it as a domain', () => {
  assert.equal(detectIocType('999.1.1.1'), null);
  assert.equal(detectIocType('256.0.0.1'), null);
  assert.equal(validateIoc('192.168.1.256').ok, false);
});

test('rejects a 33-character hex string instead of guessing a hash type', () => {
  assert.equal(detectIocType('a'.repeat(33)), null);
  assert.equal(detectIocType('z'.repeat(64)), null);
});

test('re-fangs defanged indicators', () => {
  assert.equal(refang('hxxp://evil[.]com/a').value, 'http://evil.com/a');
  assert.equal(refang('1[.]2[.]3[.]4').value, '1.2.3.4');
  assert.equal(refang('bad[at]example[.]com').value, 'bad@example.com');
});

test('extracts the registrable domain for common multi-part suffixes', () => {
  assert.equal(registrableDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('cdn.example.com'), 'example.com');
  assert.equal(registrableDomain('example.com'), 'example.com');
});

test('flags documentation ranges without rejecting them', () => {
  assert.equal(isDocumentationIpv4('203.0.113.50'), true);
  assert.equal(isDocumentationIpv4('8.8.8.8'), false);
  const result = validateIoc('203.0.113.50');
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.ok(result.warnings.some((w) => w.code === 'DOCUMENTATION_RANGE'));
  }
});

test('refuses loopback, multicast and link-local-policy IOCs', () => {
  assert.equal(validateIoc('127.0.0.1').ok, false);
  assert.equal(validateIoc('224.0.0.1').ok, false);
  assert.equal(validateIoc('::1').ok, false);
});

test('rejects shell/HTML metacharacters and oversized input', () => {
  assert.equal(validateIoc('example.com; rm -rf /').ok, false);
  assert.equal(validateIoc('a'.repeat(5000)).ok, false);
  assert.equal(validateIoc('<script>alert(1)</script>').ok, false);
});

test('shannon entropy separates random labels from dictionary labels', () => {
  assert.ok(shannonEntropy('k3yv9q2zx7m4p1n8b6w3') > shannonEntropy('loginportal'));
});

const baseVerdict = (over: Partial<ProviderVerdict>): ProviderVerdict => ({
  ...emptyVerdict({ id: 'test', name: 'Test Source' }, 'demo'),
  status: 'ok',
  ...over,
});

test('risk scoring is deterministic: identical input yields identical output', () => {
  const ioc = normalizeIocForTest('203.0.113.50', 'ipv4');
  const verdicts = [
    baseVerdict({
      providerId: 'vt',
      verdict: 'malicious',
      detections: { malicious: 10, suspicious: 2, harmless: 58, unsupported: 0, undetected: 0, total: 70, ratio: 0.1429, lastAnalysisAt: new Date().toISOString() },
      reports: 20,
      lastSeenAt: new Date().toISOString(),
    }),
  ];
  const intel = aggregateIntelligence(ioc, verdicts);
  const signals = {
    nonStandardPort: false, punycode: false, highEntropy: false,
    deepSubdomain: false, newlyRegistered: false, documentationRange: true,
  };
  const first = scoreRisk({ ioc, intel, signals, mode: 'demo' });
  const second = scoreRisk({ ioc, intel, signals, mode: 'demo' });
  assert.equal(first.score, second.score);
  assert.equal(first.level, second.level);
  assert.equal(first.confidenceScore, second.confidenceScore);
  assert.deepEqual(first.factors, second.factors);
});

test('a fully corroborated malicious indicator is clamped to 100 and the raw sum is disclosed', () => {
  const ioc = normalizeIocForTest('203.0.113.50', 'ipv4');
  const verdicts = [
    baseVerdict({
      providerId: 'vt',
      verdict: 'malicious',
      detections: { malicious: 40, suspicious: 4, harmless: 26, unsupported: 0, undetected: 0, total: 70, ratio: 0.5714, lastAnalysisAt: new Date().toISOString() },
      reports: 300,
      lastSeenAt: new Date().toISOString(),
      network: { abuseConfidenceScore: 99, totalReports: 120, country: 'Test' },
      related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [], categories: ['c2'], malware: ['A', 'B', 'C'], actors: ['Actor X'], campaigns: ['Camp Y'], behaviours: ['c2'] },
    }),
  ];
  const intel = aggregateIntelligence(ioc, verdicts);
  const assessment = scoreRisk({
    ioc,
    intel,
    signals: { nonStandardPort: true, punycode: false, highEntropy: false, deepSubdomain: false, newlyRegistered: true, documentationRange: false },
    mode: 'live',
  });
  assert.equal(assessment.score, 100);
  assert.equal(assessment.level, 'CRITICAL');
  assert.ok(assessment.rawScore > 100, 'raw sum should exceed the clamp and be disclosed');
  // Every positive factor must cite evidence and a category.
  for (const f of assessment.factors) {
    assert.ok(f.evidence.length > 0, `factor ${f.id} has no evidence`);
    assert.ok(f.sources.length > 0, `factor ${f.id} cites no source`);
  }
  // Factor arithmetic must reconcile with the disclosed raw sum.
  const sum = assessment.factors.reduce((acc, f) => acc + f.points, 0);
  assert.equal(Math.round(sum), assessment.rawScore);
});

test('trusted public resolvers receive a visible negative offset', () => {
  assert.equal(trustedInfrastructureMatch('8.8.8.8'), 'Google Public DNS (AS15169)');
  assert.equal(trustedInfrastructureMatch('203.0.113.50'), null);
  const ioc = normalizeIocForTest('8.8.8.8', 'ipv4');
  const verdicts = [
    baseVerdict({ providerId: 'vt', verdict: 'clean', detections: { malicious: 0, suspicious: 0, harmless: 70, unsupported: 0, undetected: 0, total: 70, ratio: 0, lastAnalysisAt: null }, reports: 0 }),
  ];
  const intel = aggregateIntelligence(ioc, verdicts);
  const assessment = scoreRisk({ ioc, intel, signals: { nonStandardPort: false, punycode: false, highEntropy: false, deepSubdomain: false, newlyRegistered: false, documentationRange: false }, mode: 'demo' });
  assert.equal(assessment.score, 0);
  assert.equal(assessment.level, 'CLEAN');
  assert.ok(assessment.offsets.some((o) => o.id === 'trusted_infrastructure'));
});

test('confidence drops when sources fail, and never claims certainty', () => {
  const ioc = normalizeIocForTest('example.com', 'domain');
  const good = aggregateIntelligence(ioc, [
    baseVerdict({ providerId: 'a', verdict: 'malicious', detections: { malicious: 5, suspicious: 0, harmless: 65, unsupported: 0, undetected: 0, total: 70, ratio: 0.0714, lastAnalysisAt: new Date().toISOString() } }),
  ]);
  const degraded = aggregateIntelligence(ioc, [
    baseVerdict({ providerId: 'a', verdict: 'malicious', detections: { malicious: 5, suspicious: 0, harmless: 65, unsupported: 0, undetected: 0, total: 70, ratio: 0.0714, lastAnalysisAt: new Date().toISOString() } }),
    baseVerdict({ providerId: 'b', status: 'error', error: { code: 'timeout', message: 'timed out', retryable: true } }),
  ]);
  const signals = { nonStandardPort: false, punycode: false, highEntropy: false, deepSubdomain: false, newlyRegistered: false, documentationRange: false };
  const a = scoreRisk({ ioc, intel: good, signals, mode: 'live' });
  const b = scoreRisk({ ioc, intel: degraded, signals, mode: 'live' });
  assert.ok(b.confidenceScore < a.confidenceScore, 'confidence must fall when a source fails');
  assert.ok(a.confidenceScore <= 97, 'confidence must never claim certainty');
  assert.equal(b.score, a.score, 'a failed source must not change the risk score itself');
});

test('no ATT&CK technique is invented for a clean indicator', () => {
  const ioc = normalizeIocForTest('8.8.8.8', 'ipv4');
  const verdicts = [
    baseVerdict({
      providerId: 'vt',
      verdict: 'clean',
      detections: { malicious: 0, suspicious: 0, harmless: 70, unsupported: 0, undetected: 0, total: 70, ratio: 0, lastAnalysisAt: null },
      related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [], categories: ['public-dns-resolver'], malware: [], actors: [], campaigns: [], behaviours: ['public-dns-resolver'] },
    }),
  ];
  const intel = aggregateIntelligence(ioc, verdicts);
  const techniques = mapTechniques({
    ioc,
    verdicts,
    behaviours: intel.behaviours,
    categories: intel.categories,
    malwareNames: intel.malware,
    actorNames: intel.actors,
    signals: { nonStandardPort: false, punycode: false, highEntropy: false, deepSubdomain: false, newlyRegistered: false, documentationRange: false },
  });
  assert.equal(techniques.length, 0, 'clean infrastructure must not receive ATT&CK mappings');
});

test('ATT&CK mappings only reference techniques in the curated knowledge base and cite a basis', () => {
  const ioc = normalizeIocForTest('https://cdn-update.example.net/stage/x.bin', 'url');
  const verdicts = [
    baseVerdict({
      providerId: 'dist',
      verdict: 'malicious',
      detections: { malicious: 16, suspicious: 2, harmless: 48, unsupported: 0, undetected: 4, total: 70, ratio: 0.2286, lastAnalysisAt: new Date().toISOString() },
      related: { domains: ['update-sablefish.example.net'], urls: [], hashes: [], ipAddresses: [], emails: [], categories: ['malware', 'downloader'], malware: ['Wraithdrop Loader (fictional)'], actors: [], campaigns: [], behaviours: ['malware-distribution'] },
    }),
  ];
  const intel = aggregateIntelligence(ioc, verdicts);
  const techniques = mapTechniques({
    ioc,
    verdicts,
    behaviours: intel.behaviours,
    categories: intel.categories,
    malwareNames: intel.malware,
    actorNames: intel.actors,
    signals: { nonStandardPort: false, punycode: false, highEntropy: false, deepSubdomain: false, newlyRegistered: false, documentationRange: false },
  });
  assert.ok(techniques.length > 0);
  for (const t of techniques) {
    assert.match(t.techniqueId, /^T\d{4}(\.\d{3})?$/);
    assert.ok(t.reference.startsWith('https://attack.mitre.org/techniques/'));
    assert.ok(t.relationship.length > 20, 'each mapping must explain itself');
    assert.ok(['provider-signal', 'behavioural-rule', 'malware-family-intel'].includes(t.mappingBasis));
  }
  assert.ok(techniques.some((t) => t.techniqueId === 'T1105'), 'a payload URL must map to Ingress Tool Transfer');
});

test('provider-published technique ids are honoured as a provider signal', () => {
  const ioc = normalizeIocForTest('203.0.113.50', 'ipv4');
  const verdicts = [
    baseVerdict({
      providerId: 'otx',
      verdict: 'suspicious',
      related: { domains: [], urls: [], hashes: [], ipAddresses: [], emails: [], categories: ['T1059.001'], malware: [], actors: [], campaigns: [], behaviours: [] },
    }),
  ];
  const intel = aggregateIntelligence(ioc, verdicts);
  const techniques = mapTechniques({
    ioc,
    verdicts,
    behaviours: intel.behaviours,
    categories: intel.categories,
    malwareNames: [],
    actorNames: [],
    signals: { nonStandardPort: false, punycode: false, highEntropy: false, deepSubdomain: false, newlyRegistered: false, documentationRange: false },
  });
  const mapped = techniques.find((t) => t.techniqueId === 'T1059.001');
  assert.ok(mapped, 'the provider-published technique must be mapped');
  assert.equal(mapped!.mappingBasis, 'provider-signal');
});

test('correlation graph never connects the subject to itself', () => {
  const ioc = normalizeIocForTest('203.0.113.50', 'ipv4');
  const verdicts = [
    baseVerdict({
      providerId: 'vt',
      verdict: 'malicious',
      detections: { malicious: 5, suspicious: 0, harmless: 65, unsupported: 0, undetected: 0, total: 70, ratio: 0.0714, lastAnalysisAt: new Date().toISOString() },
      related: { domains: ['c2-nightfall.example.com', '203.0.113.50'], urls: [], hashes: ['a'.repeat(64)], ipAddresses: ['203.0.113.51'], emails: [], categories: ['c2'], malware: ['Nightfall RAT (fictional)'], actors: ['Nightfall Jackal (fictional)'], campaigns: ['Op Paper Lantern'], behaviours: ['c2'] },
    }),
  ];
  const intel = aggregateIntelligence(ioc, verdicts);
  const graph = buildCorrelationGraph({ ioc, intel, riskLevel: 'CRITICAL', techniques: [], learnedEdges: [] });
  assert.equal(graph.nodes.filter((n) => n.isSubject).length, 1, 'exactly one subject node');
  for (const e of graph.edges) {
    assert.notEqual(e.source, e.target, 'self loops must be dropped');
    assert.ok(graph.nodes.some((n) => n.id === e.source) && graph.nodes.some((n) => n.id === e.target), 'every edge must reference existing nodes');
    assert.ok(e.description.length > 0, 'every edge must be explained');
  }
});

test('recommendations are defensive and include a hunt query where useful', () => {
  const ioc = normalizeIocForTest('203.0.113.50', 'ipv4');
  const verdicts = [
    baseVerdict({
      providerId: 'vt',
      verdict: 'malicious',
      detections: { malicious: 12, suspicious: 1, harmless: 57, unsupported: 0, undetected: 0, total: 70, ratio: 0.1714, lastAnalysisAt: new Date().toISOString() },
      related: { domains: ['c2-nightfall.example.com'], urls: [], hashes: [], ipAddresses: [], emails: [], categories: ['c2'], malware: ['Nightfall RAT (fictional)'], actors: ['Nightfall Jackal (fictional)'], campaigns: [], behaviours: ['c2'] },
    }),
  ];
  const intel = aggregateIntelligence(ioc, verdicts);
  const actions = buildDefensiveActions({
    iocType: 'ipv4',
    value: '203.0.113.50',
    riskLevel: 'CRITICAL',
    intel,
    relatedDomains: intel.related.domains,
    relatedIps: [],
    relatedHashes: [],
    relatedUrls: [],
    actors: intel.actors,
    malware: intel.malware,
    isDocumentation: false,
  });
  assert.ok(actions.length >= 4);
  assert.ok(actions.some((a) => /block/i.test(a.title)), 'a CRITICAL IP must produce a blocking action');
  assert.ok(actions.some((a) => a.searchQuery?.includes('203.0.113.50')), 'a pasteable hunt query must be produced');
  // Defensive only: no offensive wording may appear.
  const offensive = /\b(exploit|shellcode|payload to|inject into|reverse shell|ransom)\b/i;
  for (const a of actions) {
    assert.equal(offensive.test(`${a.title} ${a.detail}`), false, `offensive language in: ${a.title}`);
  }
  const priorities = actions.map((a) => a.priority);
  assert.deepEqual([...priorities].sort((x, y) => x - y), priorities, 'actions must be ordered by priority');
});

test('documentation ranges produce a no-action recommendation rather than a block', () => {
  const ioc = normalizeIocForTest('203.0.113.140', 'ipv4');
  const verdicts = [baseVerdict({ providerId: 'vt', verdict: 'clean', detections: { malicious: 0, suspicious: 0, harmless: 70, unsupported: 0, undetected: 0, total: 70, ratio: 0, lastAnalysisAt: null } })];
  const intel = aggregateIntelligence(ioc, verdicts);
  const actions = buildDefensiveActions({
    iocType: 'ipv4', value: '203.0.113.140', riskLevel: 'CLEAN', intel,
    relatedDomains: [], relatedIps: [], relatedHashes: [], relatedUrls: [],
    actors: [], malware: [], isDocumentation: true,
  });
  assert.ok(actions.some((a) => /No defensive action required/i.test(a.title)));
});

test('aggregation picks the most severe verdict and keeps field provenance', () => {
  const ioc = normalizeIocForTest('203.0.113.50', 'ipv4');
  const verdicts = [
    // Deliberately out of priority order: the reputation source is queried
    // first, but the abuse source is authoritative for country/ISP.
    baseVerdict({ providerId: 'virustotal', verdict: 'clean', network: { country: 'Nowhere', isp: 'ISP A' } }),
    baseVerdict({ providerId: 'abuseipdb', verdict: 'malicious', network: { country: 'Somewhere', abuseConfidenceScore: 90 } }),
  ];
  const intel = aggregateIntelligence(ioc, verdicts);
  assert.equal(intel.verdict, 'malicious');
  assert.equal(intel.network?.country, 'Somewhere');
  assert.equal(intel.networkProvenance.country, 'abuseipdb');
  assert.equal(intel.corroborationCount, 2);
  assert.equal(intel.maliciousSources.length, 1);
});

test('unknown verdicts from contextual sources do not count as corroboration', () => {
  const ioc = normalizeIocForTest('203.0.113.50', 'ipv4');
  const verdicts = [
    baseVerdict({ providerId: 'shodan', verdict: 'unknown' }),
    baseVerdict({ providerId: 'greynoise', verdict: 'unknown' }),
  ];
  const intel = aggregateIntelligence(ioc, verdicts);
  assert.equal(intel.corroborationCount, 0);
  assert.equal(intel.verdict, 'unknown');
});
