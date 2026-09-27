/**
 * ============================================================================
 * DATABASE SEED  (`npm run seed`)
 * ============================================================================
 *
 * Populates a demo-ready database:
 *   1. MITRE ATT&CK knowledge base (curated subset).
 *   2. The demo analyst account (credentials from .env, with defaults).
 *   3. A back-dated series of investigations over the built-in DEMO dataset so
 *      the dashboard, history and charts are meaningful on first launch.
 *   4. Analyst notes on a few investigations to show the assessment workflow.
 *
 * IMPORTANT: seeding ALWAYS forces DEMO mode, so `npm run seed` never consumes a
 * provider API quota and the result is identical on every machine.
 */
import { config } from '../config/env.js';
import { getDb, q } from './index.js';
import { seedTechniques } from '../repositories/knowledge.js';
import { countUsers, createUser, findUserByEmail } from '../repositories/users.js';
import { startInvestigation } from '../services/investigationService.js';
import { updateInvestigation } from '../repositories/investigations.js';
import { setModeOverride } from '../providers/registry.js';
import { DEMO_CATALOG, DEMO_HASHES, DEMO_INFRA, DEMO_PROFILES } from '../providers/demo/dataset.js';

/** Indicators used to populate the demo, with a fixed back-date in days. */
const SEED_PLAN: Array<{ value: string; daysAgo: number; note?: string; rating?: string; assessment?: string }> = [
  {
    value: DEMO_INFRA.c2Ip,
    daysAgo: 0,
    rating: 'true-positive',
    note:
      'Escalated to the incident response team at 09:20. Blocking the address and both C2 domains pushed to the perimeter deny list; DNS sinkhole rule created for the domain. Two internal hosts had outbound connections to this address in the last 72 hours - endpoints isolated and re-imaged.',
    assessment:
      'Confirmed malicious command-and-control infrastructure belonging to a known fictional cluster. Confidence is high because four independent sources agree, including a distribution-feed listing. The 8443 exposure is consistent with the documented C2 over non-standard port behaviour.',
  },
  {
    value: DEMO_INFRA.phishDomain,
    daysAgo: 1,
    rating: 'true-positive',
    note: 'Mail gateway purge executed for 3 recipients. Two users reported entering credentials; password resets forced and MFA re-enrolled. Domain added to DNS filter.',
    assessment: 'Credential harvesting infrastructure tied to a spearphishing campaign. The phishing and credential-harvesting behaviours co-occur, which is consistent with a phishing kit rather than a compromised legitimate site.',
  },
  {
    value: DEMO_INFRA.payloadUrl,
    daysAgo: 2,
    rating: 'true-positive',
    note: 'URL blocked at the proxy. EDR sweep for the associated sample hash returned no hits, so no further containment was required.',
    assessment: 'Direct payload link on a distribution feed - the strongest evidence class for a URL indicator because it is the artefact itself, not a host proxy.',
  },
  {
    value: DEMO_HASHES.nightfallRAT,
    daysAgo: 3,
    rating: 'true-positive',
    note: 'Sample submitted to the internal sandbox. Recovered configuration matched the C2 domain in the related indicators, so the hash and domain were blocked together.',
    assessment: 'Actor-attributed implant. Attribution for a file hash carries more weight than for an IP because the same file across multiple victims is a strong pivot.',
  },
  {
    value: DEMO_INFRA.loaderIp,
    daysAgo: 3,
    rating: 'true-positive',
    note: 'Added to the blocklist. Proxy log review found 4 internal clients, all belonging to a single marketing workstation that has been rebuilt.',
    assessment: 'Payload staging server. Distribution infrastructure is a weaker indicator of operator control than a C2 node, so the defensive priority is hunting rather than assuming compromise.',
  },
  {
    value: DEMO_INFRA.mail,
    daysAgo: 4,
    rating: 'suspicious',
    note: 'Sender blocklist updated. Additional mail rules created on the lure structure because the sender mailbox is likely disposable.',
    assessment: 'Sender address for spearphishing messages. Rated suspicious rather than true-positive because an email address alone is a volatile indicator - the link and landing domain are the durable ones.',
  },
  {
    value: DEMO_INFRA.c2Domain,
    daysAgo: 5,
    rating: 'true-positive',
    note: 'DNS filter block plus sinkhole. Address list synchronised to the threat feed so the two resolved addresses are covered even if DNS filtering lags.',
    assessment: 'Domain-based C2. Blocking the address alone would allow a fast fallback to the sibling domain, so domain and address were blocked in the same change window.',
  },
  {
    value: DEMO_HASHES.wraithdropLoader,
    daysAgo: 6,
    rating: 'true-positive',
    note: 'EDR query returned 1 hit on a jump host. Host isolated, parent process identified as a browser download, and the scheduled-task persistence was removed.',
    assessment: 'First-stage loader with one internal hit. Detection engineering focused on the parent process chain so the technique is caught even if the hash changes.',
  },
  { value: DEMO_INFRA.docIpv6, daysAgo: 7, rating: 'benign', note: 'Documentation prefix - no action possible or required. Recorded as a control case.', assessment: 'Reserved address space. Included to demonstrate the honest "no intelligence available" path rather than a fabricated result.' },
  { value: DEMO_INFRA.benignResolver, daysAgo: 8, rating: 'benign', note: 'False positive from the abuse reporting feed. Documented the report volume to the feed owner and whitelisted for alerting.', assessment: 'High report volume driven by ubiquity, not abuse. The trusted-infrastructure offset exists precisely for this pattern, and the offset is visible in the risk breakdown so a reviewer can challenge it.' },
  { value: DEMO_HASHES.sablefishStealer, daysAgo: 9, rating: 'true-positive', note: 'No internal matches. Retained in the blocklist.', assessment: 'Modest engine consensus and an older last-seen date, so the score is MEDIUM rather than CRITICAL. The engine is deliberately conservative: weak or stale evidence should not produce a critical alert.' },
  { value: DEMO_INFRA.phishIp, daysAgo: 10, rating: 'true-positive', note: 'Blocked; web gateway rule created for the host.', assessment: 'Phishing site host. Short-lived infrastructure typical of a rotated campaign, so monitoring continues after blocking.' },
  { value: DEMO_HASHES.nightfallScript, daysAgo: 11, rating: 'true-positive', note: 'Script hash added to the EDR detection list.', assessment: 'Script indicator - the only class in this dataset that supports a direct PowerShell ATT&CK mapping.' },
  { value: DEMO_INFRA.benignResolver2, daysAgo: 12, rating: 'benign', note: 'Benign control case.', assessment: 'Second clean control to show the offset keys off the network role rather than a hard-coded address.' },
  { value: DEMO_INFRA.benignQuad9, daysAgo: 12, rating: 'benign', note: 'Benign control case; lower confidence because fewer sources reported.', assessment: 'Clean but low-confidence: only two supporting sources. This separates risk (LOW) from confidence (lower) - two different questions.' },
  { value: DEMO_INFRA.c2Ip2, daysAgo: 13, rating: 'true-positive', note: 'Failover node blocked together with the primary.', assessment: 'Infrastructure continuity evidence: two C2 nodes one address apart indicates an actively maintained estate.' },
  { value: DEMO_INFRA.phishUrl, daysAgo: 13, rating: 'true-positive', note: 'Proxy block plus mail rule on the full URL.', assessment: 'Landing URL with a session token in the query string - a high-signal string for retro-hunting in proxy logs.' },
  { value: DEMO_INFRA.loaderDomain, daysAgo: 14, rating: 'true-positive', note: 'DNS block applied.', assessment: 'Fake-update domain serving a first-stage loader.' },
  { value: DEMO_INFRA.c2Url, daysAgo: 15, rating: 'true-positive', note: 'Beacon URL added to the proxy watchlist for hunting.', assessment: 'Beacon endpoint: hunting this exact path is high-signal and low-volume.' },
  { value: DEMO_INFRA.updateUrl, daysAgo: 16, rating: 'unclassified', note: 'Retrieved from a sandbox report. Not yet triaged.', assessment: 'Retrieved during a previous sandbox run. Left unclassified pending triage.' },
  { value: DEMO_INFRA.cleanDomain, daysAgo: 16, rating: 'benign', note: 'Reserved documentation domain. Control case.', assessment: 'RFC 2606 reserved namespace - no public feed can hold intelligence about it.' },
  { value: DEMO_INFRA.cleanUrl, daysAgo: 17, rating: 'benign', note: 'Reserved documentation URL. Control case.', assessment: 'Control case demonstrating the CLEAN path for a URL indicator.' },
  { value: DEMO_HASHES.benignEditor, daysAgo: 17, rating: 'benign', note: 'Signed software control case.', assessment: 'Clean control: zero malicious engines across 70 is the evidence behind a zero-point score.' },
  { value: DEMO_HASHES.sablefishStealerSha1, daysAgo: 18, rating: 'true-positive', note: 'Alternate hash form for the same stealer component; added to the same detection rule.', assessment: 'Same artefact, different hash algorithm. Demonstrates why a multi-format blocklist matters.' },
  { value: 'xn--pple-43d.example.com', daysAgo: 4, rating: 'suspicious', note: 'Added to the DNS watchlist and to a brand-impersonation monitoring rule. Not blocked - evidence is insufficient.', assessment: 'Suspicious, not proven. An IDN lookalike plus two suspicious verdicts justifies monitoring, and the risk breakdown shows exactly why the score is in the LOW band rather than CRITICAL.' },
  { value: 'k3yv9q2zx7m4p1n8b6w3.example.net', daysAgo: 6, rating: 'suspicious', note: 'DNS sinkhole rule written for the parent domain only. Individual DGA labels cannot be blocklisted in advance, which is the real lesson here.', assessment: 'Algorithmically generated label with a suspicious reputation. The defensive answer is sinkholing the parent domain and detecting resolution attempts, not chasing individual hosts.' },
  { value: 'a.b.c.secure.login-portal-lantern.example.com', daysAgo: 5, rating: 'true-positive', note: 'Wildcard block added for the whole phishing namespace rather than the single host.', assessment: 'Child host of a known-bad namespace. Blocking the registrable domain covers this host and any sibling generated later, which is the durable control.' },
  { value: 'b81f4c2d90a7e63517cd82fb5e0a49173d6c2b8e5f04a91c37d2e6b580af31c7', daysAgo: 19, rating: 'unclassified', note: 'Sent to the internal sandbox for a definitive verdict. No blocking action taken.', assessment: 'Single engine hit. Correctly left unclassified - this is the case that shows why the engine requires multi-engine consensus before using the word malicious.' },
  { value: '203.0.113.140', daysAgo: 20, rating: 'suspicious', note: 'Monitored, not blocked. Bulk hosting address - blocking would deny service to unrelated tenants.', assessment: 'Shared hosting with light abuse history. The recommendations engine explicitly says monitor rather than block, which is the correct call for bulk-hosting addresses.' },
];

/**
 * Shift an investigation's timestamps backwards so the demo has history.
 * Only used by the seeder - never at runtime.
 */
function backdate(investigationId: number, daysAgo: number): void {
  const at = new Date(Date.now() - daysAgo * 86_400_000).toISOString();
  q.run('UPDATE investigations SET started_at = ?, created_at = ?, updated_at = ? WHERE id = ?', [at, at, at, investigationId]);
  q.run('UPDATE investigation_timeline SET at = ? WHERE investigation_id = ?', [at, investigationId]);
  q.run('UPDATE enrichment_results SET created_at = ? WHERE investigation_id = ?', [at, investigationId]);
  q.run("UPDATE investigations SET completed_at = datetime(?, '+0.5 seconds') WHERE id = ?", [at, investigationId]);
}

async function main(): Promise<void> {
  getDb();
  const techniques = seedTechniques();
  console.log(`  seeded ${techniques} MITRE ATT&CK technique entries`);

  let analystId: number;
  if (countUsers() === 0) {
    const user = createUser({
      email: config.seedAnalyst.email,
      password: config.seedAnalyst.password,
      displayName: config.seedAnalyst.name,
      role: 'analyst',
    });
    analystId = user.id;
    console.log(`  created analyst ${user.email}`);
  } else {
    const existing = findUserByEmail(config.seedAnalyst.email);
    if (!existing) {
      const user = createUser({
        email: config.seedAnalyst.email,
        password: config.seedAnalyst.password,
        displayName: config.seedAnalyst.name,
        role: 'analyst',
      });
      analystId = user.id;
      console.log(`  created analyst ${user.email}`);
    } else {
      analystId = existing.id;
      console.log(`  analyst ${existing.email} already exists`);
    }
  }

  // Seeding always uses the demo dataset.
  setModeOverride('demo');

  const existingCount = q.get<{ n: number }>('SELECT COUNT(*) AS n FROM investigations')?.n ?? 0;
  if (existingCount > 0 && !process.argv.includes('--force')) {
    console.log(`  ${existingCount} investigation(s) already present - skipping sample data.`);
    console.log('  Run `npm run db:reset` first, or `npm run seed -- --force`, to rebuild the sample set.');
    return;
  }

  const seen = new Set<string>();
  let created = 0;
  for (const entry of SEED_PLAN) {
    if (seen.has(entry.value)) continue;
    seen.add(entry.value);

    const outcome = await startInvestigation(
      { indicator: entry.value, userId: analystId, forceMode: 'demo' },
      { awaitCompletion: true },
    );
    if (!outcome.ok) {
      console.warn(`  ! ${entry.value}: ${outcome.error.message}`);
      continue;
    }
    backdate(outcome.investigation.id, entry.daysAgo);
    if (entry.note || entry.assessment || entry.rating) {
      updateInvestigation(outcome.investigation.id, {
        analyst_notes: entry.note ?? null,
        analyst_assessment: entry.assessment ?? null,
        analyst_rating: entry.rating ?? null,
      });
    }
    created += 1;
  }

  // Restore whatever mode the environment requested (the Settings page can
  // still override it at runtime).
  setModeOverride(null);

  const summary = q.get<{ total: number }>('SELECT COUNT(*) AS total FROM investigations');
  const profiles = DEMO_PROFILES.length;
  console.log('');
  console.log(`  created ${created} sample investigations (${profiles} demo profiles available)`);
  console.log(`  database now holds ${summary?.total ?? created} investigations`);
  console.log('');
  console.log('  Demo sign-in');
  console.log(`    email    : ${config.seedAnalyst.email}`);
  console.log(`    password : ${config.seedAnalyst.password}`);
  console.log('');
  console.log('  Try the walkthrough indicators on the /investigate page:');
  for (const c of DEMO_CATALOG.slice(0, 5)) {
    console.log(`    ${c.value.padEnd(46)} ${c.expectedLevel}`);
  }
  console.log('');
}

main()
  .catch((err) => {
    console.error('seed failed:', err);
    process.exitCode = 1;
  })
  .finally(() => {
    // better-sqlite3 is synchronous, so the process exits naturally.
  });
